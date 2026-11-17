"""Every SNMP type a recording holds is served as the type it is, in each version.

A recording with each type `.snmprec` knows - the SMIv2 ones, Opaque and
Counter64, the three exceptions - in the plain, the hex (`x`) and the escaped
(`e`) forms, with the values at the edges of each type's range. The engine
path is the reference: each value has to come back as the octets the value
of its type encodes to, and the fast path has to answer every request the
way the engine path does, SNMPv1 included, where Counter64 and the
exceptions have no place. SNMPv3, which always goes through the engine, has
to serve every value as SNMPv2c does.

The messages are made and read here, octet for octet, SNMPv3 ones as well
(noAuthNoPriv): pysnmp's own client refuses an INTEGER outside the range of
Integer32, which is served as the device sent it, and leaves the request to
time out.
"""
import pytest
import snmp_messages
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp.proto import rfc1902
from pysnmp.proto import rfc1905
from snmp_messages import V1
from snmp_messages import V2C
from snmp_messages import answer
from snmp_messages import ask
from snmp_messages import engine_id

from snmpsim.grammar import unconstrained

PORTS = {"fast": 1696, "engine": 1697}

# a USM user without keys: noAuthNoPriv
V3_USER = "typer"

BASE = "1.3.6.1.4.1.99999.9"

LONG_TEXT = "x" * 1000

# (recorded tag, recorded value, the value it has to be served as); None
# for a value whose encoding is the record's own business, an exception
VALUES = [
    # INTEGER: the edges of Integer32, and one past them, which a device
    # sent and is served with the octets it sent
    ("2", "0", unconstrained.Integer32(0)),
    ("2", "-1", unconstrained.Integer32(-1)),
    ("2", "2147483647", unconstrained.Integer32(2147483647)),
    ("2", "-2147483648", unconstrained.Integer32(-2147483648)),
    ("2", "4294967295", unconstrained.Integer32(4294967295)),
    # OCTET STRING: empty, text, binary, UTF-8, escaped, pipes inside, long
    ("4", "", rfc1902.OctetString(b"")),
    ("4", "plain text", rfc1902.OctetString(b"plain text")),
    ("4x", "00ff7f80", rfc1902.OctetString(b"\x00\xff\x7f\x80")),
    ("4x", "d09fd180d0b8d0b2d0b5d182", rfc1902.OctetString("Привет".encode())),
    ("4e", r"line\nbreak\x00nul", rfc1902.OctetString(b"line\nbreak\x00nul")),
    ("4", "a|b|c", rfc1902.OctetString(b"a|b|c")),
    ("4", LONG_TEXT, rfc1902.OctetString(LONG_TEXT.encode())),
    # NULL
    ("5", "", univ.Null("")),
    # OBJECT IDENTIFIER: a plain one, a single arc (served as its two-arc
    # form), the largest arc
    ("6", "1.3.6.1.4.1.99999", rfc1902.ObjectName("1.3.6.1.4.1.99999")),
    ("6", "0", rfc1902.ObjectName("0.0")),
    ("6", "1.3.6.1.4294967295", rfc1902.ObjectName("1.3.6.1.4294967295")),
    # IpAddress, dotted and in hex
    ("64", "192.0.2.1", rfc1902.IpAddress("192.0.2.1")),
    ("64x", "c0000201", rfc1902.IpAddress("192.0.2.1")),
    ("64", "0.0.0.0", rfc1902.IpAddress("0.0.0.0")),
    ("64", "255.255.255.255", rfc1902.IpAddress("255.255.255.255")),
    # the unsigned 32-bit ones at both ends
    ("65", "0", rfc1902.Counter32(0)),
    ("65", "4294967295", rfc1902.Counter32(4294967295)),
    ("66", "0", rfc1902.Gauge32(0)),
    ("66", "4294967295", rfc1902.Gauge32(4294967295)),
    ("67", "0", rfc1902.TimeTicks(0)),
    ("67", "4294967295", rfc1902.TimeTicks(4294967295)),
    # Opaque: net-snmp's Float, and text
    ("68x", "9f780442c80000", rfc1902.Opaque(b"\x9f\x78\x04\x42\xc8\x00\x00")),
    ("68", "opaque text", rfc1902.Opaque(b"opaque text")),
    # Counter64 at both ends
    ("70", "0", rfc1902.Counter64(0)),
    ("70", "18446744073709551615", rfc1902.Counter64(18446744073709551615)),
    # the exceptions a recording may hold for a variable: the answer to a GET
    # of it, stepped over by GETNEXT and GETBULK (RFC 3416, 4.2.2)
    ("128", "", rfc1905.NoSuchObject("")),
    ("129", "", rfc1905.NoSuchInstance("")),
    ("130", "", rfc1905.EndOfMibView("")),
    # a value behind them, which a walk has to reach
    ("4", "after the exceptions", rfc1902.OctetString(b"after the exceptions")),
    # the error module asked to send one: it is sent, GETNEXT included
    ("2:error", "status=noSuchInstance", rfc1905.NoSuchInstance("")),
]

# the records a GETNEXT or GETBULK steps over
EXCEPTIONS = ("128", "129", "130")

OIDS = [f"{BASE}.{n}.0" for n in range(1, len(VALUES) + 1)]

RECORDING = "".join(
    f"{oid}|{tag}|{value}\n" for oid, (tag, value, _) in zip(OIDS, VALUES)
)


# a run of exceptions in the middle of a recording, and another at its end
EDGES = "1.3.6.1.4.1.99999.8"

EDGES_RECORDING = f"""\
{EDGES}.1.0|4|before
{EDGES}.3.0|128|
{EDGES}.4.0|129|
{EDGES}.4.1|130|
{EDGES}.5.0|4|after
{EDGES}.6.0|130|
{EDGES}.7.0|129|
"""


def message(version, pdu_type, oids, repetitions=0, community="types"):
    return snmp_messages.message(version, pdu_type, oids, community, repetitions)


def v3_message(pdu_type, oids, engine_id, repetitions=0, context="types", user=V3_USER):
    return snmp_messages.v3_message(
        pdu_type, oids, engine_id, context, user, repetitions
    )


@pytest.fixture(scope="module")
def responders(tmp_path_factory, responder_process):
    data = tmp_path_factory.mktemp("data")
    (data / "types.snmprec").write_text(RECORDING, encoding="utf-8")
    (data / "edges.snmprec").write_text(EDGES_RECORDING)

    with responder_process(
        f"--data-dir={data}",
        f"--cache-dir={tmp_path_factory.mktemp('fast-cache')}",
        "--v1-v2c-path=fast",
        # the long string and all the others in one GETBULK response
        "--max-message-size=65000",
        f"--v3-user={V3_USER}",
        port=PORTS["fast"],
        oid=OIDS[0],
        community="types",
    ), responder_process(
        f"--data-dir={data}",
        f"--cache-dir={tmp_path_factory.mktemp('engine-cache')}",
        "--v1-v2c-path=engine",
        "--max-message-size=65000",
        f"--v3-user={V3_USER}",
        port=PORTS["engine"],
        oid=OIDS[0],
        community="types",
    ):
        yield {path: engine_id(port) for path, port in PORTS.items()}


def both(request):
    fast, engine = ask(PORTS["fast"], request), ask(PORTS["engine"], request)

    assert engine is not None
    assert fast == engine

    return engine


@pytest.mark.parametrize(
    "oid, recorded, expected",
    [
        (oid, (tag, value[:40]), expected)
        for oid, (tag, value, expected) in zip(OIDS, VALUES)
    ],
    ids=[f"{tag}|{value[:20]}" for tag, value, _ in VALUES],
)
def test_v2c_get_serves_the_value_as_its_type(responders, oid, recorded, expected):
    error_status, error_index, var_binds = answer(
        both(message(V2C, "GetRequestPDU", [oid]))
    )

    assert (error_status, error_index) == (0, 0)
    assert var_binds == [(oid, encoder.encode(expected))]


@pytest.mark.parametrize("oid", OIDS, ids=[f"{t}|{v[:20]}" for t, v, _ in VALUES])
def test_v1_get_is_answered_alike(responders, oid):
    error_status, _, var_binds = answer(both(message(V1, "GetRequestPDU", [oid])))

    tag = VALUES[OIDS.index(oid)][0]

    # an SNMPv1 manager cannot be sent a Counter64 or an exception
    if tag in ("70", "128", "129", "130", "2:error"):
        assert error_status == 2

    else:
        assert error_status == 0
        assert var_binds[0][0] == oid


@pytest.mark.parametrize("version", [V1, V2C], ids=["v1", "v2c"])
def test_getnext_walks_the_types_alike(responders, version):
    oid, served = BASE, []

    while True:
        error_status, _, var_binds = answer(
            both(message(version, "GetNextRequestPDU", [oid]))
        )

        if error_status or not var_binds[0][0].startswith(BASE + "."):
            break

        oid, value = var_binds[0]
        served.append(oid)

        assert len(served) <= len(OIDS)

        # a manager's walk ends at an exception, which only the error
        # module sends here
        if value[0] in (0x80, 0x81, 0x82):
            break

    # every variable that has a value is walked onto, past the recorded
    # exceptions, up to the one the error module sends; SNMPv1 steps over the
    # Counter64 it cannot be sent, and gets noSuchName for the error module's
    skipped = set(EXCEPTIONS) | ({"70", "2:error"} if version == V1 else set())

    assert served == [
        oid for oid, (tag, _, _) in zip(OIDS, VALUES) if tag not in skipped
    ]


def test_getbulk_serves_the_types_alike(responders):
    error_status, _, var_binds = answer(
        both(message(V2C, "GetBulkRequestPDU", [BASE], repetitions=len(OIDS) + 2))
    )

    # the first answer for each variable: the repetitions past the end of
    # the recording repeat the last OID with endOfMibView
    walked = {}

    for oid, value in var_binds:
        if oid.startswith(BASE + "."):
            walked.setdefault(oid, value)

    # every variable but the recorded exceptions; the error module's is sent
    assert error_status == 0
    assert walked == {
        oid: encoder.encode(expected)
        for oid, (tag, _, expected) in zip(OIDS, VALUES)
        if tag not in EXCEPTIONS
    }


def ask_edges(version, pdu_type, oids, repetitions=0):
    return answer(
        both(message(version, pdu_type, oids, repetitions, community="edges"))
    )


@pytest.mark.parametrize(
    "start",
    [f"{EDGES}.1.0", f"{EDGES}.3", f"{EDGES}.3.0", f"{EDGES}.4.0"],
    ids=["before the run", "between records", "on an exception", "inside the run"],
)
def test_getnext_steps_over_a_run_of_exceptions(responders, start):
    error_status, _, var_binds = ask_edges(V2C, "GetNextRequestPDU", [start])

    assert error_status == 0
    assert var_binds == [
        (f"{EDGES}.5.0", encoder.encode(rfc1902.OctetString(b"after")))
    ]


def test_getnext_past_the_last_value_is_the_end_of_the_mib(responders):
    # only exceptions are left: nothing has a value any more
    _, _, var_binds = ask_edges(V2C, "GetNextRequestPDU", [f"{EDGES}.5.0"])

    assert var_binds == [(f"{EDGES}.5.0", encoder.encode(rfc1905.EndOfMibView("")))]

    error_status, error_index, _ = ask_edges(V1, "GetNextRequestPDU", [f"{EDGES}.5.0"])

    assert (error_status, error_index) == (2, 1)


def test_getbulk_steps_over_a_run_of_exceptions(responders):
    error_status, _, var_binds = ask_edges(
        V2C, "GetBulkRequestPDU", [f"{EDGES}.1"], repetitions=4
    )

    assert error_status == 0
    assert [oid for oid, _ in var_binds][:2] == [f"{EDGES}.1.0", f"{EDGES}.5.0"]
    assert all(value == b"\x82\x00" for _, value in var_binds[2:])


def test_get_of_a_recorded_exception_answers_with_it(responders):
    error_status, _, var_binds = ask_edges(
        V2C, "GetRequestPDU", [f"{EDGES}.3.0", f"{EDGES}.4.0", f"{EDGES}.4.1"]
    )

    assert error_status == 0
    assert [value for _, value in var_binds] == [b"\x80\x00", b"\x81\x00", b"\x82\x00"]


def both_v3(responders, pdu_type, oids, repetitions=0, context="types"):
    """The answer of both responders to an SNMPv3 request, which must agree.

    Each has an engine ID of its own, so the messages differ; what they
    carry must not.
    """
    answers = [
        answer(
            ask(
                port, v3_message(pdu_type, oids, responders[path], repetitions, context)
            )
        )
        for path, port in PORTS.items()
    ]

    assert answers[0] == answers[1]

    return answers[0]


@pytest.mark.parametrize(
    "oid, expected",
    [(oid, expected) for oid, (_, _, expected) in zip(OIDS, VALUES)],
    ids=[f"{tag}|{value[:20]}" for tag, value, _ in VALUES],
)
def test_v3_get_serves_the_value_as_v2c_does(responders, oid, expected):
    assert both_v3(responders, "GetRequestPDU", [oid]) == (
        0,
        0,
        [(oid, encoder.encode(expected))],
    )


def test_v3_getnext_walks_the_types_as_v2c_does(responders):
    oid, served = BASE, []

    while True:
        error_status, _, var_binds = both_v3(responders, "GetNextRequestPDU", [oid])

        if error_status or not var_binds[0][0].startswith(BASE + "."):
            break

        oid, value = var_binds[0]
        served.append(oid)

        assert len(served) <= len(OIDS)

        if value[0] in (0x80, 0x81, 0x82):
            break

    assert served == [
        oid for oid, (tag, _, _) in zip(OIDS, VALUES) if tag not in EXCEPTIONS
    ]


def test_v3_getbulk_serves_the_types_as_v2c_does(responders):
    _, _, v2c_var_binds = answer(
        both(message(V2C, "GetBulkRequestPDU", [BASE], repetitions=len(OIDS) + 2))
    )

    assert both_v3(
        responders, "GetBulkRequestPDU", [BASE], repetitions=len(OIDS) + 2
    ) == (0, 0, v2c_var_binds)


@pytest.mark.parametrize("start", [f"{EDGES}.1.0", f"{EDGES}.3", f"{EDGES}.4.0"])
def test_v3_getnext_steps_over_a_run_of_exceptions(responders, start):
    assert both_v3(responders, "GetNextRequestPDU", [start], context="edges") == (
        0,
        0,
        [(f"{EDGES}.5.0", encoder.encode(rfc1902.OctetString(b"after")))],
    )


def test_v3_answers_the_end_and_the_exceptions_as_v2c_does(responders):
    for pdu_type, oids in [
        ("GetNextRequestPDU", [f"{EDGES}.5.0"]),
        ("GetRequestPDU", [f"{EDGES}.3.0", f"{EDGES}.4.0", f"{EDGES}.4.1"]),
    ]:
        assert both_v3(responders, pdu_type, oids, context="edges") == ask_edges(
            V2C, pdu_type, oids
        )
