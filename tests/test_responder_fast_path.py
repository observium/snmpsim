"""SNMPv1 and SNMPv2c answered by the simulator itself, as the engine answers them.

`--v1-v2c-path=fast` answers SNMPv1/v2c requests without pysnmp's SNMPv3
engine, `--v1-v2c-path=engine` sends them through it, as every release before
did. The engine path is the reference: the same raw request sent to a
responder on each path must come back as the same octets.
"""
import hashlib
import json
import socket
import time

import pytest
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp.proto import api
from pysnmp.proto import rfc1902

from snmpsim import ber

FAST_PORT = 1692
ENGINE_PORT = 1693

V1 = api.SNMP_VERSION_1
V2C = api.SNMP_VERSION_2C

SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
SYS_SERVICES = "1.3.6.1.2.1.1.7.0"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6.1"

LONG_COMMUNITY = "a-community-name-longer-than-thirty-two"

# where a request to a responder with a single endpoint comes in by
TRANSPORT_ID = "1.3.6.1.6.1.1.0"

SYS_CONTACT = "1.3.6.1.2.1.1.4.0"

# a variation module that writes down the context it is called with
CONTEXT_RECORDER = """\
import json

CALL_KEYS = (
    "transportDomain",
    "transportProtocol",
    "securityModel",
    "securityName",
    "securityLevel",
    "contextName",
    "pduType",
    "nextFlag",
    "setFlag",
    "origOid",
    "dataFile",
)


def init(**context):
    moduleContext["path"] = context["options"]


def variate(oid, tag, value, **context):
    if not context["nextFlag"] and not context["exactMatch"]:
        return context["origOid"], tag, context["errorStatus"]

    seen = {key: repr(context.get(key)) for key in CALL_KEYS}

    # the peer's port differs from one request to the next, its host does not;
    # the two responders listen on ports of their own
    seen["transportAddress"] = repr(context["transportAddress"][0])
    seen["transportEndpoint"] = repr(context["transportEndpoint"].rsplit(":", 1)[0])

    # one engine per responder: what matters is that the context names it
    engine = context["snmpEngine"]
    seen["contextEngineId is the engine's"] = (
        context["contextEngineId"] == engine.snmpEngineID
    )

    with open(moduleContext["path"], "a") as recorded:
        recorded.write(json.dumps(seen, sort_keys=True) + "\\n")

    return oid, tag, value


def shutdown(**context):
    pass
"""

PLAIN = """\
1.3.6.1.2.1.1.1.0|4|a recording served by its community
1.3.6.1.2.1.1.3.0|67|123456
1.3.6.1.2.1.1.4.0|4:ctxrec|contact
1.3.6.1.2.1.1.5.0|4|plain-host
1.3.6.1.2.1.1.6.0|4:writecache|value=room
1.3.6.1.2.1.1.7.0|2:error|status=noSuchName
1.3.6.1.2.1.2.1.0|2|2
1.3.6.1.2.1.2.2.1.1.1|2|1
1.3.6.1.2.1.2.2.1.1.2|2|2
1.3.6.1.2.1.2.2.1.2.1|4|eth0
1.3.6.1.2.1.2.2.1.2.2|4|eth1
1.3.6.1.2.1.31.1.1.1.6.1|70|12345678901
1.3.6.1.2.1.31.1.1.1.6.2|70|5
"""


def message(version, community, pdu_type, var_binds, non_repeaters=0, repetitions=5):
    """Encode a request with a fixed request-id, so that answers compare."""
    proto = api.PROTOCOL_MODULES[version]

    pdu = getattr(proto, pdu_type)()

    if pdu_type == "GetBulkRequestPDU":
        proto.apiBulkPDU.set_defaults(pdu)
        proto.apiBulkPDU.set_non_repeaters(pdu, non_repeaters)
        proto.apiBulkPDU.set_max_repetitions(pdu, repetitions)

    else:
        proto.apiPDU.set_defaults(pdu)

    proto.apiPDU.set_request_id(pdu, 4242)
    proto.apiPDU.set_varbinds(
        pdu,
        [
            (rfc1902.ObjectName(oid), univ.Null("") if value is None else value)
            for oid, value in var_binds
        ],
    )

    msg = proto.Message()
    proto.apiMessage.set_defaults(msg)
    proto.apiMessage.set_community(msg, community)
    proto.apiMessage.set_pdu(msg, pdu)

    return encoder.encode(msg)


def ask(port, request):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(request, ("127.0.0.1", port))

        try:
            return sock.recv(65535)

        except socket.timeout:
            return None


def show(version, response):
    """The answer in words, for a failing assertion to say what differs."""
    if response is None:
        return "no response"

    proto = api.PROTOCOL_MODULES[version]
    msg, _ = decoder.decode(response, asn1Spec=proto.Message())
    pdu = proto.apiMessage.get_pdu(msg)

    return "error-status %s, error-index %s, %s" % (
        proto.apiPDU.get_error_status(pdu),
        proto.apiPDU.get_error_index(pdu),
        ", ".join(
            f"{oid}={value.__class__.__name__}:{value.prettyPrint()}"
            for oid, value in proto.apiPDU.get_varbinds(pdu)
        ),
    )


# requests whose answers the two paths must agree on octet for octet
SAME = [
    ("v2c GET", V2C, "plain", "GetRequestPDU", [(SYS_NAME, None)], {}),
    ("v1 GET", V1, "plain", "GetRequestPDU", [(SYS_NAME, None)], {}),
    (
        "v2c GET of three",
        V2C,
        "plain",
        "GetRequestPDU",
        [(SYS_NAME, None), ("1.3.6.1.2.1.1.3.0", None), ("1.3.6.1.2.1.1.1.0", None)],
        {},
    ),
    (
        "v2c GET missing",
        V2C,
        "plain",
        "GetRequestPDU",
        [("1.3.6.1.2.1.1.9.9", None)],
        {},
    ),
    ("v1 GET missing", V1, "plain", "GetRequestPDU", [("1.3.6.1.2.1.1.9.9", None)], {}),
    ("v1 GET Counter64", V1, "plain", "GetRequestPDU", [(IF_HC_IN_OCTETS, None)], {}),
    ("v2c GETNEXT", V2C, "plain", "GetNextRequestPDU", [("1.3.6.1.2.1.2.2", None)], {}),
    ("v1 GETNEXT", V1, "plain", "GetNextRequestPDU", [("1.3.6.1.2.1.2.2", None)], {}),
    (
        "v1 GETNEXT onto a Counter64",
        V1,
        "plain",
        "GetNextRequestPDU",
        [("1.3.6.1.2.1.31.1.1.1.6", None)],
        {},
    ),
    (
        "v2c GETNEXT past the end",
        V2C,
        "plain",
        "GetNextRequestPDU",
        [("1.3.6.1.9", None)],
        {},
    ),
    (
        "v1 GETNEXT past the end",
        V1,
        "plain",
        "GetNextRequestPDU",
        [("1.3.6.1.9", None)],
        {},
    ),
    (
        "v2c GETBULK",
        V2C,
        "plain",
        "GetBulkRequestPDU",
        [("1.3.6.1.2.1.1.1", None), ("1.3.6.1.2.1.2.2.1", None)],
        {"non_repeaters": 1, "repetitions": 4},
    ),
    (
        "v2c GETBULK past the end",
        V2C,
        "plain",
        "GetBulkRequestPDU",
        [("1.3.6.1.2.1.31.1.1.1.6", None)],
        {"repetitions": 5},
    ),
    (
        "v2c GETBULK into the error module",
        V2C,
        "plain",
        "GetBulkRequestPDU",
        [("1.3.6.1.2.1.1.5", None), ("1.3.6.1.2.1.1", None)],
        {"non_repeaters": 1, "repetitions": 3},
    ),
    (
        "v2c GET of three, the second from the error module",
        V2C,
        "plain",
        "GetRequestPDU",
        [(SYS_NAME, None), (SYS_SERVICES, None), (SYS_LOCATION, None)],
        {},
    ),
    (
        "v1 GET of three, the second from the error module",
        V1,
        "plain",
        "GetRequestPDU",
        [(SYS_NAME, None), (SYS_SERVICES, None), (SYS_LOCATION, None)],
        {},
    ),
    (
        "v2c SET",
        V2C,
        "plain",
        "SetRequestPDU",
        [(SYS_LOCATION, rfc1902.OctetString("lab"))],
        {},
    ),
    (
        "v2c SET of a record without a module",
        V2C,
        "plain",
        "SetRequestPDU",
        [(SYS_NAME, rfc1902.OctetString("x"))],
        {},
    ),
    (
        "v1 SET of a record without a module",
        V1,
        "plain",
        "SetRequestPDU",
        [(SYS_NAME, rfc1902.OctetString("x"))],
        {},
    ),
    (
        "v2c long community",
        V2C,
        LONG_COMMUNITY,
        "GetRequestPDU",
        [(SYS_NAME, None)],
        {},
    ),
    ("v2c unknown community", V2C, "nosuch", "GetRequestPDU", [(SYS_NAME, None)], {}),
    # names a recording is registered under, but no community of it
    (
        "v2c md5 of a community",
        V2C,
        hashlib.md5(b"plain").hexdigest(),
        "GetRequestPDU",
        [(SYS_NAME, None)],
        {},
    ),
    (
        "v2c community with ..",
        V2C,
        "x/../plain",
        "GetRequestPDU",
        [(SYS_NAME, None)],
        {},
    ),
    ("v2c community above", V2C, "../plain", "GetRequestPDU", [(SYS_NAME, None)], {}),
    (
        "v2c GETBULK of nothing",
        V2C,
        "plain",
        "GetBulkRequestPDU",
        [(SYS_NAME, None)],
        {"repetitions": 0},
    ),
    ("v2c GET of no variables", V2C, "plain", "GetRequestPDU", [], {}),
    (
        "v1 GET missing, then a Counter64",
        V1,
        "plain",
        "GetRequestPDU",
        [("1.3.6.1.2.1.1.9.9", None), (IF_HC_IN_OCTETS, None)],
        {},
    ),
    (
        "v1 GET Counter64, then missing",
        V1,
        "plain",
        "GetRequestPDU",
        [(IF_HC_IN_OCTETS, None), ("1.3.6.1.2.1.1.9.9", None)],
        {},
    ),
    (
        "v1 GET present, then two missing",
        V1,
        "plain",
        "GetRequestPDU",
        [(SYS_NAME, None), ("1.3.6.1.2.1.1.9.9", None), ("1.3.6.1.2.1.1.9.8", None)],
        {},
    ),
    (
        "v1 GETNEXT of three, the last onto a Counter64",
        V1,
        "plain",
        "GetNextRequestPDU",
        [
            ("1.3.6.1.2.1.1.1", None),
            ("1.3.6.1.2.1.2.2", None),
            ("1.3.6.1.2.1.31.1.1.1.6", None),
        ],
        {},
    ),
    (
        "v1 GETNEXT past the end and onto a Counter64",
        V1,
        "plain",
        "GetNextRequestPDU",
        [("1.3.6.1.9", None), ("1.3.6.1.2.1.31.1.1.1.6", None)],
        {},
    ),
    (
        "v1 GETNEXT into the error module",
        V1,
        "plain",
        "GetNextRequestPDU",
        [(SYS_LOCATION, None)],
        {},
    ),
    ("v1 long community", V1, LONG_COMMUNITY, "GetRequestPDU", [(SYS_NAME, None)], {}),
    ("v1 unknown community", V1, "nosuch", "GetRequestPDU", [(SYS_NAME, None)], {}),
    ("v1 community above", V1, "../plain", "GetRequestPDU", [(SYS_NAME, None)], {}),
    ("v1 GET of no variables", V1, "plain", "GetRequestPDU", [], {}),
    (
        "v1 data index",
        V1,
        "index",
        "GetNextRequestPDU",
        [("1.3.6.1.4.1.20408.999", None)],
        {},
    ),
    (
        "v2c data index",
        V2C,
        "index",
        "GetNextRequestPDU",
        [("1.3.6.1.4.1.20408.999", None)],
        {},
    ),
]


@pytest.fixture(scope="module")
def recordings(tmp_path_factory):
    data = tmp_path_factory.mktemp("data")

    (data / "plain.snmprec").write_text(PLAIN)
    (data / f"{LONG_COMMUNITY}.snmprec").write_text(PLAIN)

    # one recording for the requests that come in by the transport and from
    # the address of the tests, and none for the others
    (data / "byaddr" / TRANSPORT_ID).mkdir(parents=True)
    (data / "byaddr" / TRANSPORT_ID / "127.0.0.1.snmprec").write_text(
        "1.3.6.1.2.1.1.5.0|4|by-address\n"
    )

    # the same, next to a recording of the community alone
    (data / "both.snmprec").write_text("1.3.6.1.2.1.1.5.0|4|both-plain\n")
    (data / "both" / TRANSPORT_ID).mkdir(parents=True)
    (data / "both" / TRANSPORT_ID / "127.0.0.1.snmprec").write_text(
        "1.3.6.1.2.1.1.5.0|4|both-by-address\n"
    )

    return data


@pytest.fixture(scope="module")
def variation_dir(tmp_path_factory):
    modules = tmp_path_factory.mktemp("variation")
    (modules / "ctxrec.py").write_text(CONTEXT_RECORDER)
    return modules


@pytest.fixture(scope="module")
def responders(recordings, variation_dir, tmp_path_factory, responder_process):
    """One responder on each path, over the same recordings.

    Returns where each wrote down the contexts its variation modules saw and
    where each keeps its activity reports.
    """
    seen = {}

    def options(path):
        scratch = tmp_path_factory.mktemp(path)
        seen[path] = scratch

        return (
            f"--data-dir={recordings}",
            f"--cache-dir={scratch / 'cache'}",
            f"--variation-modules-dir={variation_dir}",
            f"--variation-module-options=ctxrec:{scratch / 'contexts'}",
            f"--reporting-method=fulljson:{scratch / 'reports'}:1",
            f"--v1-v2c-path={path}",
        )

    with responder_process(
        *options("fast"), port=FAST_PORT, oid=SYS_NAME, community="plain"
    ), responder_process(
        *options("engine"), port=ENGINE_PORT, oid=SYS_NAME, community="plain"
    ):
        yield seen


@pytest.mark.parametrize(
    "version, community, pdu_type, var_binds, bulk",
    [case[1:] for case in SAME],
    ids=[case[0] for case in SAME],
)
def test_both_paths_answer_alike(
    responders, version, community, pdu_type, var_binds, bulk
):
    request = message(version, community, pdu_type, var_binds, **bulk)

    engine = ask(ENGINE_PORT, request)
    fast = ask(FAST_PORT, request)

    assert show(version, fast) == show(version, engine)
    assert fast == engine


def test_octets_past_the_message_are_dropped_on_both_paths(responders):
    request = message(V2C, "plain", "GetRequestPDU", [(SYS_NAME, None)]) + b"\x00\x00"

    assert ask(ENGINE_PORT, request) is None
    assert ask(FAST_PORT, request) is None


def snmpv1_message(pdu_tag, request_id=7, error_index=0, version=0):
    """An SNMPv1 read put together by hand, for what pysnmp cannot encode."""
    var_bind = ber.tlv(0x30, ber.encode_oid((1, 3, 6, 1, 2, 1, 1, 5, 0)) + b"\x05\x00")
    pdu = ber.tlv(
        pdu_tag,
        ber.tlv(2, ber.integer_contents(request_id))
        + ber.tlv(2, b"\x00")
        + ber.tlv(2, ber.integer_contents(error_index))
        + ber.tlv(0x30, var_bind),
    )
    return ber.tlv(
        0x30, ber.tlv(2, ber.integer_contents(version)) + ber.tlv(4, b"plain") + pdu
    )


@pytest.mark.parametrize(
    "octets",
    [
        snmpv1_message(0xA5),
        snmpv1_message(0xA0, request_id=2**31),
        snmpv1_message(0xA1, request_id=-(2**70)),
        snmpv1_message(0xA0, request_id=2**31, error_index=2**31),
        snmpv1_message(0xA3, request_id=2**31),
        snmpv1_message(0xA0, error_index=-1),
        snmpv1_message(0xA0, error_index=2**31),
        snmpv1_message(0xA1, error_index=9),
    ],
    ids=[
        "v1 GETBULK",
        "request-id past Integer32",
        "negative request-id of 71 bits",
        "request-id and error-index past Integer32",
        "SET, request-id past Integer32",
        "negative error-index",
        "error-index past Integer32",
        "error-index past the var-binds",
    ],
)
def test_odd_snmpv1_reads_are_answered_alike(responders, octets):
    engine = ask(ENGINE_PORT, octets)
    fast = ask(FAST_PORT, octets)

    assert show(V1, fast) == show(V1, engine)
    assert fast == engine


def get_sys_name(port, community):
    return show(
        V2C, ask(port, message(V2C, community, "GetRequestPDU", [(SYS_NAME, None)]))
    )


def test_the_fast_path_chooses_by_transport_and_address_as_documented(responders):
    # only a recording for the transport and the address: the engine path
    # admits a community only if a recording is named exactly so
    assert "by-address" in get_sys_name(FAST_PORT, "byaddr")
    assert get_sys_name(ENGINE_PORT, "byaddr") == "no response"

    # the most specific recording first
    assert "both-by-address" in get_sys_name(FAST_PORT, "both")
    assert "both-plain" in get_sys_name(ENGINE_PORT, "both")


def recorded_contexts(responders, path):
    recorded = responders[path] / "contexts"

    if not recorded.exists():
        return []

    return [json.loads(line) for line in recorded.read_text().splitlines()]


@pytest.mark.parametrize(
    "version, pdu_type",
    [
        (V2C, "GetRequestPDU"),
        (V1, "GetRequestPDU"),
        (V2C, "GetNextRequestPDU"),
        (V1, "GetNextRequestPDU"),
        (V2C, "GetBulkRequestPDU"),
    ],
)
def test_variation_modules_are_told_the_same_on_both_paths(
    responders, version, pdu_type
):
    oid = SYS_CONTACT if pdu_type == "GetRequestPDU" else "1.3.6.1.2.1.1.3.0"
    request = message(version, "plain", pdu_type, [(oid, None)], repetitions=1)

    before = {path: len(recorded_contexts(responders, path)) for path in responders}

    assert ask(FAST_PORT, request) == ask(ENGINE_PORT, request)

    fast = recorded_contexts(responders, "fast")[before["fast"] :]
    engine = recorded_contexts(responders, "engine")[before["engine"] :]

    assert len(fast) == len(engine) == 1

    differ = {
        key: {"fast": fast[0].get(key), "engine": engine[0].get(key)}
        for key in set(fast[0]) | set(engine[0])
        if fast[0].get(key) != engine[0].get(key)
    }

    assert not differ
    assert fast[0]["contextEngineId is the engine's"] is True


def plain_branches(report):
    """The counters a report keeps for the plain recording, by dimension.

    The dimensions from the endpoint down to the recording make the key:
    transport, endpoint host, peer, engine, security model, level and name,
    context engine ID, PDU type. Ports and engine IDs differ from one
    responder to the other and are left out; counters of other recordings,
    and the per-peer packet count they share, are not looked at.
    """
    branches = {}
    engine_id = None

    def walk(node, path):
        for key, value in node.items():
            if not isinstance(value, dict):
                continue

            if key.endswith("plain.snmprec"):
                branches[tuple(path)] = {
                    k: v for k, v in value.items() if not isinstance(v, dict)
                }

            else:
                # the context engine ID is the engine's own, made per process
                walk(value, path + ["<engine>" if key == engine_id else key])

    for protocol in ("udpv4",):
        for endpoint, by_peer in report.get(protocol, {}).items():
            for peer, by_engine in by_peer.items():
                if not isinstance(by_engine, dict):
                    continue

                for engine, below in by_engine.items():
                    engine_id = engine

                    if isinstance(below, dict):
                        walk(
                            below,
                            [protocol, endpoint.rsplit(":", 1)[0], peer, "<engine>"],
                        )

    return branches


def read_reports(responders, path):
    merged = {}

    for report in sorted((responders[path] / "reports" / "fulljson").glob("*.json")):
        merge(merged, json.loads(report.read_text()))

    return plain_branches(merged)


def flushed_reports(responders):
    """The reports of both responders with everything asked so far in them.

    A report is written when a request comes after its period, a second
    here, is over: wait it out, then ask for a recording of its own.
    """
    time.sleep(1.5)

    nudge = message(V2C, LONG_COMMUNITY, "GetRequestPDU", [(SYS_NAME, None)])

    for port in (FAST_PORT, ENGINE_PORT):
        assert ask(port, nudge) is not None

    reports = {}

    for path in responders:
        deadline = time.monotonic() + 15

        while True:
            reports[path] = read_reports(responders, path)

            if reports[path] or time.monotonic() > deadline:
                break

            time.sleep(0.2)

    return reports


def difference(after, before):
    return {
        branch: {
            key: value - before.get(branch, {}).get(key, 0)
            for key, value in counters.items()
        }
        for branch, counters in after.items()
        if counters != before.get(branch)
    }


def test_activity_reports_count_the_same_on_both_paths(responders):
    # what came before - the readiness probe of each responder among it,
    # which a slow start may have sent twice - is not compared
    before = flushed_reports(responders)

    requests = [
        message(V2C, "plain", "GetRequestPDU", [(SYS_NAME, None)]),
        message(V1, "plain", "GetNextRequestPDU", [(SYS_NAME, None)]),
        message(V2C, "plain", "GetBulkRequestPDU", [(SYS_NAME, None)], repetitions=3),
    ]

    for request in requests:
        assert ask(FAST_PORT, request) == ask(ENGINE_PORT, request)

    after = flushed_reports(responders)

    counted = {path: difference(after[path], before[path]) for path in responders}

    # one branch by PDU type and security model, each with what was asked
    assert len(counted["fast"]) == 3
    assert counted["fast"] == counted["engine"]


def merge(into, report):
    """Add up reports of the same shape: counters add, the rest is kept."""
    for key, value in report.items():
        if isinstance(value, dict):
            into[key] = merge(into.get(key, {}), value)

        elif isinstance(value, int) and not isinstance(value, bool):
            into[key] = into.get(key, 0) + value

        else:
            into[key] = value

    return into
