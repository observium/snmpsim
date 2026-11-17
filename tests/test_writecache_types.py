"""A `writecache` record takes a SET of its own type, whichever type it is.

The record's type is the one its tag stands for, the unconstrained kind
that serves what a device sent outside the range of the type; the value of
a SET is of the type as SNMP has it, range and all. The two are the same
type, and the value is written - for the integer types as for the others.
A value of another type is not.
"""
import pytest
from pyasn1.codec.ber import encoder
from pysnmp.proto import rfc1902
from snmp_messages import V2C
from snmp_messages import V3
from snmp_messages import answer
from snmp_messages import ask
from snmp_messages import engine_id
from snmp_messages import message
from snmp_messages import v3_message

PORT = 1704

# a USM user without keys: noAuthNoPriv
V3_USER = "writer"

CONTEXT = "writable"

BASE = "1.3.6.1.4.1.99999.30"

# (tag, recorded value, a value of that type to write)
TYPES = {
    "integer": ("2", "1", rfc1902.Integer32(-5)),
    "octet-string": ("4", "start", rfc1902.OctetString(b"written")),
    "object-identifier": ("6", "1.3.6.1", rfc1902.ObjectName("1.3.6.1.2.1")),
    "ip-address": ("64", "192.0.2.1", rfc1902.IpAddress("198.51.100.7")),
    "counter32": ("65", "1", rfc1902.Counter32(4000000000)),
    "gauge32": ("66", "1", rfc1902.Gauge32(123)),
    "timeticks": ("67", "1", rfc1902.TimeTicks(99)),
    "opaque": ("68", "x", rfc1902.Opaque(b"\x01\x02")),
    "counter64": ("70", "1", rfc1902.Counter64(2**40)),
}

# a record of each type for each version: what one version writes cannot
# make up for what the other fails to
OIDS = {
    (kind, version): f"{BASE}.{number}.{version + 1}"
    for number, kind in enumerate(TYPES, start=1)
    for version in (V2C, V3)
}

RECORDING = "".join(
    f"{OIDS[kind, version]}|{tag}:writecache|value={value}\n"
    for kind, (tag, value, _) in TYPES.items()
    for version in (V2C, V3)
)


@pytest.fixture(scope="module")
def responder(tmp_path_factory, responder_process):
    data = tmp_path_factory.mktemp("data")
    (data / f"{CONTEXT}.snmprec").write_text(RECORDING)

    with responder_process(
        f"--data-dir={data}",
        f"--cache-dir={tmp_path_factory.mktemp('cache')}",
        f"--v3-user={V3_USER}",
        port=PORT,
        oid=OIDS["integer", V2C],
        community=CONTEXT,
    ):
        yield engine_id(PORT)


def request(responder, version, pdu_type, var_binds):
    if version == V2C:
        response = ask(PORT, message(V2C, pdu_type, var_binds, CONTEXT))

    else:
        response = ask(
            PORT, v3_message(pdu_type, var_binds, responder, CONTEXT, V3_USER)
        )

    assert response is not None

    return answer(response)


def read(responder, oid):
    _, _, ((_, value),) = request(responder, V2C, "GetRequestPDU", [oid])

    return value


@pytest.mark.parametrize("version", [V2C, V3], ids=["v2c", "v3"])
@pytest.mark.parametrize("kind", TYPES)
def test_a_value_of_the_records_type_is_written(responder, kind, version):
    _, _, value = TYPES[kind]
    oid = OIDS[kind, version]

    assert request(responder, version, "SetRequestPDU", [(oid, value)]) == (
        0,
        0,
        [(oid, encoder.encode(value))],
    )

    assert read(responder, oid) == encoder.encode(value)


@pytest.mark.parametrize("version", [V2C, V3], ids=["v2c", "v3"])
@pytest.mark.parametrize(
    "kind, other",
    [
        ("integer", rfc1902.Gauge32(5)),
        ("counter32", rfc1902.Gauge32(5)),
        ("gauge32", rfc1902.Counter32(5)),
        ("counter64", rfc1902.Counter32(5)),
        ("timeticks", rfc1902.Integer32(5)),
        ("octet-string", rfc1902.Integer32(5)),
    ],
    ids=lambda item: item if isinstance(item, str) else type(item).__name__,
)
def test_a_value_of_another_type_is_not_written(responder, kind, other, version):
    oid = OIDS[kind, version]
    before = read(responder, oid)

    request(responder, version, "SetRequestPDU", [(oid, other)])

    assert read(responder, oid) == before
