import pytest

from snmpsim.record.snmprec import SnmprecRecord
from snmpsim.record.walk import WalkRecord

OID = "1.3.6.1.4.1.2021.10.1.6.1"


def walk_to_snmprec(line):
    """Convert a line of snmpwalk output the way snmpsim-record-mib does."""
    oid, value = WalkRecord().evaluate(line.encode())
    return SnmprecRecord().format(oid, value).decode().strip()


@pytest.mark.parametrize(
    "text, payload",
    [
        # sub-tag 9f78, four octets of IEEE 754 single precision
        ("Float: 100.000000", "9f780442c80000"),
        ("Float: 12.5", "9f780441480000"),
        ("Float: -0.500000", "9f7804bf000000"),
        # sub-tag 9f79, eight octets of IEEE 754 double precision
        ("Double: 1.5", "9f79083ff8000000000000"),
        ("Double: -2.250000", "9f7908c002000000000000"),
    ],
)
def test_opaque_float_and_double_are_encoded_as_net_snmp_does(text, payload):
    record = walk_to_snmprec(f".{OID} = Opaque: {text}")

    assert record == f"{OID}|68x|{payload}"


@pytest.mark.parametrize(
    "text, payload",
    [
        ("UInt64: 18446744073709551614", "9f7b08fffffffffffffffe"),
        ("Int64: -2", "9f7a08fffffffffffffffe"),
        ("Int64: 9223372036854775806", "9f7a087ffffffffffffffe"),
    ],
)
def test_opaque_64bit_integers_keep_their_encoding(text, payload):
    record = walk_to_snmprec(f".{OID} = Opaque: {text}")

    assert record == f"{OID}|68x|{payload}"


def test_opaque_float_survives_the_snmprec_round_trip():
    record = walk_to_snmprec(f".{OID} = Opaque: Float: 100.000000")

    oid, value = SnmprecRecord().evaluate(record.encode() + b"\n")

    assert bytes(value) == bytes.fromhex("9f780442c80000")
