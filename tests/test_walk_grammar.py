import pytest

from snmpsim.record.sap import SapRecord
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


SYSNAME = "1.3.6.1.2.1.1.5.0"


def walk_value_octets(line):
    oid, value = WalkRecord().evaluate(line)
    return bytes(value)


@pytest.mark.parametrize(
    "octets",
    [
        "Привет".encode("utf-8"),
        "Привет".encode("cp1251"),
        # ends in 0xa0 and 0x85, which are white space once read as Latin-1
        "voilà".encode("utf-8"),
        "Далее…".encode("cp1251"),
    ],
)
def test_walk_string_keeps_utf8_bytes(octets):
    line = b'.%s = STRING: "%s"\n' % (SYSNAME.encode(), octets)

    assert walk_value_octets(line) == octets


@pytest.mark.parametrize(
    "octets",
    ["voilà".encode("utf-8"), "Далее…".encode("cp1251")],
)
def test_walk_unquoted_string_keeps_trailing_high_bytes(octets):
    line = b".%s = STRING: %s\r\n" % (SYSNAME.encode(), octets)

    assert walk_value_octets(line) == octets


@pytest.mark.parametrize("encoding", ["utf-8", "cp1251"])
def test_walk_hex_string_keeps_non_ascii_bytes(encoding):
    octets = "Привет".encode(encoding)
    line = b".%s = Hex-STRING: %s\n" % (SYSNAME.encode(), octets.hex(" ").encode())

    assert walk_value_octets(line) == octets


def test_walk_hex_string_ignores_non_ascii_bytes_in_its_text_column():
    # snmpwalk -OT prints the octets once more as text after the hex digits
    octets = "Привет".encode("utf-8")
    line = b".%s = Hex-STRING: %s   [%s]\n" % (
        SYSNAME.encode(),
        octets.hex(" ").upper().encode(),
        octets,
    )

    assert walk_value_octets(line) == octets


def test_walk_non_ascii_string_reaches_snmprec_as_the_same_octets():
    octets = "Привет".encode("utf-8")
    line = b'.%s = STRING: "%s"\n' % (SYSNAME.encode(), octets)

    oid, value = WalkRecord().evaluate(line)
    record = SnmprecRecord().format(oid, value)
    oid, value = SnmprecRecord().evaluate(record)

    assert bytes(value) == octets


def test_walk_file_may_start_with_a_byte_order_mark():
    # Notepad and PowerShell put one in front of the UTF-8 they save
    line = b'\xef\xbb\xbf.%s = STRING: "abc"\n' % SYSNAME.encode()

    oid, value = WalkRecord().evaluate(line)

    assert str(oid) == SYSNAME
    assert bytes(value) == b"abc"


def test_walk_string_may_start_with_the_octets_of_a_byte_order_mark():
    octets = b"\xef\xbb\xbfabc"
    line = b'.%s = STRING: "%s"\n' % (SYSNAME.encode(), octets)

    assert walk_value_octets(line) == octets


@pytest.mark.parametrize(
    "octets",
    ["voilà".encode("utf-8"), "Далее…".encode("cp1251")],
)
def test_sapwalk_string_keeps_trailing_high_bytes(octets):
    line = b"%s, OctetString, %s\r\n" % (SYSNAME.encode(), octets)

    oid, value = SapRecord().evaluate(line)

    assert str(oid) == SYSNAME
    assert bytes(value) == octets
