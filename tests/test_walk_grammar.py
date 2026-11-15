import io

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


def read_walk(text):
    """Read every record of a walk the way snmpsim-manage-records does."""
    source = io.BytesIO(text)
    record = WalkRecord()
    values = []

    while True:
        line, _, _ = record.read_record(source)
        if not line:
            return values

        oid, value = record.evaluate(line)
        values.append((str(oid), bytes(value)))


IF_DESCR = "1.3.6.1.2.1.2.2.1.2.1"


def test_walk_hex_string_wrapped_onto_several_lines_is_one_record():
    # snmpwalk starts a new line after every sixteen octets
    octets = bytes(range(40))
    rows = [octets[i : i + 16].hex(" ").upper().encode() for i in (0, 16, 32)]
    text = b'.%s = Hex-STRING: %s \n%s \n%s \n.%s = STRING: "eth0"\n' % (
        SYSNAME.encode(),
        rows[0],
        rows[1],
        rows[2],
        IF_DESCR.encode(),
    )

    assert read_walk(text) == [(SYSNAME, octets), (IF_DESCR, b"eth0")]


def test_walk_wrapped_hex_string_drops_the_text_column_of_every_line():
    # snmpwalk -OT repeats the octets of each line as text
    octets = b"0123456789abcdef [= STRING: x]"
    text = b".%s = Hex-STRING: %s   [%s]\n%s         [%s]\n" % (
        SYSNAME.encode(),
        octets[:16].hex(" ").upper().encode(),
        octets[:16],
        octets[16:].hex(" ").upper().encode(),
        octets[16:],
    )

    assert read_walk(text) == [(SYSNAME, octets)]


def test_walk_quoted_string_with_a_newline_is_one_record():
    text = b'.%s = STRING: "first\nsecond"\n.%s = STRING: "eth0"\n' % (
        SYSNAME.encode(),
        IF_DESCR.encode(),
    )

    assert read_walk(text) == [(SYSNAME, b"first\nsecond"), (IF_DESCR, b"eth0")]


def test_walk_quoted_string_keeps_blank_and_comment_like_lines_inside():
    text = b'.%s = STRING: "first\n\n# not a comment\n"\n' % SYSNAME.encode()

    assert read_walk(text) == [(SYSNAME, b"first\n\n# not a comment\n")]


def test_walk_quoted_string_keeps_the_carriage_returns_inside():
    # Cisco puts CR LF between the lines of its sysDescr
    text = b'.%s = STRING: "first\r\nsecond"\n' % SYSNAME.encode()

    assert read_walk(text) == [(SYSNAME, b"first\r\nsecond")]


def test_walk_escaped_quote_at_the_end_of_a_line_does_not_close_the_string():
    text = b'.%s = STRING: "say \\"\nhello\\""\n' % SYSNAME.encode()

    assert read_walk(text) == [(SYSNAME, b'say \\"\nhello\\"')]


def test_walk_string_that_never_closes_ends_at_the_next_record():
    text = b'.%s = STRING: "cut short\n.%s = STRING: "eth0"\n' % (
        SYSNAME.encode(),
        IF_DESCR.encode(),
    )

    assert read_walk(text) == [(SYSNAME, b'"cut short'), (IF_DESCR, b"eth0")]


def test_walk_line_after_a_closed_record_is_not_joined_to_it():
    # neither a complete string nor a hex string takes a stray line in
    text = b'.%s = STRING: "abc"\nTimeout: No Response\n' % SYSNAME.encode()
    source = io.BytesIO(text)

    first, _, _ = WalkRecord().read_record(source)
    second, _, _ = WalkRecord().read_record(source)

    assert first == b'.%s = STRING: "abc"\n' % SYSNAME.encode()
    assert second == b"Timeout: No Response\n"


def test_walk_hex_string_takes_only_hex_lines_in():
    text = b".%s = Hex-STRING: 00 01 \nEnd of MIB\n" % SYSNAME.encode()
    source = io.BytesIO(text)

    first, _, _ = WalkRecord().read_record(source)
    second, _, _ = WalkRecord().read_record(source)

    assert first == b".%s = Hex-STRING: 00 01 \n" % SYSNAME.encode()
    assert second == b"End of MIB\n"


def test_walk_reader_skips_comments_between_records():
    text = b"# walk of a switch\n\n.%s = INTEGER: 6\n" % IF_DESCR.encode()

    line, line_no, offset = WalkRecord().read_record(io.BytesIO(text), 0)

    assert line == b".%s = INTEGER: 6\n" % IF_DESCR.encode()
    assert (line_no, offset) == (3, len(b"# walk of a switch\n\n"))


def test_snmprec_reader_does_not_join_lines():
    text = b'%s|4|"first\nsecond"\n' % SYSNAME.encode()

    line, _, _ = SnmprecRecord().read_record(io.BytesIO(text))

    assert line == b'%s|4|"first\n' % SYSNAME.encode()
