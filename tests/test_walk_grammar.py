import io
import os
import time

import pytest

from snmpsim.error import SnmpsimError

from snmpsim.record.sap import SapRecord
from snmpsim.record.snmprec import SnmprecRecord
from snmpsim.record import walk as walk_module
from snmpsim.record.walk import WalkRecord, can_rewind

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
IF_PHYS = "1.3.6.1.2.1.2.2.1.6.1"


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

    assert read_walk(text) == [(SYSNAME, b'say "\nhello"')]


def test_walk_quoted_string_loses_the_backslashes_snmpwalk_escaped_with():
    # the device sent C:\Temp "x"; snmpwalk escapes quotes and backslashes
    text = b'.%s = STRING: "C:\\\\Temp \\"x\\""\n' % SYSNAME.encode()

    assert read_walk(text) == [(SYSNAME, b'C:\\Temp "x"')]


def test_walk_backslash_before_other_characters_is_kept():
    text = b'.%s = STRING: "C:\\Temp"\n' % SYSNAME.encode()

    assert read_walk(text) == [(SYSNAME, b"C:\\Temp")]


def test_walk_escaped_backslash_at_the_end_closes_the_string():
    text = b'.%s = STRING: "C:\\\\"\n.%s = STRING: "eth0"\n' % (
        SYSNAME.encode(),
        IF_DESCR.encode(),
    )

    assert read_walk(text) == [(SYSNAME, b"C:\\"), (IF_DESCR, b"eth0")]


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


@pytest.mark.parametrize(
    "start",
    [
        b"sysName.0 = STRING: x",  # snmpwalk -Os
        b".iso.org.dod.internet.mgmt.mib-2.system.sysName.0 = STRING: x",  # -Of
        b"SNMPv2-MIB::sysName.0 = STRING: x",
        b"iso.3.6.1.2.1.1.5.0 = STRING: x",
        b'.1.3.6.1.2.1.1.5.0 = ""',
        b".1.3.6.1.2.1.1.3.0 = 12345",  # snmpwalk -Ot
        b".1.3.6.1.2.1.1.5.0 = No Such Instance currently exists at this OID",
        b".1.3.6.1.2.1.1.5.0 = STRING:",
    ],
)
def test_walk_string_that_never_closes_ends_at_a_record_of_any_spelling(start):
    text = b'.%s = STRING: "cut short\n%s\n' % (SYSNAME.encode(), start)
    source = io.BytesIO(text)

    first, _, _ = WalkRecord().read_record(source)
    second, _, _ = WalkRecord().read_record(source)

    assert first == b'.%s = STRING: "cut short\n' % SYSNAME.encode()
    assert second == start + b"\n"


@pytest.mark.parametrize(
    "inside", [b"1.2 = 3 volts", b"x = INTEGER: 5", b"load.avg = high", b"a.b = "]
)
def test_walk_text_with_an_equals_sign_stays_inside_the_string(inside):
    text = b'.%s = STRING: "first\n%s\nlast"\n' % (SYSNAME.encode(), inside)

    assert read_walk(text) == [(SYSNAME, b"first\n" + inside + b"\nlast")]


def test_walk_line_after_a_string_closed_on_a_later_line_is_not_joined():
    text = b'.%s = STRING: "first\nsecond"\nTimeout: No Response\n' % (SYSNAME.encode())
    source = io.BytesIO(text)

    first, _, _ = WalkRecord().read_record(source)
    second, _, _ = WalkRecord().read_record(source)

    assert first == b'.%s = STRING: "first\nsecond"\n' % SYSNAME.encode()
    assert second == b"Timeout: No Response\n"


def test_walk_hex_row_with_tabs_between_the_octets_is_read_as_it_was_joined():
    # the line is taken in as hex octets, so it has to decode as those
    text = b".%s = Hex-STRING: 00 01 \n02\t03 \n" % SYSNAME.encode()

    assert read_walk(text) == [(SYSNAME, bytes([0, 1, 2, 3]))]


def test_walk_hex_row_with_the_text_column_glued_on_is_read_as_it_was_joined():
    text = b".%s = Hex-STRING: 41 42[AB]\n43 44[CD]\n" % SYSNAME.encode()

    assert read_walk(text) == [(SYSNAME, b"ABCD")]


def test_walk_hex_string_without_spaces_is_still_read():
    text = b".%s = HEX-STRING: 00029929AE3C\n" % SYSNAME.encode()

    assert read_walk(text) == [(SYSNAME, bytes.fromhex("00029929AE3C"))]


def test_walk_hex_string_of_anything_but_hex_is_a_broken_record():
    record = WalkRecord()

    with pytest.raises(SnmpsimError):
        record.evaluate(b".%s = Hex-STRING: 02\t0G" % SYSNAME.encode())


def test_walk_is_read_from_a_pipe():
    # a pipe cannot be moved back to the line read past the record
    octets = bytes(range(20))
    text = b'.%s = Hex-STRING: %s \n%s \n.%s = STRING: "first\nsecond"\n' % (
        IF_PHYS.encode(),
        octets[:16].hex(" ").upper().encode(),
        octets[16:].hex(" ").upper().encode(),
        SYSNAME.encode(),
    )
    reader, writer = os.pipe()

    with os.fdopen(writer, "wb") as sink:
        sink.write(text + b".%s = INTEGER: 6\n" % IF_DESCR.encode())

    with os.fdopen(reader, "rb") as source:
        assert not can_rewind(source)
        record = WalkRecord()
        lines = [record.read_record(source)[0] for _ in range(4)]

    assert [record.evaluate(line)[1] for line in lines[:3]] == [
        octets,
        b"first\nsecond",
        6,
    ]
    assert lines[3] == b""


class PipeThatSaysItSeeks(io.BufferedReader):
    """A pipe that says it seeks and whose seek() brings nothing back."""

    def seekable(self):
        return True

    def tell(self):
        return 0

    def seek(self, offset, whence=os.SEEK_SET):
        return 0


def test_walk_is_read_from_a_pipe_that_says_it_can_seek():
    octets = bytes(range(20))
    reader, writer = os.pipe()

    with os.fdopen(writer, "wb") as sink:
        sink.write(
            b".%s = Hex-STRING: %s \n%s \n.%s = STRING: eth0\n"
            % (
                IF_PHYS.encode(),
                octets[:16].hex(" ").upper().encode(),
                octets[16:].hex(" ").upper().encode(),
                IF_DESCR.encode(),
            )
        )

    with PipeThatSaysItSeeks(io.FileIO(reader, "rb")) as source:
        assert source.seekable()
        record = WalkRecord()
        lines = [record.read_record(source)[0] for _ in range(3)]

    assert lines[1:] == [b".%s = STRING: eth0\n" % IF_DESCR.encode(), b""]
    assert record.evaluate(lines[0])[1] == octets


def test_only_a_regular_file_is_moved_back(tmp_path):
    walk = tmp_path / "switch.snmpwalk"
    walk.write_bytes(b"")
    reader, writer = os.pipe()

    with open(walk, "rb") as source:
        assert can_rewind(source)

    with os.fdopen(writer, "wb"), os.fdopen(reader, "rb") as source:
        assert not can_rewind(source)


def test_regular_file_behind_a_reader_that_cannot_seek_is_not_moved_back(tmp_path):
    class Unseekable(io.BufferedReader):
        def seekable(self):
            return False

    walk = tmp_path / "switch.snmpwalk"
    walk.write_bytes(b"")

    with Unseekable(io.FileIO(walk, "rb")) as source:
        assert not can_rewind(source)


def test_what_a_file_is_gets_asked_once_for_all_its_records(tmp_path, monkeypatch):
    asked = []
    fstat = os.fstat

    def spy(descriptor):
        asked.append(descriptor)
        return fstat(descriptor)

    walk = tmp_path / "switch.snmpwalk"
    walk.write_bytes(
        b"".join(b".%s.%d = STRING: eth\n" % (IF_DESCR.encode(), n) for n in range(50))
    )
    record = WalkRecord()

    with open(walk, "rb") as source:
        monkeypatch.setattr(walk_module.os, "fstat", spy)
        lines = [record.read_record(source)[0] for _ in range(51)]
        monkeypatch.undo()

    assert all(lines[:50]) and lines[50] == b""
    assert len(asked) == 1


def test_file_without_a_descriptor_is_asked_whether_it_seeks():
    class Lines:
        def seekable(self):
            return False

    assert can_rewind(io.BytesIO())
    assert not can_rewind(Lines())


def test_walk_string_of_many_lines_is_read_in_one_pass():
    # joining used to search the whole record again for every line
    lines = 20000
    text = b'.%s = STRING: "%s"\n' % (SYSNAME.encode(), b"x\n" * lines)
    source = io.BytesIO(text)

    started = time.monotonic()
    record, _, _ = WalkRecord().read_record(source)

    assert record == text
    assert time.monotonic() - started < 5


@pytest.mark.parametrize(
    "record, line",
    [
        (WalkRecord(), b"SNMPv2-MIB::sysName.0 = STRING: switch\n"),
        (WalkRecord(), b"iso.3.6.1.2.1.1.5.0 = STRING: switch\n"),
        (WalkRecord(), b".1.3.6.1.2.1.1.5.0 = Opaque: Float: much\n"),
        (WalkRecord(), b".1.3.6.1.2.1.1.5.0 = Opaque: UInt64: many\n"),
        (WalkRecord(), b".1.3.6.1.2.1.1.5.0 = Opaque: ZZ 01\n"),
        (WalkRecord(), b".1.3.6.1.2.1.1.5.0 = BITS: ZZ 01\n"),
        (WalkRecord(), b".1.3.6.1.2.1.1.5.0 = Network Address: ZZ:00:00:01\n"),
        (SapRecord(), b"1.3.6.1.2.1.1.5.0, OctetString, 0x73ZZ\n"),
        (SapRecord(), b"sysName.0, OctetString, switch\n"),
    ],
)
def test_line_that_cannot_be_converted_is_a_broken_record(record, line):
    with pytest.raises(SnmpsimError) as raised:
        record.evaluate(line)

    # the message says what in the line is wrong, the caller adds the line
    assert str(raised.value)


def test_oid_only_evaluation_of_a_named_oid_is_a_broken_record():
    # how the index and the search read a record
    with pytest.raises(SnmpsimError):
        WalkRecord().evaluate(b"sysName.0 = STRING: switch\n", oidOnly=True)


def test_sapwalk_hex_string_is_still_read():
    oid, value = SapRecord().evaluate(b"1.3.6.1.2.1.1.5.0, OctetString, 0x73770a\n")

    assert bytes(value) == b"sw\n"


# snmpwalk -OQ prints the values without their types: a string is told by
# its quotes alone
@pytest.mark.parametrize(
    "value, octets",
    [
        ('"Linux box 6.1"', b"Linux box 6.1"),
        ('""', b""),
        ('"60:9c:9f:ec:a3:38"', b"60:9c:9f:ec:a3:38"),
        ('"C:\\\\Temp \\"x\\""', b'C:\\Temp "x"'),
        ('"12345"', b"12345"),
    ],
)
def test_walk_untagged_quoted_value_is_a_string(value, octets):
    oid, record = WalkRecord().evaluate(f".{SYSNAME} = {value}\n".encode())

    assert str(oid) == SYSNAME
    assert record.__class__.__name__ == "OctetString"
    assert bytes(record) == octets


def test_walk_untagged_quoted_value_reaches_snmprec_as_a_string():
    assert walk_to_snmprec(f'.{SYSNAME} = "switch"\n') == f"{SYSNAME}|4|switch"


def test_walk_untagged_quoted_string_with_a_newline_is_one_record():
    text = b'.%s = "first\nsecond"\n.%s = "eth0"\n' % (
        SYSNAME.encode(),
        IF_DESCR.encode(),
    )

    assert read_walk(text) == [(SYSNAME, b"first\nsecond"), (IF_DESCR, b"eth0")]


def test_walk_untagged_quoted_string_that_never_closes_ends_at_the_next_record():
    text = b'.%s = "cut short\n.%s = "eth0"\n' % (SYSNAME.encode(), IF_DESCR.encode())

    assert read_walk(text) == [(SYSNAME, b'"cut short'), (IF_DESCR, b"eth0")]


def test_walk_untagged_number_is_still_read_as_timeticks():
    # nothing tells what an untagged number is, the old guess stays
    assert walk_to_snmprec(f".{SYSNAME} = 72\n") == f"{SYSNAME}|67|72"
