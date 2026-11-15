import os
import sys

import pytest

from snmpsim.commands import rec2rec

SYSNAME = "1.3.6.1.2.1.1.5.0"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2.1"
IF_PHYS = "1.3.6.1.2.1.2.2.1.6.1"


def manage_records(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["snmpsim-manage-records", *args])
    return rec2rec.main()


def test_walk_values_wrapped_onto_several_lines_are_converted(
    tmp_path, monkeypatch, capsys
):
    text = b"first\nsecond"
    octets = bytes(range(40))
    rows = [octets[i : i + 16].hex(" ").upper() for i in (0, 16, 32)]
    source = tmp_path / "switch.snmpwalk"
    source.write_bytes(
        (
            f'.{SYSNAME} = STRING: "first\nsecond"\n'
            f".{IF_DESCR} = STRING: eth0\n"
            f".{IF_PHYS} = Hex-STRING: {rows[0]} \n{rows[1]} \n{rows[2]} \n"
        ).encode()
    )
    target = tmp_path / "switch.snmprec"

    status = manage_records(
        monkeypatch,
        "--source-record-type=snmpwalk",
        f"--input-file={source}",
        f"--output-file={target}",
    )

    assert not status
    assert target.read_bytes().splitlines() == [
        f"{SYSNAME}|4x|{text.hex()}".encode(),
        f"{IF_DESCR}|4|eth0".encode(),
        f"{IF_PHYS}|4x|{octets.hex()}".encode(),
    ]
    assert "broken 0" in capsys.readouterr().err


def test_walk_is_converted_from_a_pipe(tmp_path, monkeypatch, capsys):
    # --input-file=/dev/stdin, or a shell's <(...), is a file that cannot seek
    text = b"first\nsecond"
    reader, writer = os.pipe()

    with os.fdopen(writer, "wb") as sink:
        sink.write(
            (
                f".{IF_PHYS} = Hex-STRING: 00 01 02 03 \n04 05 \n"
                f'.{SYSNAME} = STRING: "first\nsecond"\n'
                f".{IF_DESCR} = STRING: eth0\n"
            ).encode()
        )

    monkeypatch.setattr(
        rec2rec.RECORD_TYPES["snmpwalk"],
        "open",
        lambda name: os.fdopen(reader, "rb"),
        raising=False,
    )
    target = tmp_path / "switch.snmprec"

    status = manage_records(
        monkeypatch,
        "--source-record-type=snmpwalk",
        "--input-file=walk-from-a-pipe",
        f"--output-file={target}",
    )

    assert not status
    assert target.read_bytes().splitlines() == [
        f"{IF_PHYS}|4x|000102030405".encode(),
        f"{SYSNAME}|4x|{text.hex()}".encode(),
        f"{IF_DESCR}|4|eth0".encode(),
    ]
    assert "broken 0" in capsys.readouterr().err


# lines that used to end the conversion with a traceback, by record type
UNCONVERTIBLE = [
    # OIDs by name: what snmpwalk prints without -On
    ("snmpwalk", b"SNMPv2-MIB::sysName.0 = STRING: switch\n"),
    ("snmpwalk", b"sysName.0 = STRING: switch\n"),
    ("snmpwalk", b"iso.3.6.1.2.1.1.5.0 = STRING: switch\n"),
    # values that are not what their type says
    ("snmpwalk", f".{SYSNAME} = Opaque: Float: much\n".encode()),
    ("snmpwalk", f".{SYSNAME} = Opaque: ZZ 01\n".encode()),
    ("snmpwalk", f".{SYSNAME} = BITS: ZZ 01\n".encode()),
    ("snmpwalk", f".{SYSNAME} = Network Address: ZZ:00:00:01\n".encode()),
    ("sapwalk", f"{SYSNAME}, OctetString, 0x73ZZ\n".encode()),
    ("sapwalk", b"sysName.0, OctetString, switch\n"),
    ("dump", f"{SYSNAME}|6|Hex: 73.ZZ\n".encode()),
    # no value where the type cannot do without one
    ("dump", f"{SYSNAME}|2|\n".encode()),
    ("dump", f"{SYSNAME}|5|\n".encode()),
    ("snmprec", f"{SYSNAME}|2|\n".encode()),
    ("snmprec", f"{SYSNAME}|2x|\n".encode()),
    ("snmprec", f"{SYSNAME}|66x|\n".encode()),
    ("snmprec", f"{SYSNAME}|6|\n".encode()),
]

GOOD = {
    "snmpwalk": ".%s = STRING: eth0\n",
    "sapwalk": "%s, OctetString, eth0\n",
    "dump": "%s|6|eth0\n",
    "snmprec": "%s|4|eth0\n",
}


def convert_with_a_bad_line(tmp_path, monkeypatch, record_type, bad, *options):
    good = GOOD[record_type]
    source = tmp_path / f"switch.{record_type}"
    source.write_bytes(
        (good % "1.3.6.1.2.1.1.4.0").encode() + bad + (good % IF_DESCR).encode()
    )
    target = tmp_path / "converted.snmprec"

    status = manage_records(
        monkeypatch,
        f"--source-record-type={record_type}",
        f"--input-file={source}",
        f"--output-file={target}",
        *options,
    )

    return status, target


@pytest.mark.parametrize("record_type, bad", UNCONVERTIBLE)
def test_unconvertible_line_is_skipped_as_a_broken_record(
    tmp_path, monkeypatch, capsys, record_type, bad
):
    status, target = convert_with_a_bad_line(
        tmp_path, monkeypatch, record_type, bad, "--ignore-broken-records"
    )

    assert not status
    assert target.read_bytes().splitlines() == [
        b"1.3.6.1.2.1.1.4.0|4|eth0",
        f"{IF_DESCR}|4|eth0".encode(),
    ]

    messages = capsys.readouterr().err
    assert f"# Skipping broken record <{bad!r}>" in messages
    assert "written 2," in messages
    assert "broken 1," in messages


@pytest.mark.parametrize("record_type, bad", UNCONVERTIBLE)
def test_unconvertible_line_stops_the_conversion_with_a_message(
    tmp_path, monkeypatch, capsys, record_type, bad
):
    status, target = convert_with_a_bad_line(tmp_path, monkeypatch, record_type, bad)

    assert status == 1

    messages = capsys.readouterr().err
    assert f"ERROR: broken record <{bad!r}>" in messages
    assert "Traceback" not in messages


@pytest.mark.parametrize(
    "record_type, empty",
    [
        ("dump", "|6|"),
        ("dump", '|6|""'),
        ("snmprec", "|4|"),
        ("snmprec", "|4x|"),
        ("snmprec", "|4e|"),
    ],
)
def test_empty_string_value_is_converted(
    tmp_path, monkeypatch, capsys, record_type, empty
):
    status, target = convert_with_a_bad_line(
        tmp_path, monkeypatch, record_type, f"{SYSNAME}{empty}\n".encode()
    )

    assert not status
    assert target.read_bytes().splitlines() == [
        b"1.3.6.1.2.1.1.4.0|4|eth0",
        f"{SYSNAME}|4|".encode(),
        f"{IF_DESCR}|4|eth0".encode(),
    ]
    assert "broken 0," in capsys.readouterr().err


def test_walk_with_names_for_oids_is_told_how_to_get_numbers(
    tmp_path, monkeypatch, capsys
):
    status, target = convert_with_a_bad_line(
        tmp_path, monkeypatch, "snmpwalk", b"SNMPv2-MIB::sysName.0 = STRING: switch\n"
    )

    assert status == 1

    messages = capsys.readouterr().err
    assert "'SNMPv2-MIB::sysName.0'" in messages
    assert "snmpwalk -On" in messages


def test_broken_record_is_reported_even_when_asked_to_be_quiet(
    tmp_path, monkeypatch, capsys
):
    bad = f"{SYSNAME}, OctetString, 0x73ZZ\n".encode()

    status, target = convert_with_a_bad_line(
        tmp_path, monkeypatch, "sapwalk", bad, "--quiet"
    )

    assert status == 1
    assert f"ERROR: broken record <{bad!r}>" in capsys.readouterr().err


SAMPLE_WALK = (
    f".1.3.6.1.2.1.1.1.0 = STRING: Sample switch\n"
    f".1.3.6.1.2.1.1.3.0 = Timeticks: (12345) 0:02:03.45\n"
    f'.{SYSNAME} = STRING: "first\nsecond"\n'
    f".{IF_DESCR} = STRING: eth0\n"
    f".{IF_DESCR} = STRING: eth0 again\n"
    f".{IF_PHYS} = Hex-STRING: 00 01 02 03 \n04 05 \n"
    f".1.3.6.1.2.1.2.2.1.10.1 = Counter32: 4294967295\n"
).encode()

SAMPLE_OPTIONS = [
    (),
    ("--deduplicate-records",),
    ("--escaped-strings",),
    ("--start-object=1.3.6.1.2.1.1.3.0", "--stop-object=1.3.6.1.2.1.2.2.1.6.1"),
    ("--deduplicate-records", "--stop-object=1.3.6.1.2.1.2.2.1.6.1"),
]


@pytest.mark.parametrize("options", SAMPLE_OPTIONS)
def test_unsorted_conversion_writes_what_the_sorted_one_does(
    tmp_path, monkeypatch, capsys, options
):
    # the sample is in OID order already, so sorting it, which takes holding
    # all of it, must not change a byte of what comes out
    source = tmp_path / "switch.snmpwalk"
    source.write_bytes(SAMPLE_WALK)
    outputs, counts = [], []

    for name, extra in ("streamed", ()), ("sorted", ("--sort-records",)):
        target = tmp_path / f"{name}.snmprec"

        status = manage_records(
            monkeypatch,
            "--source-record-type=snmpwalk",
            f"--input-file={source}",
            f"--output-file={target}",
            *options,
            *extra,
        )

        assert not status
        outputs.append(target.read_bytes())
        counts.append(capsys.readouterr().err.splitlines()[-1])

    assert outputs[0]
    assert outputs[0] == outputs[1]
    assert counts[0] == counts[1]


def test_unsorted_conversion_keeps_the_order_of_its_input(tmp_path, monkeypatch):
    sources = []

    for name, oids in ("b", (IF_DESCR, SYSNAME)), ("a", (IF_PHYS, SYSNAME)):
        sources.append(tmp_path / f"{name}.snmpwalk")
        sources[-1].write_bytes(
            "".join(f".{oid} = STRING: {name}\n" for oid in oids).encode()
        )

    target = tmp_path / "switch.snmprec"

    status = manage_records(
        monkeypatch,
        "--quiet",
        "--source-record-type=snmpwalk",
        "--deduplicate-records",
        *(f"--input-file={source}" for source in sources),
        f"--output-file={target}",
    )

    assert not status
    assert target.read_bytes().splitlines() == [
        f"{IF_DESCR}|4|b".encode(),
        f"{SYSNAME}|4|b".encode(),
        f"{IF_PHYS}|4|a".encode(),
    ]


class CountingSource:
    """A walk that knows how many of its lines have been asked for."""

    def __init__(self, lines):
        self.lines = lines
        self.lines_read = 0

    def seekable(self):
        # like a pipe: what has been read cannot be read again
        return False

    def readline(self):
        if self.lines_read == len(self.lines):
            return b""

        self.lines_read += 1

        return self.lines[self.lines_read - 1]


class WitnessingSink:
    """An output file that notes how far the source was read at each write."""

    def __init__(self, source):
        self.source = source
        self.writes = []

    def write(self, data):
        self.writes.append((self.source.lines_read, data))

    def flush(self):
        pass

    def close(self):
        pass


def convert_counting_lines(monkeypatch, total, *options):
    source = CountingSource(
        [f".1.3.6.1.2.1.2.2.1.2.{n} = STRING: eth{n}\n".encode() for n in range(total)]
    )
    sink = WitnessingSink(source)

    monkeypatch.setattr(
        rec2rec.RECORD_TYPES["snmpwalk"], "open", lambda name: source, raising=False
    )
    monkeypatch.setattr(
        rec2rec.RECORD_TYPES["snmprec"],
        "open",
        lambda name, mode: sink,
        raising=False,
    )

    status = manage_records(
        monkeypatch,
        "--quiet",
        "--source-record-type=snmpwalk",
        "--input-file=walk",
        "--output-file=switch",
        *options,
    )

    assert not status
    assert len(sink.writes) == total

    return sink.writes


@pytest.mark.parametrize("options", [(), ("--deduplicate-records",)])
def test_unsorted_conversion_streams(monkeypatch, options):
    total = 1000

    writes = convert_counting_lines(monkeypatch, total, *options)

    assert writes[0][1] == b"1.3.6.1.2.1.2.2.1.2.0|4|eth0\n"

    # telling where a walk record ends may take reading the line after it,
    # so writing runs at most one line behind reading
    assert all(read <= written + 2 for written, (read, _) in enumerate(writes))


def test_sorted_conversion_reads_everything_first(monkeypatch):
    total = 10

    writes = convert_counting_lines(monkeypatch, total, "--sort-records")

    assert all(read == total for read, _ in writes)


def test_streamed_conversion_keeps_what_it_wrote_before_a_broken_record(
    tmp_path, monkeypatch, capsys
):
    # nothing is held back to be dropped: the records ahead of the one that
    # stopped the conversion are in the output, and the exit status says
    # that the output is not all of the input
    status, target = convert_with_a_bad_line(
        tmp_path, monkeypatch, "snmpwalk", b"sysName.0 = STRING: switch\n"
    )

    assert status == 1
    assert target.read_bytes() == b"1.3.6.1.2.1.1.4.0|4|eth0\n"
    assert "ERROR: broken record" in capsys.readouterr().err


def convert_numbered(tmp_path, monkeypatch, record_type, lines, *options):
    source = tmp_path / f"switch.{record_type}"
    source.write_bytes("".join(line + "\n" for line in lines).encode())

    return manage_records(
        monkeypatch,
        f"--source-record-type={record_type}",
        f"--input-file={source}",
        f"--output-file={tmp_path / 'converted.snmprec'}",
        *options,
    )


WALK_WITH_A_BROKEN_SEVENTH_LINE = [
    f'.{SYSNAME} = STRING: "first',  # 1
    'second"',
    f".{IF_DESCR} = STRING: eth0",  # 3
    f".{IF_PHYS} = Hex-STRING: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F ",
    "10 11 ",
    "# what follows is not an OID",  # 6
    "sysName.0 = STRING: switch",
    ".1.3.6.1.2.1.2.2.1.7.1 = INTEGER: 1",  # 8
    "# two lines that are not records,",
    "",
    ".1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1",  # 11
]


def test_broken_record_after_records_of_several_lines_is_named_by_its_line(
    tmp_path, monkeypatch, capsys
):
    status = convert_numbered(
        tmp_path,
        monkeypatch,
        "snmpwalk",
        WALK_WITH_A_BROKEN_SEVENTH_LINE,
        "--ignore-broken-records",
    )

    assert not status

    messages = capsys.readouterr().err
    broken = [line for line in messages.splitlines() if "broken record" in line]
    lost = [line for line in messages.splitlines() if "Losing comment" in line]

    assert len(broken) == 1
    assert "> at line 7 (input file #0): " in broken[0]
    assert lost == [
        "# Losing comment at lines 6..6 (input file #0)",
        "# Losing comment at lines 9..10 (input file #0)",
    ]
    assert "ignored 2," in messages


def test_record_that_stops_the_conversion_is_named_by_its_line(
    tmp_path, monkeypatch, capsys
):
    status = convert_numbered(
        tmp_path, monkeypatch, "snmpwalk", WALK_WITH_A_BROKEN_SEVENTH_LINE, "--quiet"
    )

    assert status == 1
    assert "> at line 7 (input file #0): " in capsys.readouterr().err


def test_broken_record_of_several_lines_is_named_by_its_first_line(
    tmp_path, monkeypatch, capsys
):
    status = convert_numbered(
        tmp_path,
        monkeypatch,
        "snmpwalk",
        [
            f".{IF_DESCR} = STRING: eth0",
            f".{SYSNAME} = BITS: ZZ 01",
            f'.1.3.6.1.2.1.1.6.0 = STRING: "first',
            'second"',
            "# the next record takes two lines and is no OID at all",
            'sysName.0 = STRING: "first',
            'second"',
            ".1.3.6.1.2.1.2.2.1.7.1 = INTEGER: 1",
        ],
        "--ignore-broken-records",
    )

    assert not status

    messages = capsys.readouterr().err.splitlines()

    assert [
        line.split("> ")[1].split(": ")[0]
        for line in messages
        if "broken record" in line
    ] == ["at line 2 (input file #0)", "at line 6 (input file #0)"]
    assert [line for line in messages if "Losing comment" in line] == [
        "# Losing comment at lines 5..5 (input file #0)"
    ]


def test_lines_of_a_one_line_format_are_counted_past_the_first_comment(
    tmp_path, monkeypatch, capsys
):
    lines = [
        f"{SYSNAME}|4|switch",
        "# one comment",
        f"{IF_DESCR}|4|eth0",
        f"{IF_PHYS}|4x|0001",
        "# two",
        "# comments",
        f"{SYSNAME}|2|",  # 7
        "1.3.6.1.2.1.2.2.1.7.1|2|1",
    ]

    status = convert_numbered(
        tmp_path, monkeypatch, "snmprec", lines, "--ignore-broken-records"
    )

    assert not status

    messages = capsys.readouterr().err.splitlines()

    assert [line for line in messages if "Losing comment" in line] == [
        "# Losing comment at lines 2..2 (input file #0)",
        "# Losing comment at lines 5..6 (input file #0)",
    ]
    assert any(
        "broken record" in line and "> at line 7 (input file #0): " in line
        for line in messages
    )


def test_lines_are_counted_anew_for_each_input_file(tmp_path, monkeypatch, capsys):
    first = tmp_path / "first.snmprec"
    first.write_bytes(f"{SYSNAME}|4|switch\n{IF_DESCR}|4|eth0\n".encode())
    second = tmp_path / "second.snmprec"
    second.write_bytes(f"# a comment\n{IF_PHYS}|4x|0001\n{SYSNAME}|2|\n".encode())

    status = manage_records(
        monkeypatch,
        f"--input-file={first}",
        f"--input-file={second}",
        f"--output-file={tmp_path / 'converted.snmprec'}",
    )

    assert status == 1

    messages = capsys.readouterr().err

    assert "# Losing comment at lines 1..1 (input file #1)" in messages
    assert "> at line 3 (input file #1): " in messages
