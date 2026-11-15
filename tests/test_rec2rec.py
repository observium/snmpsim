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
]

GOOD = {
    "snmpwalk": ".%s = STRING: eth0\n",
    "sapwalk": "%s, OctetString, eth0\n",
    "dump": "%s|6|eth0\n",
}


def convert_with_a_bad_line(tmp_path, monkeypatch, record_type, bad, *options):
    good = GOOD[record_type]
    source = tmp_path / f"switch.{record_type}"
    source.write_bytes(
        (good % "1.3.6.1.2.1.1.4.0").encode() + bad + (good % IF_DESCR).encode()
    )
    target = tmp_path / "switch.snmprec"

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
