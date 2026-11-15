import os
import sys

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
