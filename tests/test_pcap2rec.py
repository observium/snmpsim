import os
import struct
import sys
import types

from pyasn1.codec.ber import encoder
from pysnmp.proto import api

from snmpsim.commands.pcap2rec import main as pcap2rec_main


def build_snmp_response(community, var_binds):
    """Encode a v2c response carrying the given var-binds."""
    p_mod = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]

    message = p_mod.Message()
    p_mod.apiMessage.set_defaults(message)
    p_mod.apiMessage.set_community(message, community)

    pdu = p_mod.ResponsePDU()
    p_mod.apiPDU.set_defaults(pdu)
    p_mod.apiPDU.set_varbinds(
        pdu,
        [
            (p_mod.ObjectIdentifier(oid), p_mod.OctetString(value))
            for oid, value in var_binds
        ],
    )

    p_mod.apiMessage.set_pdu(message, pdu)

    return encoder.encode(message)


def build_udp_frame(payload, source="192.0.2.1", source_port=161):
    """Wrap a payload into Ethernet/IPv4/UDP, the way tcpdump would see it."""
    udp = struct.pack("!HHHH", source_port, 32768, 8 + len(payload), 0) + payload

    ip = (
        struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0)
        + bytes(int(x) for x in source.split("."))
        + bytes((198, 51, 100, 1))
    )

    ethernet = bytes(6) + bytes(6) + struct.pack("!H", 0x0800)

    return ethernet + ip + udp


def write_capture(path, frames):
    """Write frames into a classic little-endian libpcap file."""
    with open(path, "wb") as capture:
        capture.write(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # Ethernet
        )

        for number, frame in enumerate(frames):
            capture.write(
                struct.pack("<IIII", 1700000000 + number, 0, len(frame), len(frame))
            )
            capture.write(frame)


def test_pcap2rec_builds_recording_from_capture(monkeypatch, tmp_path):
    """A capture of SNMP responses turns into a simulation data file."""
    capture_file = tmp_path / "snmp.pcap"
    output_dir = tmp_path / "data"

    write_capture(
        str(capture_file),
        [
            build_udp_frame(
                build_snmp_response(
                    "public",
                    [
                        ("1.3.6.1.2.1.1.1.0", "Captured device"),
                        ("1.3.6.1.2.1.1.5.0", "device-1"),
                    ],
                )
            ),
            build_udp_frame(
                build_snmp_response("public", [("1.3.6.1.2.1.1.6.0", "Server room")])
            ),
        ],
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "snmpsim-record-traffic",
            f"--capture-file={capture_file}",
            f"--output-dir={output_dir}",
            "--quiet",
        ],
    )

    assert pcap2rec_main() == 0

    recordings = [
        os.path.join(root, name)
        for root, _, names in os.walk(output_dir)
        for name in names
        if name.endswith(".snmprec")
    ]

    assert len(recordings) == 1, f"expected one recording, got {recordings}"

    with open(recordings[0], "rb") as recording:
        records = recording.read().decode("iso-8859-1").splitlines()

    # values holding non-alphanumeric bytes are written hexified
    served = {}

    for record in records:
        oid, tag, value = record.split("|", 2)
        served[oid] = bytes.fromhex(value).decode() if tag.endswith("x") else value

    assert served == {
        "1.3.6.1.2.1.1.1.0": "Captured device",
        "1.3.6.1.2.1.1.5.0": "device-1",
        "1.3.6.1.2.1.1.6.0": "Server room",
    }


def test_pcap2rec_decodes_version_by_current_name(monkeypatch, tmp_path):
    """A capture converts without pysnmp's camelCase version decoder.

    `pysnmp.proto.api.decodeMessageVersion` is a leftover alias of
    `verdec.decode_message_version`; the converter must not depend on it.
    """
    capture_file = tmp_path / "snmp.pcap"
    output_dir = tmp_path / "data"

    write_capture(
        str(capture_file),
        [
            build_udp_frame(
                build_snmp_response("public", [("1.3.6.1.2.1.1.5.0", "device1")])
            )
        ],
    )

    monkeypatch.delattr("pysnmp.proto.api.decodeMessageVersion")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "snmpsim-record-traffic",
            f"--capture-file={capture_file}",
            f"--output-dir={output_dir}",
            "--quiet",
        ],
    )

    assert pcap2rec_main() == 0

    recordings = [
        os.path.join(root, name)
        for root, _, names in os.walk(output_dir)
        for name in names
        if name.endswith(".snmprec")
    ]

    assert len(recordings) == 1, f"expected one recording, got {recordings}"

    with open(recordings[0]) as recording:
        records = set(recording.read().splitlines())

    assert records == {"1.3.6.1.2.1.1.5.0|4|device1"}


def convert(monkeypatch, tmp_path, frames, *options):
    """Run the converter over the frames, return its exit code and records.

    Records come back as the lines of the one recording written, in file
    order, or as an empty list when no recording was written.
    """
    capture_file = tmp_path / "snmp.pcap"
    output_dir = tmp_path / "data"

    write_capture(str(capture_file), frames)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "snmpsim-record-traffic",
            f"--capture-file={capture_file}",
            f"--output-dir={output_dir}",
            *options,
        ],
    )

    rc = pcap2rec_main()

    recordings = [
        os.path.join(root, name)
        for root, _, names in os.walk(output_dir)
        for name in names
    ]

    assert len(recordings) < 2, f"expected one recording, got {recordings}"

    records = []

    for filename in recordings:
        with open(filename) as recording:
            records = recording.read().splitlines()

    return rc, records


def test_pcap2rec_writes_every_oid_once(monkeypatch, tmp_path):
    """Three OIDs in the capture make three records, the last one included."""
    rc, records = convert(
        monkeypatch,
        tmp_path,
        [
            build_udp_frame(
                build_snmp_response(
                    "public",
                    [("1.3.6.1.2.1.1.1.0", "sys"), ("1.3.6.1.2.1.1.5.0", "device1")],
                )
            ),
            build_udp_frame(
                build_snmp_response("public", [("1.3.6.1.2.1.1.6.0", "rack")])
            ),
        ],
        "--quiet",
    )

    assert rc == 0
    assert records == [
        "1.3.6.1.2.1.1.1.0|4|sys",
        "1.3.6.1.2.1.1.5.0|4|device1",
        "1.3.6.1.2.1.1.6.0|4|rack",
    ]


def test_pcap2rec_writes_a_single_oid_once(monkeypatch, tmp_path):
    rc, records = convert(
        monkeypatch,
        tmp_path,
        [
            build_udp_frame(
                build_snmp_response("public", [("1.3.6.1.2.1.1.5.0", "device1")])
            )
        ],
        "--quiet",
    )

    assert rc == 0
    assert records == ["1.3.6.1.2.1.1.5.0|4|device1"]


def test_pcap2rec_skips_packets_that_are_not_snmp(monkeypatch, tmp_path, caplog):
    """Other traffic in the capture is counted and passed over.

    A capture file is not filtered, so it holds whatever else was on the
    wire: frames cut short, other protocols, UDP payloads that are not BER.
    None of them may end the conversion ahead of the SNMP that follows.
    """
    rc, records = convert(
        monkeypatch,
        tmp_path,
        [
            build_udp_frame(
                build_snmp_response("public", [("1.3.6.1.2.1.1.1.0", "sys")])
            ),
            build_udp_frame(b"hello world"),  # pysnmp raises TypeError on it
            build_udp_frame(b""),
            bytes(14),  # Ethernet header and nothing else
            bytes(14) + b"\x45",  # IPv4 header cut short
            bytes(12) + b"\x08\x06" + bytes(28),  # ARP
            build_udp_frame(
                build_snmp_response("public", [("1.3.6.1.2.1.1.5.0", "device1")])
            ),
        ],
    )

    assert rc == 0
    assert records == ["1.3.6.1.2.1.1.1.0|4|sys", "1.3.6.1.2.1.1.5.0|4|device1"]
    assert "bad packets: 5" in caplog.text


def test_pcap2rec_fails_on_error_in_packet_handler(monkeypatch, tmp_path, caplog):
    """An unexpected error while reading packets is reported, exit code 1.

    What was read before the error is still written out.
    """
    from snmpsim.commands import pcap2rec

    # only the converter's own decoder: pysnmp keeps the real one
    decode = pcap2rec.decoder.decode
    seen = []

    def decode_once(*args, **kwargs):
        seen.append(args)

        if len(seen) > 1:
            raise TypeError("decoder fell over")

        return decode(*args, **kwargs)

    monkeypatch.setattr(pcap2rec, "decoder", types.SimpleNamespace(decode=decode_once))

    rc, records = convert(
        monkeypatch,
        tmp_path,
        [
            build_udp_frame(
                build_snmp_response("public", [("1.3.6.1.2.1.1.1.0", "sys")])
            ),
            build_udp_frame(
                build_snmp_response("public", [("1.3.6.1.2.1.1.5.0", "device1")])
            ),
        ],
        "--quiet",
    )

    assert rc == 1
    assert records == ["1.3.6.1.2.1.1.1.0|4|sys"]

    assert "packet 2: TypeError: decoder fell over" in caplog.text


def test_pcap2rec_writes_nothing_for_oids_out_of_range(monkeypatch, tmp_path):
    """A context whose OIDs all fall outside the range leaves no file."""
    rc, records = convert(
        monkeypatch,
        tmp_path,
        [
            build_udp_frame(
                build_snmp_response("public", [("1.3.6.1.2.1.1.5.0", "device1")])
            )
        ],
        "--quiet",
        "--start-object=1.3.6.1.4",
    )

    assert rc == 0
    assert records == []


SNAPSHOT_MODULE = """\
from snmpsim import error


def init(**context):
    moduleContext["calls"] = []
    moduleContext["passes"] = 2


def record(oid, tag, value, **context):
    moduleContext["calls"].append((oid, context["stopFlag"]))

    if context["stopFlag"]:
        moduleContext["passes"] -= 1

        if moduleContext["passes"]:
            raise error.MoreDataNotification(period=10)

        raise error.NoDataNotification()

    return oid, tag, "%s@%s" % (value, context["iteration"])


def shutdown(**context):
    with open(context["options"], "w") as calls:
        for oid, stop_flag in moduleContext["calls"]:
            calls.write("%s %s\\n" % (oid, stop_flag))
"""


def test_pcap2rec_tells_variation_module_where_a_pass_ends(monkeypatch, tmp_path):
    """The record after the last OID carries the stop flag.

    That is the variation module's cue to ask for another pass over the
    capture, taken further down its timeline: here the module asks for a
    second pass ten seconds on, where the device reported other values.
    """
    modules_dir = tmp_path / "variation"
    modules_dir.mkdir()
    (modules_dir / "snapshot.py").write_text(SNAPSHOT_MODULE)

    calls_file = tmp_path / "calls"

    frames = [
        build_udp_frame(
            build_snmp_response(
                "public", [("1.3.6.1.2.1.1.3.0", "early"), ("1.3.6.1.2.1.1.5.0", "a")]
            )
        )
    ]

    # one frame a second: the tenth second is where the values change
    frames += [
        build_udp_frame(build_snmp_response("public", [("1.3.6.1.2.1.1.4.0", "x")]))
    ] * 9

    frames.append(
        build_udp_frame(
            build_snmp_response(
                "public", [("1.3.6.1.2.1.1.3.0", "late"), ("1.3.6.1.2.1.1.5.0", "b")]
            )
        )
    )

    rc, records = convert(
        monkeypatch,
        tmp_path,
        frames,
        "--quiet",
        f"--variation-modules-dir={modules_dir}",
        "--variation-module=snapshot",
        f"--variation-module-options={calls_file}",
    )

    assert rc == 0
    assert records == [
        "1.3.6.1.2.1.1.3.0|4|early@0",
        "1.3.6.1.2.1.1.4.0|4|x@0",
        "1.3.6.1.2.1.1.5.0|4|a@0",
        "1.3.6.1.2.1.1.3.0|4|late@1",
        "1.3.6.1.2.1.1.4.0|4|x@1",
        "1.3.6.1.2.1.1.5.0|4|b@1",
    ]

    one_pass = [
        "1.3.6.1.2.1.1.3.0 False",
        "1.3.6.1.2.1.1.4.0 False",
        "1.3.6.1.2.1.1.5.0 False",
        "1.3.6.1.2.1.1.5.0 True",
    ]

    assert calls_file.read_text().splitlines() == one_pass * 2
