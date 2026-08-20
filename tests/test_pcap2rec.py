import os
import struct
import sys

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
