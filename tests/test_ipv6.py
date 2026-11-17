"""The responders and the recorder over UDP/IPv6, on the loopback ::1.

Skipped where the machine cannot bind ::1. An endpoint without a port is
port 161, which takes root to bind: that it is taken is tested on its own
(test_responder_lite_compat.py), not here.
"""
import asyncio
import contextlib
import socket
import subprocess
import sys
import tempfile
import time

import pytest
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp.hlapi.asyncio import ContextData
from pysnmp.hlapi.asyncio import ObjectIdentity
from pysnmp.hlapi.asyncio import ObjectType
from pysnmp.hlapi.asyncio import SnmpEngine
from pysnmp.hlapi.asyncio import Udp6TransportTarget
from pysnmp.hlapi.asyncio import UsmUserData
from pysnmp.hlapi.asyncio import get_cmd
from pysnmp.hlapi.asyncio import usmAesCfb128Protocol
from pysnmp.hlapi.asyncio import usmHMACSHAAuthProtocol
from pysnmp.proto import api
from pysnmp.proto import rfc1902

from snmpsim.commands.cmd2rec import main as cmd2rec_main

FULL_PORT = 1701
LITE_PORT = 1702

V1, V2C = api.SNMP_VERSION_1, api.SNMP_VERSION_2C

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"

# the transport ID of the first, and here only, UDP/IPv6 endpoint
IPV6_TRANSPORT_ID = "1.3.6.1.2.1.100.1.2.0"

PUBLIC = """\
1.3.6.1.2.1.1.1.0|4|Test device
1.3.6.1.2.1.1.2.0|6|1.3.6.1.4.1.99999
1.3.6.1.2.1.1.3.0|67|123456
1.3.6.1.2.1.2.2.1.2.1|4|GigabitEthernet0/1
1.3.6.1.2.1.2.2.1.5.1|66|1000000000
"""

V3_USER = [
    "--v3-user=six",
    "--v3-auth-key=authkey12345",
    "--v3-auth-proto=SHA",
    "--v3-priv-key=privkey12345",
    "--v3-priv-proto=AES",
]

STARTUP_DEADLINE = 60


def ipv6_loopback():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind(("::1", 0))

    except OSError:
        return False

    return True


pytestmark = pytest.mark.skipif(not ipv6_loopback(), reason="no IPv6 loopback")


def message(version, community, oid, pdu_type="GetRequestPDU"):
    proto = api.PROTOCOL_MODULES[version]

    pdu = getattr(proto, pdu_type)()
    proto.apiPDU.set_defaults(pdu)
    proto.apiPDU.set_request_id(pdu, 4242)
    proto.apiPDU.set_varbinds(pdu, [(rfc1902.ObjectName(oid), univ.Null(""))])

    msg = proto.Message()
    proto.apiMessage.set_defaults(msg)
    proto.apiMessage.set_community(msg, community)
    proto.apiMessage.set_pdu(msg, pdu)

    return encoder.encode(msg)


def ask(port, request, timeout=1):
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(request, ("::1", port))

        try:
            return sock.recv(65535)

        # Windows tells of a port nobody listens on yet with a reset
        except (socket.timeout, ConnectionResetError):
            return None


def answer(version, response):
    """The var-binds of a response, as text."""
    proto = api.PROTOCOL_MODULES[version]
    msg, _ = decoder.decode(response, asn1Spec=proto.Message())
    pdu = proto.apiMessage.get_pdu(msg)

    return [
        (str(oid), value.prettyPrint()) for oid, value in proto.apiPDU.get_varbinds(pdu)
    ]


@contextlib.contextmanager
def started(module, port, stop, *options):
    """A responder on [::1]:port, once it answers SNMPv2c there."""
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
        probe.bind(("::1", port))

    with tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            [sys.executable, "-m", module, f"--agent-udpv6-endpoint=[::1]:{port}"]
            + list(options),
            stdout=subprocess.DEVNULL,
            stderr=stderr,
        )

        try:
            deadline = time.monotonic() + STARTUP_DEADLINE

            while ask(port, message(V2C, "public", SYS_DESCR)) is None:
                if process.poll() is not None or time.monotonic() > deadline:
                    stderr.seek(0)
                    pytest.fail(
                        "not started: " + stderr.read().decode(errors="replace")
                    )

            yield process

        finally:
            stop(process)


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    data = tmp_path_factory.mktemp("data")
    (data / "public.snmprec").write_text(PUBLIC)

    # a recording for managers at ::1 coming in by the IPv6 endpoint: the
    # colons of the address become underscores in the file's name
    by_address = data / "byaddr" / IPV6_TRANSPORT_ID
    by_address.mkdir(parents=True)
    (by_address / "__1.snmprec").write_text(f"{SYS_NAME}|4|by-ipv6-address\n")

    return data


@pytest.fixture(scope="module")
def full(data_dir, process_stopper):
    with started(
        "snmpsim.commands.responder",
        FULL_PORT,
        process_stopper,
        f"--data-dir={data_dir}",
        *V3_USER,
        "--timeout=600",
    ) as process:
        yield process


@pytest.fixture(scope="module")
def lite(data_dir, process_stopper):
    with started(
        "snmpsim.commands.responder_lite",
        LITE_PORT,
        process_stopper,
        f"--data-dir={data_dir}",
    ) as process:
        yield process


@pytest.mark.parametrize("version", [V1, V2C], ids=["v1", "v2c"])
@pytest.mark.parametrize("pdu_type", ["GetRequestPDU", "GetNextRequestPDU"])
def test_snmpv1_and_v2c_are_answered_over_ipv6(full, version, pdu_type):
    oid = SYS_DESCR if pdu_type == "GetRequestPDU" else "1.3.6.1.2.1.1"

    response = ask(FULL_PORT, message(version, "public", oid, pdu_type))

    assert response is not None
    assert answer(version, response) == [(SYS_DESCR, "Test device")]


def snmpv3_get(port, oid):
    async def get():
        engine = SnmpEngine()

        try:
            return await get_cmd(
                engine,
                UsmUserData(
                    "six",
                    "authkey12345",
                    "privkey12345",
                    authProtocol=usmHMACSHAAuthProtocol,
                    privProtocol=usmAesCfb128Protocol,
                ),
                await Udp6TransportTarget.create(("::1", port), timeout=2, retries=1),
                ContextData(contextName="public"),
                ObjectType(ObjectIdentity(oid)),
            )

        finally:
            engine.close_dispatcher()

    loop = asyncio.new_event_loop()

    try:
        return loop.run_until_complete(get())

    finally:
        loop.close()


def test_snmpv3_is_answered_over_ipv6(full):
    error_indication, error_status, _, var_binds = snmpv3_get(FULL_PORT, SYS_DESCR)

    assert error_indication is None and not error_status
    assert var_binds[0][1].prettyPrint() == "Test device"


@pytest.mark.parametrize("version", [V1, V2C], ids=["v1", "v2c"])
def test_a_recording_is_chosen_by_the_ipv6_address(full, version):
    response = ask(FULL_PORT, message(version, "byaddr", SYS_NAME))

    assert response is not None
    assert answer(version, response) == [(SYS_NAME, "by-ipv6-address")]


@pytest.mark.parametrize("version", [V1, V2C], ids=["v1", "v2c"])
def test_the_lite_responder_answers_over_ipv6_as_the_full_one(full, lite, version):
    for community, oid in (("public", SYS_DESCR), ("byaddr", SYS_NAME)):
        request = message(version, community, oid)

        response = ask(LITE_PORT, request)

        assert response is not None
        assert response == ask(FULL_PORT, request)


def record(monkeypatch, output_file, *options):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "snmpsim-record-commands",
            f"--agent-udpv6-endpoint=[::1]:{FULL_PORT}",
            f"--output-file={output_file}",
        ]
        + list(options),
    )

    assert cmd2rec_main() == 0

    return output_file.read_bytes()


@pytest.mark.parametrize("mode", ["getnext", "getbulk"])
def test_an_agent_is_recorded_over_ipv6(full, monkeypatch, tmp_path, mode):
    walk = ["--use-getbulk"] if mode == "getbulk" else []

    over_v2c = record(
        monkeypatch, tmp_path / "v2c.snmprec", "--community=public", *walk
    )

    served = {}

    for line in over_v2c.decode("iso-8859-1").splitlines():
        oid, tag, value = line.split("|", 2)
        served[oid] = bytes.fromhex(value).decode() if tag.endswith("x") else value

    assert served == {
        "1.3.6.1.2.1.1.1.0": "Test device",
        "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.99999",
        "1.3.6.1.2.1.1.3.0": "123456",
        "1.3.6.1.2.1.2.2.1.2.1": "GigabitEthernet0/1",
        "1.3.6.1.2.1.2.2.1.5.1": "1000000000",
    }

    over_v3 = record(
        monkeypatch,
        tmp_path / "v3.snmprec",
        "--v3-context-name=public",
        *V3_USER,
        *walk,
    )

    assert over_v3 == over_v2c
