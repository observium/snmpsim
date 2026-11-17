"""`snmpsim-command-responder-lite` is the full responder under its old name.

There is one command responder; the lite one takes the options it always
took, as it took them, and hands them on. What it was is kept: SNMPv1 and
SNMPv2c only, and SIGHUP ends it.
"""
import asyncio
import contextlib
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time

import pytest
from pysnmp.hlapi.asyncio import ContextData
from pysnmp.hlapi.asyncio import ObjectIdentity
from pysnmp.hlapi.asyncio import ObjectType
from pysnmp.hlapi.asyncio import SnmpEngine
from pysnmp.hlapi.asyncio import UdpTransportTarget
from pysnmp.hlapi.asyncio import UsmUserData
from pysnmp.hlapi.asyncio import get_cmd

from snmpsim import ber
from snmpsim.commands import responder_lite

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "agent")

SYS_DESCR = "1.3.6.1.2.1.1.1.0"

LITE_PORT = 1694
FULL_PORT = 1695
LITE_SIGHUP_PORT = 1699

STARTUP_DEADLINE = 60


def handed_on(*items):
    """What the full responder is given for the lite command line `items`."""
    responder_lite.build_parser().parse_args(items)

    return responder_lite.responder_arguments(
        responder_lite.build_parser(raw=True).parse_args(items)
    )


def test_options_are_handed_on_as_they_were_given():
    assert handed_on(
        "--data=/srv/a",
        "--data-dir=/srv/b",
        "--agent-udpv4-endpoint=127.0.0.1:1161",
        "--agent-udpv4-endpoint",
        "127.0.0.1:1162",
        "--logging-method=file:/var/log/sim.log:30m",
        "--reporting-method=fulljson:/var/tmp/reports",
        "--log-level=debug",
        "--debug=io",
        "--debug=msgproc",
        "--max-var-binds=10",
        "--max-message-size",
        "9000",
        "--transport-id-offset=3",
        "--quiet",
        "--force-index-rebuild",
        "--v2c-arch",
        "--v3-only",
    ) == [
        "--quiet",
        "--force-index-rebuild",
        "--logging-method=file:/var/log/sim.log:30m",
        "--log-level=debug",
        "--reporting-method=fulljson:/var/tmp/reports",
        f"--pid-file=/var/run/snmpsim.commands.responder_lite/{os.getpid()}.pid",
        "--transport-id-offset=3",
        "--max-var-binds=10",
        "--max-message-size=9000",
        "--debug=io",
        "--debug=msgproc",
        "--data-dir=/srv/a",
        "--data-dir=/srv/b",
        "--agent-udpv4-endpoint=127.0.0.1:1161",
        "--agent-udpv4-endpoint=127.0.0.1:1162",
    ]


def test_values_with_signs_in_them_are_handed_on_whole():
    assert handed_on(
        "--pid-file=/run/sim.pid",
        "--cache-dir=/var/cache/a=b",
        "--variation-module-options=sql=mydb:dbtype:sqlite3,database:/tmp/x.db",
        "--variation-modules-dir",
        "/opt/modules",
        "--agent-udpv6-endpoint=::1",
        "--agent-udpv6-endpoint=[fe80::1]",
    ) == [
        "--pid-file=/run/sim.pid",
        "--cache-dir=/var/cache/a=b",
        "--variation-modules-dir=/opt/modules",
        "--variation-module-options=sql=mydb:dbtype:sqlite3,database:/tmp/x.db",
        "--agent-udpv6-endpoint=::1",
        "--agent-udpv6-endpoint=[fe80::1]",
    ]


@pytest.mark.parametrize(
    "endpoint, address",
    [
        ("::1", ("::1", 161)),
        ("[::1]", ("::1", 161)),
        ("[::1]:1161", ("::1", 1161)),
        ("::", ("::", 161)),
    ],
)
def test_an_ipv6_endpoint_may_come_without_a_port(endpoint, address):
    # as the lite responder took it, and as the endpoint is bound
    from snmpsim import endpoints

    assert endpoints.parse_endpoint(endpoint, ipv6=True) == address


def test_an_option_left_out_is_left_to_the_full_responder():
    assert handed_on("--agent-udpv6-endpoint=[::1]:1161") == [
        f"--pid-file=/var/run/snmpsim.commands.responder_lite/{os.getpid()}.pid",
        "--agent-udpv6-endpoint=[::1]:1161",
    ]


@pytest.mark.parametrize(
    "items",
    [
        # no endpoint, and endpoints of both families
        ["--data-dir=/srv/a"],
        [
            "--agent-udpv4-endpoint=127.0.0.1:1161",
            "--agent-udpv6-endpoint=[::1]:1161",
        ],
        # what the full responder takes and the lite one never did
        ["--agent-udpv4-endpoint=127.0.0.1:1161", "--v3-user=simulator"],
        ["--agent-udpv4-endpoint=127.0.0.1:1161", "--v1-v2c-path=engine"],
        ["--agent-udpv4-endpoint=127.0.0.1:1161", "--log-level=chatty"],
    ],
    ids=["no endpoint", "both families", "v3 user", "v1-v2c-path", "log level"],
)
def test_what_the_lite_responder_refused_is_refused(items):
    with pytest.raises(SystemExit) as exc:
        responder_lite.main(items)

    assert exc.value.code == 2


@contextlib.contextmanager
def started(command, port, stderr, stop, *options):
    """A responder process, once it answers SNMPv2c on `port`."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", port))

    process = subprocess.Popen(
        [sys.executable, "-m", command, f"--data-dir={DATA_DIR}"]
        + [f"--agent-udpv4-endpoint=127.0.0.1:{port}"]
        + list(options),
        stdout=subprocess.DEVNULL,
        stderr=stderr,
    )

    try:
        deadline = time.monotonic() + STARTUP_DEADLINE

        while ask(port, read(1, 0xA0)) is None:
            if process.poll() is not None or time.monotonic() > deadline:
                stderr.seek(0)
                pytest.fail("not started: " + stderr.read().decode(errors="replace"))

        yield process

    finally:
        stop(process)


def read(version, pdu_tag):
    """A GET or GETNEXT of sysDescr from the "public" recording."""
    var_bind = ber.tlv(0x30, ber.encode_oid((1, 3, 6, 1, 2, 1, 1, 1, 0)) + b"\x05\x00")
    pdu = ber.tlv(
        pdu_tag,
        ber.tlv(2, b"\x07")
        + ber.tlv(2, b"\x00")
        + ber.tlv(2, b"\x00")
        + ber.tlv(0x30, var_bind),
    )
    return ber.tlv(0x30, ber.tlv(2, bytes([version])) + ber.tlv(4, b"public") + pdu)


def ask(port, request, timeout=1):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(request, ("127.0.0.1", port))

        try:
            return sock.recv(65535)

        # Windows tells of a port nobody listens on yet with a reset
        except (socket.timeout, ConnectionResetError):
            return None


def ask_v3(port):
    """What an SNMPv3 GET as an unknown user gets: a report, or nothing."""

    async def get():
        engine = SnmpEngine()

        try:
            return await get_cmd(
                engine,
                UsmUserData("nobody"),
                await UdpTransportTarget.create(
                    ("127.0.0.1", port), timeout=1, retries=0
                ),
                ContextData(),
                ObjectType(ObjectIdentity(SYS_DESCR)),
            )

        finally:
            engine.close_dispatcher()

    loop = asyncio.new_event_loop()

    try:
        return str(loop.run_until_complete(get())[0])

    finally:
        loop.close()


@pytest.fixture(scope="module")
def responders(process_stopper):
    with tempfile.TemporaryFile() as lite_err, tempfile.TemporaryFile() as full_err:
        # with the two options the lite responder took and did nothing with
        with started(
            "snmpsim.commands.responder_lite",
            LITE_PORT,
            lite_err,
            process_stopper,
            "--v2c-arch",
            "--v3-only",
        ) as lite, started(
            "snmpsim.commands.responder", FULL_PORT, full_err, process_stopper
        ) as full:
            yield lite, full


@pytest.mark.parametrize(
    "version, pdu_tag",
    [(0, 0xA0), (0, 0xA1), (1, 0xA0), (1, 0xA1)],
    ids=["v1 GET", "v1 GETNEXT", "v2c GET", "v2c GETNEXT"],
)
def test_snmpv1_and_v2c_are_answered_as_the_full_responder_answers(
    responders, version, pdu_tag
):
    lite = ask(LITE_PORT, read(version, pdu_tag))

    assert lite is not None
    assert lite == ask(FULL_PORT, read(version, pdu_tag))


def test_snmpv3_is_not_answered(responders):
    lite, _ = responders

    # the full responder answers an unknown user with a report
    assert "unknown" in ask_v3(FULL_PORT).lower()

    assert "no snmp response" in ask_v3(LITE_PORT).lower()

    # not answered by a responder that is there and serves the rest
    assert lite.poll() is None
    assert ask(LITE_PORT, read(1, 0xA0)) is not None


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
def test_sighup_ends_the_lite_responder_and_not_the_full_one(
    responders, process_stopper
):
    _, full = responders

    with tempfile.TemporaryFile() as stderr, started(
        "snmpsim.commands.responder_lite", LITE_SIGHUP_PORT, stderr, process_stopper
    ) as lite:
        full.send_signal(signal.SIGHUP)
        lite.send_signal(signal.SIGHUP)

        assert lite.wait(timeout=30) is not None

    # the full responder rescans and goes on answering
    time.sleep(1)
    assert full.poll() is None
    assert ask(FULL_PORT, read(1, 0xA0)) is not None


def test_a_data_directory_with_an_equals_sign_is_served(
    tmp_path, responder_process, get_from_responder
):
    # the lite responder hands --data-dir on as --data-dir=<path>, and the
    # full one took the path only up to its first "="
    data = tmp_path / "a=b"
    data.mkdir()
    (data / "public.snmprec").write_text("1.3.6.1.2.1.1.1.0|4|equals\n")

    # given as --data-dir=<path>, and as two words; a port each, as one that
    # was just given up may not be free at once
    for port, options in (
        (1698, [f"--data-dir={data}"]),
        (1700, ["--data-dir", str(data)]),
    ):
        with responder_process(*options, port=port, oid=SYS_DESCR):
            error_indication, error_status, var_binds = get_from_responder(
                port, SYS_DESCR
            )

        assert error_indication is None and not error_status
        assert var_binds[0][1].prettyPrint() == "equals"
