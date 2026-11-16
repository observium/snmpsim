"""--v1-only and --v2c-only make the responder speak one SNMP version.

An agent configured for one version does not answer the others at all: the
manager gets no error and no report, it times out. The responder used to
answer every version whatever it simulated, so a manager which wrongly fell
back to another version was never caught.
"""
import asyncio
import contextlib
import os
import socket
import subprocess
import sys
import tempfile
import time

import pytest
from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data", "agent")

V1_PORT = 1673
V2C_PORT = 1674
ALL_PORT = 1675
V3_PORT = 1676

SYS_DESCR = "1.3.6.1.2.1.1.1.0"

# a USM user without keys, so that the tests need no crypto backend
USM_USER = "tester"

STARTUP_DEADLINE = 30
LIFETIME = 600


def snmp_get(port, version, timeout=2):
    """GET sysDescr.0 from 127.0.0.1:port over the SNMP version asked for.

    Returns error-indication, error-status and the var-binds.
    """
    if version == "3":
        auth_data = UsmUserData(USM_USER)
        context_data = ContextData(contextName="public")

    else:
        auth_data = CommunityData("public", mpModel={"1": 0, "2c": 1}[version])
        context_data = ContextData()

    async def get():
        snmp_engine = SnmpEngine()
        try:
            return await get_cmd(
                snmp_engine,
                auth_data,
                await UdpTransportTarget.create(
                    ("127.0.0.1", port), timeout=timeout, retries=0
                ),
                context_data,
                ObjectType(ObjectIdentity(SYS_DESCR)),
            )

        finally:
            if snmp_engine.transport_dispatcher:
                snmp_engine.transport_dispatcher.close_dispatcher()

    loop = asyncio.new_event_loop()
    try:
        error_indication, error_status, _, var_binds = loop.run_until_complete(get())

    finally:
        loop.close()

    return error_indication, error_status, var_binds


@contextlib.contextmanager
def running_responder(*options, port, version):
    """Run a responder until the block is left.

    The block is entered once the responder has answered over `version`: the
    shared fixture always asks over SNMPv2c, which is the very thing some of
    these responders must not answer.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))

        except OSError as exc:
            pytest.fail(f"port {port} is in use, no responder started: {exc}")

    with tempfile.TemporaryFile() as stderr:
        responder = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "snmpsim.commands.responder",
                f"--data-dir={DATA_DIR}",
                f"--v3-user={USM_USER}",
                f"--agent-udpv4-endpoint=127.0.0.1:{port}",
                f"--timeout={LIFETIME}",
            ]
            + list(options),
            stdout=subprocess.DEVNULL,
            stderr=stderr,
        )

        def said():
            stderr.seek(0)
            return stderr.read().decode(errors="replace")

        try:
            deadline = time.monotonic() + STARTUP_DEADLINE

            while True:
                if responder.poll() is not None:
                    pytest.fail(
                        f"the responder on port {port} exited with "
                        f"{responder.returncode}:\n{said()}"
                    )

                error_indication, _, _ = snmp_get(port, version, timeout=0.5)

                if error_indication is None:
                    break

                if time.monotonic() > deadline:
                    pytest.fail(
                        f"the responder on port {port} did not answer SNMPv"
                        f"{version} in {STARTUP_DEADLINE} sec "
                        f"({error_indication}):\n{said()}"
                    )

                time.sleep(0.1)

            yield said

        finally:
            responder.terminate()

            try:
                responder.wait(timeout=10)

            except subprocess.TimeoutExpired:
                responder.kill()
                responder.wait()


def answers(port, version):
    error_indication, error_status, var_binds = snmp_get(port, version)

    if error_indication is not None:
        return False

    assert not error_status
    assert var_binds[0][1].asOctets() == b"Test device"

    return True


def times_out(port, version):
    error_indication, _, _ = snmp_get(port, version)

    return "timeout" in str(error_indication).lower()


def test_all_versions_are_served_by_default():
    with running_responder(port=ALL_PORT, version="2c"):
        assert answers(ALL_PORT, "1")
        assert answers(ALL_PORT, "2c")
        assert answers(ALL_PORT, "3")


def test_v1_only_answers_nothing_but_v1():
    with running_responder("--v1-only", port=V1_PORT, version="1") as said:
        assert answers(V1_PORT, "1")
        assert times_out(V1_PORT, "2c")
        assert times_out(V1_PORT, "3")
        # the disabled versions did not knock the responder over
        assert answers(V1_PORT, "1")

        assert "SNMP versions served: 1" in said()


def test_v2c_only_answers_nothing_but_v2c():
    with running_responder("--v2c-only", port=V2C_PORT, version="2c") as said:
        assert answers(V2C_PORT, "2c")
        assert times_out(V2C_PORT, "1")
        assert times_out(V2C_PORT, "3")
        assert answers(V2C_PORT, "2c")

        assert "SNMP versions served: 2c" in said()


def test_v3_only_still_answers_v3():
    with running_responder("--v3-only", port=V3_PORT, version="3"):
        assert answers(V3_PORT, "3")


@pytest.mark.parametrize(
    "flags",
    [
        ("--v1-only", "--v2c-only"),
        ("--v1-only", "--v3-only"),
        ("--v2c-only", "--v3-only"),
    ],
)
def test_two_only_flags_are_an_argument_error(flags):
    responder = subprocess.run(
        [
            sys.executable,
            "-m",
            "snmpsim.commands.responder",
            f"--data-dir={DATA_DIR}",
            "--agent-udpv4-endpoint=127.0.0.1:1677",
            "--timeout=5",
        ]
        + list(flags),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=20,
        text=True,
    )

    assert responder.returncode == 2, responder.stderr
    assert f"{flags[1]}: not allowed with argument {flags[0]}" in responder.stderr
    assert "Listening" not in responder.stderr
