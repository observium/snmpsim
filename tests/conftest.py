import asyncio
import contextlib
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
    get_cmd,
)

# how long a responder may take to answer its first request
STARTUP_DEADLINE = 30

# no test run takes that long: a responder whose pytest was killed, so that
# nobody is left to terminate it, goes away by itself
LIFETIME = 600


def snmp_get(port, oid, community="public", timeout=2):
    """Ask 127.0.0.1:port for one OID over SNMPv2c.

    Returns error-indication, error-status and the var-binds. Runs on a loop
    of its own, so it can be called from a fixture or a plain test.
    """

    async def get():
        snmp_engine = SnmpEngine()
        try:
            return await get_cmd(
                snmp_engine,
                CommunityData(community, mpModel=1),
                await UdpTransportTarget.create(
                    ("127.0.0.1", port), timeout=timeout, retries=0
                ),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
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
def running_responder(*options, port, oid, community="public"):
    """Run a responder in a process of its own for as long as the block lasts.

    The block is entered once the responder has answered a GET of `oid`, not
    after a guessed delay, and the responder lives until the block is left:
    its --timeout, which is its whole lifetime, is far longer than anything
    the tests are going to do with it.

    The port has to be free. Were somebody else answering on it, the probe
    would be answered by them and the tests would run against their data; a
    responder does not even have to fail on a taken port, where the system
    lets two processes share one.
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

        def alive():
            if responder.poll() is not None:
                pytest.fail(
                    f"the responder on port {port} exited with "
                    f"{responder.returncode}:\n{said()}"
                )

        try:
            deadline = time.monotonic() + STARTUP_DEADLINE

            while True:
                alive()

                error_indication, _, _ = snmp_get(port, oid, community, timeout=0.5)

                if error_indication is None:
                    break

                if time.monotonic() > deadline:
                    pytest.fail(
                        f"the responder on port {port} did not answer in "
                        f"{STARTUP_DEADLINE} sec ({error_indication}):\n{said()}"
                    )

                # a GET which fails at once must not turn this into a busy loop
                time.sleep(0.1)

            # the answer has to be from the responder started here: one which
            # lost the port to somebody else in the meantime is on its way out
            time.sleep(0.2)
            alive()

            yield f"127.0.0.1:{port}"

        finally:
            responder.terminate()

            try:
                responder.wait(timeout=10)

            except subprocess.TimeoutExpired:
                responder.kill()
                responder.wait()


@pytest.fixture(scope="session")
def responder_process():
    """Hand out `running_responder`, see there."""
    return running_responder


@pytest.fixture(scope="session")
def get_from_responder():
    """Hand out `snmp_get`, see there."""
    return snmp_get
