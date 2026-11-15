import asyncio
import contextlib
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
    it gets no --timeout, which is its whole lifetime and so has to be longer
    than everything the tests are going to do with it.
    """
    with tempfile.TemporaryFile() as stderr:
        responder = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "snmpsim.commands.responder",
                f"--agent-udpv4-endpoint=127.0.0.1:{port}",
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

                error_indication, _, _ = snmp_get(port, oid, community, timeout=0.5)

                if error_indication is None:
                    break

                if time.monotonic() > deadline:
                    pytest.fail(
                        f"the responder on port {port} did not answer in "
                        f"{STARTUP_DEADLINE} sec ({error_indication}):\n{said()}"
                    )

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
