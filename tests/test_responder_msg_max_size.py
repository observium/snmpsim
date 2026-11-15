"""A GETBULK response fits the message size the manager said it can take.

Every SNMPv3 message carries msgMaxSize: the largest message its sender is
able to receive (RFC 3412, 6.2). 484 octets is the smallest value allowed and
what a manager with a small receive buffer announces. The responder used to
fill the response up to its own `--max-message-size` (1472 octets) whatever
the manager announced, and pysnmp then dropped the oversized response on its
way out without a word, so the manager saw nothing but a timeout.

SNMPv1 and SNMPv2c messages carry no such field, there is nothing to respect.
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
    USM_AUTH_HMAC96_SHA,
    USM_PRIV_CFB128_AES,
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_cmd,
    bulk_walk_cmd,
)

from snmpsim import utils

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 40 rows of about 220 octets each: nine kilobytes, none of the limits here
# takes the whole table
DATA_DIR = os.path.join(BASE_DIR, "data", "bulk")

PORT = 1677

TABLE = "1.3.6.1.4.1.99999.1.1.1"
ROWS = 40
MAX_REPETITIONS = 50

USM_USER = "smallbuffer"
AUTH_PASSPHRASE = "auctoritas-maxima"
PRIV_PASSPHRASE = "privatus-maximus"

# RFC 3412, 6.2: msgMaxSize INTEGER (484..2147483647)
SMALLEST_MSG_MAX_SIZE = 484

STARTUP_DEADLINE = 30
LIFETIME = 600

V3_AUTH_PRIV = UsmUserData(
    USM_USER,
    AUTH_PASSPHRASE,
    PRIV_PASSPHRASE,
    authProtocol=USM_AUTH_HMAC96_SHA,
    privProtocol=USM_PRIV_CFB128_AES,
)
V2C = CommunityData("public", mpModel=1)


def manager(msg_max_size=None):
    """An SNMP engine of a manager, and the sizes of the responses it gets.

    `msg_max_size` is what the manager puts into msgMaxSize of its SNMPv3
    requests.
    """
    snmp_engine = SnmpEngine()

    if msg_max_size is not None:
        (max_message_size,) = snmp_engine.get_mib_builder().import_symbols(
            "__SNMP-FRAMEWORK-MIB", "snmpEngineMaxMessageSize"
        )
        max_message_size.syntax = max_message_size.syntax.clone(msg_max_size)

    response_sizes = []

    def on_response(snmp_engine, execpoint, variables, cb_ctx):
        response_sizes.append(len(variables["wholeMsg"]))

    snmp_engine.observer.register_observer(
        on_response, "rfc3412.receiveMessage:response"
    )

    return snmp_engine, response_sizes


def context(auth_data):
    # the recording is picked by the community name, or by the context name
    # where there is no community
    if isinstance(auth_data, CommunityData):
        return ContextData()

    return ContextData(contextName="public")


def run(coroutine):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coroutine)

    finally:
        loop.close()


def get_bulk(auth_data, msg_max_size=None, timeout=2):
    """One GETBULK over the table.

    Returns error-indication, error-status, the var-binds and the size of
    the response message on the wire (None when no response came).
    """

    async def request():
        snmp_engine, response_sizes = manager(msg_max_size)
        try:
            error_indication, error_status, _, var_binds = await bulk_cmd(
                snmp_engine,
                auth_data,
                await UdpTransportTarget.create(
                    ("127.0.0.1", PORT), timeout=timeout, retries=0
                ),
                context(auth_data),
                0,
                MAX_REPETITIONS,
                ObjectType(ObjectIdentity(TABLE)),
            )

        finally:
            if snmp_engine.transport_dispatcher:
                snmp_engine.transport_dispatcher.close_dispatcher()

        # with SNMPv3 the engine ID discovery is answered first
        size = response_sizes[-1] if response_sizes and var_binds else None

        return error_indication, error_status, var_binds, size

    return run(request())


def bulk_walk(auth_data, msg_max_size=None):
    """Walk the table with GETBULK.

    Returns the values and the sizes of all the response messages.
    """

    async def walk():
        snmp_engine, response_sizes = manager(msg_max_size)
        values = []
        try:
            async for error_indication, error_status, _, var_binds in bulk_walk_cmd(
                snmp_engine,
                auth_data,
                await UdpTransportTarget.create(
                    ("127.0.0.1", PORT), timeout=2, retries=0
                ),
                context(auth_data),
                0,
                MAX_REPETITIONS,
                ObjectType(ObjectIdentity(TABLE)),
                lexicographicMode=False,
            ):
                assert error_indication is None, error_indication
                assert not error_status, error_status

                values.extend(value.asOctets() for _, value in var_binds)

        finally:
            if snmp_engine.transport_dispatcher:
                snmp_engine.transport_dispatcher.close_dispatcher()

        return values, response_sizes

    return run(walk())


@contextlib.contextmanager
def running_responder(*options):
    """Run a responder until the block is left.

    The block is entered once the responder has answered a manager which
    takes messages of any size.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.bind(("127.0.0.1", PORT))

        except OSError as exc:
            pytest.fail(f"port {PORT} is in use, no responder started: {exc}")

    command = [
        sys.executable,
        "-m",
        "snmpsim.commands.responder",
        f"--v3-user={USM_USER}",
        "--v3-auth-proto=SHA",
        f"--v3-auth-key={AUTH_PASSPHRASE}",
        "--v3-priv-proto=AES",
        f"--v3-priv-key={PRIV_PASSPHRASE}",
        *options,
        f"--data-dir={DATA_DIR}",
        f"--agent-udpv4-endpoint=127.0.0.1:{PORT}",
        f"--timeout={LIFETIME}",
    ]

    with tempfile.TemporaryFile() as stderr:
        responder = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=stderr)

        def said():
            stderr.seek(0)
            return stderr.read().decode(errors="replace")

        try:
            deadline = time.monotonic() + STARTUP_DEADLINE

            while True:
                if responder.poll() is not None:
                    pytest.fail(
                        f"the responder exited with {responder.returncode}:\n{said()}"
                    )

                error_indication, _, _, _ = get_bulk(V3_AUTH_PRIV, timeout=0.5)

                if error_indication is None:
                    break

                if time.monotonic() > deadline:
                    pytest.fail(
                        f"the responder did not answer in {STARTUP_DEADLINE} sec "
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


@pytest.fixture
def responder():
    with running_responder() as said:
        yield said


def test_v3_response_fits_the_size_the_manager_takes(responder):
    error_indication, error_status, var_binds, size = get_bulk(
        V3_AUTH_PRIV, msg_max_size=SMALLEST_MSG_MAX_SIZE
    )

    assert error_indication is None, error_indication
    assert not error_status
    assert 0 < len(var_binds) < MAX_REPETITIONS
    assert size <= SMALLEST_MSG_MAX_SIZE


def test_v3_walk_gets_every_row_in_messages_that_fit(responder):
    for msg_max_size in SMALLEST_MSG_MAX_SIZE, 600, 1000:
        values, response_sizes = bulk_walk(V3_AUTH_PRIV, msg_max_size=msg_max_size)

        assert len(values) == ROWS
        assert values[0].startswith(b"row001-")
        assert values[-1].startswith(b"row040-")
        assert max(response_sizes) <= msg_max_size


def test_larger_size_gets_more_rows_into_a_response(responder):
    """The limit follows the manager, it is not just a smaller constant."""
    _, _, small, _ = get_bulk(V3_AUTH_PRIV, msg_max_size=SMALLEST_MSG_MAX_SIZE)
    _, _, medium, medium_size = get_bulk(V3_AUTH_PRIV, msg_max_size=1000)

    assert 0 < len(small) < len(medium)
    assert medium_size <= 1000


def test_v3_response_is_still_capped_by_the_responder(responder):
    """A manager able to take 64K still gets a response of one datagram."""
    error_indication, _, var_binds, size = get_bulk(V3_AUTH_PRIV)

    assert error_indication is None, error_indication
    assert len(var_binds) == 6
    assert SMALLEST_MSG_MAX_SIZE < size <= utils.MAX_MESSAGE_SIZE


def test_max_message_size_option_wins_when_it_is_smaller():
    with running_responder("--max-message-size=600"):
        _, _, var_binds, size = get_bulk(V3_AUTH_PRIV, msg_max_size=1000)

        assert var_binds
        assert size <= 600


def test_v2c_response_is_what_it_was(responder):
    """SNMPv2c has no msgMaxSize, the response is as large as it used to be."""
    error_indication, _, var_binds, size = get_bulk(V2C)

    assert error_indication is None, error_indication
    assert len(var_binds) == 6
    assert SMALLEST_MSG_MAX_SIZE < size <= utils.MAX_MESSAGE_SIZE
