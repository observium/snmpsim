"""--v3-auth-key-type and --v3-priv-key-type take USM keys that are not passphrases.

A device configuration often holds not the passphrase of a USM user but the
key made of it: the master key (the hashed passphrase, RFC 3414 A.2) or the
localized one (the master key hashed with the engine ID). The responder took
every key for a passphrase, so such a user could not be simulated.

The keys are computed here with hashlib, not with pysnmp, so that the test
does not agree with the responder merely because both ask the same library.
"""
import asyncio
import contextlib
import hashlib
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

PORT = 1678
REFUSED_PORT = 1679

SYS_DESCR = "1.3.6.1.2.1.1.1.0"

USM_USER = "keyholder"
AUTH_PASSPHRASE = "auctoritas-maxima"
PRIV_PASSPHRASE = "privatus-maximus"

ENGINE_ID = "80004fb805736e6d7073696d01"

STARTUP_DEADLINE = 30
LIFETIME = 600


def master_key(passphrase, hash_name="sha1"):
    """RFC 3414 A.2: the hash of the first megabyte of the repeated passphrase."""
    passphrase = passphrase.encode()
    megabyte = passphrase * (1048576 // len(passphrase) + 1)

    return hashlib.new(hash_name, megabyte[:1048576]).digest()


def localized_key(passphrase, engine_id=ENGINE_ID, hash_name="sha1"):
    """RFC 3414 A.2: the master key hashed with the engine ID in the middle."""
    master = master_key(passphrase, hash_name)

    return hashlib.new(hash_name, master + bytes.fromhex(engine_id) + master).digest()


# AES-128 uses the first 16 octets of a localized SHA-1 key (RFC 3826, 1.2)
AUTH_MASTER = master_key(AUTH_PASSPHRASE).hex()
PRIV_MASTER = master_key(PRIV_PASSPHRASE).hex()
AUTH_LOCALIZED = localized_key(AUTH_PASSPHRASE).hex()
PRIV_LOCALIZED = localized_key(PRIV_PASSPHRASE)[:16].hex()


def snmp_get(port, auth_key, priv_key=None, timeout=2):
    """GET sysDescr.0 over SNMPv3 with passphrases, as a manager would.

    Returns error-indication, error-status and the var-binds.
    """
    if priv_key:
        auth_data = UsmUserData(
            USM_USER,
            auth_key,
            priv_key,
            authProtocol=USM_AUTH_HMAC96_SHA,
            privProtocol=USM_PRIV_CFB128_AES,
        )

    else:
        auth_data = UsmUserData(USM_USER, auth_key, authProtocol=USM_AUTH_HMAC96_SHA)

    async def get():
        snmp_engine = SnmpEngine()
        try:
            return await get_cmd(
                snmp_engine,
                auth_data,
                await UdpTransportTarget.create(
                    ("127.0.0.1", port), timeout=timeout, retries=0
                ),
                ContextData(contextName="public"),
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


def responder_command(*options, port):
    # the options go first: --v3-engine-id opens the configuration of an
    # engine, the data directory and the endpoint after it are that engine's
    return (
        [sys.executable, "-m", "snmpsim.commands.responder"]
        + list(options)
        + [
            f"--data-dir={DATA_DIR}",
            f"--agent-udpv4-endpoint=127.0.0.1:{port}",
            f"--timeout={LIFETIME}",
        ]
    )


@contextlib.contextmanager
def running_responder(*options, port=PORT, priv=False):
    """Run a responder until the block is left.

    The block is entered once the responder has answered a manager which
    knows the passphrases of the user.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))

        except OSError as exc:
            pytest.fail(f"port {port} is in use, no responder started: {exc}")

    with tempfile.TemporaryFile() as stderr:
        responder = subprocess.Popen(
            responder_command(*options, port=port),
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

                error_indication, _, _ = snmp_get(
                    port,
                    AUTH_PASSPHRASE,
                    PRIV_PASSPHRASE if priv else None,
                    timeout=0.5,
                )

                if error_indication is None:
                    break

                if time.monotonic() > deadline:
                    pytest.fail(
                        f"the responder on port {port} did not answer in "
                        f"{STARTUP_DEADLINE} sec ({error_indication}):\n{said()}"
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


def answers(auth_key, priv_key=None, port=PORT):
    error_indication, error_status, var_binds = snmp_get(port, auth_key, priv_key)

    if error_indication is not None:
        return False

    assert not error_status
    assert var_binds[0][1].asOctets() == b"Test device"

    return True


def refused(auth_key, priv_key=None, port=PORT):
    """The responder says why it would not answer, or does not answer at all."""
    error_indication, _, var_binds = snmp_get(port, auth_key, priv_key)

    assert not var_binds

    return error_indication is not None


def test_master_auth_key():
    with running_responder(
        f"--v3-user={USM_USER}",
        "--v3-auth-proto=SHA",
        "--v3-auth-key-type=master",
        f"--v3-auth-key={AUTH_MASTER}",
    ) as said:
        assert answers(AUTH_PASSPHRASE)
        assert refused("not-the-passphrase")
        assert answers(AUTH_PASSPHRASE)

        assert "authentication key type: master" in said()


def test_master_auth_and_priv_keys():
    # the engine ID is made up by the responder: a master key fits any
    with running_responder(
        f"--v3-user={USM_USER}",
        "--v3-auth-proto=SHA",
        f"--v3-auth-key=0x{AUTH_MASTER}",
        "--v3-auth-key-type=master",
        "--v3-priv-proto=AES",
        f"--v3-priv-key=0x{PRIV_MASTER.upper()}",
        "--v3-priv-key-type=master",
        priv=True,
    ):
        assert answers(AUTH_PASSPHRASE, PRIV_PASSPHRASE)
        assert refused(AUTH_PASSPHRASE, "not-the-passphrase")
        assert refused("not-the-passphrase", PRIV_PASSPHRASE)
        assert answers(AUTH_PASSPHRASE, PRIV_PASSPHRASE)


def test_localized_auth_key():
    with running_responder(
        f"--v3-engine-id={ENGINE_ID}",
        f"--v3-user={USM_USER}",
        "--v3-auth-proto=SHA",
        f"--v3-auth-key={AUTH_LOCALIZED}",
        "--v3-auth-key-type=localized",
    ) as said:
        assert answers(AUTH_PASSPHRASE)
        assert refused("not-the-passphrase")
        assert answers(AUTH_PASSPHRASE)

        assert "authentication key type: localized" in said()


def test_localized_auth_and_priv_keys():
    with running_responder(
        f"--v3-engine-id={ENGINE_ID}",
        f"--v3-user={USM_USER}",
        "--v3-auth-proto=SHA",
        f"--v3-auth-key=0x{AUTH_LOCALIZED}",
        "--v3-auth-key-type=localized",
        "--v3-priv-proto=AES",
        f"--v3-priv-key={PRIV_LOCALIZED}",
        "--v3-priv-key-type=localized",
        priv=True,
    ):
        assert answers(AUTH_PASSPHRASE, PRIV_PASSPHRASE)
        assert refused(AUTH_PASSPHRASE, "not-the-passphrase")
        assert refused("not-the-passphrase", PRIV_PASSPHRASE)
        assert answers(AUTH_PASSPHRASE, PRIV_PASSPHRASE)


def test_a_key_localized_for_another_engine_is_a_wrong_key():
    other_engine = localized_key(AUTH_PASSPHRASE, engine_id="80004fb805ffffffff").hex()

    with running_responder(
        f"--v3-engine-id={ENGINE_ID}",
        # a user to see the responder up with
        f"--v3-user={USM_USER}",
        "--v3-auth-proto=SHA",
        f"--v3-auth-key={AUTH_PASSPHRASE}",
        "--v3-user=stranger",
        "--v3-auth-proto=SHA",
        f"--v3-auth-key={other_engine}",
        "--v3-auth-key-type=localized",
    ):
        assert answers(AUTH_PASSPHRASE)

        error_indication, _, var_binds = asyncio.run(get_as("stranger", PORT))

        assert error_indication is not None
        assert not var_binds


async def get_as(user, port):
    snmp_engine = SnmpEngine()
    try:
        error_indication, error_status, _, var_binds = await get_cmd(
            snmp_engine,
            UsmUserData(user, AUTH_PASSPHRASE, authProtocol=USM_AUTH_HMAC96_SHA),
            await UdpTransportTarget.create(("127.0.0.1", port), timeout=2, retries=0),
            ContextData(contextName="public"),
            ObjectType(ObjectIdentity(SYS_DESCR)),
        )

    finally:
        if snmp_engine.transport_dispatcher:
            snmp_engine.transport_dispatcher.close_dispatcher()

    return error_indication, error_status, var_binds


def test_passphrases_are_still_the_default():
    # a passphrase made of hex digits stays a passphrase
    passphrase = "0xdeadbeefdeadbeef"

    with running_responder(
        f"--v3-user={USM_USER}",
        "--v3-auth-proto=SHA",
        f"--v3-auth-key={AUTH_PASSPHRASE}",
        "--v3-auth-key-type=passphrase",
        "--v3-priv-proto=AES",
        f"--v3-priv-key={PRIV_PASSPHRASE}",
        "--v3-user=hexadecimal",
        "--v3-auth-proto=SHA",
        f"--v3-auth-key={passphrase}",
        priv=True,
    ) as said:
        assert answers(AUTH_PASSPHRASE, PRIV_PASSPHRASE)

        assert "key type" not in said()


def refused_to_start(*options):
    responder = subprocess.run(
        responder_command(*options, port=REFUSED_PORT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=60,
        text=True,
    )

    assert responder.returncode, responder.stderr
    assert "Traceback" not in responder.stderr

    return responder.stderr


@pytest.mark.parametrize(
    "key, complaint",
    [
        ("not-hexadecimal-at-all", "is not hexadecimal"),
        (AUTH_MASTER[:-1], "is not hexadecimal"),
        # an MD5 key where a SHA-1 one is due
        (AUTH_MASTER[:32], "16 octets long, SHA takes 20"),
    ],
)
@pytest.mark.parametrize("key_type", ["master", "localized"])
def test_a_key_that_cannot_be_one_stops_the_responder(key_type, key, complaint):
    said = refused_to_start(
        f"--v3-user={USM_USER}",
        "--v3-auth-proto=SHA",
        f"--v3-auth-key={key}",
        f"--v3-auth-key-type={key_type}",
    )

    assert complaint in said
    assert USM_USER in said


def test_a_short_localized_priv_key_stops_the_responder():
    said = refused_to_start(
        f"--v3-engine-id={ENGINE_ID}",
        f"--v3-user={USM_USER}",
        "--v3-auth-proto=SHA",
        f"--v3-auth-key={AUTH_LOCALIZED}",
        "--v3-auth-key-type=localized",
        "--v3-priv-proto=AES256",
        f"--v3-priv-key={PRIV_LOCALIZED}",
        "--v3-priv-key-type=localized",
    )

    assert "16 octets long, AES256 takes 32" in said


def test_a_key_type_nobody_knows_is_an_argument_error():
    said = refused_to_start(
        f"--v3-user={USM_USER}",
        "--v3-auth-proto=SHA",
        f"--v3-auth-key={AUTH_MASTER}",
        "--v3-auth-key-type=hashed",
    )

    assert "--v3-auth-key-type" in said
    assert "invalid choice" in said


@pytest.mark.parametrize("option", ["--v3-auth-key-type", "--v3-priv-key-type"])
def test_a_key_type_needs_a_user_and_a_key(option):
    assert "--v3-user should precede" in refused_to_start(f"{option}=master")

    said = refused_to_start(f"--v3-user={USM_USER}", f"{option}=master")

    assert "key type configured without key" in said
