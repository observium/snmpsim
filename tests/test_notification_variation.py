import os
import sys
import threading
import time
from snmpsim.commands.responder import main as responder_main
import pytest
from pysnmp.hlapi.asyncio import *

import asyncio

TIME_OUT = int(os.getenv("SNMPSIM_TEST_TIMEOUT", "15"))
PORT_NUMBER = 1614


@pytest.fixture(autouse=True)
def setup_args():
    # Store the original sys.argv
    original_argv = sys.argv
    # Define your test arguments here
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data", "notification")
    test_args = [
        "responder.py",
        f"--data-dir={data_dir}",
        f"--agent-udpv4-endpoint=127.0.0.1:{PORT_NUMBER}",
        f"--debug=app",
        f"--timeout={TIME_OUT}",
    ]
    # Set sys.argv to your test arguments
    sys.argv = test_args
    # This will run before the test function
    yield
    # Restore the original sys.argv after the test function has finished
    sys.argv = original_argv


# Fixture to run the application in a separate thread
@pytest.fixture
def run_app_in_background():
    def target():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            responder_main()
        except KeyboardInterrupt:
            print("Application interrupted.")
        finally:
            print("Application stopped.")
            loop.close()

    app_thread = threading.Thread(target=target)
    app_thread.start()
    # Allow some time for the application to initialize and run
    time.sleep(1)
    yield
    # Simulate KeyboardInterrupt after the test is done
    # This part may need to be adjusted based on how your application handles shutdown
    app_thread.join(timeout=TIME_OUT)


@pytest.mark.asyncio
async def test_main_with_specific_args(run_app_in_background, capsys):
    snmpEngine = SnmpEngine()
    try:
        # v1/v2c - using community string
        communityData = CommunityData("public", mpModel=1)  # SNMPv1

        # First GET operation
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmpEngine,
            communityData,
            await UdpTransportTarget.create(("localhost", PORT_NUMBER), retries=0),
            ContextData(),
            ObjectType(ObjectIdentity("SNMPv2-MIB", "sysLocation", 0)),
        )

        assert errorIndication is None
        assert errorStatus == 0
        assert errorIndex == 0
        assert len(varBinds) == 1
        assert varBinds[0][0].prettyPrint() == "SNMPv2-MIB::sysLocation.0"
        assert varBinds[0][1].prettyPrint() == "SNMPv1 trap sender"
        assert isinstance(varBinds[0][1], OctetString)

        # SET operation
        errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
            snmpEngine,
            communityData,
            await UdpTransportTarget.create(("localhost", PORT_NUMBER), retries=0),
            ContextData(),
            ObjectType(ObjectIdentity("SNMPv2-MIB", "sysLocation", 0), "Shanghai"),
        )

        assert errorIndication is None
        assert errorStatus == 0
        assert errorIndex == 0
        assert len(varBinds) == 1
        assert varBinds[0][0].prettyPrint() == "SNMPv2-MIB::sysLocation.0"
        assert varBinds[0][1].prettyPrint() == "Shanghai"
        assert isinstance(varBinds[0][1], OctetString)

        # Second GET operation to verify SET behavior
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmpEngine,
            communityData,
            await UdpTransportTarget.create(("localhost", PORT_NUMBER), retries=0),
            ContextData(),
            ObjectType(ObjectIdentity("SNMPv2-MIB", "sysLocation", 0)),
        )

        assert errorIndication is None
        assert errorStatus == 0
        assert errorIndex == 0
        assert len(varBinds) == 1
        assert varBinds[0][0].prettyPrint() == "SNMPv2-MIB::sysLocation.0"
        assert (
            varBinds[0][1].prettyPrint() == "SNMPv1 trap sender"
        )  # data is not cached
        assert isinstance(varBinds[0][1], OctetString)
    finally:
        if snmpEngine.transport_dispatcher:
            snmpEngine.transport_dispatcher.close_dispatcher()

        await asyncio.sleep(TIME_OUT)


V3_PORT_NUMBER = 1650
V3_TRAP_PORT_NUMBER = 1651
V3_ENGINE_ID = "80004fb805736e6d7073696d01"


@pytest.fixture
def v3_args():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data", "notification-v3")
    sys.argv = [
        "responder.py",
        # everything up to the next --v3-engine-id configures this engine
        f"--v3-engine-id={V3_ENGINE_ID}",
        f"--data-dir={data_dir}",
        "--v3-user=simulator",
        "--v3-auth-key=auctoritas",
        "--v3-auth-proto=SHA",
        "--v3-priv-key=privatus",
        "--v3-priv-proto=AES",
        f"--agent-udpv4-endpoint=127.0.0.1:{V3_PORT_NUMBER}",
        "--debug=app",
        f"--timeout={TIME_OUT}",
    ]


def _load_module():
    """Load the module the way the responder does: it is not importable."""
    import types

    import snmpsim

    path = os.path.join(
        os.path.dirname(snmpsim.__file__), "variation", "notification.py"
    )
    module = types.SimpleNamespace()

    with open(path) as fl:
        exec(compile(fl.read(), path, "exec"), module.__dict__)

    return module


async def _v3_get(snmp_engine, name):
    return await get_cmd(
        snmp_engine,
        UsmUserData(
            "simulator",
            "auctoritas",
            "privatus",
            authProtocol=usmHMACSHAAuthProtocol,
            privProtocol=usmAesCfb128Protocol,
        ),
        await UdpTransportTarget.create(
            ("127.0.0.1", V3_PORT_NUMBER), timeout=1, retries=0
        ),
        ContextData(contextName=OctetString("public").asOctets()),
        ObjectType(ObjectIdentity("SNMPv2-MIB", name, 0)),
    )


@pytest.mark.asyncio
async def test_v3_trap_keeps_the_agent_user(v3_args, run_app_in_background):
    """A trap sent as the agent's own user must not rekey that user.

    The record sends a v3 trap as user `simulator` with keys and protocols
    of its own. The agent's `simulator` must keep answering under the keys
    it was started with, and the trap must reach a receiver that knows the
    trap's keys under the agent's engine ID.
    """
    from pysnmp.carrier.asyncio.dgram import udp
    from pysnmp.entity import config, engine
    from pysnmp.entity.rfc3413 import ntfrcv

    traps = []

    def on_trap(snmp_engine, state_reference, engine_id, name, var_binds, ctx):
        traps.append([(str(oid), val.prettyPrint()) for oid, val in var_binds])

    receiver = engine.SnmpEngine()
    config.add_transport(
        receiver,
        udp.DOMAIN_NAME,
        udp.UdpTransport().open_server_mode(("127.0.0.1", V3_TRAP_PORT_NUMBER)),
    )
    config.add_v3_user(
        receiver,
        "simulator",
        config.USM_AUTH_HMAC192_SHA256,
        "trapauthkey",
        config.USM_PRIV_CFB256_AES,
        "trapprivkey",
        securityEngineId=OctetString(hexValue=V3_ENGINE_ID),
    )
    ntfrcv.NotificationReceiver(receiver, on_trap)

    managers = []

    try:
        for attempt in range(3):
            # a manager that has never talked to the agent before, so that
            # nothing it learned earlier can paper over a rekeyed user
            managers.append(SnmpEngine())

            error_indication, error_status, _, var_binds = await _v3_get(
                managers[-1], "sysName"
            )

            assert error_indication is None, f"GET {attempt}: {error_indication}"
            assert error_status == 0
            assert var_binds[0][1].prettyPrint() == "plain"

            error_indication, error_status, _, var_binds = await _v3_get(
                managers[-1], "sysLocation"
            )

            assert error_indication is None, f"GET {attempt}: {error_indication}"
            assert error_status == 0
            assert var_binds[0][1].prettyPrint() == "trap sent"

            for _ in range(20):
                if len(traps) > attempt:
                    break
                await asyncio.sleep(0.1)

            assert len(traps) == attempt + 1

        assert ("1.3.6.1.2.1.1.1.0", "snmpsim agent") in traps[0]
        assert ("1.3.6.1.6.3.1.1.4.1.0", "1.3.6.1.6.3.1.1.5.4") in traps[0]

    finally:
        for manager in managers:
            manager.close_dispatcher()

        receiver.close_dispatcher()

        await asyncio.sleep(TIME_OUT)


def test_notification_accepts_the_protocols_the_responder_does():
    """`authproto` and `privproto` take every name `--v3-*-proto` takes."""
    from snmpsim.commands import responder

    notification = _load_module()

    for name, protocol in responder.AUTH_PROTOCOLS.items():
        assert notification.AUTH_PROTOCOLS[name] == protocol
        assert notification.get_protocol(notification.AUTH_PROTOCOLS, name.lower())

    for name, protocol in responder.PRIV_PROTOCOLS.items():
        assert notification.PRIV_PROTOCOLS[name] == protocol
        assert notification.get_protocol(notification.PRIV_PROTOCOLS, name.lower())

    assert (
        notification.get_protocol(notification.AUTH_PROTOCOLS, "sha256")
        == responder.AUTH_PROTOCOLS["SHA256"]
    )
    assert notification.get_protocol(notification.AUTH_PROTOCOLS, "sha3") is None


def test_originator_keeps_sending_from_one_engine():
    """Every notification leaves through the same engine and socket.

    The engine is made once, on the first notification, and its socket
    belongs to the loop it was made on: the second notification only goes
    out if that loop is still the one doing the sending.
    """
    import socket

    notification = _load_module()

    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", V3_TRAP_PORT_NUMBER))
    listener.settimeout(2)

    originator = notification.Originator()

    try:
        sources = set()

        for _ in range(3):
            originator.send(
                None,
                CommunityData("public"),
                ("udp", "127.0.0.1", V3_TRAP_PORT_NUMBER, "127.0.0.1"),
                "trap",
                NotificationType(ObjectIdentity("1.3.6.1.6.3.1.1.5.1")),
                "test",
            )

            packet, source = listener.recvfrom(4096)

            assert b"public" in packet
            sources.add(source)

        assert len(sources) == 1
        assert len(originator._engines) == 1

    finally:
        originator.close()
        listener.close()

    assert not originator._thread.is_alive()
