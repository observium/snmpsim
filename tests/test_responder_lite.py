import asyncio
import os
import sys
import threading
import time

import pytest
from pysnmp.hlapi.asyncio import *

from snmpsim.commands.responder_lite import main as responder_main

TIME_OUT = int(os.getenv("SNMPSIM_TEST_TIMEOUT", "15"))
PORT_NUMBER = 1617  # Using a unique port to avoid conflicts with other tests


@pytest.fixture(autouse=True)
def setup_args():
    original_argv = sys.argv
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data", "agent")
    test_args = [
        "responder_lite.py",
        f"--data-dir={data_dir}",
        f"--agent-udpv4-endpoint=127.0.0.1:{PORT_NUMBER}",
    ]
    sys.argv = test_args
    yield
    sys.argv = original_argv


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

    app_thread = threading.Thread(target=target, daemon=True)
    app_thread.start()
    # Allow some time for the application to initialize and run
    time.sleep(1)
    yield
    app_thread.join(timeout=TIME_OUT)


@pytest.mark.asyncio
async def test_lite_responder_serves_v2c(run_app_in_background):
    """The v2c-only responder answers GET, GETNEXT and GETBULK.

    It talks to the MIB controllers directly rather than through an SNMP
    engine, so it is the only user of that calling convention and breaks
    without anyone noticing.
    """
    snmpEngine = SnmpEngine()

    try:
        transport = await UdpTransportTarget.create(
            ("127.0.0.1", PORT_NUMBER), retries=0
        )
        auth_data = CommunityData("public", mpModel=1)

        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmpEngine,
            auth_data,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
        )

        assert errorIndication is None, f"Error: {errorIndication}"
        assert errorStatus == 0, f"Error status: {errorStatus}"
        assert varBinds[0][1].prettyPrint() == "Test device"

        errorIndication, errorStatus, errorIndex, varBinds = await next_cmd(
            snmpEngine,
            auth_data,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.2.0")),
        )

        assert errorIndication is None, f"Error: {errorIndication}"
        assert errorStatus == 0, f"Error status: {errorStatus}"
        assert str(varBinds[0][0]) == "1.3.6.1.2.1.2.2.1.2.1"
        assert varBinds[0][1].prettyPrint() == "GigabitEthernet0/1"

        all_results = []

        async for errorIndication, errorStatus, errorIndex, varBinds in bulk_walk_cmd(
            snmpEngine,
            auth_data,
            transport,
            ContextData(),
            0,
            10,  # Non-repeaters, Max-repetitions
            ObjectType(ObjectIdentity("1.3.6.1.2.1.2")),
            lexicographicMode=False,
        ):
            assert errorIndication is None, f"Error: {errorIndication}"
            assert errorStatus == 0, f"Error status: {errorStatus}"

            all_results.extend(varBinds)

        served = {str(oid): val.prettyPrint() for oid, val in all_results}

        assert served == {
            "1.3.6.1.2.1.2.2.1.2.1": "GigabitEthernet0/1",
            "1.3.6.1.2.1.2.2.1.5.1": "1000000000",
        }

    finally:
        if snmpEngine.transport_dispatcher:
            snmpEngine.transport_dispatcher.close_dispatcher()
