import os
import sys

import pytest
from pysnmp.hlapi.asyncio import *

from snmpsim.commands.responder import main as responder_main

TIME_OUT = int(os.getenv("SNMPSIM_TEST_TIMEOUT", "15"))
PORT_NUMBER = 1619  # Using a unique port to avoid conflicts with other tests


@pytest.fixture(autouse=True)
def setup_args():
    original_argv = sys.argv
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data", "probe")
    test_args = [
        "responder.py",
        f"--data-dir={data_dir}",
        f"--agent-udpv4-endpoint=127.0.0.1:{PORT_NUMBER}",
    ]
    sys.argv = test_args
    yield
    sys.argv = original_argv


@pytest.fixture
def run_app_in_background(responder_in_thread):
    with responder_in_thread(responder_main):
        yield


@pytest.mark.asyncio
async def test_recording_is_picked_by_source_address(run_app_in_background):
    """A recording filed under the source address wins over the plain one.

    The data directory holds public.snmprec and, beside it,
    public/<transport domain>/127.0.0.1.snmprec. A request coming from that
    address has to be served the second one. This runs through the command
    responders' hook into pysnmp, which is easy to lose: a hook named after
    a method pysnmp no longer calls is simply never invoked, and the agent
    then answers from the plain recording without a word about it.
    """
    snmpEngine = SnmpEngine()

    try:
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmpEngine,
            UsmUserData(
                "simulator",
                "auctoritas",
                "privatus",
                authProtocol=usmHMACMD5AuthProtocol,
                privProtocol=usmDESPrivProtocol,
            ),
            await UdpTransportTarget.create(("127.0.0.1", PORT_NUMBER), retries=0),
            ContextData(contextName=OctetString("public").asOctets()),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
        )

        assert errorIndication is None, f"Error: {errorIndication}"
        assert errorStatus == 0, f"Error status: {errorStatus}"
        assert varBinds[0][1].prettyPrint() == "Recording for 127.0.0.1"

    finally:
        if snmpEngine.transport_dispatcher:
            snmpEngine.transport_dispatcher.close_dispatcher()
