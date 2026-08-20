import asyncio
import os
import sys
import threading
import time

import pytest
from pyasn1.codec.ber import encoder
from pysnmp.hlapi.asyncio import *

from snmpsim.commands.responder import main as responder_main
from snmpsim.error import SnmpsimError
from snmpsim.record.snmprec import SnmprecRecord

TIME_OUT = int(os.getenv("SNMPSIM_TEST_TIMEOUT", "15"))
PORT_NUMBER = 1616  # Using a unique port to avoid conflicts with other tests


@pytest.fixture(autouse=True)
def setup_args():
    original_argv = sys.argv
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data", "short-oid")
    test_args = [
        "responder.py",
        f"--data-dir={data_dir}",
        f"--agent-udpv4-endpoint=127.0.0.1:{PORT_NUMBER}",
        f"--timeout={TIME_OUT}",
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

    app_thread = threading.Thread(target=target)
    app_thread.start()
    # Allow some time for the application to initialize and run
    time.sleep(1)
    yield
    app_thread.join(timeout=TIME_OUT)


def _auth_data():
    return UsmUserData(
        "simulator",
        "auctoritas",
        "privatus",
        authProtocol=usmHMACMD5AuthProtocol,
        privProtocol=usmDESPrivProtocol,
    )


def test_single_arc_oid_is_served_as_recorded():
    """A single-arc OID value is served as the device put it on the wire.

    BER has no room for a one-arc OID - `0` and `0.0` are the very same
    octets - so the missing arc is restored rather than the record dropped.
    """
    record = SnmprecRecord()

    _, value = record.evaluate(b"1.3.6.1.2.1.47.1.1.1.1.3.2|6|0\n")

    assert value.prettyPrint() == "0.0"
    assert encoder.encode(value) == bytes.fromhex("060100")


def test_unencodable_oid_is_rejected():
    """An OID value which cannot be repaired is reported to the caller."""
    record = SnmprecRecord()

    with pytest.raises(SnmpsimError):
        record.evaluate(b"1.3.6.1.2.1.47.1.1.1.1.3.3|6|\n")


@pytest.mark.asyncio
async def test_short_oid_records_are_served(run_app_in_background):
    """A single-arc OID value is served, a broken one does not stop the walk.

    `...1.1.3.2` holds `0`, which is what the device put on the wire as
    `0.0`, and has to be served as such. `...1.1.3.3` holds an OID value
    which cannot be encoded at all - the walk has to step over it and reach
    the records behind it instead of ending there.
    """
    snmpEngine = SnmpEngine()

    try:
        transport = await UdpTransportTarget.create(
            ("localhost", PORT_NUMBER), retries=0
        )
        context = ContextData(contextName=OctetString("public").asOctets())

        # a single-arc OID value is served as recorded
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmpEngine,
            _auth_data(),
            transport,
            context,
            ObjectType(ObjectIdentity("1.3.6.1.2.1.47.1.1.1.1.3.2")),
        )

        assert errorIndication is None, f"Error: {errorIndication}"
        assert errorStatus == 0, f"Error status: {errorStatus}"
        assert varBinds[0][1].prettyPrint() == "0.0"

        # an unencodable value is answered with noSuchInstance, not silence
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmpEngine,
            _auth_data(),
            transport,
            context,
            ObjectType(ObjectIdentity("1.3.6.1.2.1.47.1.1.1.1.3.3")),
        )

        assert errorIndication is None, f"Error: {errorIndication}"
        assert errorStatus == 0, f"Error status: {errorStatus}"
        assert (
            varBinds[0][1].prettyPrint()
            == "No Such Instance currently exists at this OID"
        )

        # ... and it does not truncate the walk either
        all_results = []

        async for errorIndication, errorStatus, errorIndex, varBinds in bulk_walk_cmd(
            snmpEngine,
            _auth_data(),
            transport,
            context,
            0,
            10,  # Non-repeaters, Max-repetitions
            ObjectType(ObjectIdentity("1.3.6.1.2.1.47")),
            lexicographicMode=False,
        ):
            assert errorIndication is None, f"Error: {errorIndication}"
            assert errorStatus == 0, f"Error status: {errorStatus}"

            all_results.extend(varBinds)

        served = {str(oid): val.prettyPrint() for oid, val in all_results}

        assert served == {
            "1.3.6.1.2.1.47.1.1.1.1.3.1": "1.3.6.1.4.1.2011.20021210.11.536627",
            "1.3.6.1.2.1.47.1.1.1.1.3.2": "0.0",
            "1.3.6.1.2.1.47.1.1.1.1.3.4": "0.0",
            "1.3.6.1.2.1.47.1.1.1.1.7.1": "Slot 1",
        }

    finally:
        if snmpEngine.transport_dispatcher:
            snmpEngine.transport_dispatcher.close_dispatcher()

        await asyncio.sleep(TIME_OUT)
