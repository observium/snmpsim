import asyncio
import os
import socket
import sys
import threading
import time

import pytest
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp.proto import api

from snmpsim.commands.responder import main as responder_main
from snmpsim.record.snmprec import SnmprecRecord
from snmpsim.record.walk import WalkRecord

TIME_OUT = int(os.getenv("SNMPSIM_TEST_TIMEOUT", "15"))
PORT_NUMBER = 1622  # Using a unique port to avoid conflicts with other tests

# what `1.3.6.1.2.1.6.4.0|2|4294967295` looks like on the wire
OUT_OF_RANGE_OCTETS = bytes.fromhex("020500ffffffff")


@pytest.fixture(autouse=True)
def setup_args():
    original_argv = sys.argv
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data", "out-of-range")
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


def _exchange(pdu, oid):
    """Send one SNMPv2c request for `oid`, return the response as it arrives.

    The response is not decoded: pyasn1 enforces the RFC 1902 range at
    decoding time as well, so a manager built on it cannot read a value
    which breaks that range - which is exactly what the device sent, and
    what net-snmp prints without blinking.
    """
    pmod = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]

    request = pdu()
    pmod.apiPDU.set_defaults(request)
    pmod.apiPDU.set_varbinds(request, ((univ.ObjectIdentifier(oid), pmod.Null("")),))

    message = pmod.Message()
    pmod.apiMessage.set_defaults(message)
    pmod.apiMessage.set_community(message, "public")
    pmod.apiMessage.set_pdu(message, request)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIME_OUT)

    try:
        sock.sendto(encoder.encode(message), ("127.0.0.1", PORT_NUMBER))
        return sock.recv(65535)

    finally:
        sock.close()


def test_out_of_range_integer_is_recorded_as_walked():
    """An INTEGER no Integer32 can hold survives the conversion.

    `tcpMaxConn` walked as 4294967295 is what a device puts on the wire when
    it sends `-1` unsigned; the walk is the only evidence of what it did, so
    the record has to keep the value rather than be dropped over it.
    """
    oid, value = WalkRecord().evaluate(b".1.3.6.1.2.1.6.4.0 = INTEGER: 4294967295\n")

    assert oid.prettyPrint() == "1.3.6.1.2.1.6.4.0"
    assert value.prettyPrint() == "4294967295"


def test_out_of_range_integer_is_encoded_as_the_device_sent_it():
    """The recorded value goes back on the wire octet for octet."""
    _, value = SnmprecRecord().evaluate(b"1.3.6.1.2.1.6.4.0|2|4294967295\n")

    assert value.prettyPrint() == "4294967295"
    assert encoder.encode(value) == OUT_OF_RANGE_OCTETS


def test_out_of_range_records_are_served(run_app_in_background):
    """The out-of-range record is answered, and does not cut the walk short."""
    pmod = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]

    # GET answers with the octets the device sent, rather than timing out
    response = _exchange(pmod.GetRequestPDU, "1.3.6.1.2.1.6.4.0")

    assert OUT_OF_RANGE_OCTETS in response

    # GETNEXT steps onto it instead of ending the walk there
    response = _exchange(pmod.GetNextRequestPDU, "1.3.6.1.2.1.6.3.0")

    assert OUT_OF_RANGE_OCTETS in response

    # ... and the walk carries on past it
    response = _exchange(pmod.GetNextRequestPDU, "1.3.6.1.2.1.6.4.0")

    assert bytes.fromhex("06082b06010201060500") in response  # 1.3.6.1.2.1.6.5.0
