import asyncio
import os
import sys
import threading
import time

import pytest
from pysnmp.hlapi.asyncio import *
from pysnmp.proto import rfc1902

from snmpsim import utils
from snmpsim.commands.responder import main as responder_main

TIME_OUT = int(os.getenv("SNMPSIM_TEST_TIMEOUT", "15"))
PORT_NUMBER = 1620  # Using a unique port to avoid conflicts with other tests

MAX_REPETITIONS = 50


def _var_bind(index, value_size):
    return (
        rfc1902.ObjectName("1.3.6.1.4.1.99999.1.1.1.%d" % index),
        rfc1902.OctetString(b"x" * value_size),
    )


def _reader(value_size, count=1000):
    """Stand in for a MIB controller holding `count` equally sized records"""

    def read_next_vars(*var_binds):
        next_var_binds = []

        for oid, _ in var_binds:
            index = min(int(oid[-1]) + 1, count)
            next_var_binds.append(_var_bind(index, value_size))

        return next_var_binds

    return read_next_vars


def test_repetitions_stop_at_max_response_size():
    """Repetitions which would not fit into the response are left out"""
    var_binds = utils.get_bulk_var_binds(
        _reader(value_size=100),
        [_var_bind(0, 100)],
        non_repeaters=0,
        max_repetitions=MAX_REPETITIONS,
        max_var_binds=64,
        max_response_size=1000,
    )

    assert 0 < len(var_binds) < MAX_REPETITIONS
    assert sum(utils.var_bind_size(var_bind) for var_bind in var_binds) <= 1000


def test_repetitions_stop_at_max_var_binds():
    """A response which fits is still bounded by the var-bind count"""
    var_binds = utils.get_bulk_var_binds(
        _reader(value_size=1),
        [_var_bind(0, 1)],
        non_repeaters=0,
        max_repetitions=MAX_REPETITIONS,
        max_var_binds=10,
        max_response_size=65507,
    )

    assert len(var_binds) == 10


def test_oversized_var_bind_is_still_served():
    """A single var-bind past the size limit goes out rather than nothing

    Coming back empty-handed would fail the walk for good, while an oversized
    response at least carries the value the manager asked for.
    """
    var_binds = utils.get_bulk_var_binds(
        _reader(value_size=2000),
        [_var_bind(0, 2000)],
        non_repeaters=0,
        max_repetitions=MAX_REPETITIONS,
        max_var_binds=64,
        max_response_size=1000,
    )

    assert len(var_binds) == 1


@pytest.fixture(autouse=True)
def setup_args():
    original_argv = sys.argv
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data", "bulk")
    sys.argv = [
        "responder.py",
        f"--data-dir={data_dir}",
        f"--agent-udpv4-endpoint=127.0.0.1:{PORT_NUMBER}",
        f"--timeout={TIME_OUT}",
    ]
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
async def test_bulk_response_stays_within_one_datagram(run_app_in_background):
    """GETBULK answers with fewer repetitions rather than a huge datagram

    A response past the path MTU is fragmented and the manager may never see
    it whole, which is what used to stall walks over recordings holding long
    values.
    """
    snmp_engine = SnmpEngine()

    try:
        transport = await UdpTransportTarget.create(
            ("127.0.0.1", PORT_NUMBER), retries=0
        )
        auth_data = CommunityData("public", mpModel=1)

        errorIndication, errorStatus, errorIndex, varBinds = await bulk_cmd(
            snmp_engine,
            auth_data,
            transport,
            ContextData(),
            0,
            MAX_REPETITIONS,
            ObjectType(ObjectIdentity("1.3.6.1.4.1.99999.1.1.1")),
        )

        assert errorIndication is None, f"Error: {errorIndication}"
        assert errorStatus == 0, f"Error status: {errorStatus}"
        assert 0 < len(varBinds) < MAX_REPETITIONS

        # what the var-binds took on the wire, the hlapi hands them back
        # wrapped into its own object types
        wire_size = sum(
            utils.var_bind_size((rfc1902.ObjectName(str(oid)), value))
            for oid, value in varBinds
        )

        assert wire_size <= utils.MAX_MESSAGE_SIZE

        # every record is still reachable, just over more round trips
        served = []

        async for errorIndication, errorStatus, errorIndex, varBinds in bulk_walk_cmd(
            snmp_engine,
            auth_data,
            transport,
            ContextData(),
            0,
            MAX_REPETITIONS,
            ObjectType(ObjectIdentity("1.3.6.1.4.1.99999.1.1.1")),
            lexicographicMode=False,
        ):
            assert errorIndication is None, f"Error: {errorIndication}"
            assert errorStatus == 0, f"Error status: {errorStatus}"

            served.extend(varBinds)

        assert len(served) == 40

    finally:
        if snmp_engine.transport_dispatcher:
            snmp_engine.transport_dispatcher.close_dispatcher()
