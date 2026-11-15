import asyncio
import os
import sys
import threading
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
    next_cmd,
    set_cmd,
)
from pysnmp.proto import rfc1902

from snmpsim.commands.responder import main as responder_main

# one responder serves every test of the module, so it has to outlive them all
TIME_OUT = int(os.getenv("SNMPSIM_TEST_TIMEOUT", "15")) + 5
PORT_NUMBER = 1642

V1, V2C = 0, 1

# plain enterprise OIDs: the client has no MIB to dress their values up with
FIRST = "1.3.6.1.4.1.99999.3.1.0"
NO_SUCH_NAME = "1.3.6.1.4.1.99999.3.2.0"
BAD_VALUE_ON_SET = "1.3.6.1.4.1.99999.3.3.0"
READ_ONLY_ON_SET = "1.3.6.1.4.1.99999.3.4.0"
GEN_ERROR = "1.3.6.1.4.1.99999.3.5.0"
WRONG_VALUE_ON_SET = "1.3.6.1.4.1.99999.3.6.0"
TOO_BIG = "1.3.6.1.4.1.99999.3.7.0"
LAST = "1.3.6.1.4.1.99999.3.8.0"


@pytest.fixture(scope="module", autouse=True)
def responder():
    original_argv = sys.argv
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sys.argv = [
        "responder.py",
        "--data-dir=%s" % os.path.join(base_dir, "data", "error"),
        "--agent-udpv4-endpoint=127.0.0.1:%d" % PORT_NUMBER,
        "--timeout=%d" % TIME_OUT,
    ]

    def target():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            responder_main()
        finally:
            loop.close()

    app_thread = threading.Thread(target=target)
    app_thread.start()
    time.sleep(1)

    yield

    sys.argv = original_argv
    app_thread.join(timeout=TIME_OUT)


async def request(command, version, *var_binds):
    """Return error-status as a number, error-index and the var-binds."""
    snmp_engine = SnmpEngine()
    try:
        error_indication, error_status, error_index, var_binds = await command(
            snmp_engine,
            CommunityData("public", mpModel=version),
            await UdpTransportTarget.create(
                ("127.0.0.1", PORT_NUMBER), timeout=2, retries=0
            ),
            ContextData(),
            *[ObjectType(ObjectIdentity(oid), *value) for oid, *value in var_binds],
        )

    finally:
        if snmp_engine.transport_dispatcher:
            snmp_engine.transport_dispatcher.close_dispatcher()

    assert error_indication is None

    return (
        int(error_status),
        int(error_index),
        [(str(oid), value) for oid, value in var_binds],
    )


def octets(text):
    return rfc1902.OctetString(text)


@pytest.mark.asyncio
async def test_v1_get_reports_no_such_name():
    error_status, error_index, _ = await request(get_cmd, V1, (NO_SUCH_NAME,))

    assert (error_status, error_index) == (2, 1)


@pytest.mark.asyncio
async def test_v1_get_points_at_the_failed_variable():
    error_status, error_index, var_binds = await request(
        get_cmd, V1, (FIRST,), (NO_SUCH_NAME,)
    )

    assert (error_status, error_index) == (2, 2)
    # SNMPv1 error response repeats the request
    assert [oid for oid, _ in var_binds] == [FIRST, NO_SUCH_NAME]


@pytest.mark.asyncio
async def test_v1_getnext_reports_no_such_name():
    error_status, error_index, _ = await request(next_cmd, V1, (FIRST,))

    assert (error_status, error_index) == (2, 1)


@pytest.mark.asyncio
async def test_v1_set_reports_bad_value():
    error_status, error_index, _ = await request(
        set_cmd, V1, (BAD_VALUE_ON_SET, octets("new"))
    )

    assert (error_status, error_index) == (3, 1)


@pytest.mark.asyncio
async def test_v1_set_reports_read_only():
    error_status, error_index, _ = await request(
        set_cmd, V1, (READ_ONLY_ON_SET, octets("new"))
    )

    assert (error_status, error_index) == (4, 1)


@pytest.mark.asyncio
async def test_v1_set_points_at_the_failed_variable():
    error_status, error_index, _ = await request(
        set_cmd, V1, (LAST, octets("new")), (READ_ONLY_ON_SET, octets("new"))
    )

    assert (error_status, error_index) == (4, 2)


@pytest.mark.asyncio
async def test_v1_errors_which_translated_before_still_do():
    # genErr stays itself, wrongValue has no SNMPv1 code and becomes badValue,
    # tooBig carries no error-index
    assert (await request(get_cmd, V1, (GEN_ERROR,)))[:2] == (5, 1)
    assert (await request(set_cmd, V1, (WRONG_VALUE_ON_SET, octets("new"))))[:2] == (
        3,
        1,
    )
    assert (await request(get_cmd, V1, (TOO_BIG,)))[:2] == (1, 0)


@pytest.mark.asyncio
async def test_v1_read_passes_records_which_fail_on_set_only():
    for oid, text in (
        (BAD_VALUE_ON_SET, b"picky"),
        (READ_ONLY_ON_SET, b"fixed"),
    ):
        error_status, _, var_binds = await request(get_cmd, V1, (oid,))

        assert not error_status
        assert var_binds[0][1].asOctets() == text


@pytest.mark.asyncio
async def test_v2c_statuses_are_unchanged():
    assert (await request(get_cmd, V2C, (NO_SUCH_NAME,)))[:2] == (2, 1)
    assert (await request(get_cmd, V2C, (FIRST,), (NO_SUCH_NAME,)))[:2] == (2, 2)
    assert (await request(next_cmd, V2C, (FIRST,)))[:2] == (2, 1)
    assert (await request(set_cmd, V2C, (BAD_VALUE_ON_SET, octets("new"))))[:2] == (
        3,
        1,
    )
    assert (await request(set_cmd, V2C, (READ_ONLY_ON_SET, octets("new"))))[:2] == (
        4,
        1,
    )
    assert (await request(get_cmd, V2C, (GEN_ERROR,)))[:2] == (5, 1)
    assert (await request(set_cmd, V2C, (WRONG_VALUE_ON_SET, octets("new"))))[:2] == (
        10,
        1,
    )
    assert (await request(get_cmd, V2C, (TOO_BIG,)))[:2] == (1, 0)
