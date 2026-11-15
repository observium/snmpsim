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
PORT_NUMBER = 1640

# plain enterprise OIDs: the client has no MIB to dress their values up with
FIRST = "1.3.6.1.4.1.99999.1.1.0"
HEX_STRING = "1.3.6.1.4.1.99999.1.4.0"
HEXVALUE_STRING = "1.3.6.1.4.1.99999.1.5.0"
PLAIN_STRING = "1.3.6.1.4.1.99999.1.6.0"
HEX_BINARY = "1.3.6.1.4.1.99999.1.7.0"
HEX_HEXVALUE_STRING = "1.3.6.1.4.1.99999.1.8.0"
ESCAPED_STRING = "1.3.6.1.4.1.99999.1.9.0"
HEX_VLIST_STRING = "1.3.6.1.4.1.99999.1.10.0"
HEX_ADDRESS = "1.3.6.1.4.1.99999.2.1.10.17.0.25"
LAST = "1.3.6.1.4.1.99999.2.2.10.17.0.25"


@pytest.fixture(scope="module", autouse=True)
def responder():
    original_argv = sys.argv
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sys.argv = [
        "responder.py",
        "--data-dir=%s" % os.path.join(base_dir, "data", "writecache-hex"),
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


async def request(command, *var_binds):
    snmp_engine = SnmpEngine()
    try:
        error_indication, error_status, error_index, var_binds = await command(
            snmp_engine,
            CommunityData("public", mpModel=1),
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

    return error_status, [(str(oid), value) for oid, value in var_binds]


async def get(oid):
    error_status, var_binds = await request(get_cmd, (oid,))

    assert not error_status, error_status.prettyPrint()

    return var_binds[0][1]


@pytest.mark.asyncio
async def test_hex_flag_serves_ip_address():
    value = await get(HEX_ADDRESS)

    assert isinstance(value, rfc1902.IpAddress)
    assert value.prettyPrint() == "10.17.0.25"


@pytest.mark.asyncio
async def test_hex_flag_serves_octet_string():
    value = await get(HEX_STRING)

    assert isinstance(value, rfc1902.OctetString)
    assert value.asOctets() == b"ABC"


@pytest.mark.asyncio
async def test_hex_flag_keeps_non_printable_octets():
    assert (await get(HEX_BINARY)).asOctets() == b"\x00\xff\x80"


@pytest.mark.asyncio
async def test_escape_flag_serves_unescaped_octets():
    assert (await get(ESCAPED_STRING)).asOctets() == b"a\tb\xff"


@pytest.mark.asyncio
async def test_hexvalue_still_works():
    assert (await get(HEXVALUE_STRING)).asOctets() == b"DEF"
    assert (await get(HEX_HEXVALUE_STRING)).asOctets() == b"GHI"


@pytest.mark.asyncio
async def test_plain_value_is_served_as_written():
    assert (await get(PLAIN_STRING)).asOctets() == b"plain"


@pytest.mark.asyncio
async def test_walk_passes_through_hex_records():
    oid, seen = FIRST, []

    while oid != LAST:
        error_status, var_binds = await request(next_cmd, (oid,))

        assert not error_status, error_status.prettyPrint()

        oid = var_binds[0][0]
        seen.append(oid)

    assert seen == [
        HEX_STRING,
        HEXVALUE_STRING,
        PLAIN_STRING,
        HEX_BINARY,
        HEX_HEXVALUE_STRING,
        ESCAPED_STRING,
        HEX_VLIST_STRING,
        HEX_ADDRESS,
        LAST,
    ]


@pytest.mark.asyncio
async def test_set_then_get_round_trips_ip_address():
    error_status, var_binds = await request(
        set_cmd, (HEX_ADDRESS, rfc1902.IpAddress("192.0.2.7"))
    )

    assert not error_status, error_status.prettyPrint()
    assert var_binds[0][1].prettyPrint() == "192.0.2.7"

    value = await get(HEX_ADDRESS)

    assert isinstance(value, rfc1902.IpAddress)
    assert value.prettyPrint() == "192.0.2.7"


@pytest.mark.asyncio
async def test_set_then_get_round_trips_octets():
    octets = b"\x00caf\xe9\xff"

    error_status, var_binds = await request(
        set_cmd, (HEX_STRING, rfc1902.OctetString(octets))
    )

    assert not error_status, error_status.prettyPrint()
    assert var_binds[0][1].asOctets() == octets

    assert (await get(HEX_STRING)).asOctets() == octets


@pytest.mark.asyncio
async def test_hex_flag_applies_to_vlist_values():
    assert (await get(HEX_VLIST_STRING)).asOctets() == b"JK"

    error_status, _ = await request(
        set_cmd, (HEX_VLIST_STRING, rfc1902.OctetString(b"ZZ"))
    )

    assert error_status.prettyPrint() == "wrongValue"

    error_status, _ = await request(
        set_cmd, (HEX_VLIST_STRING, rfc1902.OctetString(b"5a5a"))
    )

    assert not error_status, error_status.prettyPrint()
    assert (await get(HEX_VLIST_STRING)).asOctets() == b"5a5a"
