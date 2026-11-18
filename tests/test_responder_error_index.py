"""An error keeps the error-index and the meaning the recording gave it.

pysnmp's command responder points error-index at the first variable whenever
the failed one is not the last of the request, and it has no error-status for
noSuchObject, noSuchInstance and endOfMibView, which are not errors in SNMPv2
but values of a variable. The responder used to pass both on to the manager:
a wrong index, and genErr for the three.
"""
import os
import shutil
import subprocess

import pytest
from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    bulk_cmd,
    get_cmd,
    next_cmd,
    set_cmd,
)
from pysnmp.proto import rfc1902, rfc1905

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# the lane's range is used up: this port is test_responder_bind's, whose
# responders are gone by the time this module starts its own
PORT_NUMBER = 1672

V1, V2C = 0, 1

BASE = "1.3.6.1.4.1.99999.4"

FIRST = BASE + ".1.0"
NO_SUCH_NAME = BASE + ".2.0"
THIRD = BASE + ".3.0"
NO_SUCH_INSTANCE = BASE + ".4.0"
FIFTH = BASE + ".5.0"
NO_SUCH_OBJECT = BASE + ".6.0"
SEVENTH = BASE + ".7.0"
END_OF_MIB = BASE + ".8.0"
NINTH = BASE + ".9.0"
GEN_ERROR = BASE + ".10.0"
ELEVENTH = BASE + ".11.0"
READ_ONLY_ON_SET = BASE + ".12.0"
# the one record a SET writes to: a plain one is read-only, and fails first
WRITABLE = BASE + ".13.0"
TOO_BIG = BASE + ".14.0"
LAST = BASE + ".15.0"

NO_SUCH_NAME_STATUS, READ_ONLY_STATUS, GEN_ERR_STATUS = 2, 4, 5

needs_net_snmp = pytest.mark.skipif(
    not shutil.which("snmpget"), reason="net-snmp tools are not installed"
)


@pytest.fixture(scope="module", autouse=True)
def responder(responder_process):
    # one responder serves every test of the module
    with responder_process(
        "--data-dir=%s" % os.path.join(BASE_DIR, "data", "error_index"),
        port=PORT_NUMBER,
        oid=FIRST,
    ):
        yield


async def request(command, version, *var_binds, bulk=()):
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
            *bulk,
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


def snmpget(version, *oids):
    """Run net-snmp's snmpget, return its exit code and all it has printed."""
    done = subprocess.run(
        [
            "snmpget",
            "-v" + version,
            "-c",
            "public",
            # numeric OIDs, and no second try without the failed variable
            "-On",
            "-Cf",
            "-t",
            "2",
            "-r",
            "0",
            "127.0.0.1:%s" % PORT_NUMBER,
        ]
        + list(oids),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    )

    return done.returncode, done.stdout


@needs_net_snmp
@pytest.mark.parametrize("version", ["1", "2c"])
def test_snmpget_is_told_which_variable_failed(version):
    exit_code, said = snmpget(version, FIRST, NO_SUCH_NAME, THIRD)

    assert exit_code
    assert "(noSuchName)" in said
    assert "Failed object: .%s\n" % NO_SUCH_NAME in said


@needs_net_snmp
@pytest.mark.parametrize("version", ["1", "2c"])
def test_snmpget_is_told_which_variable_broke(version):
    exit_code, said = snmpget(version, FIRST, GEN_ERROR, THIRD)

    assert exit_code
    assert "(genError)" in said
    assert "Failed object: .%s\n" % GEN_ERROR in said


@needs_net_snmp
def test_snmpget_v2c_gets_no_such_instance_as_a_value():
    exit_code, said = snmpget("2c", FIRST, NO_SUCH_INSTANCE, THIRD)

    assert not exit_code, said
    assert said.splitlines() == [
        '.%s = STRING: "first"' % FIRST,
        ".%s = No Such Instance currently exists at this OID" % NO_SUCH_INSTANCE,
        '.%s = STRING: "third"' % THIRD,
    ]


@needs_net_snmp
def test_snmpget_v1_gets_no_such_name_for_no_such_instance():
    exit_code, said = snmpget("1", FIRST, NO_SUCH_INSTANCE, THIRD)

    assert exit_code
    assert "(noSuchName)" in said
    assert "Failed object: .%s\n" % NO_SUCH_INSTANCE in said


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [V1, V2C])
@pytest.mark.parametrize(
    "failing, error_status",
    [(NO_SUCH_NAME, NO_SUCH_NAME_STATUS), (GEN_ERROR, GEN_ERR_STATUS)],
)
@pytest.mark.parametrize("position", [1, 2, 3, 4])
async def test_get_points_at_the_failed_variable(
    version, failing, error_status, position
):
    oids = [FIRST, THIRD, FIFTH]
    oids.insert(position - 1, failing)

    assert (await request(get_cmd, version, *[(oid,) for oid in oids]))[:2] == (
        error_status,
        position,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [V1, V2C])
async def test_getnext_points_at_the_failed_variable(version):
    # the record next to the second variable is the failing one
    assert (await request(next_cmd, version, (GEN_ERROR,), (NINTH,), (GEN_ERROR,)))[
        :2
    ] == (GEN_ERR_STATUS, 2)


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [V1, V2C])
async def test_set_points_at_the_failed_variable(version):
    new = rfc1902.OctetString("new")

    assert (
        await request(
            set_cmd, version, (WRITABLE, new), (READ_ONLY_ON_SET, new), (WRITABLE, new)
        )
    )[:2] == (READ_ONLY_STATUS, 2)


@pytest.mark.asyncio
async def test_getbulk_points_at_the_failed_variable():
    # one non-repeater, then the repeater which runs into the failing record
    assert (
        await request(bulk_cmd, V2C, (GEN_ERROR,), (NINTH,), (FIFTH,), bulk=(1, 2))
    )[:2] == (GEN_ERR_STATUS, 2)

    # no non-repeaters
    assert (await request(bulk_cmd, V2C, (GEN_ERROR,), (NINTH,), bulk=(0, 2)))[:2] == (
        GEN_ERR_STATUS,
        2,
    )

    # a failing non-repeater
    assert (
        await request(bulk_cmd, V2C, (GEN_ERROR,), (NINTH,), (GEN_ERROR,), bulk=(2, 2))
    )[:2] == (GEN_ERR_STATUS, 2)


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [V1, V2C])
async def test_too_big_points_nowhere(version):
    assert (await request(get_cmd, version, (FIRST,), (TOO_BIG,), (THIRD,)))[:2] == (
        1,
        0,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "oid, exception",
    [
        (NO_SUCH_OBJECT, rfc1905.NoSuchObject),
        (NO_SUCH_INSTANCE, rfc1905.NoSuchInstance),
        (END_OF_MIB, rfc1905.EndOfMibView),
    ],
)
async def test_v2c_get_carries_the_exception_in_the_var_bind(oid, exception):
    error_status, error_index, var_binds = await request(
        get_cmd, V2C, (FIRST,), (oid,), (THIRD,)
    )

    assert (error_status, error_index) == (0, 0)
    assert [name for name, _ in var_binds] == [FIRST, oid, THIRD]
    assert var_binds[0][1].asOctets() == b"first"
    assert var_binds[1][1].tagSet == exception.tagSet
    assert var_binds[2][1].asOctets() == b"third"


@pytest.mark.asyncio
@pytest.mark.parametrize("oid", [NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB])
async def test_v1_get_turns_the_exception_into_no_such_name(oid):
    error_status, error_index, var_binds = await request(
        get_cmd, V1, (FIRST,), (oid,), (THIRD,)
    )

    assert (error_status, error_index) == (NO_SUCH_NAME_STATUS, 2)
    # SNMPv1 error response repeats the request
    assert [name for name, _ in var_binds] == [FIRST, oid, THIRD]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "before, oid, exception",
    [
        (FIFTH, NO_SUCH_OBJECT, rfc1905.NoSuchObject),
        (THIRD, NO_SUCH_INSTANCE, rfc1905.NoSuchInstance),
        # the walk is told to end here, not carried on to the next record
        (SEVENTH, END_OF_MIB, rfc1905.EndOfMibView),
    ],
)
async def test_v2c_getnext_carries_the_exception_in_the_var_bind(
    before, oid, exception
):
    error_status, error_index, var_binds = await request(
        next_cmd, V2C, (GEN_ERROR,), (before,)
    )

    assert (error_status, error_index) == (0, 0)
    assert [name for name, _ in var_binds] == [ELEVENTH, oid]
    assert var_binds[1][1].tagSet == exception.tagSet


@pytest.mark.asyncio
async def test_v1_getnext_turns_end_of_mib_into_no_such_name():
    assert (await request(next_cmd, V1, (GEN_ERROR,), (SEVENTH,), (GEN_ERROR,)))[
        :2
    ] == (NO_SUCH_NAME_STATUS, 2)


@pytest.mark.asyncio
async def test_last_record_still_ends_the_walk():
    error_status, _, var_binds = await request(next_cmd, V2C, (LAST,))

    assert not error_status
    assert var_binds[0][1].tagSet == rfc1905.EndOfMibView.tagSet
