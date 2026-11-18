"""A SET that cannot be done is answered with the error that says why.

Such a SET is answered as net-snmp's snmpd answers it, after RFC 3416, 4.2.5:
- a variable the recording does not hold, or holds read-only - a plain
  record -, is notWritable;
- a value of another type than that of a `writecache` record is wrongType;
- the error names the first variable of the request that fails, whichever
  error it is;
- the variables come back as they were sent;
- a SET that fails changes nothing, the variables ahead of the failed one
  included.
An SNMPv1 manager gets noSuchName and badValue instead (RFC 3584, 4.4).
"""
import itertools

import pytest
from pyasn1.codec.ber import encoder
from pysnmp.proto import rfc1902
from snmp_messages import V1
from snmp_messages import V2C
from snmp_messages import V3
from snmp_messages import answer
from snmp_messages import ask
from snmp_messages import engine_id
from snmp_messages import message
from snmp_messages import v3_message

PORT = 1705

# a USM user without keys: noAuthNoPriv
V3_USER = "setter"

CONTEXT = "settable"

BASE = "1.3.6.1.4.1.99999.40"

READ_ONLY = f"{BASE}.1.0"
WRITABLE = f"{BASE}.2.0"
WRITABLE_INTEGER = f"{BASE}.3.0"
LIMITED = f"{BASE}.4.0"
REFUSING = f"{BASE}.5.0"
# the error module takes a SET where it is given no error for it
ERROR_WRITABLE = f"{BASE}.6.0"
BETWEEN = f"{BASE}.1.5"
BELOW_A_RECORD = f"{READ_ONLY}.1"
PAST_THE_END = f"{BASE}.99.0"
BEFORE_ALL = "1.3.6.1.4.1.99998.1.0"

RECORDING = f"""\
{READ_ONLY}|4|fixed
{WRITABLE}|4:writecache|value=start
{WRITABLE_INTEGER}|2:writecache|value=1
{LIMITED}|2:writecache|value=1,vlist=lt:0:wrongvalue
{REFUSING}|4:writecache|value=kept,op=set,status=notwritable
{ERROR_WRITABLE}|4:error|value=open
"""

NOT_WRITABLE, WRONG_TYPE = 17, 7
NO_SUCH_NAME, BAD_VALUE = 2, 3

V1_ERRORS = {NOT_WRITABLE: NO_SUCH_NAME, WRONG_TYPE: BAD_VALUE}

TEXT = rfc1902.OctetString(b"text")
NUMBER = rfc1902.Integer32(5)

# values no SET has written before, so that one written is told apart
FRESH = itertools.count(1000)

VERSIONS = pytest.mark.parametrize("version", [V1, V2C, V3], ids=["v1", "v2c", "v3"])


@pytest.fixture(scope="module")
def responder(tmp_path_factory, responder_process):
    data = tmp_path_factory.mktemp("data")
    (data / f"{CONTEXT}.snmprec").write_text(RECORDING)

    with responder_process(
        f"--data-dir={data}",
        f"--cache-dir={tmp_path_factory.mktemp('cache')}",
        f"--v3-user={V3_USER}",
        port=PORT,
        oid=READ_ONLY,
        community=CONTEXT,
    ):
        yield engine_id(PORT)


def set_request(responder, version, var_binds, context=CONTEXT):
    if version == V3:
        request = v3_message("SetRequestPDU", var_binds, responder, context, V3_USER)

    else:
        request = message(version, "SetRequestPDU", var_binds, context)

    response = ask(PORT, request)

    assert response is not None

    return answer(response)


def refused(version, error_status, error_index, var_binds):
    """The answer to a SET refused for the variable at `error_index`."""
    if version == V1:
        error_status = V1_ERRORS[error_status]

    return (
        error_status,
        error_index,
        [(oid, encoder.encode(value)) for oid, value in var_binds],
    )


@VERSIONS
@pytest.mark.parametrize(
    "var_binds",
    [
        [(READ_ONLY, TEXT)],
        # whether it is writable comes first
        [(READ_ONLY, NUMBER)],
        [(BETWEEN, TEXT)],
        [(BELOW_A_RECORD, TEXT)],
        [(PAST_THE_END, TEXT)],
        [(BEFORE_ALL, TEXT)],
        # a writecache record that refuses every SET, whatever the type
        [(REFUSING, NUMBER)],
        [(REFUSING, TEXT)],
    ],
    ids=[
        "read-only",
        "read-only-and-wrong-type",
        "between-records",
        "below-a-record",
        "past-the-end",
        "before-all-records",
        "refusing-and-wrong-type",
        "refusing",
    ],
)
def test_what_is_not_writable_is_not_writable(responder, version, var_binds):
    assert set_request(responder, version, var_binds) == refused(
        version, NOT_WRITABLE, 1, var_binds
    )


@VERSIONS
@pytest.mark.parametrize(
    "var_binds",
    [
        [(WRITABLE, NUMBER)],
        [(WRITABLE_INTEGER, TEXT)],
        [(WRITABLE_INTEGER, rfc1902.Gauge32(5))],
        # the type comes before what the value is compared with
        [(LIMITED, TEXT)],
    ],
    ids=[
        "integer-to-string",
        "string-to-integer",
        "gauge-to-integer",
        "before-the-value-list",
    ],
)
def test_a_value_of_another_type_is_the_wrong_type(responder, version, var_binds):
    assert set_request(responder, version, var_binds) == refused(
        version, WRONG_TYPE, 1, var_binds
    )


@VERSIONS
@pytest.mark.parametrize(
    "var_binds, error_status, error_index",
    [
        ([(WRITABLE, TEXT), (READ_ONLY, TEXT)], NOT_WRITABLE, 2),
        ([(WRITABLE, TEXT), (WRITABLE_INTEGER, TEXT)], WRONG_TYPE, 2),
        ([(WRITABLE, NUMBER), (READ_ONLY, TEXT)], WRONG_TYPE, 1),
        ([(READ_ONLY, TEXT), (WRITABLE, NUMBER)], NOT_WRITABLE, 1),
        ([(WRITABLE, NUMBER), (PAST_THE_END, TEXT)], WRONG_TYPE, 1),
        ([(PAST_THE_END, TEXT), (WRITABLE, NUMBER)], NOT_WRITABLE, 1),
    ],
    ids=[
        "written-then-read-only",
        "written-then-wrong-type",
        "wrong-type-then-read-only",
        "read-only-then-wrong-type",
        "wrong-type-then-missing",
        "missing-then-wrong-type",
    ],
)
def test_the_first_variable_that_fails_is_named(
    responder, version, var_binds, error_status, error_index
):
    assert set_request(responder, version, var_binds) == refused(
        version, error_status, error_index, var_binds
    )


@VERSIONS
def test_the_data_index_is_not_writable(responder, version):
    var_binds = [("1.3.6.1.4.1.20408.999.1.1.1", TEXT)]

    assert set_request(responder, version, var_binds, context="index") == refused(
        version, NOT_WRITABLE, 1, var_binds
    )


def read(responder, oid):
    _, _, ((_, value),) = answer(
        ask(PORT, message(V2C, "GetRequestPDU", [oid], CONTEXT))
    )

    return value


@VERSIONS
@pytest.mark.parametrize(
    "failing",
    [(READ_ONLY, TEXT), (WRITABLE_INTEGER, TEXT), (PAST_THE_END, TEXT)],
    ids=["read-only", "wrong-type", "missing"],
)
def test_a_set_that_fails_writes_nothing(responder, version, failing):
    before = {
        oid: read(responder, oid)
        for oid in (WRITABLE, WRITABLE_INTEGER, ERROR_WRITABLE)
    }
    var_binds = [
        (WRITABLE, rfc1902.OctetString(b"lost %d" % next(FRESH))),
        (WRITABLE_INTEGER, rfc1902.Integer32(next(FRESH))),
        (WRITABLE, rfc1902.OctetString(b"lost %d" % next(FRESH))),
        (ERROR_WRITABLE, rfc1902.OctetString(b"lost %d" % next(FRESH))),
        failing,
    ]

    assert set_request(responder, version, var_binds)[:2] != (0, 0)

    assert {oid: read(responder, oid) for oid in before} == before


def test_a_refusing_record_is_not_written(responder):
    set_request(responder, V2C, [(REFUSING, TEXT)])

    assert read(responder, REFUSING) == encoder.encode(rfc1902.OctetString(b"kept"))
