"""SNMPv3 is answered as SNMPv2c is, errors and all.

SNMPv1/v2c requests are answered by the responder's own fast path, SNMPv3
ones by pysnmp's engine: two ways to the same recordings, which must not
answer differently. Each request here goes once as SNMPv2c and once as
SNMPv3 (noAuthNoPriv), one right after the other, and the two have to carry
the same request-id, error-status, error-index and var-binds, the values
octet for octet: plain values, what variation modules make of a request -
errors of the `error` module, writes to `writecache` and the ones it
refuses -, OIDs that are not there, requests that mix them, GETNEXT and
GETBULK past the end, cut by the number of var-binds, and the data index.

One thing is meant to differ: a GETBULK response cut short to fit the
message size. SNMPv3 keeps room for its security parameters, which SNMPv2c
does not have, and fits fewer var-binds.
"""
import pytest
from pyasn1.codec.ber import encoder
from pysnmp.proto import rfc1902
from snmp_messages import REQUEST_ID
from snmp_messages import V2C
from snmp_messages import V3
from snmp_messages import answer
from snmp_messages import ask
from snmp_messages import engine_id
from snmp_messages import message
from snmp_messages import request_id
from snmp_messages import scoped_pdu
from snmp_messages import v3_message

PORT = 1703

# a USM user without keys: noAuthNoPriv
V3_USER = "compared"

CONTEXT = "cases"

BASE = "1.3.6.1.4.1.99999.20"

# values first, in a subtree of their own: a walk gets through all of them
# before it meets a record that answers with an error
VALUES = f"{BASE}.1"
PLAIN = f"{VALUES}.1.0"
WRITABLE = f"{VALUES}.2.0"
WRITABLE_BUT_13 = f"{VALUES}.3.0"
COLUMN = f"{VALUES}.4"
ROW_1 = f"{COLUMN}.1"
ROW_2 = f"{COLUMN}.2"
MISSING = f"{VALUES}.5.0"
COUNTER64 = f"{VALUES}.6.0"
LAST_VALUE = f"{VALUES}.7.0"

ERRORS = f"{BASE}.2"
NO_SUCH_NAME = f"{ERRORS}.1.0"
BAD_VALUE_ON_SET = f"{ERRORS}.2.0"
READ_ONLY_ON_SET = f"{ERRORS}.3.0"
GEN_ERROR = f"{ERRORS}.4.0"
WRONG_VALUE_ON_SET = f"{ERRORS}.5.0"
TOO_BIG = f"{ERRORS}.6.0"

LAST = f"{BASE}.3.0"
PAST_THE_END = f"{BASE}.99.0"
OUTSIDE = "1.3.6.1.4.1.99999.21"

RECORDING = f"""\
{PLAIN}|4|first
{WRITABLE}|4:writecache|value=start
{WRITABLE_BUT_13}|2:writecache|value=1,vlist=eq:13:wrongvalue
{ROW_1}|2|10
{ROW_2}|2|20
{COUNTER64}|70|18446744073709551615
{LAST_VALUE}|4|last value
{NO_SUCH_NAME}|4:error|status=noSuchName,value=hidden
{BAD_VALUE_ON_SET}|4:error|op=set,status=badValue,value=picky
{READ_ONLY_ON_SET}|4:error|op=set,status=readOnly,value=fixed
{GEN_ERROR}|4:error|status=genError,value=broken
{WRONG_VALUE_ON_SET}|4:error|op=set,status=wrongValue,value=strict
{TOO_BIG}|4:error|status=tooBig,value=huge
{LAST}|4|last
"""

WITH_VALUES = [PLAIN, WRITABLE, WRITABLE_BUT_13, ROW_1, ROW_2, COUNTER64, LAST_VALUE]

WITH_ERRORS = [
    NO_SUCH_NAME,
    BAD_VALUE_ON_SET,
    READ_ONLY_ON_SET,
    GEN_ERROR,
    WRONG_VALUE_ON_SET,
    TOO_BIG,
]

ALL = WITH_VALUES + WITH_ERRORS + [LAST]

# values long enough for a GETBULK to be cut by the message size
LONG = f"{BASE}.4"
LONG_RECORDING = "".join(f"{LONG}.{row}.0|4|{'x' * 100}\n" for row in range(1, 40))

TEXT = rfc1902.OctetString


def name(oid):
    """A test id for an OID: what it adds to BASE, or the whole of it."""
    if oid == BASE:
        return "base"

    if oid.startswith(BASE + "."):
        return oid[len(BASE) :]

    return oid


@pytest.fixture(scope="module")
def responder(tmp_path_factory, responder_process):
    data = tmp_path_factory.mktemp("data")
    (data / f"{CONTEXT}.snmprec").write_text(RECORDING)
    (data / "long.snmprec").write_text(LONG_RECORDING)

    with responder_process(
        f"--data-dir={data}",
        f"--cache-dir={tmp_path_factory.mktemp('cache')}",
        # SNMPv1/v2c on the fast path, whatever the default
        "--v1-v2c-path=fast",
        f"--v3-user={V3_USER}",
        port=PORT,
        oid=PLAIN,
        community=CONTEXT,
    ):
        yield engine_id(PORT)


def both(responder, pdu_type, var_binds, context, **bulk):
    """What a request is answered with as SNMPv2c and as SNMPv3."""
    return (
        ask(PORT, message(V2C, pdu_type, var_binds, context, **bulk)),
        ask(
            PORT,
            v3_message(pdu_type, var_binds, responder, context, V3_USER, **bulk),
        ),
    )


def compared(responder, pdu_type, var_binds, context=CONTEXT, **bulk):
    """The answer to a request as SNMPv2c, which SNMPv3 has to give as well."""
    v2c, v3 = both(responder, pdu_type, var_binds, context, **bulk)

    assert v2c is not None, "no SNMPv2c answer"
    assert v3 is not None, "no SNMPv3 answer"

    # a Response-PDU, not a Report-PDU, to this very request in both
    assert scoped_pdu(v2c)[0] == scoped_pdu(v3)[0] == 0xA2
    assert request_id(v2c) == request_id(v3) == REQUEST_ID

    assert answer(v3) == answer(v2c)

    return answer(v2c)


def write(responder, version, var_binds):
    if version == V2C:
        return ask(PORT, message(V2C, "SetRequestPDU", var_binds, CONTEXT))

    return ask(
        PORT, v3_message("SetRequestPDU", var_binds, responder, CONTEXT, V3_USER)
    )


@pytest.mark.parametrize(
    "oid", ALL + [MISSING, PAST_THE_END, BASE, COLUMN, OUTSIDE], ids=name
)
def test_get(responder, oid):
    compared(responder, "GetRequestPDU", [oid])


@pytest.mark.parametrize(
    "oids",
    [
        WITH_VALUES,
        WITH_VALUES + [BAD_VALUE_ON_SET, READ_ONLY_ON_SET, LAST],
        [PLAIN, MISSING, GEN_ERROR, LAST],
        [PLAIN, NO_SUCH_NAME, LAST],
        [GEN_ERROR, NO_SUCH_NAME],
        [LAST, TOO_BIG],
        [MISSING, PAST_THE_END, COUNTER64],
        ALL,
        [],
    ],
    ids=[
        "values",
        "values-and-set-only-errors",
        "missing-then-error",
        "no-such-name",
        "two-errors",
        "too-big",
        "missing-only",
        "all",
        "none",
    ],
)
def test_get_of_several(responder, oids):
    compared(responder, "GetRequestPDU", oids)


@pytest.mark.parametrize(
    "oid", [BASE] + ALL + [VALUES, COLUMN, MISSING, PAST_THE_END, OUTSIDE], ids=name
)
def test_getnext(responder, oid):
    compared(responder, "GetNextRequestPDU", [oid])


@pytest.mark.parametrize(
    "oids",
    [
        [BASE, ROW_1, LAST, COLUMN],
        [LAST_VALUE, PLAIN],
        [ROW_1, ROW_1, LAST_VALUE],
        [],
    ],
    ids=["values", "into-an-error", "error-third", "none"],
)
def test_getnext_of_several(responder, oids):
    compared(responder, "GetNextRequestPDU", oids)


def test_getnext_walks_the_values_alike(responder):
    oid, walked = BASE, []

    while len(walked) <= len(ALL):
        error_status, _, var_binds = compared(responder, "GetNextRequestPDU", [oid])

        if error_status:
            break

        oid, _ = var_binds[0]
        walked.append(oid)

    # every value is walked alike, up to the first error record
    assert walked == WITH_VALUES


@pytest.mark.parametrize(
    "oids, non_repeaters, repetitions",
    [
        ([BASE], 0, len(WITH_VALUES)),
        ([BASE], 0, 3),
        ([BASE], 0, 20),
        ([PLAIN, VALUES], 1, 3),
        ([LAST, LAST_VALUE], 1, 4),
        ([LAST, READ_ONLY_ON_SET, COLUMN], 2, 2),
        ([COLUMN, ROW_2], 0, 5),
        ([BASE, BASE], 5, 3),
        ([LAST], 0, 3),
        ([LAST, LAST, LAST], 0, 200),
        ([GEN_ERROR], 1, 0),
        ([BASE, NO_SUCH_NAME], 0, 4),
    ],
    ids=[
        "values",
        "three",
        "into-the-errors",
        "non-repeater",
        "error-in-the-repetitions",
        "two-non-repeaters",
        "two-columns",
        "non-repeaters-past-the-var-binds",
        "past-the-end",
        "cut-by-max-var-binds",
        "non-repeater-only",
        "through-errors",
    ],
)
def test_getbulk(responder, oids, non_repeaters, repetitions):
    compared(
        responder,
        "GetBulkRequestPDU",
        oids,
        non_repeaters=non_repeaters,
        repetitions=repetitions,
    )


def test_getbulk_of_the_values_serves_every_one(responder):
    _, _, var_binds = compared(
        responder, "GetBulkRequestPDU", [BASE], repetitions=len(WITH_VALUES)
    )

    assert [oid for oid, _ in var_binds] == WITH_VALUES


@pytest.mark.parametrize(
    "oids, repetitions",
    [([PLAIN], 0), ([], 5)],
    ids=["no-repetitions", "no-var-binds"],
)
def test_getbulk_of_nothing_is_dropped_alike(responder, oids, repetitions):
    """Nothing to answer with: no repetitions and no non-repeaters, or no
    var-binds at all. The engine drops it for either version."""
    assert both(
        responder, "GetBulkRequestPDU", oids, CONTEXT, repetitions=repetitions
    ) == (None, None)


def test_getbulk_cut_by_the_message_size_is_cut_shorter_for_v3(responder):
    """SNMPv3 keeps room for its security parameters: fewer var-binds fit."""
    v2c, v3 = both(responder, "GetBulkRequestPDU", [LONG], "long", repetitions=50)

    _, _, v2c_var_binds = answer(v2c)
    v3_error_status, v3_error_index, v3_var_binds = answer(v3)

    # the message size, not the 39 values there are, cuts the response
    assert 0 < len(v2c_var_binds) < 39

    assert (v3_error_status, v3_error_index) == (0, 0)
    assert 0 < len(v3_var_binds) <= len(v2c_var_binds)
    assert v3_var_binds == v2c_var_binds[: len(v3_var_binds)]


@pytest.mark.parametrize(
    "var_binds",
    [
        [(PLAIN, TEXT("other"))],
        [(BAD_VALUE_ON_SET, TEXT("other"))],
        [(READ_ONLY_ON_SET, TEXT("other"))],
        [(WRONG_VALUE_ON_SET, TEXT("other"))],
        [(GEN_ERROR, TEXT("other"))],
        [(NO_SUCH_NAME, TEXT("other"))],
        [(WRITABLE, TEXT("written"))],
        [(WRITABLE, rfc1902.Integer32(5))],
        [(WRITABLE_BUT_13, rfc1902.Integer32(13))],
        [(WRITABLE_BUT_13, rfc1902.Integer32(7))],
        [(MISSING, TEXT("other"))],
        [(WRITABLE, TEXT("written")), (READ_ONLY_ON_SET, TEXT("other"))],
        [(WRITABLE, TEXT("written")), (MISSING, TEXT("other"))],
        [],
    ],
    ids=[
        "plain",
        "bad-value",
        "read-only",
        "wrong-value",
        "gen-error",
        "no-such-name",
        "writable",
        "writable-wrong-type",
        "vlist-refuses",
        "vlist-takes",
        "missing",
        "second-read-only",
        "second-missing",
        "none",
    ],
)
def test_set(responder, var_binds):
    """The same SET twice: what is written the first time is written again."""
    compared(responder, "SetRequestPDU", var_binds)


def test_what_one_version_writes_the_other_reads(responder):
    for version, value in ((V2C, "by-v2c"), (V3, "by-v3")):
        written = write(responder, version, [(WRITABLE, TEXT(value))])

        assert answer(written)[:2] == (0, 0)

        _, _, ((_, read),) = compared(responder, "GetRequestPDU", [WRITABLE])

        assert read == encoder.encode(TEXT(value))


@pytest.mark.parametrize(
    "pdu_type, bulk",
    [("GetNextRequestPDU", {}), ("GetBulkRequestPDU", {"repetitions": 10})],
    ids=["getnext", "getbulk"],
)
def test_the_data_index(responder, pdu_type, bulk):
    error_status, _, var_binds = compared(
        responder, pdu_type, ["1.3.6"], context="index", **bulk
    )

    assert not error_status and var_binds
