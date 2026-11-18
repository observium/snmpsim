"""Recorded exceptions are answered as RFC 3416 has it, however they are served.

A recording may hold noSuchObject, noSuchInstance and endOfMibView (tags 128,
129 and 130): the agent had nothing for the variable. A GETNEXT or GETBULK
steps over them to the next variable with a value (4.2.2), a GET of an
endOfMibView is answered as a GET of a variable that is not there (4.2.1),
and a GET of the other two with them. So it is for a record that names no
variation module after the colon of its tag (`130:`), which is a plain one.
"""
import sqlite3

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

PORT = 1706

# a USM user without keys: noAuthNoPriv
V3_USER = "walker"

BASE = "1.3.6.1.4.1.99999.50"

BEFORE = f"{BASE}.1.0"
SUBTREE = f"{BASE}.2"
AFTER = f"{BASE}.3.0"

# what the snapshot or the table holds in the subtree
HELD = [
    ("1.0", "4", "one"),
    ("2.0", "128", ""),
    ("3.0", "129", ""),
    ("4.0", "130", ""),
    ("5.0", "4", "five"),
    ("6.0", "130", ""),
]

WITH_A_VALUE = [f"{SUBTREE}.1.0", f"{SUBTREE}.5.0"]

NO_SUCH_OBJECT = b"\x80\x00"
NO_SUCH_INSTANCE = b"\x81\x00"
END_OF_MIB_VIEW = b"\x82\x00"

CONTEXTS = ["wrapped"]

# the same, the exceptions in records with a colon and no module after it
WRAPPED = {"2.0": "128:|", "3.0": "129:|", "4.0": "130:|"}


def sql_oid(oid):
    """The module keeps OIDs padded so that they sort as text."""
    return ".".join("%10s" % x for x in oid.split("."))


@pytest.fixture(scope="module")
def responder(tmp_path_factory, responder_process):
    data = tmp_path_factory.mktemp("data")

    (data / "wrapped.snmprec").write_text(
        f"{BEFORE}|4|before\n"
        + "".join(
            f"{SUBTREE}.{arcs}|{WRAPPED.get(arcs, f'{tag}|{value}')}\n"
            for arcs, tag, value in HELD
        )
        + f"{AFTER}|4|after\n"
    )

    snapshots = tmp_path_factory.mktemp("snapshots")
    (snapshots / "00000.snmprec").write_text(
        "".join(f"{SUBTREE}.{arcs}|{tag}|{value}\n" for arcs, tag, value in HELD)
    )

    database = tmp_path_factory.mktemp("db") / "agent.db"
    conn = sqlite3.connect(database)
    conn.execute(
        "CREATE TABLE snmprec (oid text, tag text, value text, maxaccess text)"
    )
    conn.executemany(
        "insert into snmprec values (?, ?, ?, 'read-only')",
        [(sql_oid(f"{SUBTREE}.{arcs}"), tag, value) for arcs, tag, value in HELD],
    )
    conn.commit()
    conn.close()

    for context, served_by in (
        ("multiplexed", f":multiplex|dir={snapshots},period=100000"),
        ("tabled", ":sql|snmprec"),
    ):
        (data / f"{context}.snmprec").write_text(
            f"{BEFORE}|4|before\n{SUBTREE}|{served_by}\n{AFTER}|4|after\n"
        )

    with responder_process(
        f"--data-dir={data}",
        f"--cache-dir={tmp_path_factory.mktemp('cache')}",
        f"--variation-module-options=sql:dbtype:sqlite3,database:{database}",
        f"--v3-user={V3_USER}",
        port=PORT,
        oid=BEFORE,
        community="wrapped",
    ):
        yield engine_id(PORT)


def request(responder, version, context, pdu_type, oids, repetitions=0):
    if version == V3:
        octets = v3_message(
            pdu_type, oids, responder, context, V3_USER, repetitions=repetitions
        )

    else:
        octets = message(version, pdu_type, oids, context, repetitions=repetitions)

    return answer(ask(PORT, octets))


VERSIONS = pytest.mark.parametrize("version", [V1, V2C, V3], ids=["v1", "v2c", "v3"])
SERVED_BY = pytest.mark.parametrize("context", CONTEXTS)


@VERSIONS
@SERVED_BY
def test_getnext_steps_over_what_has_no_value(responder, version, context):
    oid, walked = BASE, []

    while True:
        error_status, _, var_binds = request(
            responder, version, context, "GetNextRequestPDU", [oid]
        )

        if error_status or not var_binds[0][0].startswith(BASE + "."):
            break

        # the end of the recording
        if var_binds[0] == (oid, END_OF_MIB_VIEW):
            break

        oid, value = var_binds[0]
        walked.append(oid)

        assert value[0] not in (0x80, 0x81, 0x82), (oid, value)
        assert len(walked) <= len(HELD) + 2

    assert walked == [BEFORE] + WITH_A_VALUE + [AFTER]


@SERVED_BY
@pytest.mark.parametrize(
    "start",
    [f"{SUBTREE}.1.0", f"{SUBTREE}.2.0", f"{SUBTREE}.3", f"{SUBTREE}.5.0"],
    ids=["before the run", "on an exception", "between", "after the last value"],
)
def test_getnext_from_anywhere_in_the_subtree(responder, context, start):
    _, _, var_binds = request(responder, V2C, context, "GetNextRequestPDU", [start])

    expected = {
        f"{SUBTREE}.1.0": (f"{SUBTREE}.5.0", b"five"),
        f"{SUBTREE}.2.0": (f"{SUBTREE}.5.0", b"five"),
        f"{SUBTREE}.3": (f"{SUBTREE}.5.0", b"five"),
        # only exceptions are left in the subtree: on to the next record
        f"{SUBTREE}.5.0": (AFTER, b"after"),
    }[start]

    assert var_binds == [
        (expected[0], encoder.encode(rfc1902.OctetString(expected[1])))
    ]


@SERVED_BY
def test_getbulk_steps_over_what_has_no_value(responder, context):
    error_status, _, var_binds = request(
        responder, V2C, context, "GetBulkRequestPDU", [BASE], repetitions=6
    )

    assert error_status == 0
    assert [oid for oid, _ in var_binds][:4] == [BEFORE] + WITH_A_VALUE + [AFTER]
    assert all(value == END_OF_MIB_VIEW for _, value in var_binds[4:])


@SERVED_BY
def test_get_answers_endofmibview_as_a_variable_that_is_not_there(responder, context):
    error_status, _, var_binds = request(
        responder,
        V2C,
        context,
        "GetRequestPDU",
        [f"{SUBTREE}.2.0", f"{SUBTREE}.3.0", f"{SUBTREE}.4.0"],
    )

    assert error_status == 0
    assert [value for _, value in var_binds] == [
        NO_SUCH_OBJECT,
        NO_SUCH_INSTANCE,
        NO_SUCH_INSTANCE,
    ]


@SERVED_BY
def test_get_of_the_last_record_an_endofmibview(responder, context):
    error_status, _, var_binds = request(
        responder, V2C, context, "GetRequestPDU", [f"{SUBTREE}.6.0"]
    )

    assert error_status == 0
    assert [value for _, value in var_binds] == [NO_SUCH_INSTANCE]


@VERSIONS
def test_set_of_a_recorded_endofmibview_is_not_writable(responder, version):
    var_binds = [(f"{SUBTREE}.6.0", rfc1902.OctetString(b"x"))]
    error_status, error_index, _ = request(
        responder, version, "wrapped", "SetRequestPDU", var_binds
    )

    # SNMPv1 has noSuchName for it (RFC 3584, 4.4)
    assert (error_status, error_index) == ((2 if version == V1 else 17), 1)
