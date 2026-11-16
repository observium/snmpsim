"""SNMPv1 and SNMPv2c answered by the simulator itself, as the engine answers them.

`--v1-v2c-path=fast` answers SNMPv1/v2c requests without pysnmp's SNMPv3
engine, `--v1-v2c-path=engine` sends them through it, as every release before
did. The engine path is the reference: the same raw request sent to a
responder on each path must come back as the same octets.
"""
import socket

import pytest
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp.proto import api
from pysnmp.proto import rfc1902

FAST_PORT = 1692
ENGINE_PORT = 1693

V1 = api.SNMP_VERSION_1
V2C = api.SNMP_VERSION_2C

SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
SYS_SERVICES = "1.3.6.1.2.1.1.7.0"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6.1"

LONG_COMMUNITY = "a-community-name-longer-than-thirty-two"

PLAIN = """\
1.3.6.1.2.1.1.1.0|4|a recording served by its community
1.3.6.1.2.1.1.3.0|67|123456
1.3.6.1.2.1.1.5.0|4|plain-host
1.3.6.1.2.1.1.6.0|4:writecache|value=room
1.3.6.1.2.1.1.7.0|2:error|status=noSuchName
1.3.6.1.2.1.2.1.0|2|2
1.3.6.1.2.1.2.2.1.1.1|2|1
1.3.6.1.2.1.2.2.1.1.2|2|2
1.3.6.1.2.1.2.2.1.2.1|4|eth0
1.3.6.1.2.1.2.2.1.2.2|4|eth1
1.3.6.1.2.1.31.1.1.1.6.1|70|12345678901
1.3.6.1.2.1.31.1.1.1.6.2|70|5
"""


def message(version, community, pdu_type, var_binds, non_repeaters=0, repetitions=5):
    """Encode a request with a fixed request-id, so that answers compare."""
    proto = api.PROTOCOL_MODULES[version]

    pdu = getattr(proto, pdu_type)()

    if pdu_type == "GetBulkRequestPDU":
        proto.apiBulkPDU.set_defaults(pdu)
        proto.apiBulkPDU.set_non_repeaters(pdu, non_repeaters)
        proto.apiBulkPDU.set_max_repetitions(pdu, repetitions)

    else:
        proto.apiPDU.set_defaults(pdu)

    proto.apiPDU.set_request_id(pdu, 4242)
    proto.apiPDU.set_varbinds(
        pdu,
        [
            (rfc1902.ObjectName(oid), univ.Null("") if value is None else value)
            for oid, value in var_binds
        ],
    )

    msg = proto.Message()
    proto.apiMessage.set_defaults(msg)
    proto.apiMessage.set_community(msg, community)
    proto.apiMessage.set_pdu(msg, pdu)

    return encoder.encode(msg)


def ask(port, request):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(request, ("127.0.0.1", port))

        try:
            return sock.recv(65535)

        except socket.timeout:
            return None


def show(version, response):
    """The answer in words, for a failing assertion to say what differs."""
    if response is None:
        return "no response"

    proto = api.PROTOCOL_MODULES[version]
    msg, _ = decoder.decode(response, asn1Spec=proto.Message())
    pdu = proto.apiMessage.get_pdu(msg)

    return "error-status %s, error-index %s, %s" % (
        proto.apiPDU.get_error_status(pdu),
        proto.apiPDU.get_error_index(pdu),
        ", ".join(
            f"{oid}={value.__class__.__name__}:{value.prettyPrint()}"
            for oid, value in proto.apiPDU.get_varbinds(pdu)
        ),
    )


# requests whose answers the two paths must agree on octet for octet
SAME = [
    ("v2c GET", V2C, "plain", "GetRequestPDU", [(SYS_NAME, None)], {}),
    ("v1 GET", V1, "plain", "GetRequestPDU", [(SYS_NAME, None)], {}),
    (
        "v2c GET of three",
        V2C,
        "plain",
        "GetRequestPDU",
        [(SYS_NAME, None), ("1.3.6.1.2.1.1.3.0", None), ("1.3.6.1.2.1.1.1.0", None)],
        {},
    ),
    (
        "v2c GET missing",
        V2C,
        "plain",
        "GetRequestPDU",
        [("1.3.6.1.2.1.1.9.9", None)],
        {},
    ),
    ("v1 GET missing", V1, "plain", "GetRequestPDU", [("1.3.6.1.2.1.1.9.9", None)], {}),
    ("v1 GET Counter64", V1, "plain", "GetRequestPDU", [(IF_HC_IN_OCTETS, None)], {}),
    ("v2c GETNEXT", V2C, "plain", "GetNextRequestPDU", [("1.3.6.1.2.1.2.2", None)], {}),
    ("v1 GETNEXT", V1, "plain", "GetNextRequestPDU", [("1.3.6.1.2.1.2.2", None)], {}),
    (
        "v1 GETNEXT onto a Counter64",
        V1,
        "plain",
        "GetNextRequestPDU",
        [("1.3.6.1.2.1.31.1.1.1.6", None)],
        {},
    ),
    (
        "v2c GETNEXT past the end",
        V2C,
        "plain",
        "GetNextRequestPDU",
        [("1.3.6.1.9", None)],
        {},
    ),
    (
        "v1 GETNEXT past the end",
        V1,
        "plain",
        "GetNextRequestPDU",
        [("1.3.6.1.9", None)],
        {},
    ),
    (
        "v2c GETBULK",
        V2C,
        "plain",
        "GetBulkRequestPDU",
        [("1.3.6.1.2.1.1.1", None), ("1.3.6.1.2.1.2.2.1", None)],
        {"non_repeaters": 1, "repetitions": 4},
    ),
    (
        "v2c GETBULK past the end",
        V2C,
        "plain",
        "GetBulkRequestPDU",
        [("1.3.6.1.2.1.31.1.1.1.6", None)],
        {"repetitions": 5},
    ),
    (
        "v2c GETBULK into the error module",
        V2C,
        "plain",
        "GetBulkRequestPDU",
        [("1.3.6.1.2.1.1.5", None), ("1.3.6.1.2.1.1", None)],
        {"non_repeaters": 1, "repetitions": 3},
    ),
    (
        "v2c GET of three, the second from the error module",
        V2C,
        "plain",
        "GetRequestPDU",
        [(SYS_NAME, None), (SYS_SERVICES, None), (SYS_LOCATION, None)],
        {},
    ),
    (
        "v1 GET of three, the second from the error module",
        V1,
        "plain",
        "GetRequestPDU",
        [(SYS_NAME, None), (SYS_SERVICES, None), (SYS_LOCATION, None)],
        {},
    ),
    (
        "v2c SET",
        V2C,
        "plain",
        "SetRequestPDU",
        [(SYS_LOCATION, rfc1902.OctetString("lab"))],
        {},
    ),
    (
        "v2c SET of a record without a module",
        V2C,
        "plain",
        "SetRequestPDU",
        [(SYS_NAME, rfc1902.OctetString("x"))],
        {},
    ),
    (
        "v1 SET of a record without a module",
        V1,
        "plain",
        "SetRequestPDU",
        [(SYS_NAME, rfc1902.OctetString("x"))],
        {},
    ),
    (
        "v2c long community",
        V2C,
        LONG_COMMUNITY,
        "GetRequestPDU",
        [(SYS_NAME, None)],
        {},
    ),
    ("v2c unknown community", V2C, "nosuch", "GetRequestPDU", [(SYS_NAME, None)], {}),
    (
        "v2c data index",
        V2C,
        "index",
        "GetNextRequestPDU",
        [("1.3.6.1.4.1.20408.999", None)],
        {},
    ),
]


@pytest.fixture(scope="module")
def recordings(tmp_path_factory):
    data = tmp_path_factory.mktemp("data")

    (data / "plain.snmprec").write_text(PLAIN)
    (data / f"{LONG_COMMUNITY}.snmprec").write_text(PLAIN)

    return data


@pytest.fixture(scope="module")
def responders(recordings, tmp_path_factory, responder_process):
    """One responder on each path, over the same recordings."""
    with responder_process(
        f"--data-dir={recordings}",
        f"--cache-dir={tmp_path_factory.mktemp('fast-cache')}",
        "--v1-v2c-path=fast",
        port=FAST_PORT,
        oid=SYS_NAME,
        community="plain",
    ), responder_process(
        f"--data-dir={recordings}",
        f"--cache-dir={tmp_path_factory.mktemp('engine-cache')}",
        "--v1-v2c-path=engine",
        port=ENGINE_PORT,
        oid=SYS_NAME,
        community="plain",
    ):
        yield


@pytest.mark.parametrize(
    "version, community, pdu_type, var_binds, bulk",
    [case[1:] for case in SAME],
    ids=[case[0] for case in SAME],
)
def test_both_paths_answer_alike(
    responders, version, community, pdu_type, var_binds, bulk
):
    request = message(version, community, pdu_type, var_binds, **bulk)

    engine = ask(ENGINE_PORT, request)
    fast = ask(FAST_PORT, request)

    assert show(version, fast) == show(version, engine)
    assert fast == engine
