"""SNMPv2c reads are decoded as pyasn1 decodes them, or left to pyasn1.

`ber.decode_read_request()` takes the plain shape of a GET, GETNEXT or
GETBULK and nothing else. The rule held here is the one that keeps it safe:
whatever it takes, pyasn1 decodes to the same; whatever pyasn1 refuses or
would have to judge, it leaves to pyasn1 (NotPlain). The limits pyasn1 has
added for crafted input since 0.6.2 hold for it as well.
"""
import random

import pytest
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp.proto import api
from pysnmp.proto import rfc1902

from snmpsim import ber

PROTO = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]

READS = ("GetRequestPDU", "GetNextRequestPDU", "GetBulkRequestPDU")


def request(pdu_type, oids, request_id=4242, first=0, second=0, community=b"public"):
    pdu = getattr(PROTO, pdu_type)()

    if pdu_type == "GetBulkRequestPDU":
        PROTO.apiBulkPDU.set_defaults(pdu)
        PROTO.apiBulkPDU.set_non_repeaters(pdu, first)
        PROTO.apiBulkPDU.set_max_repetitions(pdu, second)

    else:
        PROTO.apiPDU.set_defaults(pdu)
        PROTO.apiPDU.set_error_status(pdu, first)
        PROTO.apiPDU.set_error_index(pdu, second)

    PROTO.apiPDU.set_request_id(pdu, request_id)
    PROTO.apiPDU.set_varbinds(
        pdu, [(rfc1902.ObjectName(oid), univ.Null("")) for oid in oids]
    )

    msg = PROTO.Message()
    PROTO.apiMessage.set_defaults(msg)
    PROTO.apiMessage.set_community(msg, community)
    PROTO.apiMessage.set_pdu(msg, pdu)

    return encoder.encode(msg)


def by_pyasn1(octets):
    """What pyasn1 and pysnmp make of a read, as decode_read_request() puts it.

    Raises for anything that is not a plain SNMPv2c read with NULL values.
    """
    msg, rest = decoder.decode(octets, asn1Spec=PROTO.Message())

    if rest or int(msg[0]) != 1:
        raise ValueError("not a whole SNMPv2c message")

    pdu = PROTO.apiMessage.get_pdu(msg)

    if pdu.__class__.__name__ not in READS:
        raise ValueError(pdu.__class__.__name__)

    var_binds = PROTO.apiPDU.get_varbinds(pdu)

    if any(value.tagSet != univ.Null.tagSet for _, value in var_binds):
        raise ValueError("a value other than NULL")

    return (
        bytes(PROTO.apiMessage.get_community(msg)),
        pdu.__class__.__name__,
        int(pdu[0]),
        int(pdu[1]),
        int(pdu[2]),
        [tuple(oid) for oid, _ in var_binds],
    )


def agrees(octets):
    """Hold decode_read_request() to pyasn1 on `octets`.

    Returns True if it took them, False if it left them to pyasn1.
    """
    try:
        ours = ber.decode_read_request(octets)

    except ber.NotPlain:
        return False

    assert ours == by_pyasn1(octets), octets.hex()

    return True


def get_with_oid(oid_tlv):
    """A GET whose one var-bind has the OID encoding given."""
    var_bind = ber.tlv(0x30, oid_tlv + b"\x05\x00")
    pdu = ber.tlv(
        0xA0,
        ber.tlv(2, b"\x01")
        + ber.tlv(2, b"\x00")
        + ber.tlv(2, b"\x00")
        + ber.tlv(0x30, var_bind),
    )
    return ber.tlv(0x30, ber.tlv(2, b"\x01") + ber.tlv(4, b"public") + pdu)


@pytest.mark.parametrize("pdu_type", READS)
def test_a_plain_read_is_decoded_as_pyasn1_decodes_it(pdu_type):
    octets = request(
        pdu_type,
        ["1.3.6.1.2.1.1.5.0", "1.3.6.1.4.1.99999.2.4294967295"],
        request_id=-(2**31),
        first=3 if pdu_type == "GetBulkRequestPDU" else 0,
        second=25 if pdu_type == "GetBulkRequestPDU" else 0,
        community=b"c" * 200,
    )

    assert agrees(octets)


# Vectors from pyasn1's own decoder tests, tests/codec/ber/test_decoder.py
# (pyasn1, Copyright (c) 2005-2020, Ilya Etingof, BSD 2-Clause), put into
# the OID of a GET. None where pyasn1 refuses them, which the decoder here
# leaves to it.
PYASN1_OID_VECTORS = [
    (bytes((6, 6, 43, 6, 0, 191, 255, 126)), (1, 3, 6, 0, 0xFFFFE)),
    (bytes((6, 1, 39)), (0, 39)),
    (bytes((6, 1, 79)), (1, 39)),
    (bytes((6, 1, 120)), (2, 40)),
    (bytes((6, 5, 0x90, 0x80, 0x80, 0x80, 0x4F)), (2, 0xFFFFFFFF)),
    (bytes((6, 1, 0x7F)), (2, 47)),
    (bytes((6, 2, 0x81, 0x00)), (2, 48)),
    (bytes((6, 3, 0x81, 0x34, 0x03)), (2, 100, 3)),
    (bytes((6, 2, 133, 0)), (2, 560)),
    (bytes((6, 4, 0x88, 0x84, 0x87, 0x02)), (2, 16843570)),
    (bytes((6, 5, 85, 4, 129, 128, 0)), (2, 5, 4, 16384)),
    (
        bytes(
            (
                0x06,
                0x11,
                0x83,
                0xC6,
                0xDF,
                0xD4,
                0xCC,
                0xB3,
                0xFF,
                0xFF,
                0xFE,
                0xF0,
                0xB8,
                0xD6,
                0xB8,
                0xCB,
                0xE2,
                0xB7,
                0x17,
            )
        ),
        (2, 18446744073709551535184467440737095),
    ),
    (
        bytes(
            (
                0x06,
                0x13,
                0x88,
                0x37,
                0x83,
                0xC6,
                0xDF,
                0xD4,
                0xCC,
                0xB3,
                0xFF,
                0xFF,
                0xFE,
                0xF0,
                0xB8,
                0xD6,
                0xB8,
                0xCB,
                0xE2,
                0xB6,
                0x47,
            )
        ),
        (2, 999, 18446744073709551535184467440737095),
    ),
    # a leading 0x80 in a sub-identifier
    (bytes((6, 5, 85, 4, 128, 129, 0)), None),
    (bytes((6, 7, 1, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F)), None),
    (bytes((6, 2, 0x80, 1)), None),
    (bytes((6, 2, 0x80, 0x7F)), None),
    # constructed, empty, indefinite, reserved length
    (bytes((38, 1, 239)), None),
    (bytes((6, 0)), None),
    (bytes((6, 128, 0)), None),
    # 20 continuation octets in an arc are the most pyasn1 takes, 21 too many
    (bytes([0x06, 21]) + bytes([0x81] * 20) + bytes([0x01]), "pyasn1"),
    (bytes([0x06, 22]) + bytes([0x81] * 21) + bytes([0x01]), None),
    (bytes([0x06, 26]) + bytes([0xFF] * 25) + bytes([0x01]), None),
    (bytes([0x06, 27]) + bytes([0x55]) + bytes([0x81] * 25) + bytes([0x01]), None),
    (
        bytes([0x06, 42])
        + bytes([0x81] * 20)
        + bytes([0x01])
        + bytes([0x81] * 20)
        + bytes([0x01]),
        "pyasn1",
    ),
    # many single-octet arcs
    (bytes([0x06, 0x82, 0x10, 0x00]) + bytes([0x01] * 4096), "pyasn1"),
]


@pytest.mark.parametrize(
    "oid_tlv, arcs",
    PYASN1_OID_VECTORS,
    ids=[v[0][:8].hex() for v in PYASN1_OID_VECTORS],
)
def test_pyasn1_oid_vectors(oid_tlv, arcs):
    octets = get_with_oid(oid_tlv)

    if arcs is None:
        with pytest.raises(ber.NotPlain):
            ber.decode_read_request(octets)

        # and pyasn1, which it is left to, refuses it
        with pytest.raises(Exception):
            by_pyasn1(octets)

    else:
        assert agrees(octets)

        if arcs != "pyasn1":
            assert ber.decode_read_request(octets)[5] == [arcs]


# what pyasn1's security fixes since 0.6.2 refuse, in a request: each is
# left to pyasn1, nothing here takes it
@pytest.mark.parametrize(
    "octets",
    [
        # a length field of nine octets, of sixteen, and of a value past memory
        b"\x30\x89" + b"\xff" * 9 + b"\x01",
        b"\x30\x90" + b"\xff" * 16 + b"\x01",
        b"\x30\x88" + b"\xff" * 8,
        b"\x30\x84\x80\x00\x00\x00",
        # an indefinite length
        b"\x30\x80" + request("GetRequestPDU", ["1.3.6.1"])[2:] + b"\x00\x00",
        # a long-form tag, and an over-long one
        b"\x1f\x02\x01\x00",
        b"\x3f" + b"\x81" * 21 + b"\x01\x00",
        # the community as a constructed OCTET STRING
        bytes.fromhex("3015020101")
        + bytes.fromhex("2408040470756204026963")
        + bytes.fromhex("a000"),
    ],
    ids=[
        "9-octet length",
        "16-octet length",
        "huge length",
        "2**31 length",
        "indefinite",
        "long tag",
        "21-octet tag",
        "constructed community",
    ],
)
def test_what_pyasn1s_fixes_are_about_is_left_to_pyasn1(octets):
    with pytest.raises(ber.NotPlain):
        ber.decode_read_request(octets)


@pytest.mark.parametrize(
    "request_id, first, second, pdu_type",
    [
        (1, -1, 0, "GetBulkRequestPDU"),
        (1, 2**31, 0, "GetBulkRequestPDU"),
        (1, 0, -1, "GetBulkRequestPDU"),
        (1, 0, 2**31, "GetBulkRequestPDU"),
        (1, 0, -1, "GetRequestPDU"),
        (1, 0, 2**31, "GetRequestPDU"),
        (2**31, 0, 0, "GetRequestPDU"),
        (-(2**31) - 1, 0, 0, "GetRequestPDU"),
    ],
)
def test_fields_out_of_pysnmps_ranges_are_left_to_pyasn1(
    request_id, first, second, pdu_type
):
    tag = {"GetRequestPDU": 0xA0, "GetBulkRequestPDU": 0xA5}[pdu_type]
    var_bind = ber.tlv(0x30, ber.encode_oid((1, 3, 6, 1)) + b"\x05\x00")
    pdu = ber.tlv(
        tag,
        ber.tlv(2, ber.integer_contents(request_id))
        + ber.tlv(2, ber.integer_contents(first))
        + ber.tlv(2, ber.integer_contents(second))
        + ber.tlv(0x30, var_bind),
    )
    octets = ber.tlv(0x30, ber.tlv(2, b"\x01") + ber.tlv(4, b"public") + pdu)

    with pytest.raises(ber.NotPlain):
        ber.decode_read_request(octets)

    with pytest.raises(Exception):
        by_pyasn1(octets)


def random_oid(rng):
    first = rng.randrange(0, 3)
    second = rng.randrange(0, 40) if first < 2 else rng.randrange(0, 5000)
    return (first, second) + tuple(
        rng.choice([rng.randrange(128), rng.randrange(2**32), rng.randrange(2**70)])
        for _ in range(rng.randrange(0, 30))
    )


def test_random_reads_and_their_mutations_agree_with_pyasn1():
    rng = random.Random(20261117)
    taken = mutated_taken = 0

    for _ in range(600):
        pdu_type = rng.choice(READS)
        bulk = pdu_type == "GetBulkRequestPDU"
        octets = request(
            pdu_type,
            [random_oid(rng) for _ in range(rng.randrange(0, 40))],
            request_id=rng.randrange(-(2**31), 2**31),
            first=rng.randrange(0, 10) if bulk else 0,
            second=rng.randrange(0, 100) if bulk else 0,
            community=bytes(rng.randrange(256) for _ in range(rng.choice([0, 6, 200]))),
        )

        assert agrees(octets)
        taken += 1

        for _ in range(15):
            mutated = bytearray(octets)

            for _ in range(rng.randrange(1, 4)):
                mutated[rng.randrange(len(mutated))] = rng.randrange(256)

            if rng.random() < 0.2:
                mutated = mutated[: rng.randrange(len(mutated))]

            if rng.random() < 0.1:
                mutated += b"\x00"

            try:
                ours = ber.decode_read_request(bytes(mutated))

            except ber.NotPlain:
                continue

            # what is taken here, pyasn1 takes as well, and reads alike
            assert ours == by_pyasn1(bytes(mutated)), bytes(mutated).hex()
            mutated_taken += 1

    assert taken == 600
    assert mutated_taken


def plain_get(var_bind_list=None, pdu_extra=b"", message_extra=b"", list_extra=b""):
    """A GET with the parts given, wrapped in lengths that fit them."""
    if var_bind_list is None:
        var_bind_list = ber.tlv(0x30, ber.encode_oid((1, 3, 6, 1)) + b"\x05\x00")

    pdu = ber.tlv(
        0xA0,
        ber.tlv(2, b"\x01")
        + ber.tlv(2, b"\x00")
        + ber.tlv(2, b"\x00")
        + ber.tlv(0x30, var_bind_list + list_extra)
        + pdu_extra,
    )

    return ber.tlv(
        0x30, ber.tlv(2, b"\x01") + ber.tlv(4, b"public") + pdu + message_extra
    )


# shapes that are not plain, each refused by pyasn1 as well
@pytest.mark.parametrize(
    "octets",
    [
        # an arc cut short
        plain_get(ber.tlv(0x30, bytes.fromhex("06022b81") + b"\x05\x00")),
        # something after the NULL
        plain_get(ber.tlv(0x30, bytes.fromhex("06012b") + b"\x05\x00\x05\x00")),
        # a NULL with contents
        plain_get(ber.tlv(0x30, bytes.fromhex("06012b") + b"\x05\x01\x00")),
        # an empty var-bind
        plain_get(b"\x30\x00"),
        # octets left over inside the var-bind list, the PDU, the message
        plain_get(list_extra=b"\x00"),
        plain_get(pdu_extra=b"\x05\x00"),
        plain_get(message_extra=b"\x05\x00"),
    ],
    ids=[
        "cut arc",
        "after the null",
        "null with contents",
        "empty var-bind",
        "left in the list",
        "left in the pdu",
        "left in the message",
    ],
)
def test_shapes_pyasn1_refuses_are_not_plain(octets):
    with pytest.raises(ber.NotPlain):
        ber.decode_read_request(octets)

    with pytest.raises(Exception):
        by_pyasn1(octets)


@pytest.mark.parametrize("pdu_type", READS)
def test_the_fast_path_builds_the_same_request_either_way(pdu_type, monkeypatch):
    from snmpsim import fastpath

    bulk = pdu_type == "GetBulkRequestPDU"
    octets = request(
        pdu_type,
        ["1.3.6.1.2.1.1.5.0", "1.3.6.1.4.1.99999.2.4294967295"],
        request_id=-7,
        first=2 if bulk else 0,
        second=9 if bulk else 0,
        community=b"c" * 40,
    )

    plain = fastpath.decode_request(octets, 1)

    # the same message through pyasn1 alone
    def not_plain(octets):
        raise ber.NotPlain

    monkeypatch.setattr(ber, "decode_read_request", not_plain)
    general = fastpath.decode_request(octets, 1)

    for field in ("version", "community", "kind", "pdu_type", "request_id"):
        assert getattr(plain, field) == getattr(general, field), field

    if bulk:
        assert (plain.non_repeaters, plain.max_repetitions) == (
            general.non_repeaters,
            general.max_repetitions,
        )

    assert len(plain.var_binds) == len(general.var_binds)

    for (oid, value), (their_oid, their_value) in zip(
        plain.var_binds, general.var_binds
    ):
        assert type(oid) is type(their_oid) and oid == their_oid
        assert repr(oid) == repr(their_oid)
        assert type(value) is type(their_value) and repr(value) == repr(their_value)
