"""The simulator's BER encoding comes out as pyasn1's, octet for octet."""
import random

import pytest
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp.proto import api
from pysnmp.proto import rfc1902
from pysnmp.proto import rfc1905

from snmpsim import ber
from snmpsim import utils
from snmpsim.grammar import unconstrained

INTEGER_EDGES = [
    0,
    1,
    -1,
    127,
    128,
    255,
    256,
    -127,
    -128,
    -129,
    -255,
    -256,
    -257,
    32767,
    32768,
    -32768,
    -32769,
    65535,
    65536,
    2**31 - 1,
    2**31,
    -(2**31),
    -(2**31) - 1,
    2**32 - 1,
    2**32,
    2**63 - 1,
    2**63,
    -(2**63),
    2**64 - 1,
]

UNSIGNED_EDGES = [n for n in INTEGER_EDGES if 0 <= n < 2**32]

OIDS = [
    (1, 3, 6, 1, 2, 1, 1, 5, 0),
    (0, 0),
    (0, 39),
    (1, 39),
    (2, 0),
    (2, 39),
    (2, 40),
    (2, 999),
    (2, 2**32),
    (1, 3, 127, 128, 129, 16383, 16384, 2**21 - 1, 2**21, 2**28, 2**32 - 1),
    (1, 3, 6, 1, 4, 1, 2**64),
    tuple([1, 3] + [6] * 126),
]


def values():
    """Every kind of value a recording serves, at its edges."""
    for number in INTEGER_EDGES:
        yield unconstrained.Integer32(number)

    for number in INTEGER_EDGES:
        if -(2**31) <= number < 2**31:
            yield rfc1902.Integer32(number)

    for kind in (
        unconstrained.Counter32,
        unconstrained.Gauge32,
        unconstrained.TimeTicks,
        rfc1902.Counter32,
        rfc1902.Gauge32,
        rfc1902.TimeTicks,
        rfc1902.Unsigned32,
    ):
        for number in UNSIGNED_EDGES:
            yield kind(number)

    for number in [n for n in INTEGER_EDGES if 0 <= n < 2**64]:
        yield rfc1902.Counter64(number)

    for octets in (
        b"",
        b"a",
        b"\x00\xff",
        b"x" * 127,
        b"x" * 128,
        b"x" * 255,
        b"x" * 256,
        b"x" * 65535,
        "Привет".encode(),
    ):
        yield rfc1902.OctetString(octets)
        yield rfc1902.Opaque(octets)

    # past what SNMP allows a string, which only pyasn1's own type takes
    yield univ.OctetString(b"x" * 70000)

    for address in ("0.0.0.0", "192.0.2.1", "255.255.255.255"):
        yield rfc1902.IpAddress(address)

    for oid in OIDS:
        yield rfc1902.ObjectName(oid)

    yield univ.Null("")
    yield rfc1905.NoSuchObject("")
    yield rfc1905.NoSuchInstance("")
    yield rfc1905.EndOfMibView("")
    yield rfc1902.Bits("\x80")


def short(value):
    text = value.prettyPrint()
    return f"{value.__class__.__name__}:{text[:24]}{'...' if len(text) > 24 else ''}"


@pytest.mark.parametrize("value", list(values()), ids=short)
def test_a_value_encodes_as_pyasn1_encodes_it(value):
    assert ber.encode_value(value) == encoder.encode(value)


def test_random_integers_encode_as_pyasn1_encodes_them():
    rng = random.Random(1979)

    for _ in range(20000):
        bits = rng.randrange(0, 66)
        number = rng.randrange(-(2**bits), 2**bits) if bits else 0
        assert ber.encode_value(unconstrained.Integer32(number)) == encoder.encode(
            unconstrained.Integer32(number)
        ), number


def test_random_oids_encode_as_pyasn1_encodes_them():
    rng = random.Random(2010)

    for _ in range(5000):
        first = rng.randrange(0, 3)
        second = rng.randrange(0, 40 if first < 2 else 2**33)
        arcs = (first, second) + tuple(
            rng.choice([rng.randrange(0, 128), rng.randrange(0, 2**35)])
            for _ in range(rng.randrange(0, 20))
        )
        assert ber.encode_oid(arcs) == encoder.encode(univ.ObjectIdentifier(arcs)), arcs


def test_lengths_take_the_shortest_form():
    for size in (0, 1, 127, 128, 255, 256, 65535, 65536):
        assert ber.tlv(0x04, b"x" * size) == encoder.encode(
            univ.OctetString(b"x" * size)
        )


def test_what_is_not_a_value_is_left_to_pyasn1():
    with pytest.raises(Exception):
        ber.encode_value(univ.Integer())


def test_a_var_bind_size_is_what_it_was():
    for value in values():
        name = rfc1902.ObjectName("1.3.6.1.2.1.1.5.0")
        assert (
            utils.var_bind_size((name, value))
            == len(encoder.encode(name)) + len(encoder.encode(value)) + 4
        )


def pysnmp_response(community, request_id, error_status, error_index, var_binds):
    proto = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]

    pdu = proto.GetResponsePDU()
    proto.apiPDU.set_defaults(pdu)
    proto.apiPDU.set_request_id(pdu, request_id)
    proto.apiPDU.set_error_status(pdu, error_status)
    proto.apiPDU.set_error_index(pdu, error_index)
    proto.apiPDU.set_varbinds(pdu, var_binds)

    msg = proto.Message()
    proto.apiMessage.set_defaults(msg)
    proto.apiMessage.set_community(msg, community)
    proto.apiMessage.set_pdu(msg, pdu)

    return encoder.encode(msg)


@pytest.mark.parametrize(
    "community, request_id, error_status, error_index",
    [
        (b"public", 4242, 0, 0),
        (b"public", -1, 0, 0),
        (b"public", -(2**31), "noSuchName", 2),
        (b"public", 2**31 - 1, "tooBig", 0),
        (b"c" * 200, 7, "genErr", 1),
        (b"", 0, 0, 0),
    ],
)
def test_a_response_encodes_as_pysnmp_encodes_it(
    community, request_id, error_status, error_index
):
    rng = random.Random(request_id)

    candidates = list(values())

    for count in (0, 1, 25, 64):
        var_binds = [
            (
                rfc1902.ObjectName((1, 3, 6, 1, 4, 1, 99999, n)),
                rng.choice(candidates),
            )
            for n in range(count)
        ]

        ours = ber.response(
            1,
            community,
            request_id,
            error_status,
            error_index,
            [ber.var_bind(ber.var_bind_parts(*var_bind)) for var_bind in var_binds],
        )

        assert ours == pysnmp_response(
            community, request_id, error_status, error_index, var_binds
        )


# Vectors from pyasn1's own encoder tests, tests/codec/ber/test_encoder.py
# (pyasn1, Copyright (c) 2005-2020, Ilya Etingof, BSD 2-Clause): what pyasn1
# holds itself to for the types encoded here.
PYASN1_ENCODER_VECTORS = [
    (univ.Integer(12), bytes((2, 1, 12))),
    (univ.Integer(-12), bytes((2, 1, 244))),
    (univ.Integer(0), bytes((2, 1, 0))),
    (univ.Integer(-1), bytes((2, 1, 255))),
    (
        univ.Integer(0xFFFFFFFFFFFFFFFF),
        bytes((2, 9, 0, 255, 255, 255, 255, 255, 255, 255, 255)),
    ),
    (univ.Integer(-0xFFFFFFFFFFFFFFFF), bytes((2, 9, 255, 0, 0, 0, 0, 0, 0, 0, 1))),
    (
        univ.OctetString("Quick brown fox"),
        bytes(
            (
                4,
                15,
                81,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                32,
                102,
                111,
                120,
            )
        ),
    ),
    (univ.Null(""), bytes((5, 0))),
    (
        univ.ObjectIdentifier((1, 3, 6, 0, 0xFFFFE)),
        bytes((6, 6, 43, 6, 0, 191, 255, 126)),
    ),
    (univ.ObjectIdentifier((0, 39)), bytes((6, 1, 39))),
    (univ.ObjectIdentifier((1, 39)), bytes((6, 1, 79))),
    (univ.ObjectIdentifier((2, 40)), bytes((6, 1, 120))),
    (
        univ.ObjectIdentifier((2, 0xFFFFFFFF)),
        bytes((6, 5, 0x90, 0x80, 0x80, 0x80, 0x4F)),
    ),
    (univ.ObjectIdentifier((2, 47)), bytes((6, 1, 0x7F))),
    (univ.ObjectIdentifier((2, 48)), bytes((6, 2, 0x81, 0x00))),
    (univ.ObjectIdentifier((2, 100, 3)), bytes((6, 3, 0x81, 0x34, 0x03))),
    (univ.ObjectIdentifier((2, 560)), bytes((6, 2, 133, 0))),
    (univ.ObjectIdentifier((2, 16843570)), bytes((6, 4, 0x88, 0x84, 0x87, 0x02))),
    (univ.ObjectIdentifier((2, 5)), bytes((6, 1, 85))),
    (
        univ.ObjectIdentifier((2, 18446744073709551535184467440737095)),
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
    ),
    (
        univ.ObjectIdentifier((2, 999, 18446744073709551535184467440737095)),
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
    ),
    (
        univ.ObjectIdentifier((1, 3) + (1,) * 4096),
        bytes([0x06, 0x82, 0x10, 0x01, 0x2B]) + bytes([0x01] * 4096),
    ),
]


@pytest.mark.parametrize(
    "value, octets",
    PYASN1_ENCODER_VECTORS,
    ids=lambda x: short(x)[:30] if hasattr(x, "tagSet") else "",
)
def test_pyasn1_encoder_vectors(value, octets):
    assert ber.encode_value(value) == octets


# the OIDs pyasn1's encoder tests have it refuse: so does this encoding, by
# leaving them to pyasn1
@pytest.mark.parametrize("arcs", [(3, 1, 2), (0,), (0, 40), (1, 40)])
def test_oids_pyasn1_refuses_are_refused(arcs):
    with pytest.raises(Exception):
        ber.encode_oid(arcs)
