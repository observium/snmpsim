#
# This file is part of snmpsim software.
#
# License: https://www.pysnmp.com/snmpsim/license.html
#
"""BER encoding of what an SNMP response carries, without building it in pyasn1.

pyasn1 builds a tree of objects for a message and walks it to encode it,
which is most of what an answer to a GETBULK costs. The values served are
few kinds: an INTEGER, an OCTET STRING, an OBJECT IDENTIFIER and their SNMP
cousins. They are encoded here straight from what they hold, to the octets
pyasn1 makes of them (tests hold the two to each other); a value of any
other kind, or one that is not a value, is handed to pyasn1.
"""
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp.proto import rfc1902
from pysnmp.proto import rfc1905
from pysnmp.proto.api import v2c

# error-status of SNMPv2 by name (RFC 3416)
ERROR_STATUS = dict(v2c.GetResponsePDU().componentType.getTypeByPosition(1).namedValues)

INTEGER, OCTET_STRING, NULL, OID, SEQUENCE = 0x02, 0x04, 0x05, 0x06, 0x30

GET_RESPONSE_PDU = 0xA2

# the tag byte of each kind of value, and how its contents are made
_INTEGER_KINDS = {
    univ.Integer.tagSet: INTEGER,
    rfc1902.Counter32.tagSet: 0x41,
    rfc1902.Gauge32.tagSet: 0x42,
    rfc1902.TimeTicks.tagSet: 0x43,
    rfc1902.Counter64.tagSet: 0x46,
}

_OCTETS_KINDS = {
    univ.OctetString.tagSet: OCTET_STRING,
    rfc1902.IpAddress.tagSet: 0x40,
    rfc1902.Opaque.tagSet: 0x44,
}

# NULL, and the exceptions: NULL under a context tag of their own
_EMPTY_KINDS = {
    univ.Null.tagSet: NULL,
    rfc1905.NoSuchObject.tagSet: 0x80,
    rfc1905.NoSuchInstance.tagSet: 0x81,
    rfc1905.EndOfMibView.tagSet: 0x82,
}


def length(size):
    """The length octets of contents `size` octets long, in the shortest form."""
    if size < 0x80:
        return bytes((size,))

    octets = size.to_bytes((size.bit_length() + 7) // 8, "big")

    return bytes((0x80 | len(octets),)) + octets


def tlv(tag, contents):
    return bytes((tag,)) + length(len(contents)) + contents


def integer_contents(number):
    """Two's complement of a number, as many octets long as pyasn1 makes it.

    That is the shortest form but for a negative power of two, which takes
    an octet more than it needs (-128 is ff 80, not 80). Decoders take
    either; the engine path sends pyasn1's, and so is it sent here.
    """
    return number.to_bytes(number.bit_length() // 8 + 1, "big", signed=True)


def oid_contents(arcs):
    """The sub-identifiers of an OID, the first two arcs sharing the first."""
    first = arcs[0] * 40 + arcs[1]
    contents = bytearray()

    for arc in (first,) + tuple(arcs[2:]):
        if arc < 0x80:
            contents.append(arc)
            continue

        septets = []

        while arc:
            septets.append(arc & 0x7F)
            arc >>= 7

        septets.reverse()
        contents.extend(septet | 0x80 for septet in septets[:-1])
        contents.append(septets[-1])

    return bytes(contents)


def encode_oid(oid):
    """The BER encoding of an OBJECT IDENTIFIER given as a value or arcs."""
    arcs = tuple(oid)

    # pyasn1 refuses what BER cannot carry, a single arc for one
    if len(arcs) < 2 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] > 39):
        return encoder.encode(univ.ObjectIdentifier(arcs))

    return tlv(OID, oid_contents(arcs))


def encode_value(value):
    """The BER encoding of an SNMP value, as pyasn1 makes it."""
    tag_set = value.tagSet

    if value.isValue:
        tag = _INTEGER_KINDS.get(tag_set)

        if tag is not None:
            return tlv(tag, integer_contents(int(value)))

        tag = _OCTETS_KINDS.get(tag_set)

        if tag is not None:
            return tlv(tag, value.asOctets())

        tag = _EMPTY_KINDS.get(tag_set)

        if tag is not None:
            return bytes((tag, 0))

        if tag_set == univ.ObjectIdentifier.tagSet:
            return encode_oid(value)

    return encoder.encode(value)


def var_bind_parts(name, value):
    """The encodings of a var-bind's name and value."""
    return encode_oid(name), encode_value(value)


def var_bind(parts):
    """A var-bind SEQUENCE out of the encodings of its name and value."""
    return tlv(SEQUENCE, parts[0] + parts[1])


def response(version, community, request_id, error_status, error_index, var_binds):
    """A whole SNMPv1/v2c Response message.

    `var_binds` are encoded var-bind SEQUENCEs; `error_status` is a number
    or the name RFC 3416 gives it.
    """
    if isinstance(error_status, str):
        error_status = ERROR_STATUS[error_status]

    pdu = tlv(
        GET_RESPONSE_PDU,
        tlv(INTEGER, integer_contents(int(request_id)))
        + tlv(INTEGER, integer_contents(int(error_status)))
        + tlv(INTEGER, integer_contents(int(error_index)))
        + tlv(SEQUENCE, b"".join(var_binds)),
    )

    return tlv(
        SEQUENCE,
        tlv(INTEGER, integer_contents(int(version)))
        + tlv(OCTET_STRING, community)
        + pdu,
    )


# Decoding of requests.
#
# Only the plain shape of an SNMPv2c read is taken here: GET, GETNEXT or
# GETBULK, every length in its shortest definite form of at most four octets,
# one-octet tags, a NULL for every value, nothing left over. Anything else -
# SNMPv1, a SET, an indefinite length, a constructed string, an odd tag, a
# value out of the range pysnmp's PDU definition allows - raises NotPlain and
# is left to pyasn1, with its own checks and limits. Whatever is taken here
# decodes to what pyasn1 makes of it, which tests check on pyasn1's own
# decoder vectors and on mutated messages. The work is linear in the size of
# the message.

# the longest arc pyasn1 decodes: 20 continuation octets and the last one,
# 21 septets or 147 bits
MAX_ARC_CONTINUATIONS = 20


class NotPlain(Exception):
    """Not the plain shape this decoder takes: leave it to pyasn1."""


READ_PDUS = {
    0xA0: "GetRequestPDU",
    0xA1: "GetNextRequestPDU",
    0xA5: "GetBulkRequestPDU",
}


def _item(octets, offset, tag):
    """Return where the contents of the item of `tag` at `offset` start and end."""
    if octets[offset] != tag:
        raise NotPlain

    size = octets[offset + 1]
    offset += 2

    if size & 0x80:
        count = size & 0x7F

        # indefinite (0x80) and needlessly long forms are pyasn1's business
        if not count or count > 4 or octets[offset] == 0:
            raise NotPlain

        size = int.from_bytes(octets[offset : offset + count], "big")

        if size < 0x80:
            raise NotPlain

        offset += count

    end = offset + size

    if end > len(octets):
        raise NotPlain

    return offset, end


def _integer(octets, offset):
    start, end = _item(octets, offset, 0x02)

    if start == end:
        raise NotPlain

    return int.from_bytes(octets[start:end], "big", signed=True), end


def _oid(octets, start, end):
    if start == end:
        raise NotPlain

    arcs = []
    arc = 0
    fresh = True
    continuations = 0

    for octet in octets[start:end]:
        # a sub-identifier may not start with a needless 0x80
        if fresh and octet == 0x80:
            raise NotPlain

        arc = (arc << 7) | (octet & 0x7F)
        fresh = not octet & 0x80

        if fresh:
            arcs.append(arc)
            arc = 0
            continuations = 0

        # pyasn1's limit on an arc since 0.6.2, past which it refuses one
        # rather than let it grow without end
        else:
            continuations += 1

            if continuations > MAX_ARC_CONTINUATIONS:
                raise NotPlain

    if not fresh:
        raise NotPlain

    first = arcs[0]

    if first < 40:
        head = (0, first)
    elif first < 80:
        head = (1, first - 40)
    else:
        head = (2, first - 80)

    return head + tuple(arcs[1:])


def decode_read_request(octets):
    try:
        return _decode_read_request(bytes(octets))

    # cut short: whatever it is, it is not the plain shape
    except IndexError:
        raise NotPlain


def _decode_read_request(octets):
    """Decode an SNMPv2c GET, GETNEXT or GETBULK in its plain shape.

    Returns the community, the PDU's name, request-id, the two integers that
    follow it (error-status and error-index, or non-repeaters and
    max-repetitions) and the OIDs asked for, each as arcs. Raises NotPlain
    for anything else: another version or PDU, a value other than NULL, a
    length in a form pyasn1 would have to judge, octets left over.
    """
    start, end = _item(octets, 0, 0x30)

    if end != len(octets):
        raise NotPlain

    version, offset = _integer(octets, start)

    if version != 1:
        raise NotPlain

    community_start, offset = _item(octets, offset, 0x04)
    community = octets[community_start:offset]

    pdu_tag = octets[offset]
    pdu_type = READ_PDUS.get(pdu_tag)

    if pdu_type is None:
        raise NotPlain

    pdu_start, pdu_end = _item(octets, offset, pdu_tag)

    if pdu_end != end:
        raise NotPlain

    request_id, offset = _integer(octets, pdu_start)
    first, offset = _integer(octets, offset)
    second, offset = _integer(octets, offset)

    # the ranges pysnmp's PDU definition holds them to: request-id is an
    # Integer32; error-index, non-repeaters and max-repetitions are
    # 0..max-bindings; error-status is free
    if not -(2**31) <= request_id < 2**31 or not 0 <= second < 2**31:
        raise NotPlain

    if pdu_type == "GetBulkRequestPDU" and not 0 <= first < 2**31:
        raise NotPlain

    list_start, list_end = _item(octets, offset, 0x30)

    if list_end != pdu_end:
        raise NotPlain

    oids = []
    offset = list_start

    while offset < list_end:
        bind_start, bind_end = _item(octets, offset, 0x30)
        oid_start, oid_end = _item(octets, bind_start, 0x06)

        # the value of a read is NULL, and nothing comes after it
        if octets[oid_end : oid_end + 2] != b"\x05\x00" or oid_end + 2 != bind_end:
            raise NotPlain

        oids.append(_oid(octets, oid_start, oid_end))
        offset = bind_end

    if offset != list_end:
        raise NotPlain

    return community, pdu_type, request_id, first, second, oids
