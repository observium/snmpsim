"""SNMP requests made and responses read octet for octet, for the tests.

pysnmp's own client refuses an INTEGER outside the range of Integer32, which
a responder serves as the device sent it, and leaves the request to time
out; SNMPv3 requests here are noAuthNoPriv and reportable, which needs no
keys and leaves the scoped PDU in plain sight.
"""
import socket

from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp.proto import api
from pysnmp.proto import rfc1902
from pysnmp.proto.mpmod.rfc3412 import ScopedPDU
from pysnmp.proto.mpmod.rfc3412 import SNMPv3Message
from pysnmp.proto.secmod.rfc3414.service import UsmSecurityParameters

V1 = api.SNMP_VERSION_1
V2C = api.SNMP_VERSION_2C
V3 = 3

REQUEST_ID = 4242


def _var_binds(var_binds):
    """(OID, value) pairs; a bare OID asks with a NULL value."""
    return [
        (rfc1902.ObjectName(item), univ.Null(""))
        if isinstance(item, str)
        else (rfc1902.ObjectName(item[0]), item[1])
        for item in var_binds
    ]


def pdu(pdu_type, var_binds, repetitions=0, non_repeaters=0, version=V2C):
    proto = api.PROTOCOL_MODULES[version]

    request = getattr(proto, pdu_type)()

    if pdu_type == "GetBulkRequestPDU":
        proto.apiBulkPDU.set_defaults(request)
        proto.apiBulkPDU.set_max_repetitions(request, repetitions)
        proto.apiBulkPDU.set_non_repeaters(request, non_repeaters)

    else:
        proto.apiPDU.set_defaults(request)

    proto.apiPDU.set_request_id(request, REQUEST_ID)
    proto.apiPDU.set_varbinds(request, _var_binds(var_binds))

    return request


def message(version, pdu_type, var_binds, community, repetitions=0, non_repeaters=0):
    """An SNMPv1 or SNMPv2c request."""
    request = pdu(pdu_type, var_binds, repetitions, non_repeaters, version)

    proto = api.PROTOCOL_MODULES[version]

    msg = proto.Message()
    proto.apiMessage.set_defaults(msg)
    proto.apiMessage.set_community(msg, community)
    proto.apiMessage.set_pdu(msg, request)

    return encoder.encode(msg)


def v3_message(
    pdu_type, var_binds, engine_id, context, user, repetitions=0, non_repeaters=0
):
    """An SNMPv3 request, noAuthNoPriv, reportable."""
    scoped = ScopedPDU()
    scoped["contextEngineId"] = engine_id
    scoped["contextName"] = context

    request = pdu(pdu_type, var_binds, repetitions, non_repeaters)
    scoped["data"].setComponentByType(request.tagSet, request)

    security = UsmSecurityParameters()
    security["msgAuthoritativeEngineId"] = engine_id
    security["msgAuthoritativeEngineBoots"] = 0
    security["msgAuthoritativeEngineTime"] = 0
    security["msgUserName"] = user
    security["msgAuthenticationParameters"] = b""
    security["msgPrivacyParameters"] = b""

    msg = SNMPv3Message()
    msg["msgVersion"] = 3
    msg["msgGlobalData"]["msgID"] = 777
    msg["msgGlobalData"]["msgMaxSize"] = 65507
    msg["msgGlobalData"]["msgFlags"] = b"\x04"
    msg["msgGlobalData"]["msgSecurityModel"] = 3
    msg["msgSecurityParameters"] = encoder.encode(security)
    msg["msgData"]["plaintext"] = scoped

    return encoder.encode(msg)


def ask(port, request, timeout=3):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(request, ("127.0.0.1", port))

        try:
            return sock.recv(65535)

        except socket.timeout:
            return None


def items(octets):
    """The BER items one after the other in `octets`: (tag, contents, whole)."""
    offset = 0

    while offset < len(octets):
        tag = octets[offset]
        length = octets[offset + 1]
        start = offset + 2

        if length & 0x80:
            count = length & 0x7F
            length = int.from_bytes(octets[start : start + count], "big")
            start += count

        yield tag, octets[start : start + length], octets[offset : start + length]
        offset = start + length


def scoped_pdu(response):
    """The PDU of a response, SNMPv1, v2c or v3 (plaintext), and its tag."""
    ((_, message, _),) = items(response)
    parts = list(items(message))

    if parts[0][1] == b"\x03":
        # version, msgGlobalData, msgSecurityParameters, msgData
        _, _, _, (_, scoped, _) = parts
        _, _, (tag, contents, _) = list(items(scoped))

    else:
        # version, community, PDU
        _, _, (tag, contents, _) = parts

    return tag, contents


def request_id(response):
    """The request-id a response carries."""
    _, contents = scoped_pdu(response)
    (_, request_id, _), *_ = items(contents)

    return int.from_bytes(request_id, "big", signed=True)


def answer(response):
    """Error-status, error-index and the var-binds of a response.

    Read off the octets rather than decoded by pysnmp's message definition,
    which refuses an INTEGER outside the range of Integer32 - and such an
    integer is served as the device sent it. A var-bind is its OID and the
    whole of the value's encoding.
    """
    _, contents = scoped_pdu(response)
    _, (_, error_status, _), (_, error_index, _), (_, var_bind_list, _) = list(
        items(contents)
    )

    var_binds = []

    for _, var_bind, _ in items(var_bind_list):
        (_, _, oid), (_, _, value) = items(var_bind)
        oid, _ = decoder.decode(oid, asn1Spec=univ.ObjectIdentifier())
        var_binds.append((str(oid), value))

    return (
        int.from_bytes(error_status, "big"),
        int.from_bytes(error_index, "big"),
        var_binds,
    )


def engine_id(port):
    """The engine ID a responder reports to an SNMPv3 discovery."""
    report = ask(port, v3_message("GetRequestPDU", [], b"", b"", ""))

    assert report is not None

    ((_, message, _),) = items(report)
    _, _, _, (_, scoped, _) = list(items(message))
    (_, context_engine_id, _), _, (tag, _, _) = list(items(scoped))

    assert tag == 0xA8  # a Report-PDU

    return context_engine_id
