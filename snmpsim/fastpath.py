#
# This file is part of snmpsim software.
#
# License: https://www.pysnmp.com/snmpsim/license.html
#
"""SNMPv1 and SNMPv2c answered by the simulator itself.

`snmpsim-command-responder` hands every message to pysnmp's SNMPv3 engine
unless `--v1-v2c-path=fast` is given. With it, the dispatcher's routing
callback reads the version off a message, and an SNMPv1 or SNMPv2c message
comes here instead: no message processing model, no security model, no
access control, which is most of what an answer costs on the engine path.
SNMPv3 keeps going through the engine.

What goes back is what the engine path would send, octet for octet: the same
recording, the same values, the same error-status and error-index, the same
SNMPv1 translation (pysnmp's own, RFC 3584), the same GETBULK cut, and the
same call context for variation modules and activity reports. One thing is
done as the documentation says rather than as the engine path does: a
recording is chosen by the community, the transport the request came in by
and the manager's address, the most specific one first
(`datafile.probe_context`).

pyasn1 is touched in two functions only, `decode_request()` and
`encode_response()`; everything between them works on what they return.
"""
import collections
import hashlib

from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pysnmp import error as pysnmp_error
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.carrier.asyncio.dgram import udp6
from pysnmp.proto import api
from pysnmp.proto import error as proto_error
from pysnmp.proto import rfc1902
from pysnmp.proto.api import v2c
from pysnmp.proto.proxy import rfc2576
from pysnmp.smi import error as smi_error

from snmpsim import datafile
from snmpsim import endpoints
from snmpsim import log
from snmpsim import responding
from snmpsim import utils
from snmpsim.error import NoDataNotification

# receive id of the fast path at the transport dispatcher
RECV_ID = "snmpsim-v1-v2c-fast-path"

# the community of the data index, a context of its own on the engine path
INDEX_COMMUNITY = "index"

# what a scopedPDU wraps around a var-bind list, as the engine path counts
SCOPED_PDU_ENVELOPE_SIZE = 64

# the community model's own share of a message (pysnmp, rfc2576 secmod)
COMMUNITY_MODEL_ENVELOPE_SIZE = 128

GET, NEXT, BULK, SET = "get", "next", "bulk", "set"

PDU_KINDS = {
    v2c.GetRequestPDU.tagSet: GET,
    v2c.GetNextRequestPDU.tagSet: NEXT,
    v2c.GetBulkRequestPDU.tagSet: BULK,
    v2c.SetRequestPDU.tagSet: SET,
}


def message_version(whole_msg):
    """Return the version a message says it is, or None.

    Reads the BER header of the message itself, a SEQUENCE starting with an
    INTEGER, rather than decoding anything: this runs for every datagram.
    """
    try:
        if whole_msg[0] != 0x30:
            return None

        length = whole_msg[1]
        offset = 2

        if length & 0x80:
            offset += length & 0x7F

        if whole_msg[offset] != 0x02 or whole_msg[offset + 1] != 1:
            return None

        return whole_msg[offset + 2]

    except IndexError:
        return None


class Request:
    """A decoded SNMPv1/v2c request: plain values and what encoding needs."""

    __slots__ = (
        "version",
        "community",
        "kind",
        "pdu_type",
        "var_binds",
        "non_repeaters",
        "max_repetitions",
        "_message",
        "_v2_pdu",
        "_v1_pdu",
    )


def decode_request(whole_msg, version):
    """Decode an SNMPv1/v2c request, or return None for anything else.

    The var-binds come as the engine path sees them: an SNMPv1 PDU is
    turned into its SNMPv2 counterpart first, as pysnmp does.
    """
    proto = api.PROTOCOL_MODULES[version]

    message, _ = decoder.decode(whole_msg, asn1Spec=proto.Message())

    pdu = proto.apiMessage.get_pdu(message)

    request = Request()
    request.version = version
    request.community = bytes(proto.apiMessage.get_community(message))
    request._message = message
    request.pdu_type = pdu.__class__.__name__

    if version == api.SNMP_VERSION_1:
        request._v1_pdu = pdu
        pdu = rfc2576.v1_to_v2(pdu)

    else:
        request._v1_pdu = None

    request.kind = PDU_KINDS.get(pdu.tagSet)

    if request.kind is None:
        return None

    request._v2_pdu = pdu
    request.var_binds = list(v2c.apiPDU.get_varbinds(pdu))

    if request.kind == BULK:
        request.non_repeaters = int(v2c.apiBulkPDU.get_non_repeaters(pdu))
        request.max_repetitions = int(v2c.apiBulkPDU.get_max_repetitions(pdu))

    return request


def encode_response(request, error_status, error_index, var_binds):
    """Encode the response to `request`.

    An SNMPv1 response is made out of the SNMPv2 one by pysnmp's own
    translation; for GETNEXT it raises `StatusInformation` naming a Counter64
    an SNMPv1 manager cannot be sent, to be read past, as the engine path
    does.
    """
    pdu = v2c.apiPDU.get_response(request._v2_pdu)

    v2c.apiPDU.set_error_status(pdu, error_status)
    v2c.apiPDU.set_error_index(pdu, error_index)
    v2c.apiPDU.set_varbinds(pdu, var_binds)

    if request._v1_pdu is not None:
        pdu = rfc2576.v2_to_v1(pdu, request._v1_pdu)

    proto = api.PROTOCOL_MODULES[request.version]

    message = proto.apiMessage.get_response(request._message)
    proto.apiMessage.set_pdu(message, pdu)

    return encoder.encode(message)


class Endpoint:
    """What the fast path needs of one endpoint and the engine behind it."""

    __slots__ = (
        "snmp_engine",
        "snmp_context",
        "max_var_binds",
        "max_message_size",
        "max_size_response_scoped_pdu",
        "transport_protocol",
        "local_address",
        "context_name_syntax",
        "security_name_syntax",
    )


class FastPath:
    """Answers SNMPv1/v2c on the endpoints added to it."""

    def __init__(self, selections=4096):
        self._endpoints = {}
        self._selections = collections.OrderedDict()
        self._max_selections = selections

    def add_endpoint(
        self,
        transport_domain,
        snmp_engine,
        snmp_context,
        max_var_binds,
        max_message_size,
    ):
        endpoint = Endpoint()
        endpoint.snmp_engine = snmp_engine
        endpoint.snmp_context = snmp_context
        endpoint.max_var_binds = max_var_binds
        endpoint.max_message_size = max_message_size

        (engine_max_message_size,) = snmp_engine.get_mib_builder().import_symbols(
            "__SNMP-FRAMEWORK-MIB", "snmpEngineMaxMessageSize"
        )
        endpoint.max_size_response_scoped_pdu = (
            int(engine_max_message_size.syntax) - COMMUNITY_MODEL_ENVELOPE_SIZE
        )

        # the engine path hands on the names as the community table has them
        context_name, security_name = snmp_engine.get_mib_builder().import_symbols(
            "SNMP-COMMUNITY-MIB",
            "snmpCommunityContextName",
            "snmpCommunitySecurityName",
        )
        endpoint.context_name_syntax = context_name.syntax
        endpoint.security_name_syntax = security_name.syntax

        domain = tuple(transport_domain)

        if domain[: len(udp.DOMAIN_NAME)] == tuple(udp.DOMAIN_NAME):
            endpoint.transport_protocol = "udpv4"

        elif domain[: len(udp6.DOMAIN_NAME)] == tuple(udp6.DOMAIN_NAME):
            endpoint.transport_protocol = "udpv6"

        else:
            endpoint.transport_protocol = "unknown"

        endpoint.local_address = endpoints.local_address(transport_domain)

        self._endpoints[domain] = endpoint

    def forget_selections(self):
        """Drop the recordings chosen so far: what is served has changed."""
        self._selections.clear()

    # transport dispatcher callbacks

    def route(self, transport_domain, transport_address, whole_msg):
        """Return the receive id for a message: ours or the engine's.

        Never raises: whatever cannot be read goes to the engine, which
        counts and drops it as it always did.
        """
        try:
            endpoint = self._endpoints.get(tuple(transport_domain))

            if endpoint is not None:
                version = message_version(whole_msg)

                # the engine of the endpoint must serve that version, which
                # --v1-only and --v2c-only take away
                if version in (0, 1) and (
                    version in endpoint.snmp_engine.message_processing_subsystems
                ):
                    return RECV_ID

        except Exception:
            pass

        return transport_domain

    def receive(self, transport_dispatcher, transport_domain, transport_address, msg):
        """Answer one SNMPv1/v2c message, or drop it."""
        endpoint = self._endpoints[tuple(transport_domain)]

        try:
            response = self.answer(endpoint, transport_domain, transport_address, msg)

        except Exception as exc:
            log.error(
                "SNMPv1/v2c request from %s dropped: %s" % (transport_address, exc)
            )
            return

        if response is not None:
            transport_dispatcher.send_message(
                response, transport_domain, transport_address
            )

    # answering

    def select(self, endpoint, community, transport_domain, transport_address):
        """Return the controller and the context name serving a request.

        The candidates are the documented ones, most specific first; a
        candidate over 32 octets is registered by its md5 only, as on the
        engine path. None when nothing serves the community.
        """
        key = (tuple(transport_domain), transport_address[0], community)

        try:
            selected = self._selections[key]

        except KeyError:
            pass

        else:
            self._selections.move_to_end(key)
            return selected

        selected = None

        for candidate in datafile.probe_context(
            transport_domain,
            transport_address,
            datafile.SELF_LABEL,
            rfc1902.OctetString(community),
        ):
            name = candidate

            if len(candidate) > 32:
                name = hashlib.md5(candidate).hexdigest()

            try:
                controller = endpoint.snmp_context.get_mib_instrum(name)

            except pysnmp_error.PySnmpError:
                continue

            if candidate == INDEX_COMMUNITY.encode():
                context_name = INDEX_COMMUNITY

            else:
                context_name = hashlib.md5(candidate).hexdigest()

            selected = controller, context_name, candidate
            break

        self._selections[key] = selected

        if len(self._selections) > self._max_selections:
            self._selections.popitem(last=False)

        return selected

    def call_context(
        self, endpoint, request, transport_domain, transport_address, context_name
    ):
        """What the engine path tells a variation module about a request."""
        security_name = hashlib.md5(request.community).hexdigest()

        if request.community == INDEX_COMMUNITY.encode():
            security_name = INDEX_COMMUNITY

        return {
            "snmpEngine": endpoint.snmp_engine,
            "transportDomain": rfc1902.ObjectIdentifier(transport_domain),
            "transportAddress": transport_address,
            "transportEndpoint": endpoint.local_address,
            "transportProtocol": endpoint.transport_protocol,
            "securityModel": request.version + 1,
            "securityName": endpoint.security_name_syntax.clone(security_name),
            "securityLevel": 1,
            "contextEngineId": endpoint.snmp_engine.snmpEngineID,
            "contextName": endpoint.context_name_syntax.clone(context_name),
            "pduType": request.pdu_type,
        }

    def answer(self, endpoint, transport_domain, transport_address, whole_msg):
        """Return the encoded response to a message, or None to drop it."""
        version = message_version(whole_msg)

        # what does not decode is dropped as the engine drops it, with no
        # error logged: scanners send the odd datagram all the time
        try:
            request = decode_request(whole_msg, version)

        except Exception as exc:
            log.info(
                "Undecodable SNMPv1/v2c message from %s dropped: %s"
                % (transport_address, exc)
            )
            return None

        if request is None:
            return None

        selected = self.select(
            endpoint, request.community, transport_domain, transport_address
        )

        # an unknown community is dropped as the engine drops it, which
        # logs nothing either: it may well be somebody's scanner
        if selected is None:
            log.debug(
                "No data file selected for transport ID %s, source address %s, "
                'community name "%s"'
                % (
                    rfc1902.ObjectIdentifier(transport_domain),
                    transport_address[0],
                    request.community.decode("iso-8859-1"),
                )
            )
            return None

        controller, context_name, _ = selected

        context = {
            "callContext": self.call_context(
                endpoint, request, transport_domain, transport_address, context_name
            )
        }

        offset = 0
        takes = []

        try:
            if request.kind == GET:
                var_binds = controller.read_variables(*request.var_binds, **context)

            elif request.kind == SET:
                try:
                    var_binds = controller.write_variables(
                        *request.var_binds, **context
                    )

                # a recording that does not hold the variable cannot have it
                # written (RFC 3416, 4.2.5), as pysnmp answers
                except (
                    smi_error.NoSuchObjectError,
                    smi_error.NoSuchInstanceError,
                ) as exc:
                    error = smi_error.NotWritableError()
                    error.update(exc)
                    raise error

            elif request.kind == NEXT:
                return self.answer_next(controller, request, context)

            else:
                var_binds = self.read_bulk(
                    endpoint, controller, request, context_name, context, takes
                )

                if not var_binds:
                    raise smi_error.SmiError()

        except NoDataNotification:
            return None

        except smi_error.SmiError as exc:
            if request.kind == BULK and len(takes) > 1:
                # the non-repeaters are read in one take, the repetitions in
                # those that follow (RFC 3416, 4.2.3)
                offset = min(max(request.non_repeaters, 0), len(request.var_binds))

            return encode_response(
                request,
                *responding.error_response(exc, request.var_binds, offset),
            )

        return encode_response(request, 0, 0, var_binds)

    def answer_next(self, controller, request, context):
        """GETNEXT, read past a Counter64 for an SNMPv1 manager as pysnmp does."""
        var_binds = list(request.var_binds)

        try:
            while True:
                rsp_var_binds = controller.read_next_variables(*var_binds, **context)

                try:
                    return encode_response(request, 0, 0, rsp_var_binds)

                except proto_error.StatusInformation as exc:
                    idx = exc["idx"]
                    var_binds[idx] = (rsp_var_binds[idx][0], var_binds[idx][1])

        except NoDataNotification:
            return None

        except smi_error.SmiError as exc:
            return encode_response(
                request, *responding.error_response(exc, request.var_binds)
            )

    def read_bulk(self, endpoint, controller, request, context_name, context, takes):
        """The var-binds of a GETBULK response, cut as the engine path cuts."""
        max_response_size = endpoint.max_message_size - utils.MESSAGE_ENVELOPE_SIZE

        max_response_size = min(
            max_response_size,
            endpoint.max_size_response_scoped_pdu - SCOPED_PDU_ENVELOPE_SIZE,
        )

        max_response_size -= len(context_name)

        def read_next_vars(*var_binds):
            takes.append(None)
            return controller.read_next_variables(*var_binds, **context)

        return utils.get_bulk_var_binds(
            read_next_vars,
            request.var_binds,
            request.non_repeaters,
            request.max_repetitions,
            endpoint.max_var_binds,
            max_response_size,
        )
