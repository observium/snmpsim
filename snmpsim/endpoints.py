#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
# SNMP transport endpoints initialization harness
#
import socket

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.carrier.asyncio.dgram import udp6

from snmpsim.error import SnmpsimError

LOCAL_ADDRESSES = {}
"""Local address every transport domain listens on.

pysnmp 7 does not attach the local address to an incoming datagram, and the
activity reporters index their counters by the endpoint which received the
request, so the responder records here what it opened.
"""


def remember_local_address(transport_domain, address):
    LOCAL_ADDRESSES[tuple(transport_domain)] = tuple(address)


def local_address(transport_domain):
    """Printable "host:port" the given transport domain listens on."""
    address = LOCAL_ADDRESSES.get(tuple(transport_domain))

    if not address:
        return "unknown"

    host, port = address

    # IPv6 literals carry colons of their own
    if ":" in str(host):
        return "[%s]:%s" % (host, port)

    return "%s:%s" % (host, port)


class TransportEndpointsBase:
    def __init__(self):
        self.__endpoint = None

    def add(self, addr):
        self.__endpoint = self._addEndpoint(addr)
        return self

    def _addEndpoint(self, addr):
        raise NotImplementedError()

    def __len__(self):
        return len(self.__endpoint)

    def __getitem__(self, i):
        return self.__endpoint[i]


class IPv4TransportEndpoints(TransportEndpointsBase):
    def _addEndpoint(self, addr):
        f = lambda h, p=161: (h, int(p))

        try:
            h, p = f(*addr.split(":"))

        except Exception:
            raise SnmpsimError("improper IPv4/UDP endpoint %s" % addr)

        return udp.UdpTransport().open_server_mode((h, p)), addr, (h, p)


class IPv6TransportEndpoints(TransportEndpointsBase):
    def _addEndpoint(self, addr):
        if not udp6:
            raise SnmpsimError("This system does not support UDP/IP6")

        if addr.find("]:") != -1 and addr[0] == "[":
            h, p = addr.split("]:")

            try:
                h, p = h[1:], int(p)

            except Exception:
                raise SnmpsimError("improper IPv6/UDP endpoint %s" % addr)

        elif addr[0] == "[" and addr[-1] == "]":
            h, p = addr[1:-1], 161

        else:
            h, p = addr, 161

        return udp6.Udp6Transport().open_server_mode((h, p)), addr, (h, p)


def parse_endpoint(arg, ipv6=False):
    address = arg

    # IPv6 notation
    if ipv6 and address.startswith("["):
        address = address.replace("[", "").replace("]", "")

    try:
        if ":" in address:
            address, port = address.rsplit(":", 1)
            port = int(port)

        else:
            port = 161

    except Exception as exc:
        raise SnmpsimError(f"Malformed network endpoint address {arg}: {exc}")

    try:
        address, port = socket.getaddrinfo(
            address,
            port,
            socket.AF_INET6 if ipv6 else socket.AF_INET,
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP,
        )[0][4][:2]

    except socket.gaierror as exc:
        raise SnmpsimError(f"Unknown hostname {address}: {exc}")

    return address, port
