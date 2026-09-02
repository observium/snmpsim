#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
"""SNMP integer types without the value range RFC 1902 gives them.

Devices do put integers outside of their declared range on the wire. A
`tcpMaxConn` (`1.3.6.1.2.1.6.4.0`, an INTEGER) walked as 4294967295 is `-1`
sent as though it were unsigned - five octets, `02 05 00 ff ff ff ff`, where
an Integer32 stops at 2147483647 and four octets.

pyasn1 refuses to build such a value at all, so a recording holding one was
rejected line by line: the converters dropped the record and the responder
could not answer for it. A simulator has to reproduce what the device sent,
misencoded or not, so these types keep the tag - and with it the encoding -
of their `rfc1902` counterparts, and lose only the range check. The BER
encoder then puts out the very octets the device did.
"""

from pyasn1.type import constraint
from pyasn1.type import univ
from pysnmp.proto import rfc1902

#: The RFC 1902 range each type below no longer enforces, by type
RANGES = {}


def _unconstrained(base):
    """Return `base` with its value range constraint dropped"""
    relaxed = type(base.__name__, (base,), {"subtypeSpec": univ.Integer.subtypeSpec})

    for constr in base.subtypeSpec:
        if isinstance(constr, constraint.ValueRangeConstraint):
            RANGES[relaxed] = (constr.start, constr.stop)

    return relaxed


Integer32 = _unconstrained(rfc1902.Integer32)
Counter32 = _unconstrained(rfc1902.Counter32)
Gauge32 = _unconstrained(rfc1902.Gauge32)
Unsigned32 = _unconstrained(rfc1902.Unsigned32)
TimeTicks = _unconstrained(rfc1902.TimeTicks)
Counter64 = _unconstrained(rfc1902.Counter64)


def out_of_range(value):
    """Return the RFC 1902 range `value` breaks, `None` if it keeps to it"""
    for typ, (start, stop) in RANGES.items():
        if isinstance(value, typ) and not start <= value <= stop:
            return start, stop

    return None
