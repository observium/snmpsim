#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
from pyasn1.type import univ
from pysnmp.proto import rfc1902

from snmpsim import error
from snmpsim.grammar import abstract
from snmpsim.grammar import unconstrained


class DumpGrammar(abstract.AbstractGrammar):
    TAG_MAP = {
        "0": unconstrained.Counter32,
        "1": unconstrained.Gauge32,
        "2": unconstrained.Integer32,
        "3": rfc1902.IpAddress,
        "4": univ.Null,
        "5": univ.ObjectIdentifier,
        "6": rfc1902.OctetString,
        "7": unconstrained.TimeTicks,
        "8": unconstrained.Counter32,  # an alias
        "9": unconstrained.Counter64,
    }

    @staticmethod
    def _nullFilter(value):
        return ""  # simply drop whatever value is there when it's a Null

    @staticmethod
    def _unhexFilter(value):
        if value[:5].lower() == "hex: ":
            value = [int(x, 16) for x in value[5:].split(".")]

        # an empty value is an empty string, and a lone quote is not a pair
        elif len(value) > 1 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]

        return value

    def parse(self, line):
        filters = {"4": self._nullFilter, "6": self._unhexFilter}

        try:
            oid, tag, value = line.decode("iso-8859-1").split("|", 2)

        except Exception as exc:
            raise error.SnmpsimError(f"broken record <{line}>: {exc}")

        else:
            if oid and tag:
                handler = filters.get(tag, lambda x: x)
                return oid, tag, handler(value.strip())

            raise error.SnmpsimError("broken record <%s>" % line)
