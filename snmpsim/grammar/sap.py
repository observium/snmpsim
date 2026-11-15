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


class SapGrammar(abstract.AbstractGrammar):
    TAG_MAP = {
        "Counter": unconstrained.Counter32,
        "Gauge": unconstrained.Gauge32,
        "Integer": unconstrained.Integer32,
        "IpAddress": rfc1902.IpAddress,
        #        '<not implemented?>': univ.Null,
        "ObjectID": univ.ObjectIdentifier,
        "OctetString": rfc1902.OctetString,
        "TimeTicks": unconstrained.TimeTicks,
        "Counter64": unconstrained.Counter64,
    }

    # ASCII only: str.strip() would also take 0x85 and 0xa0, which end
    # many UTF-8 and code page strings, for white space
    WHITESPACE = " \t\n\r\x0b\x0c"

    @staticmethod
    def _stringFilter(value):
        if value[:2] == "0x":
            value = [int(value[x : x + 2], 16) for x in range(2, len(value[2:]) + 2, 2)]

        return value

    def parse(self, line):
        filters = {"OctetString": self._stringFilter}

        try:
            oid, tag, value = (
                x.strip(self.WHITESPACE)
                for x in line.decode("iso-8859-1").split(",", 2)
            )

        except Exception as exc:
            raise error.SnmpsimError(f"broken record <{line}>: {exc}")

        else:
            if oid and tag:
                handler = filters.get(tag, lambda x: x)
                return oid, tag, handler(value)

            raise error.SnmpsimError("broken record <%s>" % line)
