#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
import re
import struct

from pyasn1.type import univ
from pysnmp.proto import rfc1902

from snmpsim import error
from snmpsim.grammar import abstract
from snmpsim.grammar import unconstrained


class WalkGrammar(abstract.AbstractGrammar):
    # case-insensitive keys as snmpwalk output tend to vary
    TAG_MAP = {
        "OID:": rfc1902.ObjectName,
        "NULL:": univ.Null,
        "INTEGER:": unconstrained.Integer32,
        "STRING:": rfc1902.OctetString,
        "BITS:": rfc1902.Bits,
        "HEX-STRING:": rfc1902.OctetString,
        "GAUGE32:": unconstrained.Gauge32,
        "COUNTER32:": unconstrained.Counter32,
        "COUNTER64:": unconstrained.Counter64,
        "IPADDRESS:": rfc1902.IpAddress,
        "OPAQUE:": rfc1902.Opaque,
        "UNSIGNED32:": unconstrained.Unsigned32,  # this is not needed
        "TIMETICKS:": unconstrained.TimeTicks,  # this is made up
    }

    # ASCII only: str.strip() would also take 0x85 and 0xa0, which end
    # many UTF-8 and code page strings, for white space
    WHITESPACE = " \t\n\r\x0b\x0c"

    BOM = b"\xef\xbb\xbf"

    @staticmethod
    def _integer_filter(value):
        try:
            int(value)
            return value

        except ValueError:
            # Clean enumeration values
            # .1.3.6.1.2.1.2.2.1.3.1 = INTEGER: ethernetCsmacd(6)
            match = re.match(r".*?\((\-?[0-9]+)\)", value)
            if match:
                return match.group(1)

            # Clean values with UNIT suffix
            # .1.3.6.1.2.1.4.13.0 = INTEGER: 60 seconds
            match = re.match(r"(\-?[0-9]+)\s.+", value)
            if match:
                return match.group(1)

            return value

    # possible DISPLAY-HINTs parsing should occur here
    @staticmethod
    def _string_filter(value):
        if not value:
            return value

        elif value[0] == value[-1] == '"':
            # snmpwalk puts a backslash before every quote and backslash
            # of a quoted string, the device did not send those
            return re.sub(r'\\(["\\])', r"\1", value[1:-1])

        # .1.3.6.1.2.1.2.2.1.6.201752832 = STRING: 60:9c:9f:ec:a3:38
        elif re.match(r"^[0-9a-fA-F]{1,2}(\:[0-9a-fA-F]{1,2})+$", value):
            return [int(x, 16) for x in value.split(":")]

        else:
            return value

    @staticmethod
    def _opaque_filter(value):
        opaque_tag = ""
        match = re.match(r"^(\w+: +)", value)
        if match:
            opaque_tag = match.group(1).upper()
            value = value[len(opaque_tag) :]

        if opaque_tag.startswith("FLOAT: "):
            # .1.3.6.1.4.1.6574.4.3.1.1.0 = Opaque: Float: 100.000000
            # net-snmp sends it as sub-tag 9f78 followed by four octets
            # of IEEE 754 single precision
            return b"\x9f\x78\x04" + struct.pack(">f", float(value))

        elif opaque_tag.startswith("DOUBLE: "):
            # .1.3.6.1.4.1.2021.10.1.6.5 = Opaque: Double: 1.5
            # sub-tag 9f79 followed by eight octets of double precision
            return b"\x9f\x79\x08" + struct.pack(">d", float(value))

        elif opaque_tag.startswith("UINT64: "):
            # .1.3.6.1.4.1.2021.10.1.6.2 = Opaque: UInt64: 18446744073709551614
            # there should be BER encoder, but really I not how do this,
            # I just convert to HEX value instead
            hex = f"{int(value):X}"
            add = len(hex) % 2
            hex = add * "0" + hex
            parts = [hex[i : i + 2] for i in range(0, len(hex), 2)]

            # value len
            hex = f"{len(parts):X}"
            add = len(hex) % 2
            hex = add * "0" + hex
            parts = [hex[i : i + 2] for i in range(0, len(hex), 2)] + parts

            # UInt64 subtag is 9f7b
            value = "9F 7B " + " ".join(parts)

        elif opaque_tag.startswith("INT64: "):
            # .1.3.6.1.4.1.2021.10.1.6.3 = Opaque: Int64: 9223372036854775806
            # .1.3.6.1.4.1.2021.10.1.6.4 = Opaque: Int64: -2
            hex = f"{int(value) & (2**64 - 1):X}"
            add = len(hex) % 2
            hex = add * "0" + hex
            parts = [hex[i : i + 2] for i in range(0, len(hex), 2)]

            # value len
            hex = f"{len(parts):X}"
            add = len(hex) % 2
            hex = add * "0" + hex
            parts = [hex[i : i + 2] for i in range(0, len(hex), 2)] + parts

            # Int64 subtag is 9f7a
            value = "9F 7A " + " ".join(parts)

        return [int(y, 16) for y in value.split(" ")]

    @staticmethod
    def _bits_filter(value):
        # rfc1902.Bits does not really initialize from sequences
        if value == "":
            # .1.3.6.1.2.1.10.7.9.1.1.509 = BITS:
            return value

        # Clean bits values
        # .1.3.6.1.2.1.17.6.1.1.1.0 = BITS: 5B 00 00 00   [[...]1 3 4 6 7
        # .1.3.6.1.2.1.17.6.1.1.1.0 = BITS: 5B 00 00 00   clear(1)
        match = re.match(r"^([0-9a-fA-F]{2}(\s+[0-9a-fA-F]{2})*)", value)
        if match:
            return bytes(int(y, 16) for y in match.group(1).split(" "))

        return bytes(int(y, 16) for y in value.split(" "))

    # a line of a Hex-STRING: octets in pairs, then the text column of -OT
    HEX_ROW = re.compile(
        r"([0-9a-fA-F]{2}(?:[ \t]+[0-9a-fA-F]{2})*)[ \t]*(?:\[.*)?",
        re.ASCII | re.DOTALL,
    )

    @classmethod
    def _hex_string_filter(cls, value):
        octets = []

        # a long value takes several lines, sixteen octets on each
        for row in value.split("\n"):
            row = row.strip(cls.WHITESPACE)

            # .1.3.6.1.2.1.3.1.1.2.2.1.172.30.1.30 = Hex-STRING: 00 C0 FF 43 CE 45   [...C.E]
            match = cls.HEX_ROW.fullmatch(row)
            if match:
                octets.extend(int(y, 16) for y in match.group(1).split())

            elif " " in row:
                octets.extend(int(y, 16) for y in row.split(" ") if y)

            elif re.fullmatch(r"[0-9a-fA-F]*", row):
                # This could be the format returned by some unknown windows snmpwalk tool:
                # .1.3.6.1.2.1.2.2.1.6.1 = HEX-STRING: 00029929AE3C
                octets.extend(int(row[i : i + 2], 16) for i in range(0, len(row), 2))

            else:
                raise error.SnmpsimError("broken hex string <%s>" % row)

        return octets

    @staticmethod
    def _gauge_filter(value):
        try:
            int(value)
            return value

        except ValueError:
            # Clean values with UNIT suffix
            # .1.3.6.1.2.1.4.31.1.1.47.1 = Gauge32: 10000 milli-seconds
            match = re.match(r"(\-?[0-9]+)\s.+", value)
            if match:
                return match.group(1)

            return value

    @staticmethod
    def _net_address_filter(value):
        return ".".join([str(int(y, 16)) for y in value.split(":")])

    @staticmethod
    def _time_ticks_filter(value):
        match = re.match(r".*?\(([0-9]+)\)", value)
        if match:
            return match.group(1)

        return value

    # what a record of a walk starts with: an OID in numbers or by name,
    # with at least one dot in it, and a value the way snmpwalk prints it
    RECORD_START = re.compile(
        r"\.?[\w\-]+(?:::[\w\-]+)?\.\S+ = "
        r"(?:[A-Za-z][\w\-]*(?: [A-Za-z]+)?:(?: |$)|\"|NULL$|[0-9]+$"
        r"|No Such |No more variables |Wrong Type )",
        re.ASCII,
    )

    # the type of a value that may go on for more lines, and its beginning;
    # snmpwalk -OQ prints no type, a string then begins with its quote
    WRAPPING_VALUE = re.compile(
        r"\s*\S+ = (?:Wrong Type \(should be [^\n]*?\): )?"
        r"(?:(STRING|Hex-STRING): ?(.*)|(\".*))",
        re.ASCII | re.DOTALL | re.IGNORECASE,
    )

    # the inside of a quoted string up to the quote that closes it;
    # snmpwalk puts a backslash before the quotes that do not
    STRING_BODY = re.compile(r'(?:[^"\\]+|\\.)*', re.DOTALL)

    def continuation(self, record):
        """Return what tells if a line carries on with the value of `record`.

        That is None for a record that is complete on its one line, and
        otherwise a function to call with each line that follows, in
        order, till it says no. A record is still open when it is a
        quoted STRING whose closing quote has not come yet, or a
        Hex-STRING, which takes the lines of nothing but hex octets. A
        line that starts a record of its own never continues the one
        before it, so a string cut short costs that one value and not
        the rest of the walk.
        """
        match = self.WRAPPING_VALUE.match(record.decode("iso-8859-1"))
        if not match:
            return None

        tag, value, untagged = match.groups()

        if tag is None:
            tag, value = "STRING", untagged

        if tag.upper() == "HEX-STRING":
            return self._is_hex_row

        value = value.lstrip(self.WHITESPACE)
        if not value.startswith('"'):
            return None

        # only the text not seen yet is searched for the closing quote,
        # so a string of many lines is read in one pass
        state = {"closed": False, "escaped": False}

        def read(text):
            body = self.STRING_BODY.match(text, 1 if state["escaped"] else 0)
            rest = text[body.end() :]
            state["closed"] = rest.startswith('"')
            state["escaped"] = rest == "\\"

        def continues(line):
            line = line.decode("iso-8859-1")

            if state["closed"] or self.RECORD_START.match(line.rstrip(self.WHITESPACE)):
                return False

            read(line)
            return True

        read(value[1:])

        return None if state["closed"] else continues

    def _is_hex_row(self, line):
        row = line.decode("iso-8859-1").strip(self.WHITESPACE)
        return bool(self.HEX_ROW.fullmatch(row))

    def parse(self, line):
        filters = {
            "OPAQUE:": self._opaque_filter,
            "INTEGER:": self._integer_filter,
            "STRING:": self._string_filter,
            "BITS:": self._bits_filter,
            "HEX-STRING:": self._hex_string_filter,
            "GAUGE32:": self._gauge_filter,
            "NETWORK ADDRESS:": self._net_address_filter,
            "TIMETICKS:": self._time_ticks_filter,
        }

        # a walk saved on Windows may open with a UTF-8 byte order mark,
        # which would otherwise stick to the first OID
        if line.startswith(self.BOM):
            line = line[len(self.BOM) :]

        # Latin-1 maps every octet to the character of the same number,
        # so the value handlers get the octets of the walk back unchanged
        try:
            oid, value = (
                line.decode("iso-8859-1").strip(self.WHITESPACE).split(" = ", 1)
            )

        except Exception:
            raise error.SnmpsimError("broken record <%s>" % line)

        if oid and oid[0] == ".":
            oid = oid[1:]

        if value.startswith("Wrong Type (should be"):
            value = value[value.index(": ") + 2 :]

        if value.startswith("No more variables left in this MIB View"):
            value = "STRING: "

        match = re.match(r"^(\w+(?:[\-\ ]\w+)?:)\ ?(.*)", value, re.ASCII | re.DOTALL)
        if match:
            tag = match.group(1)
            value = match.group(2)

        # this is implicit snmpwalk's fuzziness
        elif value == "STRING:":
            tag = "STRING:"
            value = ""

        # snmpwalk -OQ prints no type, a string is told by its quote
        elif value.startswith('"'):
            tag = "STRING:"

        elif value == "NULL":
            tag = "NULL:"
            value = ""

        else:
            tag = "TimeTicks:"

        if oid and tag:
            handler = filters.get(tag.upper(), lambda x: x)

            # Need rewrite tag for Network Address after filters
            if tag == "Network Address:":
                tag = "IpAddress:"

            value = value.strip(self.WHITESPACE)

            try:
                return oid, tag.upper(), handler(value)

            except error.SnmpsimError:
                raise

            except Exception as exc:
                # .1.3.6.1.4.1.2021.10.1.6.1 = Opaque: Float: n/a
                raise error.SnmpsimError(
                    "value %r is not what %s takes: %s" % (value, tag, exc)
                )

        raise error.SnmpsimError("broken record <%s>" % line)
