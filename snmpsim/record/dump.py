#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ

from snmpsim.error import SnmpsimError
from snmpsim.grammar import dump
from snmpsim.record import abstract
from snmpsim.record.search.file import get_record


class DumpRecord(abstract.AbstractRecord):
    grammar = dump.DumpGrammar()
    ext = "dump"

    # how to get a file whose OIDs can be read, where there is a way
    oid_hint = ""

    def read_record(self, file_obj, line_no=None, offset=0):
        """Read the next record of a file that is being converted.

        One line is one record here; formats that spread a record over
        several lines override this.
        """
        return get_record(file_obj, line_no, offset)

    def evaluate_oid(self, oid):
        return univ.ObjectIdentifier(oid)

    def evaluate_value(self, oid, tag, value, **context):
        try:
            value = self.grammar.TAG_MAP[tag](value)

        except Exception as exc:
            raise SnmpsimError(
                "value evaluation error for tag %r, value %r: " "%s" % (tag, value, exc)
            )

        # not all callers supply the context - just ignore it
        try:
            if (
                not context["nextFlag"]
                and not context["exactMatch"]
                or context["setFlag"]
            ):
                return context["origOid"], tag, context["errorStatus"]

        except KeyError:
            pass

        return oid, tag, value

    def evaluate(self, line, **context):
        # whatever is wrong with a line, it is a broken record to the
        # caller, who skips it or stops; anything else is a crash
        try:
            oid, tag, value = self.grammar.parse(line)

        except SnmpsimError:
            raise

        except Exception as exc:
            raise SnmpsimError("value is not what its type takes: %s" % exc)

        try:
            oid = self.evaluate_oid(oid)

        except Exception as exc:
            raise SnmpsimError(
                "OID %r is not in numbers%s: %s" % (oid, self.oid_hint, exc)
            )

        if context.get("oidOnly"):
            value = None

        else:
            try:
                oid, tag, value = self.evaluate_value(oid, tag, value, **context)

            except PyAsn1Error as exc:
                raise SnmpsimError(
                    "value evaluation for %s = %r failed: " "%s\r\n" % (oid, value, exc)
                )

        return oid, value

    def format_oid(self, oid):
        return univ.ObjectIdentifier(oid).prettyPrint()

    def format_value(self, oid, value, **context):
        return self.format_oid(oid), self.grammar.get_tag_by_type(value), str(value)

    def format(self, oid, value, **context):
        return self.grammar.build(*self.format_value(oid, value, **context))
