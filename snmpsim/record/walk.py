#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
from snmpsim.grammar import walk
from snmpsim.record import dump
from snmpsim.record.search.file import get_record


class WalkRecord(dump.DumpRecord):
    grammar = walk.WalkGrammar()
    ext = "snmpwalk"

    def read_record(self, file_obj, line_no=None, offset=0):
        """Read the next record of a walk, however many lines it takes.

        snmpwalk starts a new line after every sixteen octets of a
        Hex-STRING and prints the newlines of a quoted STRING as they
        are, so the lines that follow may belong to the same value. The
        line number returned is that of the line the record starts on.
        """
        record, line_no, offset = get_record(file_obj, line_no, offset)

        while record:
            position = file_obj.tell()
            line = file_obj.readline()

            if not line or not self.grammar.continues(record, line):
                file_obj.seek(position)
                break

            record += line

        return record, line_no, offset
