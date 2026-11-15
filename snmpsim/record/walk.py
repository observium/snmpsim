#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
from snmpsim.grammar import walk
from snmpsim.record import dump
from snmpsim.record.search.file import get_record


class HeldLine:
    """A file read by lines that takes the last line back.

    A pipe cannot be moved back to where a line started, so the line
    that turned out to belong to the next record waits here for it.
    """

    def __init__(self, file_obj):
        self.file_obj = file_obj
        self.line = None

    def readline(self):
        line, self.line = self.line, None
        if line is None:
            line = self.file_obj.readline()

        return line


class WalkRecord(dump.DumpRecord):
    grammar = walk.WalkGrammar()
    ext = "snmpwalk"

    # MIB names are not resolved here
    oid_hint = " (snmpwalk -On prints them so)"

    _pipe = None

    def read_record(self, file_obj, line_no=None, offset=0):
        """Read the next record of a walk, however many lines it takes.

        snmpwalk starts a new line after every sixteen octets of a
        Hex-STRING and prints the newlines of a quoted STRING as they
        are, so the lines that follow may belong to the same value. The
        line number returned is that of the line the record starts on.

        Telling where a record ends takes reading one line past it. A
        file is moved back to the start of that line; a pipe cannot be,
        so its line is held for the next call on the same pipe.
        """
        if file_obj.seekable():
            source = file_obj

        else:
            if self._pipe is None or self._pipe.file_obj is not file_obj:
                self._pipe = HeldLine(file_obj)

            source = self._pipe

        record, line_no, offset = get_record(source, line_no, offset)

        continues = self.grammar.continuation(record) if record else None
        lines = [record]

        while continues:
            if source is file_obj:
                position = file_obj.tell()

            line = source.readline()

            if line and continues(line):
                lines.append(line)
                continue

            if source is file_obj:
                file_obj.seek(position)

            else:
                source.line = line

            break

        if not record:
            self._pipe = None

        return b"".join(lines), line_no, offset
