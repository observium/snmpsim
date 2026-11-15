#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
import os
import stat

from snmpsim.grammar import walk
from snmpsim.record import dump
from snmpsim.record.search.file import get_record


def can_rewind(file_obj):
    """Tell whether a file can be moved back to a line it has given out.

    seekable() is not the answer: on Windows it is true of a pipe, whose
    seek() then succeeds and brings nothing back. So only a regular file
    is moved back; a pipe, a FIFO or a console is not, whatever it says.
    A file without a descriptor, a BytesIO, is taken at its word.
    """
    try:
        mode = os.fstat(file_obj.fileno()).st_mode

    except (AttributeError, OSError, ValueError):
        return file_obj.seekable()

    return stat.S_ISREG(mode)


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
        regular file is moved back to the start of that line; anything
        else (see can_rewind) cannot be, so its line is held for the
        next call on the same file.
        """
        if self._pipe is not None and self._pipe.file_obj is file_obj:
            source = self._pipe

        elif can_rewind(file_obj):
            source = file_obj

        else:
            source = self._pipe = HeldLine(file_obj)

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
