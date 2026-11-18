#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#

import dbm
import hashlib
import importlib
import os
import sys
import threading
from time import monotonic

from snmpsim import confdir
from snmpsim import error
from snmpsim import log
from snmpsim.record.search.file import get_record


def _select_dbm_backend():
    """Pick the DBM implementation index files are built with.

    Indexes are written with gdbm's "fast" flag, which skips the fsync per
    write; without it, indexing a large data file takes minutes. Python 3.13
    made `dbm.sqlite3` the default backend and it fsyncs every write, so use
    gdbm whenever the interpreter has it.

    Any other choice is left to the standard library. `dbm.ndbm` builds
    indexes faster than sqlite3 as well, but `dbm.whichdb()` does not
    recognise the files it writes, and an unrecognised index is rebuilt on
    every start - which costs far more than the indexing itself saves.
    """
    try:
        import dbm.gnu as backend

    except ImportError:
        return dbm

    return backend


def _let_gdbm_finalize_while_reading():
    """Make PyPy's gdbm lock reentrant, lest the responder stop for good.

    PyPy's `_gdbm` is written in Python. Every method of a handle takes one
    lock of the module, a plain one, and a handle's `__del__` is `close()`,
    which takes it again even for a handle closed long ago. PyPy runs
    `__del__` whenever its collector finds a handle dead, in whatever thread
    runs then - inside a `get()` of another handle, too, and that thread
    then waits for the lock it holds itself, for good. An index just built
    leaves such handles behind, and the next lookup could be the last one
    the responder ever answered.

    With a reentrant lock the collector closes the dead handle and the read
    goes on: it only ever closes a handle nobody holds, never the one being
    read. Threads still keep out of each other's way as before. CPython's
    gdbm is in C and has no such lock, and is left alone.
    """
    try:
        import _gdbm

    except ImportError:
        return

    lock = getattr(_gdbm, "_lock", None)

    if lock is not None and not isinstance(lock, type(threading.RLock())):
        _gdbm._lock = threading.RLock()


DBM_BACKEND = _select_dbm_backend()

if DBM_BACKEND.__name__ == "dbm.gnu":
    _let_gdbm_finalize_while_reading()

# What each DBM implementation adds to the name it is asked to open, the file
# holding the data first. An index is called the same whichever of them wrote
# it, so these are all the files that can be taken for one - and
# `dbm.whichdb()` tries them in an order of its own, ndbm's first.
DBM_FILES = {
    "dbm.gnu": ("",),
    "dbm.sqlite3": ("", "-wal", "-shm", "-journal"),
    "dbm.ndbm": (".db", ".pag", ".dir"),
    "dbm.dumb": (".dat", ".dir", ".bak"),
}

# What an index is called while it is being built, before the DBM
# implementation adds its own to the name.
PART_SUFFIX = ".part"

# Berkeley DB - ndbm on many Linux builds, PyPy's too - writes a new database
# under this prefix to its name and renames it when it is there. A process
# killed in between leaves that file, and Berkeley DB will not create the
# database for as long as it stays: every attempt waits for it a hundred
# times over, some 100 sec, and fails.
BERKELEY_DB_TEMP_PREFIX = "__db."
BERKELEY_DB_SUFFIX = ".db"

# The octets a file name may have on the file systems in use, and the most
# an index name is given on top of its own: Berkeley DB's prefix and its
# suffix to the name an index is built under, or sqlite3's journal to it.
NAME_MAX = 255
NAME_ADDED = max(
    len(BERKELEY_DB_TEMP_PREFIX) + len(PART_SUFFIX) + len(BERKELEY_DB_SUFFIX),
    len(PART_SUFFIX)
    + max(len(suffix) for suffixes in DBM_FILES.values() for suffix in suffixes),
)


def index_name(name):
    """The file name of an index named `name`, which fits into NAME_MAX.

    `name` is the whole path of the recording with its separators made into
    `_`, and with a long path, or a long community, it does not fit. Such a
    name is cut, between characters, and ended with a hash of the whole of
    it, so that two names cut alike stay apart and every process makes the
    same of one. A name that fits is left as it is: the indexes built under
    it are still found.
    """
    stem, extension = os.path.splitext(name)
    encoded = os.fsencode(name)

    if len(encoded) + NAME_ADDED <= NAME_MAX:
        return name

    digest = "-" + hashlib.sha256(encoded).hexdigest()[:32]
    room = NAME_MAX - NAME_ADDED - len(os.fsencode(digest + extension))

    while len(os.fsencode(stem)) > room:
        stem = stem[:-1]

    return stem + digest + extension


class RecordIndex:
    # an open data file is looked at for changes no more often than this,
    # in seconds: a stat() per request is a system call per request, and a
    # recording edited under a running responder may as well be picked up a
    # moment later
    change_check_interval = 1.0

    def __init__(self, text_file, text_parser):
        self._text_file = text_file
        self._text_parser = text_parser

        try:
            self._db_file = text_file[: text_file.rindex(os.path.extsep)]

        except ValueError:
            self._db_file = text_file

        self._db_file += os.path.extsep + "dbm"

        self._db_file = os.path.join(
            confdir.cache,
            index_name(os.path.splitdrive(self._db_file)[1].replace(os.path.sep, "_")),
        )

        self._db = self._text = None
        self._db_type = "?"
        self._db_module = None

        self._text_file_time = 0
        self._change_checked_at = None

    def __str__(self):
        return "Data file {}, {}-indexed, {}".format(
            self._text_file,
            self._db_type,
            self._db and "opened" or "closed",
        )

    def is_open(self):
        return self._db is not None

    def get_handles(self):
        if self.is_open() and self._change_check_due():
            if self._text_file_time != os.stat(self._text_file)[8]:
                log.info("Text file %s modified, closing" % self._text_file)
                self.close()

        if not self.is_open():
            self.create()
            self.open()

            # create() has just looked at the data file
            self._change_checked_at = monotonic()

        return self._text, self._db

    def _change_check_due(self):
        """Tell if the data file is to be looked at, and note that it is."""
        now = monotonic()

        if (
            self._change_checked_at is not None
            and now - self._change_checked_at < self.change_check_interval
        ):
            return False

        self._change_checked_at = now

        return True

    @staticmethod
    def _files_of(db_file):
        """Every file some DBM implementation could make of this name."""
        suffixes = []

        for backend_suffixes in DBM_FILES.values():
            for suffix in backend_suffixes:
                if suffix not in suffixes:
                    suffixes.append(suffix)

        return tuple(db_file + suffix for suffix in suffixes)

    @property
    def _db_files(self):
        """Every file some DBM implementation could take for this index."""
        return self._files_of(self._db_file)

    @property
    def _part_file(self):
        """The name an index is built under until all of it is written."""
        return self._db_file + PART_SUFFIX

    def _remove_db_files(self, db_file=None):
        db_files = self._files_of(db_file or self._db_file)

        # what a Berkeley DB killed while creating one of them left goes too
        db_files += tuple(
            os.path.join(
                os.path.dirname(name),
                BERKELEY_DB_TEMP_PREFIX + os.path.basename(name),
            )
            for name in db_files
            if name.endswith(BERKELEY_DB_SUFFIX)
        )

        for db_file in db_files:
            try:
                os.remove(db_file)

            except FileNotFoundError:
                pass

            except OSError as exc:
                # left in place it would be read instead of the index that
                # is about to be built
                raise error.SnmpsimError(
                    f"Failed to remove index file {db_file} of data file "
                    f"{self._text_file}: {exc}"
                )

    def _discard_db_files(self, db_file=None):
        try:
            self._remove_db_files(db_file)

        except error.SnmpsimError as exc:
            log.error(str(exc))

    def _install_part_files(self):
        """Put the index that has just been built where it is read from."""
        # the "n" flag emptied only the files of the implementation the
        # index was built with: those of the others go as well
        self._remove_db_files()

        part_files = self._files_of(self._part_file)

        try:
            for part_file, db_file in zip(part_files, self._db_files):
                if os.path.exists(part_file):
                    os.replace(part_file, db_file)

        except OSError as exc:
            # some of it is in place and some is not: none of it is an index
            self._discard_db_files(self._part_file)
            self._discard_db_files()

            raise error.SnmpsimError(
                f"Failed to put index {self._db_file} of data file "
                f"{self._text_file} in place: {exc}"
            )

    @property
    def db_file(self):
        """The name the index is built under, less what a DBM adds to it."""
        return self._db_file

    def needs_build(self):
        """Tell if create() would build the index, without building it."""
        return self._why_index_needed(os.stat(self._text_file)[8]) is not None

    def _why_index_needed(self, text_file_time):
        """Say why the index on disk cannot be served from, None if it can."""
        present = [db_file for db_file in self._db_files if os.path.exists(db_file)]

        if not present:
            return "Index {} does not exist for data file {}".format(
                self._db_file,
                self._text_file,
            )

        db_type = dbm.whichdb(self._db_file)

        if db_type not in DBM_FILES:
            return "Unsupported index format, rebuilding index %s" % self._db_file

        # another Python, sharing the cache directory, may have written it
        # with a module this one is built without - gdbm, as often as not
        try:
            importlib.import_module(db_type)

        except ImportError:
            return (
                "Index %s is written with %s, which this Python lacks, rebuilding"
                % (
                    self._db_file,
                    db_type,
                )
            )

        # only the files of the implementation that will read the index may
        # be there: next to another one's, `dbm.whichdb()` says which it
        # looked at first, not which is the index of the data file as it is
        own = [self._db_file + suffix for suffix in DBM_FILES[db_type]]

        foreign = [db_file for db_file in present if db_file not in own]

        if foreign:
            return (
                "Index %s (%s) sits next to the files of another DBM "
                "implementation (%s), rebuilding"
                % (self._db_file, db_type, ", ".join(foreign))
            )

        for db_file in own:
            if db_file in present:
                if text_file_time < os.stat(db_file)[8]:
                    return None

                return "Index %s out of date" % db_file

        return "Index %s is incomplete" % self._db_file

    def create(self, force_index_build=False, validate_data=False):
        text_file_time = os.stat(self._text_file)[8]

        if force_index_build:
            index_needed = True
            log.info("Forced index rebuild %s" % self._db_file)

        else:
            reason = self._why_index_needed(text_file_time)

            index_needed = reason is not None

            if index_needed:
                log.info(reason)

        db_module = None

        if index_needed:
            # these might speed-up indexing
            open_flags = "nfu"

            errors = []

            # The index is built under another name and gets its own when
            # all of it is written. A build that is cut short - the process
            # killed, the machine stopped - then leaves nothing that could
            # be taken for an index: half of one is newer than the data file
            # just as a whole one is, and would be served from.
            self._remove_db_files(self._part_file)

            while open_flags:
                try:
                    db = DBM_BACKEND.open(self._part_file, open_flags)

                except Exception as exc:
                    log.debug(
                        'DBM open with flags "%s" failed on file '
                        "%s: %s" % (open_flags, self._db_file, exc)
                    )
                    errors.append(str(exc))
                    open_flags = open_flags[:-1]
                    continue

                else:
                    break
            else:
                raise error.SnmpsimError(
                    "Failed to create %s for data file "
                    "%s: %s" % (self._db_file, self._text_file, "; ".join(errors))
                )

            try:
                text = self._text_parser.open(self._text_file)

            except Exception as exc:
                raise error.SnmpsimError(
                    f"Failed to open data file {self._db_file}: {exc}"
                )

            log.info(
                "Building index %s for data file %s with %s (open flags "
                '"%s")...'
                % (self._db_file, self._text_file, DBM_BACKEND.__name__, open_flags)
            )

            sys.stdout.flush()

            line_no = 0
            offset = 0
            prev_offset = -1

            try:
                while True:
                    line, line_no, offset = get_record(text, line_no, offset)

                    if not line:
                        # reference to last OID in data file
                        db["last"] = "%d,%d,%d" % (offset, 0, prev_offset)
                        break

                    try:
                        oid, tag, val = self._text_parser.grammar.parse(line)

                    except Exception as exc:
                        raise error.SnmpsimError(
                            "Data error at %s:%d:"
                            " %s" % (self._text_file, line_no, exc)
                        )

                    if validate_data:
                        try:
                            self._text_parser.evaluate_oid(oid)

                        except Exception as exc:
                            raise error.SnmpsimError(
                                "OID error at %s:%d: %s"
                                % (self._text_file, line_no, exc)
                            )

                        try:
                            self._text_parser.evaluate_value(
                                oid, tag, val, dataValidation=True
                            )

                        except Exception as exc:
                            log.info(
                                "ERROR at line %s, value %r: "
                                "%s" % (line_no, val, exc)
                            )

                    # for lines serving subtrees, type is empty in tag field
                    db[oid] = "%d,%d,%d" % (offset, tag[0] == ":", prev_offset)

                    if tag[0] == ":":
                        prev_offset = offset

                    else:
                        prev_offset = -1  # not a subtree - no back reference

                    offset += len(line)

            except BaseException:
                # an error in the data or the build cut short: either way
                # what is written so far is not an index
                text.close()
                db.close()

                self._discard_db_files(self._part_file)

                raise

            text.close()
            db.close()

            self._install_part_files()

            log.info("...%d entries indexed" % line_no)

            if DBM_BACKEND is not dbm:
                db_module = DBM_BACKEND

        self._text_file_time = os.stat(self._text_file)[8]

        self._db_type = dbm.whichdb(self._db_file)

        # read the index with what wrote it: left to `dbm.open()`, the choice
        # is made again from the files found, on every open
        self._db_module = db_module or self._module_of(self._db_type)

        return self

    @staticmethod
    def _module_of(db_type):
        if db_type in DBM_FILES:
            return importlib.import_module(db_type)

        return dbm

    def lookup(self, oid):
        return self._db[oid]

    def open(self):
        self._text = self._text_parser.open(self._text_file)
        if self._db_module is None:
            self._db_module = self._module_of(dbm.whichdb(self._db_file))

        self._db = self._db_module.open(self._db_file)

    def close(self):
        # an index can be built without ever being opened - create() does
        # exactly that - and closing one twice is easier to arrange than it
        # looks, so neither is an error here
        if self._text is not None:
            self._text.close()

        if self._db is not None:
            self._db.close()

        self._db = self._text = None
