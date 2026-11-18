#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
# Simulation data file management tools
#
import collections
import importlib
import multiprocessing
import os
import stat
import sys
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from time import monotonic

from pyasn1.type import univ
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.carrier.asyncio.dgram import udp6
from pysnmp.proto import rfc1902
from pysnmp.proto import rfc1905
from pysnmp.smi import exval
from pysnmp.smi.error import GenError
from pysnmp.smi.error import MibOperationError
from pysnmp.smi.error import NotWritableError

from snmpsim import confdir
from snmpsim import log
from snmpsim import variation
from snmpsim.error import NoDataNotification
from snmpsim.error import SnmpsimError
from snmpsim.record.search import database
from snmpsim.record.search.database import RecordIndex
from snmpsim.record.search.file import get_record
from snmpsim.record.search.file import search_record_by_oid
from snmpsim.reporting.manager import ReportingManager

# the values a variable has when it has none, as a recording may hold them
EXCEPTION_TAG_SETS = frozenset(
    (
        rfc1905.NoSuchObject.tagSet,
        rfc1905.NoSuchInstance.tagSet,
        rfc1905.EndOfMibView.tagSet,
    )
)

END_OF_MIB_VIEW_TAG_SET = rfc1905.EndOfMibView.tagSet

# the tags of those values in a .snmprec record
EXCEPTION_TAGS = frozenset(("128", "129", "130"))

SELF_LABEL = "self"


# never more data files than this are kept open, whatever the process may open
MAX_OPEN_FILES = 256

# descriptors left to everything that is not a data file: sockets, logs, the
# modules and the files variation modules open
RESERVED_DESCRIPTORS = 64


def default_max_open_files():
    """Tell how many data files to keep open unless told otherwise.

    An open data file holds two descriptors, the recording and its index, so
    half of what the process may open, less a reserve, is the most that fits.
    Where the limit cannot be asked for, as on Windows, or there is none, the
    answer is `MAX_OPEN_FILES`.
    """
    try:
        import resource

        soft_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]

    except (ImportError, AttributeError, OSError, ValueError):
        return MAX_OPEN_FILES

    if soft_limit == resource.RLIM_INFINITY or soft_limit < 0:
        return MAX_OPEN_FILES

    return max(1, min(MAX_OPEN_FILES, (soft_limit - RESERVED_DESCRIPTORS) // 2))


def open_files_limit(text):
    """Read a number of data files to keep open off the command line."""
    max_open_files = int(text)

    if max_open_files < 1:
        raise ValueError("at least one data file has to be kept open")

    return max_open_files


def set_max_open_files(max_open_files):
    """Keep at most this many data files open, closing those over it now."""
    if max_open_files < 1:
        raise SnmpsimError(
            "At least one data file has to be kept open, not %s" % max_open_files
        )

    DataFile.max_open_files = max_open_files
    DataFile.close_idle()


# never more processes than this build indexes, however many CPUs there are:
# past it they wait for the disk rather than for each other
MAX_INDEX_WORKERS = 8


def default_index_workers():
    """Tell how many processes build indexes unless told otherwise.

    That is one per CPU this process may run on, which under a container or
    `taskset` is fewer than the machine has, and `MAX_INDEX_WORKERS` at most.
    """
    try:
        cpus = len(os.sched_getaffinity(0))

    except (AttributeError, OSError):
        # macOS and Windows cannot be asked
        cpus = os.cpu_count()

    return max(1, min(MAX_INDEX_WORKERS, cpus or 1))


def index_workers(text):
    """Read a number of indexing processes off the command line."""
    workers = int(text)

    if workers < 1:
        raise ValueError("at least one process has to build the indexes")

    return workers


def configured_data_dirs(options, default_dirs):
    """Tell which directories the SNMP engines on a command line serve.

    `options` are the responder's per-engine options in the order given,
    each a pair of a name and a value. An engine serves the directories
    named for it, or for its SNMPv3 context engines; one given none serves
    `default_dirs`. Every directory is listed once, in the order met.
    """
    served = []

    def serve(dirs):
        for data_dir in dirs:
            if data_dir not in served:
                served.append(data_dir)

    def configure():
        for context_dirs in context_engines or [[]]:
            serve(context_dirs or data_dirs or default_dirs)

    configured = False

    context_engines, data_dirs = [], []

    for option in options:
        name, value = option[0], option[1]

        if name in ("--v3-engine-id", "end-of-options"):
            if configured:
                configure()

            configured = True

            context_engines, data_dirs = [], []

        elif name == "--v3-context-engine-id":
            context_engines.append([])

        elif name == "--data-dir":
            if context_engines:
                context_engines[-1].append(value)

            else:
                data_dirs.append(value)

    return served


def find_data_files(data_dirs):
    """List the recordings in these directories with their parsers.

    A directory that is not there or cannot be read is passed over: whoever
    serves it is going to say so.
    """
    data_files = []

    for data_dir in data_dirs:
        try:
            found = get_data_files(data_dir)

        except OSError as exc:
            log.debug(f"Not looking for data files in {data_dir}: {exc}")
            continue

        data_files.extend((full_path, parser) for full_path, parser, _ in found)

    return data_files


def _build_index(
    text_file,
    text_parser,
    force_index_build,
    validate_data,
    cache_dir,
    backend,
    log_level,
):
    """Build the index of one data file, in a process of its own.

    The process is a fresh interpreter, so it is told what the one that
    started it had been told: where indexes go, what writes them and what is
    worth logging. It has no log of its own - several of them writing to one
    file or one terminal would interleave - and hands its lines back instead,
    together with what went wrong, if anything did.
    """
    lines = []

    confdir.cache = cache_dir
    database.DBM_BACKEND = importlib.import_module(backend)

    log.msg = lines.append
    log.log_level = log_level

    try:
        RecordIndex(text_file, text_parser).create(force_index_build, validate_data)

    except Exception as exc:
        return lines, str(exc) or exc.__class__.__name__

    return lines, None


def _start_resource_tracker():
    """Start multiprocessing's resource tracker off the standard streams.

    The tracker is started with the first process of a pool and lives until
    this process ends. Like any child it has the standard input, output and
    error of whoever started it, and it never lets go of them: a daemon
    which leaves its terminal once it serves would leave the tracker on it,
    and whoever reads the daemon's output through a pipe would wait for the
    end of it for as long as the daemon lives. So the tracker is started
    here, ahead of the pool, with the three of them pointing nowhere for
    the time that takes. What it would have had to say - a warning about
    semaphores a killed process left behind - is lost with that.

    Nothing is done where there is no tracker, and a tracker that is running
    already is left as it is.
    """
    if os.name != "posix":
        return

    try:
        from multiprocessing import resource_tracker

    except ImportError:
        return

    saved = []
    failure = None

    try:
        # what is buffered is written while there is still where to
        for stream in sys.stdout, sys.stderr:
            try:
                stream.flush()

            except Exception:
                pass

        nowhere = os.open(os.devnull, os.O_RDWR)

        try:
            for fd in 0, 1, 2:
                try:
                    saved.append((fd, os.dup(fd)))

                except OSError:
                    # closed: there is nothing for the tracker to hold
                    continue

                os.dup2(nowhere, fd)

        finally:
            os.close(nowhere)

        resource_tracker.ensure_running()

    except Exception as exc:
        # the pool starts a tracker of its own then
        failure = exc

    finally:
        for fd, copy in saved:
            os.dup2(copy, fd)
            os.close(copy)

    # logged only now: until the streams are back, stderr goes nowhere
    if failure is not None:
        log.debug(f"Resource tracker not started ahead of the pool: {failure}")


def index_data_files(data_files, workers, force_index_build=False, validate_data=False):
    """Build the indexes that are missing or out of date, several at a time.

    `data_files` are pairs of a recording and its parser. Each index that
    has to be built is built by one of up to `workers` processes; one that
    fails is reported and does not stop the others. With one worker, or
    fewer than two indexes to build, nothing is done here: an index is built
    when its data file is set up, as it always was.

    Returns what was taken on: the error, or None, by recording. A recording
    with None has an index that is up to date, `force_index_build` included.
    """
    if workers < 2:
        return {}

    pending = []
    seen_text_files = set()
    seen_db_files = set()

    for text_file, text_parser in data_files:
        if text_file in seen_text_files:
            continue

        seen_text_files.add(text_file)

        record_index = RecordIndex(text_file, text_parser)

        try:
            if not force_index_build and not record_index.needs_build():
                continue

        except OSError:
            # gone since the directory was read, or not to be looked at
            continue

        # recordings of different kinds under one name share an index, and
        # two processes must not write it at once: the first one gets it
        if record_index.db_file in seen_db_files:
            continue

        seen_db_files.add(record_index.db_file)

        pending.append((text_file, text_parser))

    if len(pending) < 2:
        return {}

    workers = min(workers, len(pending))

    started = monotonic()

    try:
        # a process started afresh shares neither sockets nor an event loop
        # nor a log with this one, and is what Windows and macOS do anyway.
        # On POSIX it brings multiprocessing's resource tracker with it: one
        # more child, idle, that stays when the pool is gone and ends with
        # this process.
        _start_resource_tracker()

        executor = ProcessPoolExecutor(
            max_workers=workers, mp_context=multiprocessing.get_context("spawn")
        )

    except Exception as exc:
        log.error(
            "Cannot start processes to build indexes, building them one by "
            "one: %s" % exc
        )
        return {}

    log.info("Indexing %d data files in %d processes..." % (len(pending), workers))

    results = {}

    try:
        futures = [
            (
                text_file,
                executor.submit(
                    _build_index,
                    text_file,
                    text_parser,
                    force_index_build,
                    validate_data,
                    confdir.cache,
                    database.DBM_BACKEND.__name__,
                    log.log_level,
                ),
            )
            for text_file, text_parser in pending
        ]

        for text_file, future in futures:
            try:
                lines, failure = future.result()

            except BrokenProcessPool as exc:
                # a process died and took the others with it: what they
                # have not handed back is left to the caller
                log.error(
                    "Processes building indexes are gone, the remaining %d "
                    "are built one by one: %s"
                    % (len(pending) - len(results), exc or exc.__class__.__name__)
                )
                break

            except Exception as exc:
                # nothing is known about this file, leave it to the caller
                log.error(
                    "Process indexing data file %s failed, its index is "
                    "built later: %s" % (text_file, exc or exc.__class__.__name__)
                )
                continue

            for line in lines:
                log.msg(line)

            if failure:
                log.error(f"Failed to index data file {text_file}: {failure}")

            results[text_file] = failure

    except BaseException:
        executor.shutdown(wait=False, cancel_futures=True)
        raise

    executor.shutdown()

    failed = len([text_file for text_file in results if results[text_file]])

    log.info(
        "...%d indexed, %d failed in %.1f sec"
        % (len(results) - failed, failed, monotonic() - started)
    )

    return results


class AbstractLayout:
    layout = "?"


class DataFile(AbstractLayout):
    layout = "text"
    # open data files, the one asked for the longest ago first; a data file
    # is in here once, and only while it is open
    _opened = collections.OrderedDict()
    max_open_files = default_max_open_files()  # each has a text and an index file
    max_broken_records = 100  # max number of broken records skipped in a row

    def __init__(self, textFile, textParser, variationModules):
        self._record_index = RecordIndex(textFile, textParser)
        self._text_parser = textParser
        self._text_file = textFile
        self._variation_modules = variationModules

    def index_text(self, forceIndexBuild=False, validateData=False):
        self._record_index.create(forceIndexBuild, validateData)
        return self

    def close(self):
        DataFile._opened.pop(self, None)
        self._record_index.close()

    @classmethod
    def close_idle(cls, keep=None):
        """Close the files asked for the longest ago until the rest fits.

        The file being served is passed as `keep`: it is the most recently
        used one, and is not closed even when there is room for none.
        """
        opened = DataFile._opened

        while len(opened) > cls.max_open_files:
            data_file = next(iter(opened))

            if data_file is keep:
                break

            log.info(
                "Closing %s, the least recently used of %d open data files"
                % (data_file, len(opened))
            )

            data_file.close()

    def get_handles(self):
        opened = DataFile._opened

        kept_open = self._record_index.is_open() and self in opened

        if not kept_open:
            log.info("Opening %s" % self)

        try:
            # a file that is open is reopened by this if it has changed
            handles = self._record_index.get_handles()

        except Exception:
            # whatever was opened before it failed must not stay open, and
            # a file that cannot be served takes nobody's place
            self.close()
            raise

        opened[self] = True
        opened.move_to_end(self)

        if not kept_open:
            # only now: a file that fails to open closes nobody, at the price
            # of one file over the limit for a moment
            self.close_idle(keep=self)

        return handles

    def process_var_binds(self, var_binds, **context):
        rsp_var_binds = []

        if context.get("nextFlag"):
            error_status = exval.endOfMib

        else:
            error_status = exval.noSuchInstance

        try:
            text, db = self.get_handles()

        except SnmpsimError as exc:
            log.error("Problem with data file or its index: %s" % exc)

            ReportingManager.update_metrics(
                data_file=self._text_file,
                datafile_failure_count=1,
                transport_call_count=1,
                **context,
            )

            # nothing is written to a recording that cannot be read
            if context.get("setFlag") and var_binds:
                raise GenError(name=var_binds[0][0], idx=0)

            return [(vb[0], error_status) for vb in var_binds]

        vars_remaining = vars_total = len(var_binds)
        err_total = 0

        # what fails a SET, raised once the request is counted
        refused = None

        # every value is turned into text for these two lines, which is not
        # worth doing for a log that drops them
        log_var_binds = log.is_enabled(log.LOG_INFO)

        if log_var_binds:
            log.info(
                "Request var-binds: %s, flags: %s, "
                "%s"
                % (
                    ", ".join([f"{vb[0]}=<{vb[1].prettyPrint()}>" for vb in var_binds]),
                    context.get("nextFlag") and "NEXT" or "EXACT",
                    context.get("setFlag") and "SET" or "GET",
                )
            )

        separator = b","

        # the index is keyed by the OID as the data file has it, which is
        # what grammar.parse() reads off a line: no OID object is needed to
        # look one up
        parse = self._text_parser.grammar.parse

        for oid, val in var_binds:
            arcs = oid.asTuple() if isinstance(oid, univ.ObjectIdentifier) else oid
            text_oid = ".".join(map(str, arcs))

            try:
                line = self._record_index.lookup(text_oid)

            except KeyError:
                offset = search_record_by_oid(oid, text, self._text_parser)
                subtree_flag = exact_match = False

            else:
                offset, subtree_flag, prev_offset = line.split(separator, 2)
                subtree_flag, exact_match = int(subtree_flag), True

            offset = int(offset)

            text.seek(offset)

            vars_remaining -= 1

            line, _, _ = get_record(text)  # matched line

            broken_records = 0

            while True:
                if exact_match:
                    if context.get("nextFlag") and not subtree_flag:
                        _next_line, _, _ = get_record(text)  # next line

                        if _next_line:
                            _next_oid = parse(_next_line)[0]

                            try:
                                _, subtree_flag, _ = self._record_index.lookup(
                                    _next_oid
                                ).split(separator, 2)

                            except KeyError:
                                log.error(
                                    "data error for %s at %s, index "
                                    "broken?" % (self, _next_oid)
                                )
                                line = ""  # fatal error

                            else:
                                subtree_flag = int(subtree_flag)
                                line = _next_line

                        else:
                            line = _next_line

                else:  # search function above always rounds up to the next OID
                    if line:
                        _oid, _ = self._text_parser.evaluate(line, oidOnly=True)

                    else:  # eom
                        _oid = "last"

                    try:
                        _, _, _prev_offset = self._record_index.lookup(str(_oid)).split(
                            separator, 2
                        )

                    except KeyError:
                        log.error(
                            "data error for %s at %s, index " "broken?" % (self, _oid)
                        )
                        line = ""  # fatal error

                    else:
                        _prev_offset = int(_prev_offset)

                        # previous line serves a subtree?
                        if _prev_offset >= 0:
                            text.seek(_prev_offset)
                            _prev_line, _, _ = get_record(text)
                            _prev_oid, _ = self._text_parser.evaluate(
                                _prev_line, oidOnly=True
                            )

                            if _prev_oid.isPrefixOf(oid):
                                # use previous line to the matched one
                                line = _prev_line
                                subtree_flag = True

                if not line:
                    _oid = oid
                    _val = error_status
                    break

                call_context = context.copy()
                call_context.update(
                    (),
                    origOid=oid,
                    origValue=val,
                    dataFile=self._text_file,
                    subtreeFlag=subtree_flag,
                    exactMatch=exact_match,
                    errorStatus=error_status,
                    varsTotal=vars_total,
                    varsRemaining=vars_remaining,
                    variationModules=self._variation_modules,
                )

                try:
                    _oid, _val = self._text_parser.evaluate(line, **call_context)

                    if _val is exval.endOfMib:
                        exact_match = True
                        subtree_flag = False
                        continue

                    # A recorded noSuchObject, noSuchInstance or
                    # endOfMibView is no answer to GETNEXT or GETBULK, which
                    # name the next variable that has a value (RFC 3416,
                    # 4.2.2): a manager's walk stops at an exception. One a
                    # variation module made of a record of another type -
                    # the error module simulating an agent that sends it -
                    # is still sent.
                    if (
                        context.get("nextFlag")
                        and _val.tagSet in EXCEPTION_TAG_SETS
                        and self._records_exception(line)
                    ):
                        exact_match = True
                        subtree_flag = False
                        continue

                    # endOfMibView is no answer to a GET (RFC 3416, 4.2.1):
                    # a recorded one says the agent had nothing there, and
                    # the GET is answered as for a variable the recording
                    # does not hold
                    if (
                        not context.get("nextFlag")
                        and _val.tagSet == END_OF_MIB_VIEW_TAG_SET
                        and self._records_exception(line)
                    ):
                        _val = error_status

                except NoDataNotification:
                    raise

                except MibOperationError:
                    raise

                except Exception as exc:
                    err_total += 1
                    log.error(f"data error at {self} for {text_oid}: {exc}")

                    # a broken record must not cut the walk short - step over
                    # it so that the client still reaches the records behind
                    if (
                        context.get("nextFlag")
                        and broken_records < self.max_broken_records
                    ):
                        broken_records += 1
                        exact_match = True
                        subtree_flag = False
                        continue

                    # a SET of a broken record cannot be done, for no
                    # reason the manager could act on
                    if context.get("setFlag"):
                        refused = GenError(
                            name=oid, idx=vars_total - vars_remaining - 1
                        )

                    _oid = oid
                    _val = error_status

                break

            # A variable which is not written - one the recording does not
            # hold, or holds in a plain record, which is read-only - fails
            # the SET as notWritable (RFC 3416, 4.2.5), and the first
            # variable to fail is the one named, as net-snmp answers
            if (
                refused is None
                and context.get("setFlag")
                and getattr(_val, "tagSet", None) in EXCEPTION_TAG_SETS
            ):
                refused = NotWritableError(
                    name=oid, idx=vars_total - vars_remaining - 1
                )

            if refused is not None:
                break

            rsp_var_binds.append((_oid, _val))

        if log_var_binds:
            log.info(
                "Response var-binds: %s"
                % (
                    ", ".join(
                        [f"{vb[0]}=<{vb[1].prettyPrint()}>" for vb in rsp_var_binds]
                    )
                )
            )

        ReportingManager.update_metrics(
            data_file=self._text_file,
            varbind_count=vars_total,
            datafile_call_count=1,
            datafile_failure_count=err_total,
            transport_call_count=1,
            **context,
        )

        if refused is not None:
            raise refused

        return rsp_var_binds

    def _records_exception(self, line):
        """Tell if an exception a record is served as is the one it records.

        A `.snmprec` record of tag 128, 129 or 130 records one, with a
        variation module after a colon in its tag or without; a record of
        another type served as one has a variation module make it. The other
        formats record no exceptions at all.
        """
        if not isinstance(self._text_parser, variation.SnmprecRecordMixIn):
            return True

        _, tag, _ = self._text_parser.grammar.parse(line)

        return tag.split(":", 1)[0] in EXCEPTION_TAGS

    def __str__(self):
        return "%s controller" % self._text_file


def get_data_files(tgt_dir, top_len=None):
    # If top_len is not provided, calculate it based on the target directory
    if top_len is None:
        top_len = len(tgt_dir.rstrip(os.path.sep).split(os.path.sep))

    # Start processing the directory
    return process_directory(tgt_dir, top_len)


def process_directory(tgt_dir, top_len):
    # Initialize an empty list to store directory content
    dir_content = []
    # Iterate over each file in the target directory
    for d_file in os.listdir(tgt_dir):
        # Get the full path of the file
        full_path = os.path.join(tgt_dir, d_file)
        # Get the inode information of the file
        inode = os.lstat(full_path)
        # If the file is a symbolic link, process it
        if stat.S_ISLNK(inode.st_mode):
            full_path, inode = process_symlink(full_path, tgt_dir)
        # Calculate the relative path of the file
        rel_path = full_path.split(os.path.sep)[top_len:]
        # If the file is a directory, recursively process it
        if stat.S_ISDIR(inode.st_mode):
            dir_content += get_data_files(full_path, top_len)
        # If the file is a regular file, process it
        elif stat.S_ISREG(inode.st_mode):
            dir_content += process_file(d_file, full_path, rel_path)
    # Return the directory content
    return dir_content


def process_symlink(full_path, tgt_dir):
    # Read the target of the symbolic link
    full_path = os.readlink(full_path)
    # If the target is not an absolute path, prepend the target directory
    if not os.path.isabs(full_path):
        full_path = os.path.join(tgt_dir, full_path)
    # Get the inode information of the target file
    inode = os.stat(full_path)
    # Return the full path and inode
    return full_path, inode


def process_file(d_file, full_path, rel_path):
    # Check if the file extension matches any of the record types
    for dExt in variation.RECORD_TYPES:
        if d_file.endswith(dExt):
            # If it does, process the file extension
            return process_file_extension(d_file, full_path, rel_path, dExt)
    # If it does not, return an empty list
    return []


def process_file_extension(d_file, full_path, rel_path, dExt):
    # Process the relative path to create an identifier for the file
    if rel_path[0] == SELF_LABEL:
        rel_path = rel_path[1:]
    if len(rel_path) == 1 and rel_path[0] == SELF_LABEL + os.path.extsep + dExt:
        rel_path[0] = rel_path[0][4:]
    # Join the elements of the relative path to create the identifier
    ident = os.path.join(*rel_path)
    # Remove the file extension from the identifier
    ident = ident[: -len(dExt) - 1]
    # Replace any path separators in the identifier with a forward slash
    ident = ident.replace(os.path.sep, "/")
    # Return a tuple containing the full path, the record type, and the identifier
    return [(full_path, variation.RECORD_TYPES[dExt], ident)]


def probe_context(transport_domain, transport_address, context_engine_id, context_name):
    """Suggest variations of context name based on request data"""
    if context_engine_id:
        candidate = [
            context_engine_id,
            context_name,
            ".".join([str(x) for x in transport_domain]),
        ]

    else:
        # try legacy layout w/o contextEngineId in the path
        candidate = [context_name, ".".join([str(x) for x in transport_domain])]

    if transport_domain[: len(udp.DOMAIN_NAME)] == udp.DOMAIN_NAME:
        candidate.append(transport_address[0])

    elif udp6 and transport_domain[: len(udp6.DOMAIN_NAME)] == udp6.DOMAIN_NAME:
        candidate.append(str(transport_address[0]).replace(":", "_"))

    candidate = [str(x) for x in candidate if x]

    while candidate:
        yield rfc1902.OctetString(
            os.path.normpath(os.path.sep.join(candidate)).replace(os.path.sep, "/")
        ).asOctets()
        del candidate[-1]

    # try legacy layout w/o contextEngineId in the path
    if context_engine_id:
        for candidate in probe_context(
            transport_domain, transport_address, None, context_name
        ):
            yield candidate
