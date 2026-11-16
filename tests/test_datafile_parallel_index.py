"""Indexes that are missing or out of date are built by several processes.

A responder started over many recordings with an empty cache used to index
them one after another before it answered anything. Each index is a file of
its own built from a file of its own, so they are built side by side, and the
responder then finds them up to date.
"""
import importlib
import os
import subprocess
import sys
import time

import pytest

from snmpsim import confdir
from snmpsim import datafile
from snmpsim import log
from snmpsim.record.search import database
from snmpsim.record.search.database import RecordIndex
from snmpsim.variation import RECORD_TYPES

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"

PORT_NUMBER = 1683

PARSER = RECORD_TYPES["snmprec"]


def _available_backends():
    backends = []

    for name in ("dbm.gnu", "dbm.ndbm", "dbm.sqlite3", "dbm.dumb"):
        try:
            backends.append(importlib.import_module(name))

        except ImportError:
            pass

    return backends


BACKENDS = _available_backends()


@pytest.fixture
def cache(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    os.makedirs(cache)
    monkeypatch.setattr(confdir, "cache", str(cache))

    return cache


@pytest.fixture
def logged(monkeypatch):
    """What the code under test logs, a line an item."""
    lines = []

    monkeypatch.setattr(log, "msg", lines.append)
    monkeypatch.setattr(log, "log_level", log.LOG_INFO)

    return lines


def _recording(number):
    lines = [
        "%s|4|Device %d\n" % (SYS_DESCR, number),
        "%s|4|dev%d\n" % (SYS_NAME, number),
    ]

    lines += [
        "%s.%d|4|port %d of %d\n" % (IF_DESCR, port, port, number)
        for port in range(1, number + 2)
    ]

    return "".join(lines)


def _make_recordings(data_dir, count=20, age=60):
    """Write recordings as if they were saved `age` seconds ago."""
    os.makedirs(data_dir, exist_ok=True)

    then = time.time() - age

    recordings = []

    for number in range(count):
        recording = data_dir / ("device%02d.snmprec" % number)
        recording.write_text(_recording(number), encoding="iso-8859-1")
        os.utime(recording, (then, then))

        recordings.append(str(recording))

    return recordings


def _contents(recording):
    """Everything the index of a recording holds, built first if need be."""
    index = RecordIndex(recording, PARSER).create()
    index.open()

    try:
        text, db = index.get_handles()

        return {bytes(key): bytes(db[key]) for key in db.keys()}

    finally:
        index.close()


def _data_files(recordings):
    return [(recording, PARSER) for recording in recordings]


def _index_files(cache):
    return sorted(os.listdir(cache))


def _index_of(name):
    """The index a file in the cache belongs to.

    An index is one file or several, as the backend keeps it: dbm.dumb, the
    only one Python 3.12 on Windows has, writes three.
    """
    return name[: name.rindex(".dbm") + len(".dbm")]


def _indexes(cache):
    return {_index_of(name) for name in _index_files(cache)}


@pytest.mark.parametrize("backend", BACKENDS, ids=lambda backend: backend.__name__)
def test_four_workers_build_what_one_builds(
    tmp_path, cache, monkeypatch, logged, backend
):
    """20 recordings, 4 workers: every index is there and says the same."""
    monkeypatch.setattr(database, "DBM_BACKEND", backend)

    recordings = _make_recordings(tmp_path / "data")

    results = datafile.index_data_files(_data_files(recordings), workers=4)

    assert results == {recording: None for recording in recordings}

    for recording in recordings:
        index = RecordIndex(recording, PARSER)

        assert not index.needs_build(), recording
        assert dbm_type(index) == backend.__name__

    del logged[:]

    in_parallel = {recording: _contents(recording) for recording in recordings}

    # reading them built nothing: the responder finds its indexes ready
    assert not [line for line in logged if "Building index" in line]

    sequential_cache = tmp_path / "sequential"
    os.makedirs(sequential_cache)
    monkeypatch.setattr(confdir, "cache", str(sequential_cache))

    one_by_one = {recording: _contents(recording) for recording in recordings}

    assert [line for line in logged if "Building index" in line]

    assert in_parallel == one_by_one
    assert len(in_parallel[recordings[7]]) == 2 + 8 + 1  # and "last"


def dbm_type(index):
    import dbm

    return dbm.whichdb(index.db_file)


def test_a_broken_recording_does_not_stop_the_others(tmp_path, cache, logged):
    recordings = _make_recordings(tmp_path / "data")

    broken = recordings[11]

    then = os.stat(broken).st_mtime

    with open(broken, "a") as recording:
        recording.write("this is not a record\n")

    os.utime(broken, (then, then))

    results = datafile.index_data_files(_data_files(recordings), workers=4)

    assert sorted(results) == recordings

    assert [recording for recording in results if results[recording]] == [broken]
    assert "%s:%d" % (broken, 15) in results[broken]

    # it is reported, by name
    errors = [line for line in logged if line.startswith("ERROR")]

    assert len(errors) == 1
    assert broken in errors[0]

    for recording in recordings:
        assert RecordIndex(recording, PARSER).needs_build() == (recording == broken)

    # and nothing of its index is left to be taken for one
    assert len(_indexes(cache)) == 19
    assert not [name for name in _index_files(cache) if "device11" in name]


def test_indexes_that_are_up_to_date_are_left_alone(tmp_path, cache, logged):
    recordings = _make_recordings(tmp_path / "data", count=6)

    datafile.index_data_files(_data_files(recordings), workers=3)

    built_at = {name: os.stat(cache / name).st_mtime_ns for name in _index_files(cache)}

    del logged[:]

    # nothing to do takes no processes at all
    monkeypatch_pool = pytest.MonkeyPatch()
    monkeypatch_pool.setattr(
        datafile, "ProcessPoolExecutor", lambda *args, **kwargs: pytest.fail("pool")
    )

    try:
        assert datafile.index_data_files(_data_files(recordings), workers=3) == {}

    finally:
        monkeypatch_pool.undo()

    assert not logged

    # two of them change: only those are built again
    for recording in recordings[:2]:
        with open(recording, "a") as text:
            text.write("1.3.6.1.2.1.1.6.0|4|here\n")

    results = datafile.index_data_files(_data_files(recordings), workers=3)

    assert results == {recording: None for recording in recordings[:2]}

    rebuilt = {
        _index_of(name)
        for name in _index_files(cache)
        if os.stat(cache / name).st_mtime_ns != built_at[name]
    }

    assert len(rebuilt) == 2
    assert b"1.3.6.1.2.1.1.6.0" in _contents(recordings[0])


def test_a_forced_rebuild_builds_every_index(tmp_path, cache, logged):
    recordings = _make_recordings(tmp_path / "data", count=4)

    datafile.index_data_files(_data_files(recordings), workers=2)

    results = datafile.index_data_files(
        _data_files(recordings), workers=2, force_index_build=True
    )

    assert results == {recording: None for recording in recordings}


def test_one_worker_leaves_indexing_to_the_caller(tmp_path, cache, monkeypatch):
    """--index-workers 1 is the responder as it was: no processes started."""
    monkeypatch.setattr(
        datafile, "ProcessPoolExecutor", lambda *args, **kwargs: pytest.fail("pool")
    )

    recordings = _make_recordings(tmp_path / "data", count=4)

    assert datafile.index_data_files(_data_files(recordings), workers=1) == {}
    assert _index_files(cache) == []


def test_a_recording_listed_twice_is_indexed_once(tmp_path, cache, logged):
    recordings = _make_recordings(tmp_path / "data", count=3)

    results = datafile.index_data_files(_data_files(recordings * 2), workers=4)

    assert results == {recording: None for recording in recordings}
    assert len([line for line in logged if "Building index" in line]) == 3


def test_recordings_sharing_an_index_are_not_built_side_by_side(
    tmp_path, cache, logged
):
    """device.snmprec and device.snmpwalk are indexed into one file.

    Two processes writing it at once would leave it to chance what is in it,
    so only the first is built ahead; the other is left to the caller.
    """
    recordings = _make_recordings(tmp_path / "data", count=2)

    walk = tmp_path / "data" / "device00.snmpwalk"
    walk.write_text('.%s = STRING: "Device 0"\n' % SYS_DESCR)

    data_files = _data_files(recordings) + [(str(walk), RECORD_TYPES["snmpwalk"])]

    results = datafile.index_data_files(data_files, workers=4)

    assert results == {recording: None for recording in recordings}


def test_workers_that_cannot_be_started_leave_indexing_to_the_caller(
    tmp_path, cache, monkeypatch, logged
):
    def no_pool(*args, **kwargs):
        raise OSError("no semaphores here")

    monkeypatch.setattr(datafile, "ProcessPoolExecutor", no_pool)

    recordings = _make_recordings(tmp_path / "data", count=4)

    assert datafile.index_data_files(_data_files(recordings), workers=4) == {}

    assert [line for line in logged if "no semaphores here" in line]


def _die(*args):
    os._exit(1)


def test_workers_that_die_leave_indexing_to_the_caller(
    tmp_path, cache, monkeypatch, logged
):
    monkeypatch.setattr(datafile, "_build_index", _die)

    recordings = _make_recordings(tmp_path / "data", count=6)

    assert datafile.index_data_files(_data_files(recordings), workers=2) == {}

    # said once, not for each of the six
    assert len([line for line in logged if line.startswith("ERROR")]) == 1

    assert _index_files(cache) == []


def _die_halfway(text_file, text_parser, *args):
    """Build an index as a worker does, and be gone three records into it."""
    get_record = database.get_record

    def get_some_records(text, line_no, offset):
        if line_no == 3:
            os._exit(1)

        return get_record(text, line_no, offset)

    database.get_record = get_some_records

    return datafile._build_index(text_file, text_parser, *args)


@pytest.mark.parametrize("backend", BACKENDS, ids=lambda backend: backend.__name__)
def test_an_index_a_dead_worker_left_half_built_is_built_again(
    tmp_path, cache, monkeypatch, logged, backend
):
    """Half an index is newer than its recording, as a whole one is.

    Workers that die, or are killed with the rest when one of them does,
    stop in the middle of an index. What they leave must not pass for one:
    the responder would answer from it for as long as the recording stays
    unchanged.
    """
    monkeypatch.setattr(database, "DBM_BACKEND", backend)
    monkeypatch.setattr(datafile, "_build_index", _die_halfway)

    recordings = _make_recordings(tmp_path / "data", count=6)

    assert datafile.index_data_files(_data_files(recordings), workers=2) == {}

    for recording in recordings:
        assert RecordIndex(recording, PARSER).needs_build(), recording

    del logged[:]

    # the caller builds them, over whatever the workers left behind
    for number, recording in enumerate(recordings):
        contents = _contents(recording)

        assert len(contents) == 2 + number + 1 + 1, recording
        assert b"last" in contents

    assert len([line for line in logged if "Building index" in line]) == 6

    # and nothing of what they left is still there
    assert not [name for name in _index_files(cache) if ".part" in name]


class _Interrupted:
    """A grammar that is interrupted at the third record it is shown."""

    def __init__(self):
        self.parsed = 0

    def parse(self, line):
        self.parsed += 1

        if self.parsed == 3:
            raise KeyboardInterrupt()

        return PARSER.grammar.parse(line)


def test_an_interrupted_build_keeps_the_index_there_was(
    tmp_path, cache, monkeypatch, logged
):
    """Ctrl-C in the middle of a rebuild leaves the old index, or none."""
    (recording,) = _make_recordings(tmp_path / "data", count=1)

    index = RecordIndex(recording, PARSER)

    monkeypatch.setattr(PARSER, "grammar", _Interrupted())

    with pytest.raises(KeyboardInterrupt):
        index.create()

    assert index.needs_build()

    monkeypatch.undo()
    monkeypatch.setattr(confdir, "cache", str(cache))

    before = _contents(recording)

    assert b"last" in before

    # built again by force, and interrupted: what was there still is
    monkeypatch.setattr(PARSER, "grammar", _Interrupted())

    with pytest.raises(KeyboardInterrupt):
        RecordIndex(recording, PARSER).create(force_index_build=True)

    monkeypatch.undo()
    monkeypatch.setattr(confdir, "cache", str(cache))

    assert not RecordIndex(recording, PARSER).needs_build()
    assert _contents(recording) == before


def _build_index_slowly(*args):
    """Build an index as a worker does, and say which process did."""
    lines, failure = datafile._build_index(*args)

    # long enough for the other processes to come up and take their share
    time.sleep(0.3)

    return lines + ["built by %d" % os.getpid()], failure


def test_indexes_are_built_by_other_processes(tmp_path, cache, monkeypatch, logged):
    monkeypatch.setattr(datafile, "_build_index", _build_index_slowly)

    recordings = _make_recordings(tmp_path / "data", count=8)

    results = datafile.index_data_files(_data_files(recordings), workers=4)

    assert results == {recording: None for recording in recordings}

    builders = [int(line.split()[-1]) for line in logged if "built by" in line]

    assert len(builders) == 8
    assert os.getpid() not in builders
    assert len(set(builders)) > 1


def test_the_default_number_of_workers(monkeypatch):
    assert 1 <= datafile.default_index_workers() <= 8

    monkeypatch.setattr(
        os, "sched_getaffinity", lambda pid: set(range(3)), raising=False
    )

    assert datafile.default_index_workers() == 3

    monkeypatch.setattr(
        os, "sched_getaffinity", lambda pid: set(range(64)), raising=False
    )

    assert datafile.default_index_workers() == 8

    # no such call on macOS and Windows
    monkeypatch.delattr(os, "sched_getaffinity", raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: 2)

    assert datafile.default_index_workers() == 2

    monkeypatch.setattr(os, "cpu_count", lambda: None)

    assert datafile.default_index_workers() == 1


def test_data_dirs_are_those_the_engines_are_going_to_serve():
    options = [
        ("--v3-engine-id", "auto"),
        ("--data-dir", "/data/a"),
        ("--agent-udpv4-endpoint", "127.0.0.1:1161"),
        ("--v3-engine-id", "010203040506"),
        ("--v3-context-engine-id", "0a0b0c"),
        ("--data-dir", "/data/b"),
        ("--data-dir", "/data/c"),
        ("--v3-context-engine-id", "0d0e0f"),
        ("--v3-engine-id", "010203040507"),
        ("end-of-options", ""),
    ]

    # a context engine with no directory of its own, and an engine with
    # none at all, serve the default ones
    assert datafile.configured_data_dirs(options, ["/default"]) == [
        "/data/a",
        "/data/b",
        "/data/c",
        "/default",
    ]


def test_responder_rejects_no_workers():
    responder = subprocess.run(
        [sys.executable, "-m", "snmpsim.commands.responder", "--index-workers=0"],
        capture_output=True,
        text=True,
    )

    assert responder.returncode == 2
    assert "--index-workers" in responder.stderr


def test_responder_indexes_in_parallel_before_it_configures(
    responder_process, get_from_responder, tmp_path
):
    data_dir = tmp_path / "data"

    recordings = _make_recordings(data_dir, count=8)

    with open(recordings[5], "a") as recording:
        recording.write("this is not a record\n")

    # a broken recording stops the responder as it always did, but not
    # before the others are indexed
    log_file = tmp_path / "broken.log"

    responder = subprocess.run(
        [
            sys.executable,
            "-m",
            "snmpsim.commands.responder",
            "--agent-udpv4-endpoint=127.0.0.1:%d" % PORT_NUMBER,
            "--timeout=1",
            "--data-dir=%s" % data_dir,
            "--cache-dir=%s" % (tmp_path / "cache"),
            "--index-workers=4",
            "--logging-method=file:%s" % log_file,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert responder.returncode == 1
    assert "Data error at %s:9" % recordings[5] in responder.stderr

    said = log_file.read_text()

    assert "Indexing 8 data files in 4 processes" in said
    assert "7 indexed, 1 failed" in said
    # eight times side by side, and once more where the responder stopped
    assert said.count("Building index") == 9

    os.remove(recordings[5])
    os.remove(log_file)

    log_file = tmp_path / "responder.log"

    with responder_process(
        "--data-dir=%s" % data_dir,
        "--cache-dir=%s" % (tmp_path / "cache"),
        "--index-workers=4",
        "--logging-method=file:%s" % log_file,
        port=PORT_NUMBER,
        oid=SYS_DESCR,
        community="device00",
    ):
        for number in (0, 3, 7):
            error_indication, error_status, var_binds = get_from_responder(
                PORT_NUMBER, SYS_NAME, community="device%02d" % number
            )

            assert error_indication is None
            assert not error_status
            assert var_binds[0][1].asOctets() == b"dev%d" % number

    said = log_file.read_text()

    # the second start found seven indexes in the cache and built none
    assert "Indexing" not in said
    assert "Building index" not in said


def test_a_forced_rebuild_is_done_once_at_start_and_again_on_a_rescan(
    tmp_path, cache, monkeypatch
):
    from snmpsim.commands import responder

    recording = _make_recordings(tmp_path / "data", count=1)[0]

    forced = []

    def index_text(self, force_index_build=False, validate_data=False):
        forced.append(bool(force_index_build))
        self._record_index.create(False, validate_data)
        return self

    monkeypatch.setattr(datafile.DataFile, "index_text", index_text)

    # what the processes have just built, as the responder is handed it
    indexed = {recording: None}

    recordings = responder.Recordings(
        [str(tmp_path / "data")],
        {},
        None,
        None,
        None,
        force_index_rebuild=True,
        indexed=indexed,
    )

    recordings.load(recording, PARSER).close()

    # the start is over: a recording a rescan finds is indexed by force
    indexed.clear()

    recordings.load(recording, PARSER).close()

    assert forced == [False, True]
