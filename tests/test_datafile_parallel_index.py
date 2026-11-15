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
    assert len(_index_files(cache)) >= 19
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

    rebuilt = [
        name
        for name in _index_files(cache)
        if os.stat(cache / name).st_mtime_ns != built_at[name]
    ]

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
