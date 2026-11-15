"""Data files are kept open while they are being asked for.

A responder serving more recordings than it may hold open has to close some
of them. The ones to close are those nobody asked for the longest: a file
closed in the middle of being polled is reopened at the next request.
"""
import collections
import os
import re
import subprocess
import sys

import pytest

from snmpsim import confdir
from snmpsim import datafile
from snmpsim import log
from snmpsim.datafile import DataFile
from snmpsim.error import SnmpsimError
from snmpsim.record.search.database import RecordIndex
from snmpsim.record.snmprec import SnmprecRecord

SYS_DESCR = "1.3.6.1.2.1.1.1.0"

PORT_NUMBER = 1680


@pytest.fixture(autouse=True)
def nothing_open(monkeypatch):
    """Every test starts with no data file open and leaves none behind."""
    monkeypatch.setattr(DataFile, "_opened", collections.OrderedDict())

    yield

    for data_file in list(DataFile._opened):
        data_file.close()


@pytest.fixture
def cache(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    os.makedirs(cache)
    monkeypatch.setattr(confdir, "cache", str(cache))

    return cache


@pytest.fixture
def recordings(tmp_path, cache):
    """Make data files by name, each over a recording of its own."""

    def make(*names, content="%s|4|Device %%s\n" % SYS_DESCR):
        data_files = []

        for name in names:
            recording = tmp_path / ("%s.snmprec" % name)
            recording.write_text(
                "%" in content and content % name or content, encoding="iso-8859-1"
            )

            data_files.append(DataFile(str(recording), SnmprecRecord(), {}))

        return data_files

    return make


@pytest.fixture
def closes(monkeypatch):
    """Count how many times each open index was closed, by its data file."""
    closed = collections.Counter()

    close = RecordIndex.close

    def counting_close(self):
        if self.is_open():
            closed[self._text_file] += 1

        close(self)

    monkeypatch.setattr(RecordIndex, "close", counting_close)

    return closed


@pytest.fixture
def logged(monkeypatch):
    lines = []

    monkeypatch.setattr(log, "msg", lines.append)
    monkeypatch.setattr(log, "log_level", log.LOG_INFO)

    return lines


def is_open(data_file):
    return data_file._record_index.is_open()


def test_the_least_recently_used_file_is_closed(recordings, monkeypatch):
    """A, B, C, A, D with room for three closes B: A was asked for after it."""
    monkeypatch.setattr(DataFile, "max_open_files", 3)

    a, b, c, d = recordings("a", "b", "c", "d")

    for data_file in a, b, c, a, d:
        data_file.get_handles()

    assert [is_open(data_file) for data_file in (a, b, c, d)] == [
        True,
        False,
        True,
        True,
    ]


def test_no_more_files_are_open_than_allowed(recordings, monkeypatch):
    monkeypatch.setattr(DataFile, "max_open_files", 3)

    data_files = recordings(*"abcdefgh")

    for data_file in data_files:
        data_file.get_handles()

        assert sum(is_open(data_file) for data_file in data_files) <= 3

    assert [is_open(data_file) for data_file in data_files] == [False] * 5 + [True] * 3


def test_an_evicted_file_is_closed_once(recordings, closes, monkeypatch):
    monkeypatch.setattr(DataFile, "max_open_files", 3)

    a, b, c, d, e, f = recordings(*"abcdef")

    for data_file in a, b, c, a, d:
        data_file.get_handles()

    assert closes == {b._text_file: 1}

    # the files evicted next are others, the one already closed is not
    # closed again
    for data_file in e, f:
        data_file.get_handles()

    assert closes[b._text_file] == 1
    assert sorted(closes) == sorted(x._text_file for x in (a, b, c))
    assert set(closes.values()) == {1}


def test_an_evicted_file_is_reopened_when_asked_for(recordings, monkeypatch):
    monkeypatch.setattr(DataFile, "max_open_files", 3)

    a, b, c, d = recordings("a", "b", "c", "d")

    for data_file in a, b, c, a, d:
        data_file.get_handles()

    assert not is_open(b)

    text, db = b.get_handles()

    assert is_open(b)
    assert SYS_DESCR.encode() in db
    assert text.readline().rstrip().endswith(b"Device b")

    # and C, by now the one asked for the longest ago, made room for it
    assert [is_open(data_file) for data_file in (a, c, d)] == [True, False, True]


def test_a_file_is_counted_once(recordings, monkeypatch):
    monkeypatch.setattr(DataFile, "max_open_files", 3)

    a, b, c = recordings("a", "b", "c")

    for data_file in a, a, b, a, c, a, a:
        data_file.get_handles()

    assert list(DataFile._opened) == [b, c, a]
    assert all(is_open(data_file) for data_file in (a, b, c))


def test_a_file_closed_by_its_owner_is_not_kept(recordings, closes, monkeypatch):
    """A data file closed by hand leaves the cache, and comes back once."""
    monkeypatch.setattr(DataFile, "max_open_files", 2)

    a, b, c = recordings("a", "b", "c")

    a.get_handles()
    a.close()

    assert list(DataFile._opened) == []

    a.get_handles()
    b.get_handles()

    assert list(DataFile._opened) == [a, b]

    # with A queued twice, as it used to be, the next file would close the
    # same A two times and leave three files open
    c.get_handles()

    assert [is_open(data_file) for data_file in (a, b, c)] == [False, True, True]
    assert closes[a._text_file] == 2


def test_a_file_that_fails_to_open_takes_no_room(recordings, closes, monkeypatch):
    """A broken recording asked for over and over evicts nobody."""
    monkeypatch.setattr(DataFile, "max_open_files", 2)

    a, b = recordings("a", "b")
    (broken,) = recordings("broken", content="not a record\n")

    a.get_handles()
    b.get_handles()

    for _ in range(5):
        with pytest.raises(SnmpsimError):
            broken.get_handles()

    assert list(DataFile._opened) == [a, b]
    assert is_open(a) and is_open(b)
    assert not closes


def test_a_modified_file_is_reopened_in_place(recordings, closes, monkeypatch):
    monkeypatch.setattr(DataFile, "max_open_files", 2)

    a, b = recordings("a", "b")

    a.get_handles()
    b.get_handles()

    stamp = os.stat(a._text_file)

    with open(a._text_file, "w") as recording:
        recording.write("%s|4|Another device\n" % SYS_DESCR)

    os.utime(a._text_file, (stamp.st_atime + 10, stamp.st_mtime + 10))

    # an open file is looked at for changes once in a while, not every time
    monkeypatch.setattr(RecordIndex, "change_check_interval", 0)

    text, db = a.get_handles()

    assert text.readline().rstrip().endswith(b"Another device")
    assert list(DataFile._opened) == [b, a]
    assert closes == {a._text_file: 1}


def test_eviction_is_logged_with_the_evicted_file(recordings, logged, monkeypatch):
    monkeypatch.setattr(DataFile, "max_open_files", 3)

    a, b, c, d = recordings("a", "b", "c", "d")

    for data_file in a, b, c, a, d:
        data_file.get_handles()

    closing = [line for line in logged if line.startswith("Closing")]

    assert len(closing) == 1
    assert b._text_file in closing[0]
    assert d._text_file not in closing[0]


def test_lowering_the_limit_closes_what_is_over_it(recordings):
    a, b, c, d = recordings("a", "b", "c", "d")

    datafile.set_max_open_files(4)

    try:
        for data_file in a, b, c, d:
            data_file.get_handles()

        datafile.set_max_open_files(2)

        assert [is_open(data_file) for data_file in (a, b, c, d)] == [
            False,
            False,
            True,
            True,
        ]

    finally:
        datafile.set_max_open_files(datafile.default_max_open_files())


@pytest.mark.parametrize("limit", [0, -1])
def test_a_limit_below_one_is_refused(limit):
    with pytest.raises(SnmpsimError):
        datafile.set_max_open_files(limit)


@pytest.mark.skipif(sys.platform == "win32", reason="no resource limits on Windows")
@pytest.mark.parametrize(
    "soft, expected",
    [
        (1024, 256),  # the usual Linux limit
        (256, 96),  # the usual macOS limit
        (1048576, 256),
        (576, 256),
        (574, 255),
        (64, 1),
        (10, 1),
    ],
)
def test_default_limit_follows_the_descriptor_limit(soft, expected, monkeypatch):
    import resource

    monkeypatch.setattr(resource, "getrlimit", lambda what: (soft, soft))

    assert datafile.default_max_open_files() == expected


@pytest.mark.skipif(sys.platform == "win32", reason="no resource limits on Windows")
def test_default_limit_without_a_descriptor_limit(monkeypatch):
    import resource

    monkeypatch.setattr(
        resource,
        "getrlimit",
        lambda what: (resource.RLIM_INFINITY, resource.RLIM_INFINITY),
    )

    assert datafile.default_max_open_files() == 256


def test_default_limit_where_limits_cannot_be_asked_for(monkeypatch):
    # what `import resource` does on Windows
    monkeypatch.setitem(sys.modules, "resource", None)

    assert datafile.default_max_open_files() == 256


def test_the_class_starts_with_the_default_limit():
    assert DataFile.max_open_files == datafile.default_max_open_files()


@pytest.mark.parametrize("command", ["responder", "responder_lite"])
@pytest.mark.parametrize("limit", ["0", "-3", "many"])
def test_responder_refuses_a_bad_limit(command, limit, tmp_path):
    responder = subprocess.run(
        [
            sys.executable,
            "-m",
            "snmpsim.commands.%s" % command,
            "--max-open-data-files=%s" % limit,
            "--data-dir=%s" % tmp_path,
            "--cache-dir=%s" % tmp_path,
            "--agent-udpv4-endpoint=127.0.0.1:%d" % PORT_NUMBER,
            "--timeout=1",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert responder.returncode == 2
    assert "--max-open-data-files" in responder.stderr


def test_responder_keeps_no_more_files_open_than_told(
    responder_process, get_from_responder, tmp_path
):
    """Three recordings served with room for two: the idle one is closed."""
    data_dir = tmp_path / "data"
    os.makedirs(data_dir)

    for name in "abc":
        (data_dir / ("%s.snmprec" % name)).write_text(
            "%s|4|Device %s\n" % (SYS_DESCR, name)
        )

    log_file = tmp_path / "responder.log"

    def closed():
        return re.findall(r"Closing (\S+) controller", log_file.read_text())

    def ask(community):
        error_indication, error_status, var_binds = get_from_responder(
            PORT_NUMBER, SYS_DESCR, community=community
        )

        assert error_indication is None
        assert not error_status
        assert var_binds[0][1].asOctets() == b"Device " + community.encode()

    with responder_process(
        "--data-dir=%s" % data_dir,
        "--cache-dir=%s" % (tmp_path / "cache"),
        "--max-open-data-files=2",
        "--logging-method=file:%s" % log_file,
        "--log-level=info",
        port=PORT_NUMBER,
        oid=SYS_DESCR,
        community="a",
    ):
        ask("b")
        ask("a")

        assert closed() == []

        ask("c")

        assert closed() == [str(data_dir / "b.snmprec")]

        ask("b")

        assert closed() == [str(data_dir / "b.snmprec"), str(data_dir / "a.snmprec")]

    assert "Data files kept open at most: 2" in log_file.read_text()
