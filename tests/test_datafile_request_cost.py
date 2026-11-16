"""A request costs no more than answering it takes.

Two things used to be paid for on every request whether they were needed or
not: the request and the response were formatted for a log line that the log
level then dropped, and the data file was stat()ed to see if it had changed.
"""
import collections
import os

import pytest
from pyasn1.type import univ
from pysnmp.proto import rfc1902

from snmpsim import confdir
from snmpsim import log
from snmpsim.datafile import DataFile
from snmpsim.record.search import database
from snmpsim.record.snmprec import SnmprecRecord

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"


class Clock:
    """The monotonic clock of the index, moved by hand."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture(autouse=True)
def nothing_open(monkeypatch):
    monkeypatch.setattr(DataFile, "_opened", collections.OrderedDict())

    yield

    for data_file in list(DataFile._opened):
        data_file.close()


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()

    monkeypatch.setattr(database, "monotonic", clock)

    return clock


@pytest.fixture
def data_file(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    os.makedirs(cache)
    monkeypatch.setattr(confdir, "cache", str(cache))

    recording = tmp_path / "device.snmprec"
    recording.write_text(
        "%s|4|Device\n%s|4|box\n" % (SYS_DESCR, SYS_NAME), encoding="iso-8859-1"
    )

    return DataFile(str(recording), SnmprecRecord(), {})


@pytest.fixture
def logged(monkeypatch):
    lines = []

    monkeypatch.setattr(log, "msg", lines.append)
    monkeypatch.setattr(log, "log_level", log.LOG_INFO)

    return lines


@pytest.fixture
def pretty_prints(monkeypatch):
    """Count the values and the OIDs turned into text."""
    calls = collections.Counter()

    for cls in univ.Null, univ.OctetString, univ.ObjectIdentifier:

        def counting(self, *args, _cls=cls, _pretty_print=cls.prettyPrint, **kwargs):
            calls[_cls.__name__] += 1

            return _pretty_print(self, *args, **kwargs)

        monkeypatch.setattr(cls, "prettyPrint", counting)

    return calls


@pytest.fixture
def stats(monkeypatch, data_file):
    """Record every stat() of the data file."""
    calls = []

    stat = os.stat

    def counting_stat(path, *args, **kwargs):
        if path == data_file._text_file:
            calls.append(path)

        return stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", counting_stat)

    return calls


def get(data_file, *oids, **context):
    return data_file.process_var_binds(
        [(rfc1902.ObjectName(oid), univ.Null("")) for oid in oids], **context
    )


def values(var_binds):
    # not str(oid): that is the formatting being counted
    return [(".".join("%d" % x for x in oid), bytes(value)) for oid, value in var_binds]


def modify(data_file, text):
    """Rewrite the recording, a while after it was written."""
    stamp = os.stat(data_file._text_file)

    with open(data_file._text_file, "w", encoding="iso-8859-1") as recording:
        recording.write(text)

    os.utime(data_file._text_file, (stamp.st_atime + 10, stamp.st_mtime + 10))


def test_nothing_is_formatted_for_a_log_that_drops_it(
    data_file, pretty_prints, monkeypatch
):
    lines = []

    monkeypatch.setattr(log, "msg", lines.append)
    monkeypatch.setattr(log, "log_level", log.LOG_ERROR)

    assert values(get(data_file, SYS_DESCR, SYS_NAME)) == [
        (SYS_DESCR, b"Device"),
        (SYS_NAME, b"box"),
    ]

    assert lines == []
    assert not pretty_prints


def test_nothing_is_formatted_for_no_logger(data_file, pretty_prints, monkeypatch):
    """--logging-method null prints nothing at any level."""
    monkeypatch.setattr(log, "msg", log.NullLogger("snmpsim"))
    monkeypatch.setattr(log, "log_level", log.LOG_DEBUG)

    assert values(get(data_file, SYS_DESCR)) == [(SYS_DESCR, b"Device")]

    assert not pretty_prints


def test_requests_and_responses_are_logged_at_info(data_file, logged):
    get(data_file, SYS_DESCR, SYS_NAME)

    assert [line for line in logged if "var-binds" in line] == [
        "Request var-binds: %s=<>, %s=<>, flags: EXACT, GET " % (SYS_DESCR, SYS_NAME),
        "Response var-binds: %s=<Device>, %s=<box> " % (SYS_DESCR, SYS_NAME),
    ]

    del logged[:]

    get(data_file, SYS_DESCR, nextFlag=True, setFlag=True)

    assert logged == [
        "Request var-binds: %s=<>, flags: NEXT, SET " % SYS_DESCR,
        "Response var-binds: %s=<box> " % SYS_NAME,
    ]


def test_the_log_says_if_a_level_is_printed(monkeypatch):
    monkeypatch.setattr(log, "msg", [].append)

    monkeypatch.setattr(log, "log_level", log.LOG_INFO)

    assert log.is_enabled(log.LOG_ERROR)
    assert log.is_enabled(log.LOG_INFO)
    assert not log.is_enabled(log.LOG_DEBUG)

    monkeypatch.setattr(log, "msg", log.NullLogger("snmpsim"))

    assert not log.is_enabled(log.LOG_ERROR)


def test_a_data_file_is_checked_for_changes_once_a_second(data_file, clock, stats):
    get(data_file, SYS_DESCR)

    clock.advance(1)

    del stats[:]

    for _ in range(100):
        get(data_file, SYS_DESCR)

    assert len(stats) == 1

    clock.advance(0.5)

    get(data_file, SYS_DESCR)

    assert len(stats) == 1

    clock.advance(0.5)

    for _ in range(100):
        get(data_file, SYS_DESCR)

    assert len(stats) == 2


def test_a_file_just_opened_is_not_checked_again(data_file, clock, stats):
    get(data_file, SYS_DESCR)

    del stats[:]

    for _ in range(100):
        get(data_file, SYS_DESCR)

    assert stats == []


def test_each_data_file_has_a_second_of_its_own(data_file, tmp_path, clock, stats):
    other_recording = tmp_path / "other.snmprec"
    other_recording.write_text("%s|4|Other\n" % SYS_DESCR, encoding="iso-8859-1")

    other = DataFile(str(other_recording), SnmprecRecord(), {})

    get(data_file, SYS_DESCR)

    clock.advance(0.6)

    get(other, SYS_DESCR)

    clock.advance(0.6)

    del stats[:]

    # the second of the first file is over, that of the other one is not
    get(other, SYS_DESCR)
    get(data_file, SYS_DESCR)

    assert len(stats) == 1


def test_a_changed_file_is_noticed_when_the_second_is_over(data_file, clock):
    assert values(get(data_file, SYS_DESCR)) == [(SYS_DESCR, b"Device")]

    modify(data_file, "%s|4|Another device\n" % SYS_DESCR)

    clock.advance(1)

    assert values(get(data_file, SYS_DESCR)) == [(SYS_DESCR, b"Another device")]


def test_a_changed_file_is_served_from_what_is_open_within_the_second(data_file, clock):
    """The price of not looking: the old file answers for up to a second."""
    get(data_file, SYS_DESCR)

    old_handles = data_file.get_handles()

    modify(data_file, "%s|4|Another device\n" % SYS_DESCR)

    clock.advance(0.9)

    assert data_file.get_handles() == old_handles

    clock.advance(0.1)

    assert data_file.get_handles() != old_handles
    assert values(get(data_file, SYS_DESCR)) == [(SYS_DESCR, b"Another device")]
