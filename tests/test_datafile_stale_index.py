"""An index is only ever read with the backend that wrote it.

The dbm modules of the standard library keep an index called `<name>` in
different files: gdbm and sqlite3 in `<name>` itself, ndbm in `<name>.db` or
`<name>.dir` and `<name>.pag`, dumb in `<name>.dat`, `<name>.dir` and
`<name>.bak`. A cache directory that outlives a change of interpreter can
hold the files of two of them, and `dbm.whichdb()` looks at ndbm's first.
"""
import importlib
import itertools
import os
import time

import pytest

from snmpsim import confdir
from snmpsim.record.search import database
from snmpsim.record.search.database import RecordIndex
from snmpsim.record.snmprec import SnmprecRecord

OLD_OID = "1.3.6.1.2.1.1.1.0"
NEW_OID = "1.3.6.1.2.1.1.5.0"

OLD_RECORDING = "%s|4|Old device\n" % OLD_OID
NEW_RECORDING = "%s|4|New device\n" % NEW_OID


def _available_backends():
    backends = []

    for name in ("dbm.gnu", "dbm.ndbm", "dbm.sqlite3", "dbm.dumb"):
        try:
            backends.append(importlib.import_module(name))

        except ImportError:
            pass

    return backends


BACKENDS = _available_backends()

BACKEND_PAIRS = [
    pytest.param(first, second, id="%s-then-%s" % (first.__name__, second.__name__))
    for first, second in itertools.permutations(BACKENDS, 2)
]


@pytest.fixture
def cache(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    os.makedirs(cache)
    monkeypatch.setattr(confdir, "cache", str(cache))

    return cache


@pytest.fixture
def recording(tmp_path):
    return tmp_path / "device.snmprec"


def _write(recording, text, age):
    """Write the recording as if it was saved `age` seconds ago."""
    recording.write_text(text, encoding="iso-8859-1")

    _set_age(recording, age)


def _set_age(path, age):
    then = time.time() - age

    os.utime(path, (then, then))


def _build(recording, backend, monkeypatch):
    monkeypatch.setattr(database, "DBM_BACKEND", backend)

    return RecordIndex(str(recording), SnmprecRecord()).create()


def _line_of(index, oid):
    """The line of the recording the index points at for this OID."""
    text, db = index.get_handles()

    offset = int(index.lookup(oid).split(b",")[0])

    text.seek(offset)

    return text.readline().decode("iso-8859-1")


def _index_files_of(recording, backend, tmp_path):
    """The files this backend alone would leave in an empty directory."""
    alone = tmp_path / ("alone-" + backend.__name__)
    os.makedirs(alone)

    db = backend.open(str(alone / "index.dbm"), "n")
    db["last"] = "0,0,-1"
    db.close()

    return sorted(name.replace("index.dbm", "", 1) for name in os.listdir(alone))


def _suffixes(cache):
    names = os.listdir(cache)
    prefix = os.path.commonprefix(names)
    prefix = prefix[: prefix.index(".dbm") + len(".dbm")]

    return sorted(name[len(prefix) :] for name in names)


@pytest.mark.parametrize("first,second", BACKEND_PAIRS)
def test_a_changed_recording_is_not_served_from_another_backends_index(
    first, second, cache, recording, tmp_path, monkeypatch
):
    _write(recording, OLD_RECORDING, age=300)

    index = _build(recording, first, monkeypatch)

    assert _line_of(index, OLD_OID) == OLD_RECORDING

    index.close()

    # the recording changes after the index was built, and the interpreter
    # that comes back to it builds indexes with another dbm module
    for name in os.listdir(cache):
        _set_age(cache / name, 200)

    _write(recording, NEW_RECORDING, age=100)

    index = _build(recording, second, monkeypatch)

    assert _line_of(index, NEW_OID) == NEW_RECORDING

    with pytest.raises(KeyError):
        index.lookup(OLD_OID)

    index.close()

    # nothing of the first index is left to be picked up later
    assert _suffixes(cache) == _index_files_of(recording, second, tmp_path)


@pytest.mark.parametrize("first,second", BACKEND_PAIRS)
def test_two_indexes_side_by_side_are_replaced_by_one(
    first, second, cache, recording, tmp_path, monkeypatch
):
    """What an earlier release left behind: both newer than the recording."""
    _write(recording, OLD_RECORDING, age=300)

    _build(recording, first, monkeypatch)

    stale = {name: (cache / name).read_bytes() for name in os.listdir(cache)}

    for name in os.listdir(cache):
        os.remove(cache / name)

    _write(recording, NEW_RECORDING, age=100)

    _build(recording, second, monkeypatch)

    for name, content in stale.items():
        if not (cache / name).exists():
            (cache / name).write_bytes(content)

    index = _build(recording, second, monkeypatch)

    assert _line_of(index, NEW_OID) == NEW_RECORDING

    with pytest.raises(KeyError):
        index.lookup(OLD_OID)

    index.close()

    assert _suffixes(cache) == _index_files_of(recording, second, tmp_path)


@pytest.mark.parametrize("backend", BACKENDS, ids=lambda backend: backend.__name__)
def test_an_index_that_is_up_to_date_is_not_rebuilt(
    backend, cache, recording, monkeypatch
):
    _write(recording, NEW_RECORDING, age=300)

    _build(recording, backend, monkeypatch).close()

    class NoBuilding:
        __name__ = "none"

        @staticmethod
        def open(*args):
            raise AssertionError("the index is being rebuilt")

    # whichever backend this interpreter prefers, a good index is read with
    # the one that wrote it
    index = _build(recording, NoBuilding, monkeypatch)

    assert _line_of(index, NEW_OID) == NEW_RECORDING

    index.close()


@pytest.mark.parametrize("backend", BACKENDS, ids=lambda backend: backend.__name__)
def test_a_failed_build_leaves_no_index_files(backend, cache, recording, monkeypatch):
    _write(recording, NEW_RECORDING + "not a record\n", age=300)

    with pytest.raises(Exception, match="Data error"):
        _build(recording, backend, monkeypatch)

    assert os.listdir(cache) == []
