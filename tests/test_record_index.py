import os

import pytest

from snmpsim import confdir
from snmpsim.record.search.database import RecordIndex
from snmpsim.record.snmprec import SnmprecRecord


@pytest.fixture
def index(tmp_path, monkeypatch):
    """An index over a one-line recording, built but not opened."""
    recording = tmp_path / "device.snmprec"
    recording.write_text("1.3.6.1.2.1.1.1.0|4|Device\n", encoding="iso-8859-1")

    cache = tmp_path / "cache"
    os.makedirs(cache)
    monkeypatch.setattr(confdir, "cache", str(cache))

    return RecordIndex(str(recording), SnmprecRecord()).create()


def test_an_index_that_was_never_opened_can_be_closed(index):
    """create() builds the index without opening it.

    Building indexes ahead of time and closing them is what a caller warming
    a cache does, and what the multiplex variation module does between files.
    """
    assert not index.is_open()

    index.close()

    assert not index.is_open()


def test_closing_twice_is_not_an_error(index):
    index.open()

    assert index.is_open()

    index.close()
    index.close()

    assert not index.is_open()


def test_an_open_index_is_still_closed(index):
    index.open()

    text, db = index.get_handles()

    index.close()

    assert not index.is_open()

    # the handles really were closed, not just forgotten
    with pytest.raises(ValueError):
        text.read()
