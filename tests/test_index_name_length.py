"""An index whose name would be too long for the file system gets a shorter one.

The index of a recording is named after the whole path of it, with the
directory separators made into `_`, in the cache directory. A recording deep
in a data directory, or named after a long community, makes a name longer
than the 255 octets a file name may have, and the index could not be made:
the responder did not start. Such a name is cut and made unique with a hash
of the whole of it; a name that fits stays what it always was, so that the
indexes already built are still found.
"""
import os
import subprocess
import sys
import time

import pytest

from snmpsim import confdir
from snmpsim.record.search import database
from snmpsim.record.search.database import RecordIndex
from snmpsim.record.snmprec import SnmprecRecord

OID = "1.3.6.1.2.1.1.5.0"

# what a file name may have, in octets, on the file systems in use
NAME_MAX = 255


@pytest.fixture
def cache(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    os.makedirs(cache)
    monkeypatch.setattr(confdir, "cache", str(cache))

    return cache


def recording_at(directory, name):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name + ".snmprec")

    with open(path, "w") as f:
        f.write(f"{OID}|4|{name[:20]}\n")

    # older than an index built now, which is not taken for out of date
    os.utime(path, (time.time() - 10, time.time() - 10))

    return path


def deep(tmp_path, depth, part="a-directory-of-recordings-with-a-long-name"):
    return os.path.join(str(tmp_path), "data", *([part] * depth))


def served(path):
    index = RecordIndex(path, SnmprecRecord())
    index.create()
    index.open()

    try:
        return index.lookup(OID)

    finally:
        index.close()


def every_name_fits(cache):
    names = os.listdir(cache)

    assert names

    for name in names:
        assert len(os.fsencode(name)) <= NAME_MAX, name


def test_an_index_of_a_recording_deep_in_the_data_directory_is_built(cache, tmp_path):
    path = recording_at(deep(tmp_path, 8), "public")

    assert len(os.fsencode(path)) > NAME_MAX

    assert served(path)
    every_name_fits(cache)


def test_an_index_of_a_recording_with_a_long_name_is_built(cache, tmp_path):
    # a community of 240 characters, its recording just under NAME_MAX itself
    path = recording_at(os.path.join(str(tmp_path), "data"), "c" * 240)

    assert served(path)
    every_name_fits(cache)


def test_a_long_name_of_non_ascii_characters_is_cut_between_characters(cache, tmp_path):
    path = recording_at(deep(tmp_path, 3, "каталог-записей-с-длинным-именем"), "public")

    assert served(path)
    every_name_fits(cache)

    for name in os.listdir(cache):
        name.encode("utf-8")


def test_two_long_names_that_differ_at_the_end_get_indexes_of_their_own(
    cache, tmp_path
):
    first = recording_at(deep(tmp_path, 8), "first")
    second = recording_at(deep(tmp_path, 8), "second")

    assert (
        RecordIndex(first, SnmprecRecord()).db_file
        != RecordIndex(second, SnmprecRecord()).db_file
    )

    assert served(first)
    assert served(second)

    # the second did not take the place of the first
    assert not RecordIndex(first, SnmprecRecord()).needs_build()


def test_the_name_is_the_same_from_one_process_to_the_next(cache, tmp_path):
    path = recording_at(deep(tmp_path, 8), "public")

    # derived from the path alone: index workers and later starts find it
    other = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys\n"
            "from snmpsim import confdir\n"
            "confdir.cache = sys.argv[1]\n"
            "from snmpsim.record.search.database import RecordIndex\n"
            "from snmpsim.record.snmprec import SnmprecRecord\n"
            "print(RecordIndex(sys.argv[2], SnmprecRecord()).db_file)\n",
            str(cache),
            path,
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert other.stdout.strip() == RecordIndex(path, SnmprecRecord()).db_file


@pytest.mark.parametrize("length, kept", [(242, True), (243, False)])
def test_a_name_is_kept_up_to_what_leaves_room_for_the_backends(length, kept):
    # 13 octets are added at most: "__db." + ".part" + ".db" by Berkeley DB,
    # ".part" + "-journal" by sqlite3
    name = "n" * (length - len(".dbm")) + ".dbm"

    assert (database.index_name(name) == name) is kept
    assert len(database.index_name(name)) <= 242


def test_a_name_that_fits_is_what_it_always_was(cache, tmp_path):
    path = recording_at(os.path.join(str(tmp_path), "data"), "public")

    assert RecordIndex(path, SnmprecRecord()).db_file == os.path.join(
        str(cache), path[: -len(".snmprec")].replace(os.path.sep, "_") + ".dbm"
    )


def test_what_is_made_of_a_long_name_fits_as_well(cache, tmp_path):
    db_file = RecordIndex(
        recording_at(deep(tmp_path, 8), "public"), SnmprecRecord()
    ).db_file

    # what the backends make of the name an index is built under
    part = os.path.basename(db_file) + ".part"
    made = [
        part + suffix
        for suffix in (
            "",
            "-wal",
            "-shm",
            "-journal",
            ".db",
            ".pag",
            ".dir",
            ".dat",
            ".bak",
        )
    ] + ["__db." + part + ".db"]

    assert max(len(os.fsencode(name)) for name in made) <= NAME_MAX
