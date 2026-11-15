import os
import shutil
import socket
import sys

import pytest
from pysnmp.smi import compiler

from snmpsim.commands import mib2rec

MIBS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "mibs")

TEST_MIB = "1.3.6.1.3.9999"
PORT_NAME = TEST_MIB + ".1.1.2"
PORT_EXT_ALIAS = TEST_MIB + ".2.1.1"
PORT_STATS_ERRORS = TEST_MIB + ".3.1.1"
PORT_QUEUE_DROPS = TEST_MIB + ".4.1.2"

IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"


class Answers:
    """Standing in for the terminal: the same answer to every question."""

    def __init__(self, answer):
        self.answer = answer

    def readline(self):
        return self.answer + "\n"


def off_the_network(*args, **kwargs):
    raise OSError("this test brings its own MIB")


def record_mibs(monkeypatch, tmp_path, *args, online=False):
    # pysnmp loads the MIBs it compiled earlier from this directory, the
    # user's own by default: give it one of the test, with our MIB in it
    compiled = tmp_path / "compiled"
    shutil.copytree(MIBS, compiled)
    monkeypatch.setattr(compiler, "DEFAULT_DEST", str(compiled))

    if not online:
        monkeypatch.setattr(socket.socket, "connect", off_the_network)

    target = tmp_path / "generated.snmprec"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "snmpsim-record-mibs",
            "--quiet",
            f"--output-file={target}",
            *args,
        ],
    )

    status = mib2rec.main()

    oids = []

    if target.exists():
        oids = [
            line.split(b"|")[0].decode() for line in target.read_bytes().splitlines()
        ]

    return status, oids


def rows(oids, column):
    """Indexes of the rows a column has, in the order they were written."""
    return [oid[len(column) + 1 :] for oid in oids if oid.startswith(column + ".")]


def test_tables_that_augment_each_other_get_the_same_rows(tmp_path, monkeypatch):
    status, oids = record_mibs(
        monkeypatch,
        tmp_path,
        "--mib-module=SNMPSIM-TEST-MIB",
        "--integer32-range=1,2147483647",
    )

    assert not status

    ports = rows(oids, PORT_NAME)

    assert len(ports) == 10
    assert len(set(ports)) == 10
    assert rows(oids, PORT_EXT_ALIAS) == ports


def test_tables_with_the_same_index_clause_get_the_same_rows(tmp_path, monkeypatch):
    status, oids = record_mibs(
        monkeypatch,
        tmp_path,
        "--mib-module=SNMPSIM-TEST-MIB",
        "--integer32-range=1,2147483647",
    )

    assert not status
    assert rows(oids, PORT_STATS_ERRORS) == rows(oids, PORT_NAME)


def test_table_with_one_more_index_column_gets_rows_of_its_own(tmp_path, monkeypatch):
    status, oids = record_mibs(
        monkeypatch,
        tmp_path,
        "--mib-module=SNMPSIM-TEST-MIB",
        "--integer32-range=1,2147483647",
    )

    assert not status

    queues = rows(oids, PORT_QUEUE_DROPS)

    assert len(queues) == 10
    assert all(len(queue.split(".")) == 2 for queue in queues)
    assert not {queue.split(".")[0] for queue in queues} & set(rows(oids, PORT_NAME))


def test_shared_rows_follow_the_table_size(tmp_path, monkeypatch):
    status, oids = record_mibs(
        monkeypatch,
        tmp_path,
        "--mib-module=SNMPSIM-TEST-MIB",
        "--integer32-range=1,2147483647",
        "--table-size=3",
    )

    assert not status
    assert len(rows(oids, PORT_NAME)) == 3
    assert rows(oids, PORT_EXT_ALIAS) == rows(oids, PORT_NAME)
    assert rows(oids, PORT_STATS_ERRORS) == rows(oids, PORT_NAME)


def test_if_table_and_ifx_table_get_the_same_rows(tmp_path, monkeypatch, capsys):
    # ifPhysAddress is still asked for, as the random strings do not fit it
    monkeypatch.setattr(sys, "stdin", Answers("0x001122334455"))

    # IF-MIB comes from the public MIB site
    status, oids = record_mibs(
        monkeypatch, tmp_path, "--mib-module=IF-MIB", online=True
    )

    if status and "failed on MIB IF-MIB" in capsys.readouterr().err:
        pytest.skip("IF-MIB could not be fetched")

    assert not status

    interfaces = rows(oids, IF_DESCR)

    assert interfaces
    assert rows(oids, IF_NAME) == interfaces
