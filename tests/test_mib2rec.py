import io
import os
import shutil
import socket
import sys

import pytest
from pysnmp.smi import compiler

from snmpsim.commands import mib2rec
from snmpsim.record.snmprec import SnmprecRecord

MIBS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "mibs")

TEST_MIB = "1.3.6.1.3.9999"
PORT_NAME = TEST_MIB + ".1.1.2"
PORT_EXT_ALIAS = TEST_MIB + ".2.1.1"
PORT_STATS_ERRORS = TEST_MIB + ".3.1.1"
PORT_QUEUE_DROPS = TEST_MIB + ".4.1.2"

SLOT = TEST_MIB + ".5.1"
SLOT_STATE = SLOT + ".2"
SLOT_KIND = SLOT + ".3"
SLOT_POWER = SLOT + ".4"
SLOT_OFFSET = SLOT + ".5"
SLOT_SPEED = SLOT + ".6"
SLOT_LOAD = SLOT + ".7"
SLOT_SERIAL = SLOT + ".8"
SLOT_TAG = SLOT + ".9"
SLOT_LABEL = SLOT + ".10"
SLOT_KEY = SLOT + ".11"
SLOT_MAC = SLOT + ".12"
SLOT_BUILT = SLOT + ".13"
SLOT_FLAGS = SLOT + ".14"
SLOT_VOID = SLOT + ".15"
SLOT_ERRORS = SLOT + ".16"
VOID_TABLE = TEST_MIB + ".6"
VOID_SETTING = TEST_MIB + ".7"
LAST_SETTING = TEST_MIB + ".8"

IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_LINK_UP_DOWN_TRAP_ENABLE = "1.3.6.1.2.1.31.1.1.1.14"


class NoTerminal:
    """Standing in for the terminal nobody sits at: a question is a failure."""

    def readline(self):
        raise AssertionError("the tool asked for a value")


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


def generate(monkeypatch, tmp_path, *args, stdin=None, online=False):
    """Records of the MIBs, as {OID: (tag, value)}, with nobody to ask."""
    monkeypatch.setattr(sys, "stdin", stdin or NoTerminal())

    status, oids = record_mibs(monkeypatch, tmp_path, *args, online=online)

    records = {}

    if oids:
        for line in (tmp_path / "generated.snmprec").read_bytes().splitlines():
            oid, tag, value = line.split(b"|", 2)
            records[oid.decode()] = tag.decode(), value

    return status, records


def column_values(records, column):
    return [
        value for oid, (tag, value) in records.items() if oid.startswith(column + ".")
    ]


def numbers(records, column):
    return [int(value) for value in column_values(records, column)]


def octets(records, column):
    """Values of a column of strings, as the octets that go on the wire."""
    values = []

    for oid, (tag, value) in records.items():
        if oid.startswith(column + "."):
            assert tag in ("4", "4x", "4e")

            if tag == "4x":
                value = bytes.fromhex(value.decode())

            elif tag == "4e":
                value = bytes(SnmprecRecord().evaluate_raw_string(value.decode()))

            values.append(value)

    return values


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
    monkeypatch.setattr(sys, "stdin", NoTerminal())

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


def test_enumerated_column_gets_only_members(tmp_path, monkeypatch):
    status, records = generate(
        monkeypatch, tmp_path, "--mib-module=SNMPSIM-TEST-MIB", "--table-size=40"
    )

    assert not status

    states = numbers(records, SLOT_STATE)

    assert len(states) >= 10
    assert set(states) <= {40, 50, 60}
    assert len(set(states)) > 1


def test_enumeration_without_a_constraint_gets_only_members(tmp_path, monkeypatch):
    status, records = generate(
        monkeypatch, tmp_path, "--mib-module=SNMPSIM-TEST-MIB", "--table-size=40"
    )

    assert not status

    kinds = numbers(records, SLOT_KIND)

    assert len(kinds) >= 10
    assert set(kinds) <= {1, 2, 3}


def test_ranged_integers_stay_in_range(tmp_path, monkeypatch):
    status, records = generate(
        monkeypatch, tmp_path, "--mib-module=SNMPSIM-TEST-MIB", "--table-size=40"
    )

    assert not status

    powers = numbers(records, SLOT_POWER)
    offsets = numbers(records, SLOT_OFFSET)
    speeds = numbers(records, SLOT_SPEED)

    assert len(powers) >= 10
    assert all(1000 <= power <= 2000 for power in powers)
    assert len(set(powers)) > 1

    assert len(offsets) == len(powers)
    assert all(-20 <= offset <= -10 or 100 <= offset <= 110 for offset in offsets)

    assert len(speeds) == len(powers)
    assert all(4000000000 <= speed <= 4000000010 for speed in speeds)

    assert 1000 <= int(records[LAST_SETTING + ".0"][1]) <= 2000


def test_range_given_on_the_command_line_narrows_the_range_of_the_mib(
    tmp_path, monkeypatch
):
    status, records = generate(
        monkeypatch,
        tmp_path,
        "--mib-module=SNMPSIM-TEST-MIB",
        "--table-size=40",
        "--integer32-range=1500,1503",
        "--counter-range=7,7",
    )

    assert not status

    powers = numbers(records, SLOT_POWER)

    # 1500..1503 is inside 1000..2000, and has nothing in common with the
    # ranges of the other columns, which then keep to the MIB
    assert len(powers) > 2
    assert set(powers) <= {1500, 1501, 1502, 1503}
    assert set(numbers(records, SLOT_STATE)) <= {40, 50, 60}
    assert set(numbers(records, SLOT_ERRORS)) == {7}


def test_display_hint_does_not_scale_the_number(tmp_path, monkeypatch):
    status, records = generate(
        monkeypatch, tmp_path, "--mib-module=SNMPSIM-TEST-MIB", "--table-size=40"
    )

    assert not status

    loads = numbers(records, SLOT_LOAD)

    assert len(loads) >= 10
    assert all(4000 <= load <= 5000 for load in loads)


def test_sized_strings_get_a_permitted_length(tmp_path, monkeypatch):
    status, records = generate(
        monkeypatch, tmp_path, "--mib-module=SNMPSIM-TEST-MIB", "--table-size=40"
    )

    assert not status

    serials = octets(records, SLOT_SERIAL)

    assert len(serials) >= 10
    assert {len(serial) for serial in serials} == {6}

    assert len(octets(records, SLOT_TAG)) == len(serials)
    assert all(len(tag) <= 2 for tag in octets(records, SLOT_TAG))

    assert len(octets(records, SLOT_LABEL)) == len(serials)
    assert all(100 <= len(label) <= 120 for label in octets(records, SLOT_LABEL))

    assert len(octets(records, SLOT_KEY)) == len(serials)
    assert {len(key) for key in octets(records, SLOT_KEY)} <= {16, 20}


def test_strings_are_made_of_the_words_given(tmp_path, monkeypatch):
    status, records = generate(
        monkeypatch,
        tmp_path,
        "--mib-module=SNMPSIM-TEST-MIB",
        "--integer32-range=1,2147483647",
        "--string-pool=ab",
        "--string-pool=cd",
    )

    assert not status

    names = octets(records, PORT_NAME)

    assert len(names) == 10
    assert all(name and set(name.split(b" ")) <= {b"ab", b"cd"} for name in names)
    assert set(octets(records, SLOT_TAG)) <= {b"ab", b"cd"}


def test_strings_shown_as_numbers_get_octets_of_a_permitted_length(
    tmp_path, monkeypatch
):
    status, records = generate(
        monkeypatch, tmp_path, "--mib-module=SNMPSIM-TEST-MIB", "--table-size=40"
    )

    assert not status

    macs = octets(records, SLOT_MAC)

    assert len(macs) >= 10
    assert {len(mac) for mac in macs} == {6}
    assert len(set(macs)) > 1

    assert len(octets(records, SLOT_BUILT)) == len(macs)
    # DateAndTime is 8 or 11 octets, and not the words that strings get
    assert {len(built) for built in octets(records, SLOT_BUILT)} == {8}
    assert len(set(octets(records, SLOT_BUILT))) > 1


def test_bits_are_drawn_from_the_named_ones(tmp_path, monkeypatch):
    status, records = generate(
        monkeypatch, tmp_path, "--mib-module=SNMPSIM-TEST-MIB", "--table-size=40"
    )

    assert not status

    flags = octets(records, SLOT_FLAGS)

    assert len(flags) >= 10

    # present(0), powered(1) and faulty(9): 0xc0 in the first octet, 0x40 in
    # the second
    for value in flags:
        assert 1 <= len(value) <= 2
        assert not value[0] & ~0xC0
        assert not value[1:] or value[1] == 0x40


def test_object_no_value_fits_is_reported_and_left_out(tmp_path, monkeypatch, capsys):
    status, records = generate(monkeypatch, tmp_path, "--mib-module=SNMPSIM-TEST-MIB")

    assert not status

    errors = capsys.readouterr().err

    # said once, not for every row
    assert not column_values(records, SLOT_VOID)
    assert errors.count("SNMPSIM-TEST-MIB::slotVoid") == 1

    assert VOID_SETTING + ".0" not in records
    assert "SNMPSIM-TEST-MIB::voidSetting" in errors

    # the neighbours of what was left out are all there
    assert len(column_values(records, SLOT_ERRORS)) == len(
        column_values(records, SLOT_POWER)
    )
    assert LAST_SETTING + ".0" in records


def test_table_no_index_fits_is_reported_and_left_out(tmp_path, monkeypatch, capsys):
    status, records = generate(monkeypatch, tmp_path, "--mib-module=SNMPSIM-TEST-MIB")

    assert not status

    errors = capsys.readouterr().err

    assert not [oid for oid in records if oid.startswith(VOID_TABLE + ".")]
    assert errors.count("SNMPSIM-TEST-MIB::voidEntry") == 1
    assert LAST_SETTING + ".0" in records


def test_manual_values_end_with_the_answers(tmp_path, monkeypatch, capsys):
    # one answer for sysDescr, then the terminal is gone
    status, records = generate(
        monkeypatch,
        tmp_path,
        "--mib-module=SNMPv2-MIB",
        "--manual-values",
        "--stop-object=1.3.6.1.2.1.1.3",
        stdin=io.StringIO("box\n"),
    )

    assert not status
    assert records == {"1.3.6.1.2.1.1.1.0": ("4", b"box")}
    assert "SNMPv2-MIB::sysObjectID" in capsys.readouterr().err


def test_manual_values_still_take_what_is_typed(tmp_path, monkeypatch):
    status, records = generate(
        monkeypatch,
        tmp_path,
        "--mib-module=SNMPSIM-TEST-MIB",
        "--manual-values",
        "--start-object=" + LAST_SETTING,
        stdin=io.StringIO("\n7\n0x5dc\n"),
    )

    # nothing typed and 7, which is out of range, are asked about again
    assert not status
    assert records == {LAST_SETTING + ".0": ("2", b"1500")}


def test_if_mib_is_generated_with_nobody_to_ask(tmp_path, monkeypatch, capsys):
    # IF-MIB comes from the public MIB site
    status, records = generate(
        monkeypatch, tmp_path, "--mib-module=IF-MIB", online=True
    )

    errors = capsys.readouterr().err

    if status and "failed on MIB IF-MIB" in errors:
        pytest.skip("IF-MIB could not be fetched")

    assert not status
    assert "no value" not in errors

    addresses = octets(records, IF_PHYS_ADDRESS)

    assert addresses
    assert {len(address) for address in addresses} == {6}

    # up(1), down(2), testing(3); enabled(1), disabled(2)
    assert len(numbers(records, IF_ADMIN_STATUS)) == len(addresses)
    assert set(numbers(records, IF_ADMIN_STATUS)) <= {1, 2, 3}
    assert set(numbers(records, IF_LINK_UP_DOWN_TRAP_ENABLE)) <= {1, 2}
    assert all(1 <= kind <= 300 for kind in numbers(records, IF_TYPE))
