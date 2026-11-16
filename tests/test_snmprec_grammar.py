import pytest

from snmpsim.error import SnmpsimError
from snmpsim.record.dump import DumpRecord
from snmpsim.record.snmprec import SnmprecRecord


def test_escaped_value_preserves_trailing_space():
    record = SnmprecRecord()

    oid, value = record.evaluate(
        b"1.3.6.1.2.1.3.1.1.3.3.1.85.209.202.32|64e|U\\xd1\\xca \n"
    )

    assert oid.prettyPrint() == "1.3.6.1.2.1.3.1.1.3.3.1.85.209.202.32"
    assert list(value) == [85, 209, 202, 32]


SYSNAME = "1.3.6.1.2.1.1.5.0"


@pytest.mark.parametrize("tag", ["4", "4x", "4e", "68", "68x"])
def test_empty_value_of_a_string_type_is_zero_octets(tag):
    oid, value = SnmprecRecord().evaluate(f"{SYSNAME}|{tag}|\n".encode())

    assert oid.prettyPrint() == SYSNAME
    assert value.isValue
    assert value.asOctets() == b""


# an empty hex value used to come out as an object with no value at all:
# nothing complained until the answer had to be encoded
@pytest.mark.parametrize(
    "tag",
    ["2", "2x", "2e", "6", "6x", "64", "64x", "65", "65x", "66", "66x"]
    + ["67", "67x", "70", "70x"],
)
def test_empty_value_of_a_type_that_has_none_is_a_broken_record(tag):
    with pytest.raises(SnmpsimError):
        SnmprecRecord().evaluate(f"{SYSNAME}|{tag}|\n".encode())


@pytest.mark.parametrize("text", ["", '""', " ", "\r"])
def test_empty_string_in_a_dump_is_zero_octets(text):
    oid, value = DumpRecord().evaluate(f"{SYSNAME}|6|{text}\n".encode())

    assert oid.prettyPrint() == SYSNAME
    assert value.asOctets() == b""


def test_lone_quote_in_a_dump_is_kept():
    oid, value = DumpRecord().evaluate(f'{SYSNAME}|6|"\n'.encode())

    assert value.asOctets() == b'"'


@pytest.mark.parametrize("tag", ["0", "1", "2", "3", "5", "7", "8", "9"])
def test_empty_value_in_a_dump_is_a_broken_record_where_the_type_has_none(tag):
    with pytest.raises(SnmpsimError):
        DumpRecord().evaluate(f"{SYSNAME}|{tag}|\n".encode())
