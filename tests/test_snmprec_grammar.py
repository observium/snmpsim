from snmpsim.record.snmprec import SnmprecRecord


def test_escaped_value_preserves_trailing_space():
    record = SnmprecRecord()

    oid, value = record.evaluate(
        b"1.3.6.1.2.1.3.1.1.3.3.1.85.209.202.32|64e|U\\xd1\\xca \n"
    )

    assert oid.prettyPrint() == "1.3.6.1.2.1.3.1.1.3.3.1.85.209.202.32"
    assert list(value) == [85, 209, 202, 32]
