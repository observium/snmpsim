import os
import sys

import pytest
from pysnmp.proto import rfc1902, rfc1905

import snmpsim
from snmpsim.variation import SnmprecRecord

MODULE = os.path.join(os.path.dirname(snmpsim.__file__), "variation", "subprocess.py")

OID = "1.3.6.1.4.1.99999.1.1.0"

# writes the octets given in hex to stdout, nothing more
EMIT = "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))"


@pytest.fixture
def module():
    """Load the module the way the responder does: by executing its source."""
    ctx = {"path": MODULE, "alias": "subprocess", "args": "", "moduleContext": {}}

    with open(MODULE) as fl:
        exec(compile(fl.read(), MODULE, "exec"), ctx)

    # no shell anywhere: the command line would be quoted differently by each
    ctx["init"](options="shell:0", mode="variating")

    return ctx


@pytest.fixture
def command(tmp_path):
    script = tmp_path / "emit.py"
    script.write_text(EMIT)

    def build(output):
        # the module cuts the command at the longest run of spaces it finds,
        # so three of them keep a path with a space in it in one piece
        return "   ".join((sys.executable, str(script), output.hex()))

    return build


def answer(module, tag, value):
    """What the responder would put on the wire for the record."""
    context = {
        "variationModules": {"subprocess": (module, {}, {})},
        "dataFile": "subprocess.snmprec",
        "origOid": rfc1902.ObjectName(OID),
        "origValue": rfc1902.Integer32(0),
        "errorStatus": rfc1905.noSuchInstance,
        "setFlag": False,
        "nextFlag": False,
        "subtreeFlag": False,
        "exactMatch": True,
    }

    oid, tag, value = SnmprecRecord().evaluate_value(
        OID, tag + ":subprocess", value, **context
    )

    return value


def test_line_feed_ending_the_output_is_dropped(module, command):
    value = answer(module, "4", command(b"hello\n"))

    assert isinstance(value, rfc1902.OctetString)
    assert value.asOctets() == b"hello"


def test_carriage_return_before_the_line_feed_is_dropped(module, command):
    assert answer(module, "4", command(b"hello\r\n")).asOctets() == b"hello"


def test_only_one_line_ending_is_dropped(module, command):
    assert answer(module, "4", command(b"a\n\n")).asOctets() == b"a\n"
    assert answer(module, "4", command(b"a\r\n\r\n")).asOctets() == b"a\r\n"


def test_output_without_a_line_ending_is_left_alone(module, command):
    assert answer(module, "4", command(b"hello")).asOctets() == b"hello"
    assert answer(module, "4", command(b" padded \t")).asOctets() == b" padded \t"
    assert answer(module, "4", command(b"a\r")).asOctets() == b"a\r"
    assert answer(module, "4", command(b"\n\rhello")).asOctets() == b"\n\rhello"


def test_output_of_nothing_but_a_line_ending_is_empty(module, command):
    assert answer(module, "4", command(b"\n")).asOctets() == b""
    assert answer(module, "4", command(b"")).asOctets() == b""


def test_non_ascii_octets_survive(module, command):
    assert answer(module, "4", command(b"\xff\x00\xe9\n")).asOctets() == b"\xff\x00\xe9"


def test_hex_output_gives_exactly_its_octets(module, command):
    value = answer(module, "4x", command(b"07e30307001b01152b0000\n"))

    assert value.asOctets() == bytes.fromhex("07e30307001b01152b0000")


def test_hex_output_without_a_line_ending(module, command):
    value = answer(module, "4x", command(b"07e30307001b01152b0000"))

    assert value.asOctets() == bytes.fromhex("07e30307001b01152b0000")


def test_number_is_read_from_a_line(module, command):
    value = answer(module, "2", command(b"123455\n"))

    assert isinstance(value, rfc1902.Integer32)
    assert value == 123455


@pytest.mark.skipif(sys.platform == "win32", reason="echo is a shell builtin there")
def test_echo(module):
    assert answer(module, "4", "echo hello").asOctets() == b"hello"
    assert answer(module, "4x", "echo 07e30307").asOctets() == b"\x07\xe3\x03\x07"


def test_failed_command_still_reports_an_error(module, tmp_path):
    script = tmp_path / "fail.py"
    script.write_text("import sys; print('oops'); sys.exit(1)")

    value = answer(module, "4", "   ".join((sys.executable, str(script))))

    assert value is rfc1905.noSuchInstance
