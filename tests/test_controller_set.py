"""A SET is done as a whole or changes nothing (RFC 3416, 4.2.5).

Variation modules hand the controller what takes a write back and what
makes it stay; the controller runs the one or the other, as the SET goes.
"""
import pytest
from pysnmp.proto import rfc1902
from pysnmp.smi import error

from snmpsim.controller import MibInstrumController

OID = rfc1902.ObjectName("1.3.6.1.4.1.99999.50.1.0")
VALUE = rfc1902.OctetString(b"value")


class DataFile:
    """Writes as a variation module would, then fails or not."""

    def __init__(self, failure=None, commit_failure=None):
        self.failure = failure
        self.commit_failure = commit_failure
        self.ran = []

    def process_var_binds(self, var_binds, **context):
        for name in ("first", "second"):
            context["setUndo"].append(lambda name=name: self.ran.append("undo " + name))
            context["setDone"].append(lambda name=name: self.done(name))

        if self.failure is not None:
            raise self.failure

        return list(var_binds)

    def done(self, name):
        if self.commit_failure is not None:
            raise self.commit_failure

        self.ran.append("done " + name)


def test_a_set_done_keeps_its_writes():
    data_file = DataFile()

    assert MibInstrumController(data_file).write_variables((OID, VALUE)) == [
        (OID, VALUE)
    ]
    assert data_file.ran == ["done first", "done second"]


@pytest.mark.parametrize(
    "failure", [error.NotWritableError(name=OID, idx=0), RuntimeError("broken")]
)
def test_a_set_that_fails_takes_its_writes_back_last_first(failure):
    data_file = DataFile(failure=failure)

    with pytest.raises(type(failure)):
        MibInstrumController(data_file).write_variables((OID, VALUE))

    assert data_file.ran == ["undo second", "undo first"]


def test_a_write_that_does_not_stay_fails_the_set():
    data_file = DataFile(commit_failure=RuntimeError("disk full"))

    with pytest.raises(error.CommitFailedError):
        MibInstrumController(data_file).write_variables((OID, VALUE))

    assert data_file.ran == ["undo second", "undo first"]
