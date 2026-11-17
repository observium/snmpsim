"""PyPy's gdbm and its garbage collector must not stop the responder.

PyPy's `_gdbm` is written in Python: every method of a handle takes one
lock of the module, a plain one, and a handle's `__del__` is its `close()`,
which takes that lock again - closed or not. PyPy runs `__del__` when its
collector finds a handle dead, in whichever thread is running then, and that
thread may be in the middle of a `get()` on another handle: it then waits
for the lock it holds itself, for good. In the responder that was a lookup in
an index right after an index had been built, and no request was answered
from then on.
"""
import subprocess
import sys

import pytest

FINALIZED_WHILE_READING = """
import dbm.gnu
import gc
import sys

# the responder's index code is what sets this right
from snmpsim.record.search import database  # noqa: F401


class Key(str):
    # a key is encoded with the lock held: collect then, and the handles
    # nobody holds any more are finalized in the middle of the read
    def encode(self, *args):
        gc.collect()
        return str(self).encode(*args)


reading = dbm.gnu.open(sys.argv[1] + "/reading", "c")
reading[b"key"] = b"value"

for name in ("closed", "open"):
    dead = dbm.gnu.open(sys.argv[1] + "/" + name, "c")
    if name == "closed":
        dead.close()

del dead

assert reading.get(Key("key")) == b"value"
"""


def test_a_gdbm_handle_finalized_during_a_read_does_not_hang(tmp_path):
    _gdbm = pytest.importorskip("_gdbm")

    if not hasattr(_gdbm, "_lock"):
        pytest.skip("the gdbm of this interpreter has no lock of its own")

    try:
        subprocess.run(
            [sys.executable, "-c", FINALIZED_WHILE_READING, str(tmp_path)],
            check=True,
            timeout=60,
        )

    except subprocess.TimeoutExpired:
        pytest.fail("a gdbm handle finalized during a read stopped the thread")
