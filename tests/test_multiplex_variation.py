import os
import time

import pytest
from pysnmp.proto import rfc1902

MODULE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "snmpsim",
    "variation",
    "multiplex.py",
)

OID = "1.3.6.1.2.1.1.1.0"
PERIOD = 60


def load():
    """Load the module the way the responder does: by executing its source."""
    ctx = {
        "path": MODULE,
        "alias": "multiplex",
        "args": "",
        "moduleContext": {},
        "recordContext": {},
    }

    with open(MODULE) as fl:
        exec(compile(fl.read(), MODULE, "exec"), ctx)

    ctx["init"](options="", mode="variating")

    return ctx


def served(module, snapshots_dir, uptime=0):
    """Return what the snapshot in turn after `uptime` seconds holds for OID."""
    module["moduleContext"]["booted"] = time.time() - uptime

    _, _, value = module["variate"](
        rfc1902.ObjectName("1.3.6.1.2.1"),
        "4",
        f"dir={snapshots_dir},period={PERIOD}",
        origOid=rfc1902.ObjectName(OID),
        nextFlag=False,
        setFlag=False,
        errorStatus=None,
    )

    return value.asOctets().decode()


@pytest.fixture
def snapshots(tmp_path, monkeypatch):
    """Write snapshots, to be listed in the order they were asked for."""
    listdir = os.listdir
    order = []

    def write(*names):
        for name in names:
            with open(tmp_path / name, "w") as snapshot:
                snapshot.write(f"{OID}|4|from {name}\n")

            order.append(name)

        return tmp_path

    monkeypatch.setattr(
        os,
        "listdir",
        lambda path: list(order) if str(path) == str(tmp_path) else listdir(path),
    )

    return write


@pytest.mark.parametrize(
    "names",
    [
        ("00000.snmprec", "00000..snmprec"),
        ("00000..snmprec", "00000.snmprec"),
    ],
)
def test_snapshot_under_the_old_name_gives_way(snapshots, names):
    """Of "00000.snmprec" and "00000..snmprec" the former is served.

    The two-dot name is what the module used to record under; a directory
    recorded into again has both, and the old snapshot is the stale one.
    """
    snapshots_dir = snapshots(*names)

    assert served(load(), snapshots_dir) == "from 00000.snmprec"


def test_snapshot_under_the_old_name_is_served_alone(snapshots):
    snapshots_dir = snapshots("00000..snmprec")

    assert served(load(), snapshots_dir) == "from 00000..snmprec"
