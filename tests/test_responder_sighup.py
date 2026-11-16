"""SIGHUP makes the responder look into its data directories again.

A recording added to a data directory was served after a restart only, and
one taken away kept its community name, each request for it failing at the
file which is not there. SIGHUP was no way round it: it ended a daemon, and
killed a responder running in the foreground.
"""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

import pytest
from pyasn1.type import univ

from snmpsim import confdir
from snmpsim import controller
from snmpsim import log

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="there is no SIGHUP on Windows"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "data", "agent", "public.snmprec")

PORT = 1670
DAEMON_PORT = 1671

SYS_DESCR = "1.3.6.1.2.1.1.1.0"

LIFETIME = 120
DEADLINE = 30


def write_recording(path, descr):
    """Put a recording of one sysDescr where the responder is to find it.

    The file appears under its name complete, as one copied into a data
    directory of a running responder should.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(str(path) + ".tmp", "w") as fl:
        fl.write(f"{SYS_DESCR}|4|{descr}\n")

    os.rename(str(path) + ".tmp", path)


def wait_for(condition, what, said=lambda: ""):
    deadline = time.monotonic() + DEADLINE

    while not condition():
        if time.monotonic() > deadline:
            pytest.fail(f"{what} did not happen in {DEADLINE} sec\n{said()}")

        time.sleep(0.1)


@pytest.fixture
def datadir(tmp_path):
    os.mkdir(tmp_path / "data")
    shutil.copy(DATA_FILE, tmp_path / "data")
    return tmp_path / "data"


@pytest.fixture
def ask(get_from_responder):
    """Ask a community for sysDescr, get its octets or None for no answer."""

    def ask(port, community, timeout=0.5):
        error_indication, error_status, var_binds = get_from_responder(
            port, SYS_DESCR, community, timeout=timeout
        )

        if error_indication is not None:
            return None

        assert not error_status

        return var_binds[0][1].asOctets()

    return ask


@pytest.fixture
def responder(tmp_path, datadir, ask):
    """A responder in the foreground serving `datadir`, and what it logged."""
    with tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "snmpsim.commands.responder",
                f"--agent-udpv4-endpoint=127.0.0.1:{PORT}",
                f"--data-dir={datadir}",
                f"--cache-dir={tmp_path / 'cache'}",
                f"--timeout={LIFETIME}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=stderr,
        )

        def said():
            stderr.seek(0)
            return stderr.read().decode(errors="replace")

        process.said = said

        try:
            wait_for(
                lambda: process.poll() is not None or ask(PORT, "public"),
                "the first answer of the responder",
                said,
            )

            assert process.poll() is None, said()

            yield process

        finally:
            process.terminate()

            try:
                process.wait(timeout=10)

            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def test_recording_added_is_served_after_sighup(responder, datadir, ask):
    write_recording(datadir / "added.snmprec", "Added device")
    write_recording(datadir / "site" / "deep.snmprec", "Deep device")

    # nothing looks into the directory by itself
    assert ask(PORT, "added") is None

    responder.send_signal(signal.SIGHUP)

    def served():
        # the recording which was there is served all the while
        assert ask(PORT, "public", timeout=2) == b"Test device", responder.said()
        return ask(PORT, "added") == b"Added device"

    wait_for(served, "serving the recording added", responder.said)

    assert ask(PORT, "site/deep") == b"Deep device"
    assert responder.poll() is None, responder.said()


def test_recording_removed_is_not_served_after_sighup(responder, datadir, ask):
    write_recording(datadir / "doomed.snmprec", "Doomed device")

    responder.send_signal(signal.SIGHUP)

    wait_for(
        lambda: ask(PORT, "doomed") == b"Doomed device",
        "serving the recording added",
        responder.said,
    )

    os.remove(datadir / "doomed.snmprec")

    responder.send_signal(signal.SIGHUP)

    def gone():
        assert ask(PORT, "public", timeout=2) == b"Test device", responder.said()
        return "0 added, 1 removed, 1 unchanged" in responder.said()

    wait_for(gone, "the end of serving the recording removed", responder.said)

    asked = len(responder.said())

    assert ask(PORT, "doomed") is None

    # the community is unknown now: nothing looks for the file any more
    assert "doomed" not in responder.said()[asked:]

    assert ask(PORT, "public") == b"Test device"
    assert responder.poll() is None, responder.said()


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads any file"
)
def test_recording_which_cannot_be_read_does_not_stop_the_others(
    responder, datadir, ask
):
    """What a rescan fails at is logged, the rest of it is done."""
    write_recording(datadir / "broken.snmprec", "Broken device")
    os.chmod(datadir / "broken.snmprec", 0)

    write_recording(datadir / "zz-added.snmprec", "Added device")

    responder.send_signal(signal.SIGHUP)

    wait_for(
        lambda: responder.poll() is not None
        or ask(PORT, "zz-added") == b"Added device",
        "serving the recording added",
        responder.said,
    )

    assert responder.poll() is None, responder.said()
    assert "broken.snmprec is not served" in responder.said()
    assert ask(PORT, "broken") is None
    assert ask(PORT, "public") == b"Test device"

    # put right, it is served after the next rescan
    os.chmod(datadir / "broken.snmprec", 0o644)

    responder.send_signal(signal.SIGHUP)

    wait_for(
        lambda: ask(PORT, "broken") == b"Broken device",
        "serving the recording put right",
        responder.said,
    )


def test_directory_which_cannot_be_read_leaves_recordings_as_they_are(
    responder, datadir, ask
):
    """Nothing is dropped for a scan which did not see it."""
    os.symlink(datadir / "nowhere", datadir / "dangling.snmprec")
    write_recording(datadir / "added.snmprec", "Added device")

    responder.send_signal(signal.SIGHUP)

    wait_for(
        lambda: responder.poll() is not None or "rescan failed" in responder.said(),
        "the report of the rescan",
        responder.said,
    )

    assert responder.poll() is None, responder.said()
    assert ask(PORT, "public") == b"Test device"
    assert ask(PORT, "added") is None

    os.remove(datadir / "dangling.snmprec")

    responder.send_signal(signal.SIGHUP)

    wait_for(
        lambda: ask(PORT, "added") == b"Added device",
        "serving the recording added",
        responder.said,
    )


def test_same_recordings_are_left_alone(responder, datadir, ask):
    responder.send_signal(signal.SIGHUP)

    wait_for(
        lambda: "0 added, 0 removed, 1 unchanged" in responder.said(),
        "the report of the rescan",
        responder.said,
    )

    assert ask(PORT, "public") == b"Test device"

    # the recording was configured once, at the start
    assert responder.said().count("Configuring") == 1
    assert responder.poll() is None, responder.said()


def test_daemon_rescans_on_sighup(tmp_path, datadir, ask):
    pid_file = tmp_path / "responder.pid"

    started = subprocess.run(
        [
            sys.executable,
            "-m",
            "snmpsim.commands.responder",
            "--daemonize",
            f"--agent-udpv4-endpoint=127.0.0.1:{DAEMON_PORT}",
            f"--data-dir={datadir}",
            f"--cache-dir={tmp_path / 'cache'}",
            f"--pid-file={pid_file}",
            f"--timeout={LIFETIME}",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=DEADLINE,
        text=True,
    )

    assert started.returncode == 0, started.stderr

    with open(pid_file) as fl:
        pid = int(fl.read())

    try:
        assert ask(DAEMON_PORT, "public") == b"Test device"

        write_recording(datadir / "added.snmprec", "Added device")

        os.kill(pid, signal.SIGHUP)

        wait_for(
            lambda: ask(DAEMON_PORT, "added") == b"Added device",
            "serving the recording added",
        )

        assert ask(DAEMON_PORT, "public") == b"Test device"

    finally:
        try:
            os.kill(pid, signal.SIGTERM)

            for _ in range(100):
                os.kill(pid, 0)
                time.sleep(0.1)

            os.kill(pid, signal.SIGKILL)

        except ProcessLookupError:
            pass


class Engine:
    """As much of an SNMP engine as registering a community takes."""

    def __init__(self):
        self.communities = {}


class Context:
    """SNMP context names and what serves them."""

    def __init__(self):
        self.names = {}

    def register_context_name(self, name, mib_instrum):
        assert name not in self.names
        self.names[name] = mib_instrum

    def unregister_context_name(self, name):
        del self.names[name]


@pytest.fixture
def recordings(tmp_path, datadir, monkeypatch):
    from snmpsim.commands import responder

    monkeypatch.setattr(log, "msg", log.NullLogger("test"))
    monkeypatch.setattr(confdir, "cache", str(tmp_path / "cache"))
    os.mkdir(tmp_path / "cache")

    engine = Engine()

    monkeypatch.setattr(
        responder.config,
        "add_v1_system",
        lambda engine, index, community, contextName: engine.communities.update(
            {index: community}
        ),
    )
    monkeypatch.setattr(
        responder.config,
        "delete_v1_system",
        lambda engine, index: engine.communities.pop(index),
    )

    recordings = responder.Recordings(
        [str(datadir)],
        {},
        engine,
        Context(),
        controller.DataIndexInstrumController(),
    )
    recordings.rescan()

    return recordings


def index_of(recordings):
    """Paths and communities the index of data files has, row by row."""
    column = {}

    for oid, value in recordings.data_index._db.items():
        column.setdefault(oid[-2], []).append(value.prettyPrint())

    return list(zip(column.get(1, []), column.get(2, [])))


def test_files_of_recording_removed_are_closed(recordings, datadir):
    write_recording(datadir / "doomed.snmprec", "Doomed device")

    assert recordings.rescan() == (1, 0, 1)

    engine, context = recordings.snmp_engine, recordings.snmp_context

    assert sorted(engine.communities.values()) == ["doomed", "public"]
    assert sorted(index_of(recordings)) == [
        (str(datadir / "doomed.snmprec"), "doomed"),
        (str(datadir / "public.snmprec"), "public"),
    ]

    kept = context.names["public"]
    doomed = context.names["doomed"]

    for mib_instrum in kept, doomed:
        mib_instrum.read_variables(((1, 3, 6, 1, 2, 1, 1, 1, 0), univ.Null("")))

    kept_index = kept._data_file._record_index
    doomed_index = doomed._data_file._record_index

    assert kept_index.is_open() and doomed_index.is_open()

    os.remove(datadir / "doomed.snmprec")

    assert recordings.rescan() == (0, 1, 1)

    assert not doomed_index.is_open()
    assert list(engine.communities.values()) == ["public"]
    assert "doomed" not in context.names
    assert len(context.names) == 2  # the community and its MD5
    assert index_of(recordings) == [(str(datadir / "public.snmprec"), "public")]

    # what stays is the very object which served before, its files open
    assert context.names["public"] is kept
    assert kept_index.is_open()


def test_recording_replaced_under_its_name_takes_the_community(recordings, datadir):
    """A community goes to the file which is first in the directory now."""
    write_recording(datadir / "self" / "public.snmprec", "Other device")

    # the one served already keeps the community, whichever comes first
    assert recordings.rescan() == (0, 0, 1)

    os.remove(datadir / "public.snmprec")

    assert recordings.rescan() == (1, 1, 0)

    context = recordings.snmp_context

    assert index_of(recordings) == [
        (str(datadir / "self" / "public.snmprec"), "public")
    ]
    assert context.names["public"].read_variables(
        ((1, 3, 6, 1, 2, 1, 1, 1, 0), univ.Null(""))
    )[0][1].asOctets() == (b"Other device")
