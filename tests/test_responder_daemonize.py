"""A daemonized responder says whether it started, and finds its files.

The process which was started used to exit with 0 right after fork(), long
before the daemon had read anything, so a daemon which then died of a port
in use, or of a pid file it could not write, looked just like one which
came up. The daemon also changes into "/", and took every relative path it
was given from there.
"""
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="there are no daemons on Windows"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "data", "agent", "public.snmprec")

PORT = 1675
BUSY_PORT = 1676

SYS_DESCR = "1.3.6.1.2.1.1.1.0"

# a daemon nobody stopped goes away by itself
LIFETIME = 60
DEADLINE = 30


def daemonize(cwd, port, *options):
    """Start a daemon from `cwd`, return how the process started ended."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "snmpsim.commands.responder",
            "--daemonize",
            f"--agent-udpv4-endpoint=127.0.0.1:{port}",
            f"--timeout={LIFETIME}",
        ]
        + list(options),
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=DEADLINE,
        text=True,
    )


def stop(pid_file):
    """Terminate the daemon the pid file names, wait until it is gone."""
    try:
        with open(pid_file) as fl:
            pid = int(fl.read())

    except (OSError, ValueError):
        return

    try:
        os.kill(pid, signal.SIGTERM)

        for _ in range(100):
            os.kill(pid, 0)
            time.sleep(0.1)

        os.kill(pid, signal.SIGKILL)

    except ProcessLookupError:
        pass


@pytest.fixture
def workdir(tmp_path):
    """A directory with a recording in data/, and the daemon stopped after."""
    os.mkdir(tmp_path / "data")
    shutil.copy(DATA_FILE, tmp_path / "data")

    yield tmp_path

    stop(tmp_path / "responder.pid")


def test_relative_paths_are_taken_from_where_the_daemon_was_started(
    workdir, get_from_responder
):
    started = daemonize(
        workdir,
        PORT,
        "--data-dir=data",
        "--cache-dir=cache",
        "--pid-file=responder.pid",
    )

    assert started.returncode == 0, started.stderr

    # no waiting and no retries: the daemon is up when its parent exits
    error_indication, error_status, var_binds = get_from_responder(PORT, SYS_DESCR)

    assert error_indication is None
    assert not error_status
    assert var_binds[0][1].asOctets() == b"Test device"

    assert os.listdir(workdir / "cache")

    with open(workdir / "responder.pid") as fl:
        pid = int(fl.read())

    assert pid != os.getpid()

    # the pid is the daemon's: with that process gone nobody answers
    stop(workdir / "responder.pid")

    error_indication, _, _ = get_from_responder(PORT, SYS_DESCR, timeout=0.5)

    assert error_indication is not None
    assert not os.path.exists(workdir / "responder.pid")


def test_port_in_use_is_reported_by_the_process_started(workdir):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as holder:
        holder.bind(("127.0.0.1", BUSY_PORT))

        started = daemonize(
            workdir,
            BUSY_PORT,
            "--data-dir=data",
            "--cache-dir=cache",
            "--pid-file=responder.pid",
        )

    assert started.returncode == 1, started.stderr
    assert f"failed to bind UDP/IPv4 endpoint 127.0.0.1:{BUSY_PORT}" in started.stderr
    assert "daemon did not start" in started.stderr
    assert not os.path.exists(workdir / "responder.pid")


def test_failure_logged_to_a_file_is_still_an_error_of_the_process_started(workdir):
    """The log file is relative too, and the parent points at it."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as holder:
        holder.bind(("127.0.0.1", BUSY_PORT))

        started = daemonize(
            workdir,
            BUSY_PORT,
            "--data-dir=data",
            "--cache-dir=cache",
            "--pid-file=responder.pid",
            "--logging-method=file:responder.log",
        )

    assert started.returncode == 1, started.stderr
    assert "daemon did not start" in started.stderr

    with open(workdir / "responder.log") as fl:
        assert f"failed to bind UDP/IPv4 endpoint 127.0.0.1:{BUSY_PORT}" in fl.read()


def test_pid_file_which_cannot_be_written_is_reported(workdir):
    started = daemonize(
        workdir,
        PORT,
        "--data-dir=data",
        "--cache-dir=cache",
        "--pid-file=no-such-directory/responder.pid",
    )

    assert started.returncode == 1, started.stderr
    assert "Failed to create PID file" in started.stderr
