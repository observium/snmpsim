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
LITE_PORT = 1677
NO_PID_FILE_PORT = 1678
POOL_PORT = 1685

SYS_DESCR = "1.3.6.1.2.1.1.1.0"

# a daemon nobody stopped goes away by itself
LIFETIME = 60
DEADLINE = 30


def daemonize(cwd, port, *options, lifetime=LIFETIME):
    """Start a daemon from `cwd`, return how the process started ended."""
    return started_process(
        cwd,
        "-m",
        "snmpsim.commands.responder",
        "--daemonize",
        f"--agent-udpv4-endpoint=127.0.0.1:{port}",
        f"--timeout={lifetime}",
        *options,
    )


def started_process(cwd, *command):
    """Run python from `cwd` until it exits and nobody holds its stderr.

    A daemon which kept the standard error it was started with is waited
    for as well, up to the deadline.
    """
    return subprocess.run(
        [sys.executable] + list(command),
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


def test_nobody_holds_the_terminal_after_indexes_were_built_in_processes(
    workdir, get_from_responder
):
    """With two indexes to build there is a pool of processes, and with it
    multiprocessing's resource tracker, which lives as long as the daemon
    does: it must not have the standard error the daemon was started with.
    """
    for name in "first", "second", "third":
        shutil.copy(DATA_FILE, workdir / "data" / f"{name}.snmprec")

    # is back before the daemon ends, or runs into the deadline
    started = subprocess.run(
        [
            sys.executable,
            "-m",
            "snmpsim.commands.responder",
            "--daemonize",
            f"--agent-udpv4-endpoint=127.0.0.1:{POOL_PORT}",
            f"--timeout={LIFETIME}",
            "--data-dir=data",
            "--cache-dir=cache",
            "--pid-file=responder.pid",
            "--index-workers=2",
        ],
        cwd=workdir,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=DEADLINE,
        text=True,
    )

    assert started.returncode == 0, started.stderr
    assert "Indexing 4 data files in 2 processes" in started.stderr

    error_indication, _, var_binds = get_from_responder(POOL_PORT, SYS_DESCR)

    assert error_indication is None
    assert var_binds[0][1].asOctets() == b"Test device"


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
    """Nothing of it reaches the terminal, the exit code has to tell."""
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


def test_reports_are_written_where_the_daemon_was_started(workdir, get_from_responder):
    """The reports directory is made before the fork, and written to after."""
    started = daemonize(
        workdir,
        PORT,
        "--data-dir=data",
        "--cache-dir=cache",
        "--pid-file=responder.pid",
        "--reporting-method=fulljson:reports:1",
    )

    assert started.returncode == 0, started.stderr

    reports = workdir / "reports" / "fulljson"
    deadline = time.monotonic() + DEADLINE

    # a report is dumped by the first request after its period is over
    while not [name for name in os.listdir(reports) if name.endswith(".json")]:
        assert time.monotonic() < deadline, "no report was written"

        error_indication, _, _ = get_from_responder(PORT, SYS_DESCR)

        assert error_indication is None

        time.sleep(0.5)


def test_variation_modules_are_found_where_the_daemon_was_started(
    workdir, get_from_responder
):
    os.mkdir(workdir / "modules")

    with open(workdir / "modules" / "nearby.py", "w") as fl:
        fl.write(
            "def variate(oid, tag, value, **context):\n"
            "    return oid, tag, 'from a module nearby'\n"
        )

    with open(workdir / "data" / "public.snmprec", "w") as fl:
        fl.write(f"{SYS_DESCR}|4:nearby|\n")

    started = daemonize(
        workdir,
        PORT,
        "--data-dir=data",
        "--cache-dir=cache",
        "--pid-file=responder.pid",
        "--variation-modules-dir=modules",
    )

    assert started.returncode == 0, started.stderr

    error_indication, error_status, var_binds = get_from_responder(PORT, SYS_DESCR)

    assert error_indication is None
    assert not error_status
    assert var_binds[0][1].asOctets() == b"from a module nearby"


def test_no_pid_file_is_written_for_an_empty_name(workdir, get_from_responder):
    """Who cannot write /var/run asks for no pid file with --pid-file="""
    lifetime = 3

    started = daemonize(
        workdir,
        NO_PID_FILE_PORT,
        "--data-dir=data",
        "--cache-dir=cache",
        "--pid-file=",
        lifetime=lifetime,
    )

    try:
        assert started.returncode == 0, started.stderr

        error_indication, _, _ = get_from_responder(NO_PID_FILE_PORT, SYS_DESCR)

        assert error_indication is None
        assert sorted(os.listdir(workdir)) == ["cache", "data"]
        assert not [name for name in os.listdir(workdir.parent) if "tmp" in name]

    finally:
        # there is no pid to stop it by, it ends by its --timeout
        time.sleep(lifetime + 1)


def test_daemonize_does_not_wait_unless_asked_to(workdir):
    """Who never calls ready() must not keep its parent, nor the terminal."""
    with open(workdir / "daemon.py", "w") as fl:
        fl.write(
            "import sys, time\n"
            "from snmpsim import daemon\n"
            "daemon.daemonize(sys.argv[1])\n"
            "sys.stderr.write('said by the daemon')\n"
            "sys.stderr.flush()\n"
            f"time.sleep({LIFETIME})\n"
        )

    # is back before the daemon ends, or runs into the deadline
    started = started_process(workdir, "daemon.py", str(workdir / "responder.pid"))

    assert started.returncode == 0, started.stderr
    assert started.stderr == ""

    with open(workdir / "responder.pid") as fl:
        os.kill(int(fl.read()), 0)


def test_lite_responder_still_daemonizes(workdir, get_from_responder):
    """It does not report when it is ready, so nobody may wait for that."""
    started = started_process(
        workdir,
        "-m",
        "snmpsim.commands.responder_lite",
        "--daemonize",
        f"--agent-udpv4-endpoint=127.0.0.1:{LITE_PORT}",
        f"--data-dir={workdir / 'data'}",
        f"--cache-dir={workdir / 'cache'}",
        f"--pid-file={workdir / 'responder.pid'}",
    )

    assert started.returncode == 0, started.stderr

    deadline = time.monotonic() + DEADLINE

    while True:
        error_indication, _, var_binds = get_from_responder(
            LITE_PORT, SYS_DESCR, timeout=0.5
        )

        if error_indication is None:
            break

        assert time.monotonic() < deadline, error_indication

        time.sleep(0.1)

    assert var_binds[0][1].asOctets() == b"Test device"
