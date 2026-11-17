import asyncio
import contextlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

import pytest
from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    get_cmd,
)

# how long a responder may take to answer its first request
STARTUP_DEADLINE = 30

# no test run takes that long: a responder whose pytest was killed, so that
# nobody is left to terminate it, goes away by itself
LIFETIME = 600


def snmp_get(port, oid, community="public", timeout=2):
    """Ask 127.0.0.1:port for one OID over SNMPv2c.

    Returns error-indication, error-status and the var-binds. Runs on a loop
    of its own, so it can be called from a fixture or a plain test.
    """

    async def get():
        snmp_engine = SnmpEngine()
        try:
            return await get_cmd(
                snmp_engine,
                CommunityData(community, mpModel=1),
                await UdpTransportTarget.create(
                    ("127.0.0.1", port), timeout=timeout, retries=0
                ),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )

        finally:
            if snmp_engine.transport_dispatcher:
                snmp_engine.transport_dispatcher.close_dispatcher()

    loop = asyncio.new_event_loop()
    try:
        error_indication, error_status, _, var_binds = loop.run_until_complete(get())

    finally:
        loop.close()

    return error_indication, error_status, var_binds


def stop_process(process):
    """End a process started with `sys.executable`, and whatever it started.

    On Windows the python.exe of a virtual environment is a launcher which
    runs the interpreter as a process of its own: terminating the launcher
    leaves the responder serving, its port taken. The whole tree goes there.
    """
    if process.poll() is None:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        else:
            process.terminate()

    try:
        process.wait(timeout=10)

    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


@pytest.fixture(scope="session")
def process_stopper():
    """Hand out `stop_process`, see there."""
    return stop_process


@contextlib.contextmanager
def responder_thread(main):
    """Run `main`, a responder's, in a thread for as long as the block lasts.

    The responder takes its options from `sys.argv`. The block is entered
    once its indexes are built and its endpoints bound - the moment its
    dispatcher starts serving - not after a guessed delay; when the block is
    left, the dispatcher is closed and the thread waited for, so that the
    port is free again for whoever comes next. A --timeout is not needed and
    had better be left out: it is the responder's whole lifetime, and a slow
    machine could see it end in the middle of a test.

    A responder which is still starting when the block is left - it took
    too long - does not get to serve: its dispatcher closes itself instead.
    """
    from snmpsim.commands import responder

    serving = threading.Event()
    stopping = threading.Event()
    dispatchers = []
    failures = []

    class Dispatcher(responder.AsyncioDispatcher):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            dispatchers.append(self)

        def run_dispatcher(self, timeout=0.0):
            if stopping.is_set():
                self.close_dispatcher()
                return

            # set from within the loop: it runs, the endpoints are bound
            self.loop.call_soon(serving.set)
            super().run_dispatcher(timeout)

    def target():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            status = main()

            if status:
                failures.append(f"the responder exited with {status}")

        except BaseException as exc:
            failures.append(f"the responder raised {exc!r}")

        finally:
            # closed transports let their sockets go in a callback of the
            # loop, which has stopped by now: give it a turn to run that
            loop.run_until_complete(asyncio.sleep(0.05))
            loop.close()

    def stop():
        stopping.set()

        for dispatcher in dispatchers:
            try:
                dispatcher.loop.call_soon_threadsafe(dispatcher.close_dispatcher)

            except RuntimeError:  # its loop is closed, the responder ended
                pass

        thread.join(STARTUP_DEADLINE)

    thread = threading.Thread(target=target, daemon=True)

    original, responder.AsyncioDispatcher = responder.AsyncioDispatcher, Dispatcher

    try:
        thread.start()

        deadline = time.monotonic() + STARTUP_DEADLINE

        while not serving.wait(0.1):
            if not thread.is_alive():
                pytest.fail(
                    "the responder ended before serving: "
                    + ("; ".join(failures) or "no reason given")
                    + " - its log is in the captured output"
                )

            if time.monotonic() > deadline:
                pytest.fail(f"the responder did not serve in {STARTUP_DEADLINE} sec")

        yield

    finally:
        stop()
        responder.AsyncioDispatcher = original

    # reached only when the block went well: a failure of its own comes first
    if thread.is_alive():
        pytest.fail("the responder did not stop")

    if failures:
        pytest.fail("; ".join(failures) + " - its log is in the captured output")


@pytest.fixture(scope="session")
def responder_in_thread():
    """Hand out `responder_thread`, see there."""
    return responder_thread


@contextlib.contextmanager
def running_responder(*options, port, oid, community="public"):
    """Run a responder in a process of its own for as long as the block lasts.

    The block is entered once the responder has answered a GET of `oid`, not
    after a guessed delay, and the responder lives until the block is left:
    its --timeout, which is its whole lifetime, is far longer than anything
    the tests are going to do with it. That --timeout comes last and wins
    over one in `options`.

    `options` come first on the command line, the endpoint after them, so
    that an engine given by --v3-engine-id gets the endpoint: options after
    a --v3-engine-id belong to that engine, and an endpoint before it would
    make an engine of its own. With several --v3-engine-id, only the last
    engine gets it.

    The port has to be free, and is checked before the responder starts.
    Were somebody else answering on it, the probe could be answered by them
    before our responder has given up on the port, and the tests would run
    against their data.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))

        except OSError as exc:
            pytest.fail(f"port {port} is in use, no responder started: {exc}")

    with tempfile.TemporaryFile() as stderr:
        responder = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "snmpsim.commands.responder",
            ]
            + list(options)
            + [
                f"--agent-udpv4-endpoint=127.0.0.1:{port}",
                f"--timeout={LIFETIME}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=stderr,
        )

        def said():
            stderr.seek(0)
            return stderr.read().decode(errors="replace")

        def alive():
            if responder.poll() is not None:
                pytest.fail(
                    f"the responder on port {port} exited with "
                    f"{responder.returncode}:\n{said()}"
                )

        try:
            deadline = time.monotonic() + STARTUP_DEADLINE

            while True:
                alive()

                error_indication, _, _ = snmp_get(port, oid, community, timeout=0.5)

                if error_indication is None:
                    break

                if time.monotonic() > deadline:
                    pytest.fail(
                        f"the responder on port {port} did not answer in "
                        f"{STARTUP_DEADLINE} sec ({error_indication}):\n{said()}"
                    )

                # a GET which fails at once must not turn this into a busy loop
                time.sleep(0.1)

            # a responder which crashed right after its first answer would
            # otherwise leave the tests talking to nobody
            time.sleep(0.2)
            alive()

            yield f"127.0.0.1:{port}"

        finally:
            stop_process(responder)


@pytest.fixture(scope="session")
def responder_process():
    """Hand out `running_responder`, see there."""
    return running_responder


@pytest.fixture(scope="session")
def get_from_responder():
    """Hand out `snmp_get`, see there."""
    return snmp_get
