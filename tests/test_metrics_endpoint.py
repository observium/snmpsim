import asyncio
import glob
import hashlib
import json
import os
import sys
import threading
import time

import pytest
from pysnmp.hlapi.asyncio import *

from snmpsim.commands.responder import main as responder_main

TIME_OUT = int(os.getenv("SNMPSIM_TEST_TIMEOUT", "15"))
PORT_NUMBER = 1620  # Using a unique port to avoid conflicts with other tests


@pytest.fixture
def reports_dir(tmp_path):
    return tmp_path / "metrics"


@pytest.fixture(autouse=True)
def setup_args(reports_dir):
    original_argv = sys.argv
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data", "probe")
    sys.argv = [
        "responder.py",
        f"--data-dir={data_dir}",
        f"--agent-udpv4-endpoint=127.0.0.1:{PORT_NUMBER}",
        # dump after every second, so one request and a pause is enough
        f"--reporting-method=fulljson:{reports_dir}:1",
    ]
    yield
    sys.argv = original_argv


@pytest.fixture
def run_app_in_background():
    def target():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            responder_main()
        except KeyboardInterrupt:
            print("Application interrupted.")
        finally:
            loop.close()

    app_thread = threading.Thread(target=target, daemon=True)
    app_thread.start()
    time.sleep(1)
    yield
    app_thread.join(timeout=TIME_OUT)


async def _get(oid="1.3.6.1.2.1.1.1.0"):
    snmpEngine = SnmpEngine()

    try:
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmpEngine,
            CommunityData("public"),
            await UdpTransportTarget.create(("127.0.0.1", PORT_NUMBER), retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        assert errorIndication is None, f"Error: {errorIndication}"
        assert errorStatus == 0, f"Error status: {errorStatus}"

    finally:
        if snmpEngine.transport_dispatcher:
            snmpEngine.transport_dispatcher.close_dispatcher()


@pytest.mark.asyncio
async def test_activity_is_reported_per_recording(run_app_in_background, reports_dir):
    """A served request has to end up in the metrics dump, counters and all.

    Two things used to keep this empty. The dump was built in a temporary file
    in the system temp directory and renamed into the reports directory, which
    fails wherever /tmp is a filesystem of its own. And the reporting context
    carried no transport endpoint - pysnmp 7 renamed the accessor for it, so
    the port left the key out entirely and every counter update was dropped on
    a KeyError, leaving a dump with nothing but its header.
    """
    await _get()

    time.sleep(1.5)

    # the reporter writes from within a request, so the second one flushes
    await _get()

    time.sleep(0.5)

    dumps = glob.glob(os.path.join(str(reports_dir), "fulljson", "*.json"))

    assert dumps, "no metrics dump was written at all"

    with open(sorted(dumps)[-1]) as fl:
        doc = json.load(fl)

    assert doc["format"] == "fulljson"

    endpoint = doc["udpv4"][f"127.0.0.1:{PORT_NUMBER}"]

    assert endpoint["transport_domain"]

    peer = endpoint["127.0.0.1"]

    assert peer["packets"] >= 1

    recordings = [
        (path, counters)
        for path, counters in _leaves(peer)
        if path[-1].endswith(".snmprec")
    ]

    assert recordings, "the dump carries no per-recording counters"

    path, counters = recordings[0]

    # the responder registers each community under the md5 of its name, so
    # that is what the security name in the metrics is
    assert path[3] == hashlib.md5(b"public").hexdigest()
    assert path[-2].endswith("RequestPDU")
    assert counters["pdus"] >= 1
    assert counters["varbinds"] >= 1


def _leaves(node, path=()):
    for key, value in node.items():
        if not isinstance(value, dict):
            continue

        if isinstance(value.get("pdus"), int):
            yield path + (key,), value

        else:
            yield from _leaves(value, path + (key,))
