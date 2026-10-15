import asyncio
import os
import sys
import threading
import time

import pytest

from snmpsim.commands import cmd2rec
from snmpsim.commands.cmd2rec import main as cmd2rec_main
from snmpsim.commands.responder import main as responder_main

TIME_OUT = int(os.getenv("SNMPSIM_TEST_TIMEOUT", "15"))
PORT_NUMBER = 1618  # Using a unique port to avoid conflicts with other tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data", "agent")


@pytest.fixture
def run_app_in_background():
    original_argv = sys.argv

    def target():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        sys.argv = [
            "responder.py",
            f"--data-dir={DATA_DIR}",
            f"--agent-udpv4-endpoint=127.0.0.1:{PORT_NUMBER}",
        ]
        try:
            responder_main()
        except KeyboardInterrupt:
            print("Application interrupted.")
        finally:
            print("Application stopped.")
            loop.close()

    app_thread = threading.Thread(target=target, daemon=True)
    app_thread.start()
    # Allow some time for the application to initialize and run
    time.sleep(1)
    yield
    sys.argv = original_argv
    app_thread.join(timeout=TIME_OUT)


@pytest.mark.parametrize("mode", ["getnext", "getbulk"])
def test_recording_an_agent(run_app_in_background, monkeypatch, tmp_path, mode):
    """Walking an agent produces a recording of everything it serves.

    pysnmp hands over one response per request and does not continue a walk
    on its own, so the recorder drives it; without that it used to write an
    empty file and hang forever.
    """
    output_file = tmp_path / "recorded.snmprec"

    argv = [
        "snmpsim-record-commands",
        f"--agent-udpv4-endpoint=127.0.0.1:{PORT_NUMBER}",
        "--community=public",
        f"--output-file={output_file}",
    ]

    if mode == "getbulk":
        argv.append("--use-getbulk")

    monkeypatch.setattr(sys, "argv", argv)

    assert cmd2rec_main() == 0

    with open(output_file, "rb") as recording:
        records = recording.read().decode("iso-8859-1").splitlines()

    served = {}

    for record in records:
        oid, tag, value = record.split("|", 2)
        served[oid] = bytes.fromhex(value).decode() if tag.endswith("x") else value

    assert served == {
        "1.3.6.1.2.1.1.1.0": "Test device",
        "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.99999",
        "1.3.6.1.2.1.1.3.0": "123456",
        "1.3.6.1.2.1.2.2.1.2.1": "GigabitEthernet0/1",
        "1.3.6.1.2.1.2.2.1.5.1": "1000000000",
    }


def test_progress_counts_oids_not_passes():
    """Progress shows how many OIDs are in, and the pass only when there is one.

    It used to print "pass/count", so a plain walk read as "0/100".
    """
    assert cmd2rec._progress_message(total=300, iteration=0) == "OIDs dumped: 300"
    assert (
        cmd2rec._progress_message(total=1300, iteration=2)
        == "OIDs dumped: 1300, iteration 2"
    )


def test_summary_rate_is_over_all_oids():
    """The rate is every OID over the elapsed time, fractions included.

    It used to floor-divide the count of the last pass only, so 362 OIDs in
    71.18 sec read as 5.00 and a multi-pass recording as 0.00.
    """
    assert cmd2rec._summary_message(total=362, elapsed=71.18, errors=0) == (
        "OIDs dumped: 362, elapsed: 71.18 sec, rate: 5.09 OIDs/sec, errors: 0"
    )
    assert cmd2rec._summary_message(total=0, elapsed=0, errors=1) == (
        "OIDs dumped: 0, elapsed: 0.00 sec, rate: 0.00 OIDs/sec, errors: 1"
    )
