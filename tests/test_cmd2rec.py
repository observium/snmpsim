import asyncio
import logging
import os
import socket
import subprocess
import sys
import textwrap
import threading
import time
import warnings

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


def _record_with_multiplex(monkeypatch, output_file, snapshots_dir):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "snmpsim-record-commands",
            f"--agent-udpv4-endpoint=127.0.0.1:{PORT_NUMBER}",
            "--community=public",
            "--start-object=1.3.6.1.2.1",
            f"--output-file={output_file}",
            "--variation-module=multiplex",
            # two colons, so a drive letter stays part of the path on Windows
            f"--variation-module-options=dir::{snapshots_dir.as_posix()}",
        ],
    )

    assert cmd2rec_main() == 0


def test_recording_with_multiplex_dumps_oids(
    run_app_in_background, monkeypatch, tmp_path, caplog
):
    """A variation module is told which OID the recording starts at.

    The recorder handed that over under a name no module reads, so the
    multiplex, sql and redis modules failed on the first OID and the
    recording came out empty.

    The snapshot is complete by the time the recorder returns, too: multiplex
    closed it only between iterations, so after the last one it was whatever
    the interpreter got around to flushing on its way out - nothing at times.
    """
    caplog.set_level(logging.DEBUG)

    output_file = tmp_path / "recorded.snmprec"
    snapshots_dir = tmp_path / "snapshots"

    _record_with_multiplex(monkeypatch, output_file, snapshots_dir)

    # the recording itself is one record sending the responder to the snapshots
    with open(output_file, "rb") as recording:
        records = recording.read().decode("iso-8859-1").splitlines()

    assert records == [
        f"1.3.6.1.2.1|:multiplex|dir={snapshots_dir.as_posix()},period=10.00"
    ]

    # ...and the snapshot holds everything the agent serves
    snapshots = sorted(snapshots_dir.iterdir())

    assert [snapshot.name for snapshot in snapshots] == ["00000.snmprec"]

    with open(snapshots[0], "rb") as snapshot:
        dumped = [line.split("|")[0] for line in snapshot.read().decode().splitlines()]

    assert dumped == [
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.2.1.1.2.0",
        "1.3.6.1.2.1.1.3.0",
        "1.3.6.1.2.1.2.2.1.2.1",
        "1.3.6.1.2.1.2.2.1.5.1",
    ]

    summary = [line for line in caplog.messages if "elapsed:" in line]

    assert len(summary) == 1
    assert summary[0].startswith("OIDs dumped: 1, ")


MULTIPLEX_PORT_NUMBER = 1690


@pytest.mark.parametrize("snapshot_name", ["00000.snmprec", "00000..snmprec"])
def test_multiplex_recording_is_served(
    run_app_in_background,
    responder_process,
    get_from_responder,
    monkeypatch,
    tmp_path,
    snapshot_name,
):
    """What multiplex has recorded, the responder serves.

    Snapshots used to be named with two dots, "00000..snmprec", which the
    responder could not make a number of; those already on disk are served
    as well.
    """
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    snapshots_dir = tmp_path / "snapshots"

    _record_with_multiplex(monkeypatch, data_dir / "public.snmprec", snapshots_dir)

    (snapshots_dir / "00000.snmprec").rename(snapshots_dir / snapshot_name)

    with responder_process(
        f"--data-dir={data_dir}",
        port=MULTIPLEX_PORT_NUMBER,
        # outside of the recorded subtree, so the snapshot is not opened yet
        oid="1.3.6.1.4.1.1.0",
    ):
        error_indication, error_status, var_binds = get_from_responder(
            MULTIPLEX_PORT_NUMBER, "1.3.6.1.2.1.1.1.0"
        )

    assert error_indication is None
    assert not error_status, error_status.prettyPrint()
    assert var_binds[0][1].asOctets() == b"Test device"


V3_PORT_NUMBER = 1630

V3_USERS = {
    "authNoPriv": [
        "--v3-user=recauth",
        "--v3-auth-key=authkey12345",
        "--v3-auth-proto=SHA",
    ],
    "authPriv": [
        "--v3-user=recpriv",
        "--v3-auth-key=authkey12345",
        "--v3-auth-proto=SHA",
        "--v3-priv-key=privkey12345",
        "--v3-priv-proto=AES",
    ],
}


@pytest.fixture(scope="module")
def v3_agent(responder_process):
    """A responder of its own, knowing one USM user per security level"""
    with responder_process(
        f"--data-dir={DATA_DIR}",
        *[option for options in V3_USERS.values() for option in options],
        port=V3_PORT_NUMBER,
        oid="1.3.6.1.2.1.1.1.0",
    ) as endpoint:
        yield endpoint


def _record(monkeypatch, output_file, endpoint, *options):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "snmpsim-record-commands",
            f"--agent-udpv4-endpoint={endpoint}",
            f"--output-file={output_file}",
        ]
        + list(options),
    )

    assert cmd2rec_main() == 0

    with open(output_file, "rb") as recording:
        return recording.read()


@pytest.mark.parametrize("sec_level", list(V3_USERS))
@pytest.mark.parametrize("mode", ["getnext", "getbulk"])
def test_recording_an_agent_over_v3(v3_agent, monkeypatch, tmp_path, sec_level, mode):
    """An agent that only answers SNMPv3 can be recorded.

    The recorder took all the --v3-* options, but --protocol-version knew
    only 1 and 2c, so none of them was ever used: with --v3-user it went on
    asking over v2c with the "public" community.
    """
    walk = ["--use-getbulk"] if mode == "getbulk" else []

    over_v2c = _record(
        monkeypatch, tmp_path / "v2c.snmprec", v3_agent, "--community=public", *walk
    )

    over_v3 = _record(
        monkeypatch,
        tmp_path / "v3.snmprec",
        v3_agent,
        "--v3-context-name=public",
        *V3_USERS[sec_level],
        *walk,
    )

    assert len(over_v2c.splitlines()) == 5
    assert over_v3 == over_v2c


def test_recording_over_v3_names_the_context(v3_agent, monkeypatch, tmp_path, caplog):
    """The context name is sent as given and shows up in the log.

    It was kept as a plain string, which the line logging the SNMPv3
    settings could not print.
    """
    caplog.set_level(logging.DEBUG)

    _record(
        monkeypatch,
        tmp_path / "v3.snmprec",
        v3_agent,
        "--protocol-version=3",
        "--v3-context-name=public",
        *V3_USERS["authPriv"],
    )

    assert "Context name: public, SecurityName: recpriv" in caplog.text


def test_v3_user_implies_protocol_3():
    """The protocol follows from the credentials unless it is spelled out."""
    resolve = cmd2rec._resolve_protocol_version

    assert resolve(None, "recauth") == "3"
    assert resolve("3", "recauth") == "3"
    assert resolve(None, None) == "2c"
    assert resolve("2c", None) == "2c"
    assert resolve("1", None) == "1"
    # asking for v3 without a user is reported where the user is looked for
    assert resolve("3", None) == "3"


@pytest.mark.parametrize("version", ["1", "2c"])
def test_v3_user_with_v2c_is_rejected(monkeypatch, tmp_path, capsys, version):
    """A USM user can not go with a community-based protocol version.

    Nothing is written either: an existing recording is not truncated by a
    command line that is going to be turned down.
    """
    output_file = tmp_path / "recorded.snmprec"
    output_file.write_bytes(b"1.3.6.1.2.1.1.1.0|4|kept\n")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "snmpsim-record-commands",
            f"--agent-udpv4-endpoint=127.0.0.1:{V3_PORT_NUMBER + 1}",
            f"--output-file={output_file}",
            f"--protocol-version={version}",
            "--v3-user=recauth",
        ],
    )

    assert cmd2rec_main() == 1

    assert (
        f"ERROR: --v3-user can not be used with --protocol-version {version}"
        in capsys.readouterr().err
    )
    assert output_file.read_bytes() == b"1.3.6.1.2.1.1.1.0|4|kept\n"


FAILURES_PORT_NUMBER = 1631
SILENT_PORT_NUMBER = 1632


@pytest.fixture(scope="module")
def plain_agent(responder_process):
    """A responder for the recordings whose exit code is looked at"""
    with responder_process(
        f"--data-dir={DATA_DIR}",
        port=FAILURES_PORT_NUMBER,
        oid="1.3.6.1.2.1.1.1.0",
    ) as endpoint:
        yield endpoint


def _run_recorder(*options):
    """Run the recorder the way its console script does, in its own process"""
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from snmpsim.commands.cmd2rec import main; sys.exit(main())",
        ]
        + list(options),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )


def test_recorder_compiles_without_warnings():
    """Nothing in the recorder makes the compiler complain.

    main() returned from inside a "finally" block, which Python 3.14 warns
    about on every start of the recorder.
    """
    with open(cmd2rec.__file__, encoding="utf-8") as source:
        code = source.read()

    with warnings.catch_warnings():
        warnings.simplefilter("error")

        compile(code, cmd2rec.__file__, "exec")


def test_good_recording_exits_with_zero(plain_agent, tmp_path):
    output_file = tmp_path / "recorded.snmprec"

    recorder = _run_recorder(
        f"--agent-udpv4-endpoint={plain_agent}",
        "--community=public",
        f"--output-file={output_file}",
    )

    assert recorder.returncode == 0, recorder.stderr.decode()
    assert len(output_file.read_bytes().splitlines()) == 5


def test_silent_agent_fails_the_recording(tmp_path):
    """Nobody answering is an error, and the exit code says so."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
        # holds the port without ever answering on it
        silent.bind(("127.0.0.1", SILENT_PORT_NUMBER))

        recorder = _run_recorder(
            f"--agent-udpv4-endpoint=127.0.0.1:{SILENT_PORT_NUMBER}",
            "--community=public",
            "--timeout=1",
            "--retries=0",
            f"--output-file={tmp_path / 'recorded.snmprec'}",
        )

    stderr = recorder.stderr.decode()

    assert recorder.returncode == 1, stderr
    assert "No SNMP response received before timeout" in stderr
    assert "errors: 1" in stderr


FAILING_HANDLERS = {
    "init": ("init", 'raise RuntimeError("no way to start")', "no way to start"),
    "record": ("record", 'raise RuntimeError("no way to write")', "no way to write"),
    "record-refused": (
        "record",
        'raise error.SnmpsimError("no way to keep")',
        "no way to keep",
    ),
    "shutdown": ("shutdown", 'raise RuntimeError("no way to end")', "no way to end"),
}


@pytest.mark.parametrize("failure", list(FAILING_HANDLERS))
def test_failing_variation_module_fails_the_recording(plain_agent, tmp_path, failure):
    """A variation module that fails does not leave a recording called good.

    main() ended with a "return" inside "finally", so whatever the walk
    raised was dropped there and the recorder exited with 0. A module that
    failed to initialize was walked with all the same, and a record it
    refused was not counted as an error.
    """
    handler, body, complaint = FAILING_HANDLERS[failure]

    handlers = {name: "pass" for name in ("init", "shutdown")}
    handlers["record"] = "return oid, tag, value"
    handlers[handler] = body

    modules_dir = tmp_path / "variation"
    modules_dir.mkdir()

    (modules_dir / "failing.py").write_text(
        "from snmpsim import error\n\n"
        + "".join(
            f"def {name}({signature}**context):\n"
            + textwrap.indent(handlers[name], "    ")
            + "\n\n"
            for name, signature in (
                ("init", ""),
                ("record", "oid, tag, value, "),
                ("shutdown", ""),
            )
        )
    )

    recorder = _run_recorder(
        f"--agent-udpv4-endpoint={plain_agent}",
        "--community=public",
        f"--output-file={tmp_path / 'recorded.snmprec'}",
        f"--variation-modules-dir={modules_dir}",
        "--variation-module=failing",
    )

    stderr = recorder.stderr.decode()

    assert recorder.returncode == 1, stderr
    assert complaint in stderr
    assert "Traceback" not in stderr


@pytest.mark.parametrize("mode", ["getnext", "getbulk"])
def test_multiplex_iterations_need_no_stop_object(plain_agent, tmp_path, mode):
    """Every iteration asked of multiplex makes a snapshot of its own.

    The module starts the next snapshot once it is told the walk is over,
    and it was told so only when the walk ran into --stop-object. A walk up
    to the end of the MIB just ended, so however many iterations were asked
    for, a single snapshot was made.
    """
    output_file = tmp_path / "recorded.snmprec"
    snapshots_dir = tmp_path / "snapshots"

    recorder = _run_recorder(
        f"--agent-udpv4-endpoint={plain_agent}",
        "--community=public",
        "--start-object=1.3.6.1.2.1",
        f"--output-file={output_file}",
        "--variation-module=multiplex",
        f"--variation-module-options=dir::{snapshots_dir.as_posix()},"
        "iterations:3,period:1",
        *(["--use-getbulk"] if mode == "getbulk" else []),
    )

    stderr = recorder.stderr.decode()

    assert recorder.returncode == 0, stderr

    assert sorted(snapshot.name for snapshot in snapshots_dir.iterdir()) == [
        "00000.snmprec",
        "00001.snmprec",
        "00002.snmprec",
    ]

    # each of them holds everything the agent serves, and nothing else
    for snapshot in snapshots_dir.iterdir():
        dumped = [
            line.split("|")[0] for line in snapshot.read_text().splitlines() if line
        ]

        assert dumped == [
            "1.3.6.1.2.1.1.1.0",
            "1.3.6.1.2.1.1.2.0",
            "1.3.6.1.2.1.1.3.0",
            "1.3.6.1.2.1.2.2.1.2.1",
            "1.3.6.1.2.1.2.2.1.5.1",
        ], snapshot.name

    # the recording itself still is the one record leading to the snapshots
    assert output_file.read_text().splitlines() == [
        f"1.3.6.1.2.1|:multiplex|dir={snapshots_dir.as_posix()},period=1.00"
    ]

    assert "errors: 0" in stderr


def test_end_of_walk_is_not_a_record(plain_agent, tmp_path):
    """A module is told the walk is over, and nothing is written for that.

    What a module makes of the notice is no record of the agent's, even if
    the module hands one back.
    """
    modules_dir = tmp_path / "variation"
    modules_dir.mkdir()

    (modules_dir / "witness.py").write_text(
        "import sys\n\n"
        "def init(**context):\n"
        "    pass\n\n"
        "def record(oid, tag, value, **context):\n"
        "    if context['stopFlag']:\n"
        "        sys.stderr.write('walk is over after %s\\n' % oid)\n"
        "    return oid, tag, value\n\n"
        "def shutdown(**context):\n"
        "    pass\n"
    )

    output_file = tmp_path / "recorded.snmprec"

    recorder = _run_recorder(
        f"--agent-udpv4-endpoint={plain_agent}",
        "--community=public",
        f"--output-file={output_file}",
        f"--variation-modules-dir={modules_dir}",
        "--variation-module=witness",
    )

    stderr = recorder.stderr.decode()

    assert recorder.returncode == 0, stderr
    assert stderr.count("walk is over after") == 1, stderr
    # the module writes "\n", which Windows turns into "\r\n" in text mode
    assert "walk is over after 1.3.6.1.2.1.2.2.1.5.1" in stderr.splitlines()
    assert len(output_file.read_bytes().splitlines()) == 5
    assert "OIDs dumped: 5, " in stderr
