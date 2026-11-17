import asyncio
import os
import sys
import threading
import time

import pytest
from pysnmp.hlapi.asyncio import *

from snmpsim.commands.responder_lite import main as responder_main

TIME_OUT = int(os.getenv("SNMPSIM_TEST_TIMEOUT", "15"))
PORT_NUMBER = 1617  # Using a unique port to avoid conflicts with other tests


@pytest.fixture(autouse=True)
def setup_args():
    original_argv = sys.argv
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data", "agent")
    test_args = [
        "responder_lite.py",
        f"--data-dir={data_dir}",
        f"--agent-udpv4-endpoint=127.0.0.1:{PORT_NUMBER}",
    ]
    sys.argv = test_args
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
            print("Application stopped.")
            loop.close()

    app_thread = threading.Thread(target=target, daemon=True)
    app_thread.start()
    # Allow some time for the application to initialize and run
    time.sleep(1)
    yield
    app_thread.join(timeout=TIME_OUT)


@pytest.mark.asyncio
async def test_lite_responder_serves_v2c(run_app_in_background):
    """The lite responder answers GET, GETNEXT and GETBULK."""
    snmpEngine = SnmpEngine()

    try:
        transport = await UdpTransportTarget.create(
            ("127.0.0.1", PORT_NUMBER), retries=0
        )
        auth_data = CommunityData("public", mpModel=1)

        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmpEngine,
            auth_data,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
        )

        assert errorIndication is None, f"Error: {errorIndication}"
        assert errorStatus == 0, f"Error status: {errorStatus}"
        assert varBinds[0][1].prettyPrint() == "Test device"

        errorIndication, errorStatus, errorIndex, varBinds = await next_cmd(
            snmpEngine,
            auth_data,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.2.0")),
        )

        assert errorIndication is None, f"Error: {errorIndication}"
        assert errorStatus == 0, f"Error status: {errorStatus}"
        assert str(varBinds[0][0]) == "1.3.6.1.2.1.2.2.1.2.1"
        assert varBinds[0][1].prettyPrint() == "GigabitEthernet0/1"

        all_results = []

        async for errorIndication, errorStatus, errorIndex, varBinds in bulk_walk_cmd(
            snmpEngine,
            auth_data,
            transport,
            ContextData(),
            0,
            10,  # Non-repeaters, Max-repetitions
            ObjectType(ObjectIdentity("1.3.6.1.2.1.2")),
            lexicographicMode=False,
        ):
            assert errorIndication is None, f"Error: {errorIndication}"
            assert errorStatus == 0, f"Error status: {errorStatus}"

            all_results.extend(varBinds)

        served = {str(oid): val.prettyPrint() for oid, val in all_results}

        assert served == {
            "1.3.6.1.2.1.2.2.1.2.1": "GigabitEthernet0/1",
            "1.3.6.1.2.1.2.2.1.5.1": "1000000000",
        }

    finally:
        if snmpEngine.transport_dispatcher:
            snmpEngine.transport_dispatcher.close_dispatcher()


LANE_PORT_NUMBER = 1660


@pytest.fixture
def lane_port():
    """Start the next responder on a port of its own.

    The responder of an earlier test keeps serving its port from a daemon
    thread, so a second one has to listen elsewhere.
    """
    sys.argv = [
        f"--agent-udpv4-endpoint=127.0.0.1:{LANE_PORT_NUMBER}"
        if arg.startswith("--agent-udpv4-endpoint=")
        else arg
        for arg in sys.argv
    ]


@pytest.mark.asyncio
async def test_lite_responder_decodes_version_by_current_name(
    monkeypatch, lane_port, run_app_in_background
):
    """A GET is answered without pysnmp's camelCase version decoder.

    `pysnmp.proto.api.decodeMessageVersion` is a leftover alias of
    `verdec.decode_message_version`; the responder must not depend on it.
    """
    monkeypatch.delattr("pysnmp.proto.api.decodeMessageVersion")

    snmpEngine = SnmpEngine()

    try:
        transport = await UdpTransportTarget.create(
            ("127.0.0.1", LANE_PORT_NUMBER), timeout=TIME_OUT, retries=0
        )

        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmpEngine,
            CommunityData("public", mpModel=1),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
        )

        assert errorIndication is None, f"Error: {errorIndication}"
        assert errorStatus == 0, f"Error status: {errorStatus}"
        assert varBinds[0][1].prettyPrint() == "Test device"

    finally:
        if snmpEngine.transport_dispatcher:
            snmpEngine.transport_dispatcher.close_dispatcher()


ARGS_FILE_PORT_NUMBER = 1661


@pytest.fixture
def args_file(tmp_path):
    """Leave nothing but `--args-from-file` on the command line."""
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "agent")

    path = tmp_path / "responder.args"
    path.write_text(
        f"--data-dir={data_dir}\n"
        f"--agent-udpv4-endpoint=127.0.0.1:{ARGS_FILE_PORT_NUMBER}\n"
    )

    sys.argv = ["responder_lite.py", f"--args-from-file={path}"]


@pytest.mark.asyncio
async def test_lite_responder_reads_options_from_file(args_file, run_app_in_background):
    """Options kept in a file configure the responder as if typed in.

    The file has the format the full responder reads: `--option=value`
    items separated by whitespace.
    """
    snmpEngine = SnmpEngine()

    try:
        transport = await UdpTransportTarget.create(
            ("127.0.0.1", ARGS_FILE_PORT_NUMBER), timeout=TIME_OUT, retries=0
        )

        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmpEngine,
            CommunityData("public", mpModel=1),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
        )

        assert errorIndication is None, f"Error: {errorIndication}"
        assert errorStatus == 0, f"Error status: {errorStatus}"
        assert varBinds[0][1].prettyPrint() == "Test device"

    finally:
        if snmpEngine.transport_dispatcher:
            snmpEngine.transport_dispatcher.close_dispatcher()


def test_lite_responder_reports_unreadable_args_file(tmp_path, capsys):
    """A missing options file is an error message, not a traceback."""
    missing = tmp_path / "no-such.args"

    sys.argv = ["responder_lite.py", f"--args-from-file={missing}"]

    assert responder_main() == 1

    assert "ERROR: file %s opening failure" % missing in capsys.readouterr().err


BOTH_SOURCES_PORT_NUMBER = 1662


@pytest.fixture
def args_file_and_command_line(tmp_path):
    """Give a data directory in the file and another on the command line."""
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "agent")

    more_data = tmp_path / "more-data"
    more_data.mkdir()
    (more_data / "other.snmprec").write_text("1.3.6.1.2.1.1.1.0|4|Other device\n")

    path = tmp_path / "responder.args"
    path.write_text(
        f"--data-dir={data_dir}\n"
        f"--agent-udpv4-endpoint=127.0.0.1:{BOTH_SOURCES_PORT_NUMBER}\n"
    )

    sys.argv = [
        "responder_lite.py",
        f"--args-from-file={path}",
        f"--data-dir={more_data}",
    ]


@pytest.mark.asyncio
async def test_lite_responder_adds_up_repeatable_options(
    args_file_and_command_line, run_app_in_background
):
    """`--data-dir` on the command line does not replace the one in the file.

    An option that can be given more than once collects the values of both
    sources, so both directories are served.
    """
    snmpEngine = SnmpEngine()

    try:
        transport = await UdpTransportTarget.create(
            ("127.0.0.1", BOTH_SOURCES_PORT_NUMBER), timeout=TIME_OUT, retries=0
        )

        for community, expected in (
            ("public", "Test device"),
            ("other", "Other device"),
        ):
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                snmpEngine,
                CommunityData(community, mpModel=1),
                transport,
                ContextData(),
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
            )

            assert errorIndication is None, f"{community}: {errorIndication}"
            assert errorStatus == 0, f"{community}: {errorStatus}"
            assert varBinds[0][1].prettyPrint() == expected

    finally:
        if snmpEngine.transport_dispatcher:
            snmpEngine.transport_dispatcher.close_dispatcher()


def test_lite_responder_refuses_endpoint_families_split_between_sources(
    tmp_path, capsys
):
    """IPv4 endpoints in the file do not mix with IPv6 ones typed in."""
    path = tmp_path / "responder.args"
    path.write_text("--agent-udpv4-endpoint=127.0.0.1:1663\n")

    sys.argv = [
        "responder_lite.py",
        f"--args-from-file={path}",
        "--agent-udpv6-endpoint=[::1]:1663",
    ]

    with pytest.raises(SystemExit) as exit_info:
        responder_main()

    assert exit_info.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err
