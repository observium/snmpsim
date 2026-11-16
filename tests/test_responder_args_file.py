"""The full responder takes --max-var-binds from --args-from-file as well.

The engine options of a file given by --args-from-file are read by the
responder itself, not by its command-line parser, and --max-var-binds was
looked for there as --max-varbinds, a name no command line takes: the
documented name in such a file was passed over without a word, and the
engine served its GETBULK responses with the limit of the command line, 64
if none was given there. The old name is still read, a file written for it
keeps working.
"""
import asyncio
import os

import pytest
from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    bulk_cmd,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 40 rows, more than any limit below; about 200 octets each, so the message
# size is raised for the tests, lest it cut the response short first
DATA_DIR = os.path.join(BASE_DIR, "data", "bulk")

PORT = 1664

TABLE = "1.3.6.1.4.1.99999.1.1.1"
FIRST_ROW = TABLE + ".1"
MAX_REPETITIONS = 10


def bulk(port):
    """Ask for MAX_REPETITIONS rows of TABLE, return the OIDs answered."""

    async def run():
        snmp_engine = SnmpEngine()
        try:
            error_indication, error_status, _, var_binds = await bulk_cmd(
                snmp_engine,
                CommunityData("public", mpModel=1),
                await UdpTransportTarget.create(
                    ("127.0.0.1", port), timeout=2, retries=0
                ),
                ContextData(),
                0,
                MAX_REPETITIONS,
                ObjectType(ObjectIdentity(TABLE)),
            )

        finally:
            if snmp_engine.transport_dispatcher:
                snmp_engine.transport_dispatcher.close_dispatcher()

        assert error_indication is None
        assert not error_status

        return [str(name) for name, _ in var_binds]

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(run())

    finally:
        loop.close()


@pytest.mark.parametrize("option", ["--max-var-binds", "--max-varbinds"])
def test_max_var_binds_from_the_args_file_limits_getbulk(
    responder_process, tmp_path, option
):
    args_file = tmp_path / "responder.args"
    args_file.write_text(f"{option}=3\n")

    with responder_process(
        f"--data-dir={DATA_DIR}",
        f"--cache-dir={tmp_path / 'cache'}",
        "--max-message-size=65000",
        f"--args-from-file={args_file}",
        port=PORT,
        oid=FIRST_ROW,
    ):
        assert bulk(PORT) == [f"{TABLE}.{row}" for row in (1, 2, 3)]


def test_max_var_binds_on_the_command_line_still_limits_getbulk(
    responder_process, tmp_path
):
    with responder_process(
        f"--data-dir={DATA_DIR}",
        f"--cache-dir={tmp_path / 'cache'}",
        "--max-message-size=65000",
        "--max-var-binds=4",
        port=PORT,
        oid=FIRST_ROW,
    ):
        assert bulk(PORT) == [f"{TABLE}.{row}" for row in (1, 2, 3, 4)]
