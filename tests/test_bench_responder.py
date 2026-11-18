"""The benchmark harness in scripts/ counts what was served and runs both responders."""
import importlib.util
import os
import shutil
import sys

import pytest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(BASE_DIR), "scripts", "bench_responder.py")

# 40 rows under one table column
DATA_DIR = os.path.join(BASE_DIR, "data", "bulk")
TABLE = ".1.3.6.1.4.1.99999"
ROWS = 40

PORT = 1663


def load():
    spec = importlib.util.spec_from_file_location("bench_responder", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_walk_output_is_counted_by_the_values_served():
    bench = load()

    output = (
        b'.1.3.6.1.2.1.1.1.0 = STRING: "first\n'
        b'second"\n'
        b".1.3.6.1.2.1.1.5.0 = STRING: switch\n"
        b".1.3.6.1.2.1.1.6.0 = No Such Object available on this agent at this OID\n"
        b".1.3.6.1.2.1.1.7.0 = No more variables left in this MIB View (It is past"
        b" the end of the MIB tree)\n"
        b".1.3.6.1.2.1.1.7.0 = No more variables left in this MIB View (It is past"
        b" the end of the MIB tree)\n"
    )

    assert bench.count_oids(output) == 2


@pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("snmpget", "snmpbulkwalk", "snmpwalk")),
    reason="net-snmp tools are not installed",
)
@pytest.mark.skipif(sys.platform == "win32", reason="the harness is POSIX only")
@pytest.mark.parametrize("responder", ["full", "lite"])
def test_harness_walks_the_whole_table(tmp_path, responder):
    bench = load()

    result = bench.run(
        bench.parse_args(
            [
                f"--data-dir={DATA_DIR}",
                "--community=public",
                f"--cache-dir={tmp_path / 'cache'}",
                f"--responder={responder}",
                f"--port={PORT}",
                f"--bulk-oid={TABLE}",
                f"--getnext-oid={TABLE}",
                f"--profile={tmp_path / 'responder.prof'}",
            ]
        )
    )

    assert result["responder"] == responder
    assert result["bulk"]["oids"] == ROWS
    assert result["getnext"]["oids"] == ROWS
    assert result["bulk"]["oids_per_second"] > 0
    assert result["start_seconds"] > 0
    assert "pyasn1" in result["busy_seconds_by_package"]


def test_a_line_of_a_value_that_starts_like_an_oid_is_not_an_oid():
    bench = load()

    output = (
        b'.1.3.6.1.2.1.1.1.0 = STRING: "first\n'
        b'.1 is how the second line of it starts"\n'
        b".1.3.6.1.2.1.1.5.0 = STRING: switch\n"
    )

    assert bench.count_oids(output) == 2


def test_a_port_somebody_else_listens_on_is_refused():
    import socket

    bench = load()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as squatter:
        squatter.bind(("127.0.0.1", 0))
        port = squatter.getsockname()[1]

        with pytest.raises(SystemExit, match="in use"):
            bench.check_port_free(port)


def test_options_are_passed_on_to_the_responder(tmp_path):
    bench = load()

    args = bench.parse_args(
        [
            f"--data-dir={DATA_DIR}",
            "--community=public",
            "--responder-option=--max-open-data-files=8",
            "--responder-option=--max-var-binds=10",
        ]
    )

    command = bench.responder_command(args, str(tmp_path))

    assert command[-2:] == ["--max-open-data-files=8", "--max-var-binds=10"]
