"""A responder which cannot bind an endpoint says so and exits.

pysnmp binds a UDP endpoint in a task of the event loop. Nobody looked at
how that task ended, so with the port taken, or an address the host does not
have, the responder logged "Listening" and went on serving nothing.
"""
import os
import socket
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data", "agent")

BUSY_PORT = 1670
FREE_PORT = 1671
OTHER_PORT = 1672

SYS_DESCR = "1.3.6.1.2.1.1.1.0"

# the responder is told to live that long; one which does not notice the
# failed bind is caught by the shorter wait below
LIFETIME = 20
DEADLINE = 10


def run_responder(*endpoints):
    """Run a responder to its end, return its exit status and what it logged."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "snmpsim.commands.responder",
            f"--data-dir={DATA_DIR}",
            f"--timeout={LIFETIME}",
        ]
        + list(endpoints),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=DEADLINE,
        text=True,
    )


def test_port_in_use_ends_the_responder():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as holder:
        holder.bind(("127.0.0.1", BUSY_PORT))

        responder = run_responder(f"--agent-udpv4-endpoint=127.0.0.1:{BUSY_PORT}")

    assert responder.returncode == 1, responder.stderr
    assert (
        f"ERROR failed to bind UDP/IPv4 endpoint 127.0.0.1:{BUSY_PORT}"
        in responder.stderr
    )
    assert "Listening" not in responder.stderr


def test_one_port_in_use_out_of_two_ends_the_responder():
    """The endpoint that failed is the one named, not its neighbour."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as holder:
        holder.bind(("127.0.0.1", BUSY_PORT))

        responder = run_responder(
            f"--agent-udpv4-endpoint=127.0.0.1:{OTHER_PORT}",
            f"--agent-udpv4-endpoint=127.0.0.1:{BUSY_PORT}",
        )

    assert responder.returncode == 1, responder.stderr

    failures = [
        line for line in responder.stderr.splitlines() if "failed to bind" in line
    ]

    assert len(failures) == 1, responder.stderr
    assert f"127.0.0.1:{BUSY_PORT}" in failures[0]


def test_address_of_another_host_ends_the_responder():
    # 192.0.2.0/24 is reserved for documentation, no host has it
    responder = run_responder(f"--agent-udpv4-endpoint=192.0.2.1:{FREE_PORT}")

    assert responder.returncode == 1, responder.stderr
    assert (
        f"ERROR failed to bind UDP/IPv4 endpoint 192.0.2.1:{FREE_PORT}"
        in responder.stderr
    )


def test_free_port_is_served(responder_process, get_from_responder):
    with responder_process(f"--data-dir={DATA_DIR}", port=FREE_PORT, oid=SYS_DESCR):
        error_indication, error_status, var_binds = get_from_responder(
            FREE_PORT, SYS_DESCR
        )

    assert error_indication is None
    assert not error_status
    assert var_binds[0][1].asOctets() == b"Test device"
