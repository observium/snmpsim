import os
import socket

import pytest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data", "agent")
PORT_NUMBER = 1691

SYS_DESCR = "1.3.6.1.2.1.1.1.0"


def test_responder_process_answers_and_goes_away(responder_process, get_from_responder):
    with responder_process(f"--data-dir={DATA_DIR}", port=PORT_NUMBER, oid=SYS_DESCR):
        error_indication, error_status, var_binds = get_from_responder(
            PORT_NUMBER, SYS_DESCR
        )

        assert error_indication is None
        assert not error_status
        assert var_binds[0][1].asOctets() == b"Test device"

    error_indication, _, _ = get_from_responder(PORT_NUMBER, SYS_DESCR, timeout=0.5)

    assert error_indication is not None


def test_responder_process_fails_on_a_port_in_use(responder_process):
    """A port somebody else holds is reported, not waited for."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as holder:
        holder.bind(("127.0.0.1", PORT_NUMBER))

        with pytest.raises(pytest.fail.Exception, match="is in use"):
            with responder_process(
                f"--data-dir={DATA_DIR}", port=PORT_NUMBER, oid=SYS_DESCR
            ):
                pass


def test_responder_process_is_not_taken_for_another_one(responder_process):
    """Somebody else answering on the port does not pass for our responder.

    The readiness probe was answered by the responder already there, the one
    just started died of the port being taken, and the tests went on against
    the wrong data.
    """
    with responder_process(f"--data-dir={DATA_DIR}", port=PORT_NUMBER, oid=SYS_DESCR):
        with pytest.raises(pytest.fail.Exception, match="is in use"):
            with responder_process(
                f"--data-dir={os.path.join(BASE_DIR, 'data', 'error')}",
                port=PORT_NUMBER,
                oid=SYS_DESCR,
            ):
                pass
