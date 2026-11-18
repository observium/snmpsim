"""What pysnmp's SNMPv3 engine answered SNMPv1 and SNMPv2c requests with.

Up to 2026.11.6 the command responder could send SNMPv1/v2c requests through
pysnmp's SNMPv3 engine (`--v1-v2c-path=engine`), the way every release before
2026.11.4 answered them, and the tests compared the simulator's own answers
with the engine's octet for octet. The option is gone; what the engine
answered the requests of these tests with is kept in
`data/engine-answers.json`, recorded by 2026.11.6, and the answers of today
are compared with that.

Answers are keyed by the request octets in hex. A few things the engine was
asked about depend on where the test put its recordings, and are kept in a
form without that path: the data index answers in words, with `<data>` for
the directory, and the data file a variation module was told about by its
name alone. What a variation module was told is kept as pyasn1 values by
class and value, not as their repr(), which a pyasn1 release may change.
An answer that is meant to change - one the RFCs or net-snmp have otherwise -
is changed in the file, with the reason in the commit.
"""
import json
import pathlib

import pytest

PATH = pathlib.Path(__file__).parent / "data" / "engine-answers.json"

_recorded = None


def _load():
    global _recorded

    if _recorded is None:
        _recorded = json.loads(PATH.read_text())

    return _recorded


def engine_answer(request):
    """The octets the engine answered `request` with, None for no answer."""
    answers = _load()["answers"]

    if request.hex() not in answers:
        pytest.fail(
            f"no answer of the engine is recorded for {request.hex()}: a request "
            f"a test makes must be one 2026.11.6 was asked"
        )

    response = answers[request.hex()]

    return None if response is None else bytes.fromhex(response)


def engine_value(name):
    """Something else the engine path was seen to do, by the name it was kept as."""
    values = _load()["values"]

    if name not in values:
        pytest.fail(f"nothing the engine did is recorded as {name!r}")

    return values[name]
