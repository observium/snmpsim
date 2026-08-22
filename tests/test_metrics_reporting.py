import json
import os

import pytest

from snmpsim import utils
from snmpsim.reporting.formats import alljson
from snmpsim.reporting.formats.alljson import FullJsonReporter


def _reporter(tmp_path):
    reporter = FullJsonReporter(str(tmp_path))
    # dump on the very next update rather than five minutes from now
    reporter._next_dump = 0
    return reporter


def test_metrics_are_dumped_next_to_their_directory(tmp_path):
    """The dump is renamed into place, which cannot cross a filesystem.

    Writing the temporary file into the system temp directory made every dump
    fail with EXDEV wherever /tmp is a filesystem of its own.
    """
    reporter = _reporter(tmp_path)

    reporter.update_metrics(
        transport_protocol="udpv4",
        transport_endpoint="127.0.0.1:1161",
        transport_domain="1.3.6.1.6.1.1.0",
        transport_address="192.0.2.10",
        transport_call_count=1,
        snmp_engine="0x8000",
        security_model="2",
        security_level="1",
        security_name="public",
        context_engine_id="0x8000",
        pdu_type="GetRequestPDU",
        data_file="/data/device.snmprec",
        datafile_call_count=1,
        varbind_count=3,
    )

    reporter.flush()

    reports_dir = tmp_path / "fulljson"
    dumps = [name for name in os.listdir(reports_dir) if name.endswith(".json")]

    assert len(dumps) == 1

    with open(reports_dir / dumps[0]) as fl:
        doc = json.load(fl)

    assert doc["format"] == "fulljson"
    assert doc["version"] == 1

    counters = doc["udpv4"]["127.0.0.1:1161"]["192.0.2.10"]["0x8000"]["2"]["1"][
        "public"
    ]["0x8000"]["GetRequestPDU"]["/data/device.snmprec"]

    assert counters["pdus"] == 1
    assert counters["varbinds"] == 3

    # nothing left behind, and the counters start over
    assert os.listdir(reports_dir) == dumps
    assert not reporter._metrics


def test_counters_survive_a_failed_dump(tmp_path, monkeypatch):
    """A dump that cannot be written must not take the counters with it."""
    reporter = _reporter(tmp_path)

    reporter.update_metrics(
        transport_protocol="udpv4",
        transport_endpoint="127.0.0.1:1161",
        transport_domain="1.3.6.1.6.1.1.0",
        transport_address="192.0.2.10",
        transport_call_count=1,
        snmp_engine="0x8000",
        security_model="2",
        security_level="1",
        security_name="public",
        context_engine_id="0x8000",
        pdu_type="GetRequestPDU",
        data_file="/data/device.snmprec",
        datafile_call_count=1,
        varbind_count=3,
    )

    def no_rename(*args, **kwargs):
        raise OSError("cross-device link")

    monkeypatch.setattr(alljson.os, "rename", no_rename)

    reporter._next_dump = 0
    reporter.flush()

    reports_dir = tmp_path / "fulljson"

    assert reporter._metrics, "the counters were thrown away"
    assert os.listdir(reports_dir) == [], "the temporary file was left behind"

    monkeypatch.undo()

    reporter._next_dump = 0
    reporter.flush()

    assert len(os.listdir(reports_dir)) == 1
    assert not reporter._metrics


@pytest.mark.parametrize(
    "argument, expected",
    [
        ("null", ["null"]),
        ("fulljson:/var/lib/snmpsim", ["fulljson", "/var/lib/snmpsim"]),
        ("fulljson:/var/lib/snmpsim:300", ["fulljson", "/var/lib/snmpsim", "300"]),
        # a Windows path keeps the colon after its drive letter
        (r"fulljson:C:\metrics", ["fulljson", r"C:\metrics"]),
        (r"fulljson:C:\metrics:1", ["fulljson", r"C:\metrics", "1"]),
    ],
)
def test_reporting_method_is_split_around_the_period(argument, expected):
    assert utils.parse_reporting_method(argument) == expected
