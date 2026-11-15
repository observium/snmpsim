import os

import pytest

from pysnmp.proto import rfc1902

import snmpsim
from snmpsim import error

MODULE = os.path.join(os.path.dirname(snmpsim.__file__), "variation", "numeric.py")


def load_module():
    """Load the module the way the recorder does: by executing its source."""
    ctx = {"path": MODULE, "moduleContext": {}}

    with open(MODULE) as fl:
        exec(compile(fl.read(), MODULE, "exec"), ctx)

    return ctx


def recording_settings(options):
    module = load_module()
    module["init"](mode="recording", options=options)
    return module["moduleContext"]["settings"]


def test_recording_options_are_parsed():
    settings = recording_settings("iterations:1,period:5,taglist:65,addon:a,addon:b")

    assert settings["iterations"] == 1
    assert settings["period"] == 5.0
    assert isinstance(settings["period"], float)
    assert settings["addon"] == ["a", "b"]
    assert settings["taglist"] == "65"


def test_recording_option_defaults():
    settings = recording_settings("addon:rate=5")

    assert settings["period"] == 10.0
    assert settings["addon"] == ["rate=5"]

    assert settings["taglist"] == "2-65-66-67-70"

    assert "iterations" not in settings


def test_recording_option_value_may_contain_a_colon():
    settings = recording_settings("taglist:65-70,addon:function=sin:cos")

    assert settings["addon"] == ["function=sin:cos"]
    assert settings["taglist"] == "65-70"


def test_recording_without_options_leaves_settings_empty():
    assert recording_settings("") == {}
    assert recording_settings(None) == {}


def test_recording_option_without_a_value_is_reported():
    with pytest.raises(error.SnmpsimError, match="taglist"):
        recording_settings("iterations:1,taglist")


def record_one(module, tag, value):
    return module["record"]("1.3.6.1.2.1.2.2.1.10.1", tag, str(value), origValue=value)


def test_recording_with_a_taglist_writes_numeric_records():
    module = load_module()
    module["init"](mode="recording", options="taglist:65")

    assert record_one(module, "65", rfc1902.Counter32(5)) == (
        "1.3.6.1.2.1.2.2.1.10.1",
        "65:numeric",
        "initial=5",
    )

    # a type the taglist leaves out stays a plain value
    assert record_one(module, "66", rfc1902.Gauge32(7)) == (
        "1.3.6.1.2.1.2.2.1.10.1",
        "66",
        "7",
    )


@pytest.mark.parametrize(
    "options, named",
    [
        ("iterations:2,period:5,taglist", "taglist"),
        ("taglist:65,bogus", "bogus"),
        ("taglist:65,iterations:x", "iterations:x"),
        ("taglist:65,period:soon", "period:soon"),
    ],
)
def test_rejected_recording_options_apply_nothing(options, named):
    module = load_module()

    with pytest.raises(error.SnmpsimError, match=named):
        module["init"](mode="recording", options=options)

    assert module["moduleContext"]["settings"] == {}

    # the recorder carries on after a failed initialization: it must get
    # plain values, not a crash and not the options parsed so far
    assert record_one(module, "65", rfc1902.Counter32(5)) == (
        "1.3.6.1.2.1.2.2.1.10.1",
        "65",
        "5",
    )
