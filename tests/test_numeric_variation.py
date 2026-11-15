import os

import pytest

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
    assert "65" in settings["taglist"]
    assert "2" not in settings["taglist"]
    assert "70" not in settings["taglist"]


def test_recording_option_defaults():
    settings = recording_settings("addon:rate=5")

    assert settings["period"] == 10.0
    assert settings["addon"] == ["rate=5"]

    for tag in ("2", "65", "66", "67", "70"):
        assert tag in settings["taglist"]

    assert "iterations" not in settings


def test_recording_option_value_may_contain_a_colon():
    settings = recording_settings("taglist:65-70,addon:function=sin:cos")

    assert settings["addon"] == ["function=sin:cos"]
    assert "70" in settings["taglist"]


def test_recording_without_options_leaves_settings_empty():
    assert recording_settings("") == {}
    assert recording_settings(None) == {}


def test_recording_option_without_a_value_is_reported():
    with pytest.raises(error.SnmpsimError, match="taglist"):
        recording_settings("iterations:1,taglist")
