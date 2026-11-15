import math
import os
import textwrap

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


# What the module computes while simulating. The formula is not restated
# here: it is read out of the documentation and executed, so the two can
# not drift apart again.

DOCS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "docs",
    "source",
    "documentation",
    "simulation-with-variation-modules.rst",
)

BOOTED = 1000000.0

OID = "1.3.6.1.2.1.2.2.1.10.1"


def documented_formula():
    """Return the source of the formula in the numeric module section."""
    with open(DOCS) as fl:
        text = fl.read()

    section = text[
        text.index(".. _variate-numeric:") : text.index(".. _variate-delay:")
    ]

    lines = section[section.index(".. code-block:: python") :].splitlines()[1:]

    block = []

    for line in lines:
        if line.strip() and not line.startswith("  "):
            break

        block.append(line)

    return textwrap.dedent("\n".join(block))


def lowest(start, stop):
    """Stand in for random.randrange(): always the lowest value on offer."""
    assert isinstance(start, int) and isinstance(stop, int)
    return start


def documented_values(record, tag, times):
    """Run the documented formula over requests made at the given times."""
    settings = dict(x.split("=") for x in record.split(","))

    name, *args = settings.pop("function", "<identity>").split("%")
    function = (lambda x: x) if name == "<identity>" else getattr(math, name)

    def call(x):
        if not args:
            return function(x)

        return function(*[x if a == "<time>" else float(a) for a in args])

    def rand(low, high):
        return lowest(int(low), int(high)) if int(high) else 0

    flags = {k: k in settings for k in ("atime", "wrap", "cumulative")}
    settings = {k: float(v) for k, v in settings.items() if k not in flags}

    settings.setdefault("min", 0)
    settings.setdefault("max", 2**64 - 1 if tag == "70" else 2**32 - 1)
    settings.setdefault("initial", settings["min"])

    for k, default in ("rate", 1), ("scale", 1), ("offset", 0), ("deviation", 0):
        settings.setdefault(k, default)

    formula = compile(documented_formula(), DOCS, "exec")

    values = []

    prev_v, prev_time = settings["initial"], BOOTED

    for now in times:
        scope = dict(
            settings,
            function=call,
            RAND=rand,
            TIMENOW=now,
            UPTIME=now - BOOTED,
            ELAPSED=now - prev_time,
            prev_v=prev_v,
            **flags,
        )

        exec(formula, scope)

        prev_v, prev_time = scope["v"], now

        values.append(scope["v"])

    return values


def simulated_values(monkeypatch, record, tag, times):
    """Ask the module for the same OID at the given times."""
    module = load_module()
    module["BOOTED"] = BOOTED
    module["recordContext"] = {}

    monkeypatch.setattr(module["random"], "randrange", lowest)

    values = []

    for now in times:
        monkeypatch.setattr(module["time"], "time", lambda: now)

        oid, _tag, value = module["variate"](
            OID,
            tag,
            record,
            origOid=OID,
            nextFlag=False,
            exactMatch=True,
            setFlag=False,
            errorStatus=None,
        )

        assert (oid, _tag) == (OID, tag)

        values.append(value)

    return values


@pytest.mark.parametrize(
    "tag, record",
    [
        # the examples of the documentation
        ("65", "scale=10,deviation=1,function=cos,cumulative=1,wrap=1"),
        ("66", "min=5,max=50,initial=25"),
        ("70", "scale=0,offset=100,cumulative=1,initial=5000"),
        # what the recorder writes
        ("67", "initial=16808012,rate=100"),
        ("2", "initial=6,rate=0"),
        ("65", "initial=30374688,rate=1234.5"),
        # every term of the plain formula
        ("66", "initial=10,rate=3,scale=2,offset=7,deviation=4"),
        ("66", "min=20,initial=10,rate=0"),
        ("66", "atime=1,function=sin,scale=100,initial=100"),
        ("66", "function=pow%<time>%2,rate=0.5"),
        ("66", "function=pow%2%<time>,rate=0.1,max=1000"),
        # the offset of a counter grows with the time between requests
        ("65", "cumulative=1"),
        ("65", "cumulative=1,rate=2,offset=3,scale=0.5"),
        ("65", "cumulative=1,offset=-2,initial=1000"),
        ("65", "cumulative=1,scale=0,offset=1,deviation=30,min=2"),
        # the limits apply after the previous value is added
        ("65", "cumulative=1,initial=400,max=500"),
        ("65", "cumulative=1,initial=400,max=500,wrap=1"),
        ("65", "cumulative=1,initial=400,min=100,max=500,wrap=1"),
        ("66", "initial=90,max=100,wrap=1"),
        # a flag is on when its key is there, whatever the value
        ("66", "initial=90,max=100,wrap=0"),
        ("65", "cumulative=0,initial=400"),
        ("66", "atime=0,rate=0.001"),
    ],
)
def test_numeric_formula_matches_docs(monkeypatch, tag, record):
    times = [BOOTED + x for x in (0.0, 10.0, 25.5, 26.0, 100.0, 3600.25)]

    simulated = simulated_values(monkeypatch, record, tag, times)

    assert simulated == pytest.approx(documented_values(record, tag, times))

    # the examples are not all constants, or the comparison proves little
    if "rate=0" not in record.split(","):
        assert len(set(simulated)) > 1


def test_numeric_deviation_stays_within_its_range():
    module = load_module()
    module["recordContext"] = {}

    values = set()

    for _ in range(200):
        _oid, _tag, value = module["variate"](
            OID,
            "66",
            "initial=100,rate=0,deviation=2",
            origOid=OID,
            nextFlag=False,
            exactMatch=True,
            setFlag=False,
            errorStatus=None,
        )

        values.add(value)

    # whole numbers from -deviation up to, but not including, deviation
    assert values == {98, 99, 100, 101}


def test_numeric_deviation_below_one_adds_nothing():
    module = load_module()
    module["recordContext"] = {}

    _oid, _tag, value = module["variate"](
        OID,
        "66",
        "initial=100,rate=0,deviation=0.5",
        origOid=OID,
        nextFlag=False,
        exactMatch=True,
        setFlag=False,
        errorStatus=None,
    )

    assert value == 100
