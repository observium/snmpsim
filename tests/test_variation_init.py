"""Variation modules nobody configured do not log an error at startup.

Every variation module found is initialized, whether or not a recording uses
it, and the sql and redis modules cannot work without options naming their
database. Each start of a responder logged two ERROR lines for them in an
installation that has no database at all, which buried the errors that do
matter. A module that got no options at all says so in an ordinary line now;
options given but wrong are still an error.
"""
import os

import pytest

import snmpsim
from snmpsim import log
from snmpsim import variation

MODULES_DIR = os.path.join(os.path.dirname(snmpsim.__file__), "variation")


def load(name, args):
    """Load a module the way the responder does: by executing its source."""
    path = os.path.join(MODULES_DIR, name + ".py")
    ctx = {"path": path, "alias": name, "args": args, "moduleContext": {}}

    with open(path) as fl:
        exec(compile(fl.read(), path, "exec"), ctx)

    return ctx, {}, {}


@pytest.fixture
def logged(monkeypatch):
    lines = {"error": [], "info": []}

    monkeypatch.setattr(
        log, "error", lambda message, ctx="": lines["error"].append(message)
    )
    monkeypatch.setattr(
        log, "info", lambda message, ctx="": lines["info"].append(message)
    )

    return lines


@pytest.mark.parametrize(
    "name, reason",
    [
        ("redis", "Redis connect parameters not specified"),
        ("sql", "database type not specified"),
    ],
)
def test_module_without_options_is_not_an_error(logged, name, reason):
    variation.initialize_variation_modules({name: load(name, "")}, mode="variating")

    assert logged["error"] == []
    assert any(
        f'"{name}"' in line and "not configured" in line and reason in line
        for line in logged["info"]
    )


@pytest.mark.parametrize(
    "name, args, reason",
    [
        ("redis", "key-spaces-id:1", "Redis connect parameters not specified"),
        ("sql", "database:snmpsim.db", "database type not specified"),
    ],
)
def test_module_with_options_that_do_not_do_is_an_error(logged, name, args, reason):
    variation.initialize_variation_modules({name: load(name, args)}, mode="variating")

    assert any(
        f'"{name}"' in line and "load FAILED" in line and reason in line
        for line in logged["error"]
    )


@pytest.mark.parametrize("name", ["redis", "sql"])
def test_record_of_a_module_without_options_fails(logged, name):
    body = load(name, "")
    variation.initialize_variation_modules({name: body}, mode="variating")

    with pytest.raises(snmpsim.error.SnmpsimError, match="not initialized"):
        body[0]["variate"]("1.3.6.1.2.1.1.5.0", "4", "", origOid="1.3.6.1.2.1.1.5.0")
