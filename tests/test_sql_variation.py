import os
import shutil
import sqlite3
import sys
import types

import pytest
from pysnmp.proto import rfc1902, rfc1905

import snmpsim
from snmpsim import error

MODULE = os.path.join(os.path.dirname(snmpsim.__file__), "variation", "sql.py")

FIRST = "1.3.6.1.4.1.99999.6.1.0"
SECOND = "1.3.6.1.4.1.99999.6.2.0"


def sql_oid(oid):
    """The module keeps OIDs padded so that they sort as text."""
    return ".".join("%10s" % x for x in oid.split("."))


def populate(path):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE snmprec (oid text, tag text, value text, maxaccess text)"
    )
    conn.executemany(
        "insert into snmprec values (?, ?, ?, 'read-write')",
        [(sql_oid(FIRST), "4", "first"), (sql_oid(SECOND), "2", "42")],
    )
    conn.commit()
    conn.close()


def stored(path, oid):
    """What a client of the database sees, on a connection of its own."""
    conn = sqlite3.connect(path)
    try:
        return conn.execute(
            "select tag, value from snmprec where oid=?", (sql_oid(oid),)
        ).fetchone()
    finally:
        conn.close()


def load():
    """Load the module the way the responder does: by executing its source."""
    ctx = {"path": MODULE, "alias": "sql", "args": "", "moduleContext": {}}

    with open(MODULE) as fl:
        exec(compile(fl.read(), MODULE, "exec"), ctx)

    return ctx


@pytest.fixture
def database(tmp_path):
    # a relative name keeps the drive letter colon out of the module options
    os.makedirs(tmp_path / "db")
    populate(tmp_path / "db" / "agent.db")

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        yield os.path.join("db", "agent.db")
    finally:
        os.chdir(cwd)


@pytest.fixture
def module(database):
    ctx = load()
    ctx["init"](options="dbtype:sqlite3,database:%s" % database, mode="variating")

    yield ctx

    ctx["shutdown"](mode="variating")


@pytest.fixture
def counting_driver(monkeypatch):
    """sqlite3 under another name, counting the connections it opened."""
    driver = types.ModuleType("snmpsim_test_sql_driver")
    driver.__dict__.update(
        {k: v for k, v in vars(sqlite3).items() if not k.startswith("__")}
    )
    driver.connections = []

    def connect(**params):
        conn = sqlite3.connect(**params)
        driver.connections.append(conn)
        return conn

    driver.connect = connect

    monkeypatch.setitem(sys.modules, driver.__name__, driver)

    return driver


def variate(module, oid, set_to=None, next_flag=False, vars_remaining=0):
    context = {
        "origOid": rfc1902.ObjectName(oid),
        "origValue": set_to,
        "errorStatus": rfc1905.noSuchInstance,
        "setFlag": set_to is not None,
        "nextFlag": next_flag,
        "varsRemaining": vars_remaining,
    }

    oid, tag, value = module["variate"](oid, "4", "", **context)

    return str(oid), tag, value


def drop_connection(module):
    """What a database server restart looks like from inside the module."""
    module["moduleContext"]["dbConn"].close()


def test_get_is_answered_from_the_database(module):
    assert variate(module, FIRST) == (FIRST, "4", "first")


def test_get_is_answered_after_the_connection_dropped(module):
    drop_connection(module)

    assert variate(module, FIRST) == (FIRST, "4", "first")

    # and on a connection that stays: nothing is reopened for the next one
    conn = module["moduleContext"]["dbConn"]

    assert variate(module, SECOND) == (SECOND, "2", "42")
    assert module["moduleContext"]["dbConn"] is conn


def test_getnext_is_answered_after_the_connection_dropped(module):
    drop_connection(module)

    assert variate(module, FIRST, next_flag=True) == (SECOND, "2", "42")


def test_set_is_stored_after_the_connection_dropped(module, database):
    drop_connection(module)

    oid, tag, value = variate(module, FIRST, set_to=rfc1902.OctetString("changed"))

    assert (oid, tag, value) == (FIRST, "4", rfc1902.OctetString("changed"))
    assert stored(database, FIRST) == ("4", "changed")


def test_database_that_stays_away_is_reported_and_then_found_again(module, database):
    drop_connection(module)
    shutil.move("db", "elsewhere")

    with pytest.raises(sqlite3.Error):
        variate(module, FIRST)

    # still away at the next request: the same report, no stale handle kept
    with pytest.raises(sqlite3.Error):
        variate(module, FIRST)

    shutil.move("elsewhere", "db")

    assert variate(module, FIRST) == (FIRST, "4", "first")


def test_connection_is_reopened_once_per_request(counting_driver, database):
    ctx = load()
    ctx["init"](
        options="dbtype:%s,database:%s" % (counting_driver.__name__, database),
        mode="variating",
    )

    try:
        assert len(counting_driver.connections) == 1

        drop_connection(ctx)

        assert variate(ctx, FIRST) == (FIRST, "4", "first")
        assert len(counting_driver.connections) == 2

    finally:
        ctx["shutdown"](mode="variating")

    # every connection the module gave up on was closed, not left to leak
    for conn in counting_driver.connections:
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("select 1")


def test_refused_statement_does_not_reconnect(counting_driver, database):
    """A missing table is the database's answer, not a lost connection."""
    ctx = load()
    ctx["init"](
        options="dbtype:%s,database:%s,dbtable:nosuchtable"
        % (counting_driver.__name__, database),
        mode="variating",
    )

    reconnects = []
    reconnect = ctx["_reconnect"]
    ctx["_reconnect"] = lambda: reconnects.append(1) or reconnect()

    try:
        conn = ctx["moduleContext"]["dbConn"]

        for _ in range(3):
            with pytest.raises(sqlite3.OperationalError, match="no such table"):
                variate(ctx, FIRST)

        assert not reconnects
        assert len(counting_driver.connections) == 1
        assert ctx["moduleContext"]["dbConn"] is conn

        # the spy does see a reconnect when there is one
        drop_connection(ctx)

        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            variate(ctx, FIRST)

        assert reconnects == [1]
        assert len(counting_driver.connections) == 2

    finally:
        ctx["shutdown"](mode="variating")


def test_refused_statement_undoes_the_request_it_failed(module, database):
    """Checking the connection rolls back what the failed SET left open."""
    variate(module, FIRST, set_to=rfc1902.OctetString("half"), vars_remaining=1)

    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        module["variate"](
            SECOND,
            "2",
            "nosuchtable",
            origOid=rfc1902.ObjectName(SECOND),
            origValue=rfc1902.Integer32(7),
            errorStatus=rfc1905.noSuchInstance,
            setFlag=True,
            nextFlag=False,
            varsRemaining=0,
        )

    assert variate(module, FIRST) == (FIRST, "4", "first")
    assert stored(database, FIRST) == ("4", "first")


def test_broken_dsn_fails_at_start(tmp_path):
    ctx = load()

    with pytest.raises(sqlite3.OperationalError):
        ctx["init"](
            options="dbtype:sqlite3,database:%s"
            % os.path.join("no-such-directory", "agent.db"),
            mode="variating",
        )

    with pytest.raises(error.SnmpsimError, match="not initialized"):
        variate(ctx, FIRST)

    # nothing to close, nothing to trip over
    ctx["shutdown"](mode="variating")
