import os
import shutil
import sqlite3
import sys
import types

import pytest
from pysnmp.proto import rfc1902, rfc1905
from pysnmp.smi import error as smi_error

import snmpsim
from snmpsim import error
from snmpsim.controller import MibInstrumController

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
    """A failed SET takes the message's earlier variable bindings with it.

    They were answered already but not committed; the rollback that keeps
    the connection usable discards them.
    """
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


def set_through_responder(module, oid, value, fails):
    """One SET of `oid` and a variable after it, which fails it or not.

    The module hands over what makes its write stay and what takes it
    back; the responder runs the one or the other, as the SET goes.
    """
    done, undo = [], []

    module["variate"](
        oid,
        "4",
        "",
        origOid=rfc1902.ObjectName(oid),
        origValue=value,
        errorStatus=rfc1905.noSuchInstance,
        setFlag=True,
        nextFlag=False,
        varsRemaining=1,
        setDone=done,
        setUndo=undo,
    )

    for step in reversed(undo) if fails else done:
        step()


def test_a_set_that_fails_after_the_write_is_taken_back(module, database):
    set_through_responder(module, FIRST, rfc1902.OctetString("half"), fails=True)

    assert variate(module, FIRST) == (FIRST, "4", "first")
    assert stored(database, FIRST) == ("4", "first")


def test_a_set_done_stays_whatever_the_next_one_does(module, database):
    # the variable written is not the last of its SET, which is done
    set_through_responder(module, FIRST, rfc1902.OctetString("done"), fails=False)

    assert stored(database, FIRST) == ("4", "done")

    set_through_responder(module, SECOND, rfc1902.Integer32(7), fails=True)

    assert variate(module, FIRST) == (FIRST, "4", "done")
    assert stored(database, FIRST) == ("4", "done")
    assert stored(database, SECOND) == ("2", "42")


class DataFile:
    """Asks the module for every variable of a SET, as a data file does."""

    def __init__(self, module, between=None):
        self.module = module
        self.between = between

    def process_var_binds(self, var_binds, **context):
        answered = []

        for place, (oid, value) in enumerate(var_binds):
            if place and self.between:
                self.between()

            _, _, value = self.module["variate"](
                str(oid),
                "4",
                "",
                **dict(
                    context,
                    origOid=rfc1902.ObjectName(oid),
                    origValue=value,
                    errorStatus=rfc1905.noSuchInstance,
                    nextFlag=False,
                    varsRemaining=len(var_binds) - place - 1,
                ),
            )

            answered.append((oid, value))

        return answered


def write(data_file, *var_binds):
    return MibInstrumController(data_file).write_variables(
        *[(rfc1902.ObjectName(oid), value) for oid, value in var_binds]
    )


def test_a_set_the_connection_dropped_in_keeps_nothing(spying_driver, database):
    module = start(spying_driver, database)

    try:
        data_file = DataFile(module, between=lambda: drop_connection(module))

        # the first variable went with the connection: keeping the second
        # alone would keep half of the SET
        with pytest.raises(smi_error.CommitFailedError):
            write(
                data_file,
                (FIRST, rfc1902.OctetString("a")),
                (SECOND, rfc1902.OctetString("b")),
            )

        assert stored(database, FIRST) == ("4", "first")
        assert stored(database, SECOND) == ("2", "42")

        data_file.between = None

        write(
            data_file,
            (FIRST, rfc1902.OctetString("c")),
            (SECOND, rfc1902.OctetString("d")),
        )

        assert stored(database, FIRST) == ("4", "c")
        assert stored(database, SECOND) == ("4", "d")

    finally:
        module["shutdown"](mode="variating")


def test_a_variable_set_twice_keeps_the_last_value(module, database):
    write(
        DataFile(module),
        (FIRST, rfc1902.OctetString("a")),
        (FIRST, rfc1902.OctetString("b")),
    )

    assert stored(database, FIRST) == ("4", "b")


class Connection:
    """A sqlite3 connection that tells when it was rolled back."""

    def __init__(self, conn, rollback_error=None):
        self._conn = conn
        self._rollback_error = rollback_error
        self.rollbacks = 0

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def rollback(self):
        self.rollbacks += 1

        if self._rollback_error:
            raise self._rollback_error

        self._conn.rollback()


@pytest.fixture
def spying_driver(counting_driver):
    """The counting driver, handing out connections that report rollbacks."""
    connect = counting_driver.connect
    counting_driver.rollback_error = None

    def spying_connect(**params):
        conn = Connection(connect(**params), counting_driver.rollback_error)
        counting_driver.connections[-1] = conn
        return conn

    counting_driver.connect = spying_connect

    return counting_driver


def start(driver, database, extra=""):
    ctx = load()
    ctx["init"](
        options="dbtype:%s,database:%s%s" % (driver.__name__, database, extra),
        mode="variating",
    )

    return ctx


def set_in(module, table, oid, value, vars_remaining=0):
    return module["variate"](
        oid,
        "4",
        table,
        origOid=rfc1902.ObjectName(oid),
        origValue=rfc1902.OctetString(value),
        errorStatus=rfc1905.noSuchInstance,
        setFlag=True,
        nextFlag=False,
        varsRemaining=vars_remaining,
    )


def test_statement_refused_on_the_new_connection_is_rolled_back(
    spying_driver, database
):
    """The retry can fail too, and its connection is the one that is kept."""
    ctx = start(spying_driver, database, ",dbtable:nosuchtable")

    try:
        drop_connection(ctx)

        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            variate(ctx, FIRST)

        first, second = spying_driver.connections

        assert ctx["moduleContext"]["dbConn"] is second
        assert second.rollbacks == 1

    finally:
        ctx["shutdown"](mode="variating")


def test_error_about_the_data_is_rolled_back_without_reconnecting(
    spying_driver, database
):
    """An error outside the connection's classes still ends the transaction."""
    conn = sqlite3.connect(database)
    conn.execute(
        "CREATE TABLE picky (oid text, tag text, "
        "value text check (value != 'bad'), maxaccess text)"
    )
    conn.commit()
    conn.close()

    ctx = start(spying_driver, database)

    try:
        set_in(ctx, "picky", FIRST, "good", vars_remaining=1)

        with pytest.raises(sqlite3.IntegrityError):
            set_in(ctx, "picky", SECOND, "bad")

        (conn,) = spying_driver.connections

        assert conn.rollbacks == 1
        assert ctx["moduleContext"]["dbConn"] is conn

        # the first variable binding of the message went with the second
        assert conn.execute("select count(*) from picky").fetchone() == (0,)

        assert variate(ctx, FIRST) == (FIRST, "4", "first")

    finally:
        ctx["shutdown"](mode="variating")


@pytest.mark.parametrize(
    "rollback_error", [AttributeError("rollback"), sqlite3.NotSupportedError()]
)
def test_driver_without_rollback_is_judged_by_the_probe(
    spying_driver, database, rollback_error
):
    """DB-API makes rollback() optional: lacking it is not a dead connection."""
    spying_driver.rollback_error = rollback_error

    ctx = start(spying_driver, database, ",dbtable:nosuchtable")

    try:
        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            variate(ctx, FIRST)

        assert len(spying_driver.connections) == 1

        # a connection that is gone is still found out and replaced
        drop_connection(ctx)

        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            variate(ctx, FIRST)

        assert len(spying_driver.connections) == 2

    finally:
        ctx["shutdown"](mode="variating")


def test_rollback_failing_otherwise_means_a_dead_connection(spying_driver, database):
    spying_driver.rollback_error = sqlite3.OperationalError("server has gone away")

    ctx = start(spying_driver, database, ",dbtable:nosuchtable")

    try:
        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            variate(ctx, FIRST)

        assert len(spying_driver.connections) == 2

    finally:
        ctx["shutdown"](mode="variating")


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


def test_getnext_steps_over_exceptions_whatever_the_tag_column_is(tmp_path):
    # a tag column of no declared type keeps numbers as numbers, and a tag
    # may be padded: neither is an exception the less
    os.makedirs(tmp_path / "untyped")
    conn = sqlite3.connect(tmp_path / "untyped" / "agent.db")
    conn.execute("CREATE TABLE snmprec (oid, tag, value, maxaccess)")
    conn.executemany(
        "insert into snmprec values (?, ?, ?, 'read-only')",
        [
            (sql_oid(FIRST), "4", "first"),
            (sql_oid("1.3.6.1.4.1.99999.6.1.5"), 130, ""),
            (sql_oid("1.3.6.1.4.1.99999.6.1.6"), " 129", ""),
            (sql_oid(SECOND), 2, "42"),
        ],
    )
    conn.commit()
    conn.close()

    cwd = os.getcwd()
    os.chdir(tmp_path)

    try:
        ctx = load()
        ctx["init"](
            options="dbtype:sqlite3,database:%s" % os.path.join("untyped", "agent.db"),
            mode="variating",
        )

        try:
            assert variate(ctx, FIRST, next_flag=True) == (SECOND, "2", "42")

            # a GET of the endOfMibView: as for a variable not there
            assert variate(ctx, "1.3.6.1.4.1.99999.6.1.5")[2] is rfc1905.noSuchInstance

        finally:
            ctx["shutdown"](mode="variating")

    finally:
        os.chdir(cwd)
