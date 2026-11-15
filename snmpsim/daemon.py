#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
import sys

from snmpsim import error

if sys.platform[:3] == "win":

    def daemonize(pidfile, wait=False):
        raise error.SnmpsimError("Windows is not inhabited with daemons!")

    class PrivilegesOf:
        """Context manager performing nothing on Windows"""

        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            pass

        def __exit__(self, *args):
            pass

else:
    import os
    import pwd
    import grp
    import atexit
    import signal
    import tempfile

    def _leave_terminal():
        """Send standard output and error of the daemon to nowhere."""
        sys.stdout.flush()
        sys.stderr.flush()
        so = open(os.devnull, "a+")
        se = open(os.devnull, "a+")

        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

    class Startup:
        """The daemon's end of the pipe its parent waits on.

        The process which was started stays until the daemon calls `ready()`
        and exits with 0 then. A daemon which ends before that closes the
        pipe by ending, and the parent exits with 1.

        Nobody waits for a daemon made without `wait`, `ready()` does nothing
        there.
        """

        READY = b"ready"

        def __init__(self, fd):
            self._fd = fd

        def ready(self):
            """Tell the parent that the daemon serves, let go of the terminal."""
            if self._fd is None:
                return

            # the terminal first: whoever reads our stderr through a pipe
            # must not be left waiting for it once the parent has exited
            _leave_terminal()

            fd, self._fd = self._fd, None

            try:
                os.write(fd, self.READY)

            except OSError:
                # nobody waits any more, which is no reason not to serve
                pass

            os.close(fd)

    def _await_daemon(fd):
        """Stay until the daemon is ready or gone, exit with 0 or 1."""
        said = b""

        while True:
            try:
                chunk = os.read(fd, 64)

            except InterruptedError:
                continue

            except OSError:
                break

            if not chunk:
                break

            said += chunk

        if said == Startup.READY:
            os._exit(0)

        try:
            sys.stderr.write(
                "ERROR: daemon did not start, its error is above or in its log\r\n"
            )
            sys.stderr.flush()

        except Exception:
            pass

        os._exit(1)

    def daemonize(pidfile, wait=False):
        """Become a daemon, return the `Startup` to call `ready()` on.

        The process which called this does not return. It exits with 0 at
        once, and the daemon is off the terminal when this returns, unless
        `wait` is set.

        With `wait` the process which called this stays until the daemon
        reports that it is ready, and exits with 0, or with 1 if the daemon
        ended without saying so. Until then the daemon keeps the standard
        output and error it was started with, so that what it fails with is
        seen by whoever started it. A caller which sets `wait` has to call
        `ready()`, or whoever started it waits for as long as the daemon
        lives.

        The daemon changes into "/": relative paths must have been made
        absolute by now.
        """
        sys.stdout.flush()
        sys.stderr.flush()

        ready_r = ready_w = None

        if wait:
            try:
                ready_r, ready_w = os.pipe()

            except OSError as exc:
                raise error.SnmpsimError("ERROR: pipe failed: %s" % exc)

        try:
            pid = os.fork()
            if pid > 0:
                if not wait:
                    # exit first parent
                    os._exit(0)

                # first parent: see how the daemon fares, then exit
                os.close(ready_w)
                _await_daemon(ready_r)

        except OSError as exc:
            if wait:
                os.close(ready_r)
                os.close(ready_w)

            raise error.SnmpsimError("ERROR: fork #1 failed: %s" % exc)

        if wait:
            os.close(ready_r)

        # decouple from parent environment
        try:
            os.chdir("/")
            os.setsid()

        except OSError:
            pass

        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                os._exit(0)

        except OSError as exc:
            raise error.SnmpsimError("ERROR: fork #2 failed: %s" % exc)

        def signal_cb(s, f):
            raise KeyboardInterrupt

        # The full responder takes SIGHUP over once its event loop is there,
        # and rescans its data directories on it.
        for s in signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT:
            signal.signal(s, signal_cb)

        # write pidfile
        def atexit_cb():
            try:
                if pidfile:
                    os.remove(pidfile)

            except OSError:
                pass

        atexit.register(atexit_cb)

        try:
            if pidfile:
                fd, nm = tempfile.mkstemp(dir=os.path.dirname(pidfile))
                os.write(fd, ("%d\n" % os.getpid()).encode("utf-8"))
                os.close(fd)
                os.rename(nm, pidfile)

        except Exception as exc:
            raise error.SnmpsimError(f"Failed to create PID file {pidfile}: {exc}")

        si = open(os.devnull)

        os.dup2(si.fileno(), sys.stdin.fileno())

        if not wait:
            _leave_terminal()

        # otherwise standard output and error stay as they are until `ready()`

        return Startup(ready_w)

    class PrivilegesOf:
        """Context manager executing under reduced privileges"""

        def __init__(self, uname, gname, final=False):
            self._uname = uname
            self._gname = gname
            self._final = final
            self._olduid = self._oldgid = None

        def __enter__(self):
            if os.getenv("SNMPSIM_ALLOW_ROOT") == "true":
                return

            if os.getuid() != 0:
                if self._uname or self._gname:
                    try:
                        pw_name = pwd.getpwnam(self._uname).pw_name
                        gr_name = grp.getgrnam(self._gname).gr_name

                    except Exception as exc:
                        raise error.SnmpsimError(
                            "getpwnam()/getgrnam() failed for %s/%s: "
                            "%s" % (self._uname, self._gname, exc)
                        )

                    if self._uname != pw_name or self._gname != gr_name:
                        raise error.SnmpsimError(
                            "Process is running under different UID/GID"
                        )
                else:
                    return

            else:
                if not self._uname or not self._gname:
                    raise error.SnmpsimError(
                        "Must drop privileges to a non-privileged user&group"
                    )

            try:
                runningUid = pwd.getpwnam(self._uname).pw_uid
                runningGid = grp.getgrnam(self._gname).gr_gid

            except Exception as exc:
                raise error.SnmpsimError(
                    "getpwnam()/getgrnam() failed for %s/%s: "
                    "%s" % (self._uname, self._gname, exc)
                )

            try:
                os.setgroups([])

            except Exception as exc:
                raise error.SnmpsimError("setgroups() failed: %s" % exc)

            try:
                if self._final:
                    os.setgid(runningGid)
                    os.setuid(runningUid)

                else:
                    self._olduid = os.getuid()
                    self._oldgid = os.getgid()

                    os.setegid(runningGid)
                    os.seteuid(runningUid)

            except Exception as exc:
                raise error.SnmpsimError(
                    "%s failed for %s/%s: %s"
                    % (
                        self._final and "setgid()/setuid()" or "setegid()/seteuid()",
                        runningGid,
                        runningUid,
                        exc,
                    )
                )

            os.umask(63)  # 0077

        def __exit__(self, *args):
            if self._olduid is None or self._oldgid is None:
                return

            try:
                os.setegid(self._oldgid)
                os.seteuid(self._olduid)

            except Exception as exc:
                raise error.SnmpsimError(
                    "setegid()/seteuid() failed for %s/%s: %s"
                    % (self._oldgid, self._olduid, exc)
                )
