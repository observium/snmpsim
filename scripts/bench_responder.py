#!/usr/bin/env python3
"""Measure how fast a command responder serves a recording.

Starts `snmpsim-command-responder` (or the lite one) with the given interpreter
on a local port, waits until it answers, then times, with net-snmp's tools:

* the start: building missing indexes and binding the port, until the first
  answer;
* a bulk walk (`snmpbulkwalk -Cr<repetitions>`) of one subtree;
* a GETNEXT walk (`snmpwalk`, one request per OID) of another.

Warm-up walks go first and are not timed, so that a JIT, PyPy's, is not
measured cold. With --profile the responder runs under cProfile and the time
it was busy is split by package: pyasn1, pysnmp, snmpsim, the rest.

The responder is the one of the checkout this script belongs to, unless
--installed asks for the interpreter's own. Recordings, their community and
the cache are arguments: nothing about them is kept here.

    python scripts/bench_responder.py --data-dir=/srv/recordings \\
        --community=vendor/model --bulk-oid=.1 --getnext-oid=.1.3.6.1.2.1.2

needs snmpget, snmpbulkwalk and snmpwalk on the PATH. POSIX only.
"""
import argparse
import collections
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

CHECKOUT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RESPONDERS = {
    "full": "snmpsim.commands.responder",
    "lite": "snmpsim.commands.responder_lite",
}

TOOLS = ("snmpget", "snmpbulkwalk", "snmpwalk")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--data-dir", required=True, help="recordings to serve")
    parser.add_argument(
        "--community", required=True, help="community that selects the recording"
    )
    parser.add_argument(
        "--cache-dir",
        help="index cache; a fresh temporary one if left out, so that the start "
        "includes building the indexes",
    )
    parser.add_argument(
        "--python", default=sys.executable, help="interpreter to run the responder"
    )
    parser.add_argument("--responder", choices=sorted(RESPONDERS), default="full")
    parser.add_argument(
        "--installed",
        action="store_true",
        help="run the snmpsim the interpreter has installed, not this checkout",
    )
    parser.add_argument(
        "--responder-option",
        metavar="OPTION",
        action="append",
        default=[],
        help="pass an option on to the responder, e.g. "
        "--responder-option=--v1-v2c-path=engine; may be given more than once",
    )
    parser.add_argument("--port", type=int, default=11161)
    parser.add_argument("--bulk-oid", default=".1", help="subtree of the bulk walk")
    parser.add_argument(
        "--getnext-oid",
        default=".1.3.6.1.2.1.2",
        help="subtree of the GETNEXT walk",
    )
    parser.add_argument("--repetitions", type=int, default=25)
    parser.add_argument(
        "--warmup",
        type=int,
        default=1,
        help="untimed GETNEXT walks of --getnext-oid before the timed ones",
    )
    parser.add_argument(
        "--start-timeout", type=float, default=1800, help="seconds to wait for it"
    )
    parser.add_argument(
        "--profile",
        metavar="FILE",
        help="run the responder under cProfile, write the profile here and "
        "print the busy time by package",
    )
    parser.add_argument("--json", action="store_true", help="print JSON")
    return parser.parse_args(argv)


def snmp_args(args, *more):
    return [
        "-v2c",
        "-c",
        args.community,
        "-On",
        "-t",
        "10",
        "-r",
        "1",
        *more,
        f"127.0.0.1:{args.port}",
    ]


# what net-snmp prints for a var-bind that carries no value: the last response
# of a bulk walk repeats endOfMibView for every repetition left
NO_VALUE = (b"= No more variables left", b"= No Such Object", b"= No Such Instance")


# a line that starts a var-bind of `-On` output; the lines a quoted value goes
# on with may start with ".1" as well, but not with an OID and " = "
VARBIND = re.compile(rb"\.1[.0-9]* = ")


def count_oids(output):
    """OIDs served in the output of a walk.

    A value wrapped onto more lines counts once, a var-bind that says there
    is no value does not count.
    """
    return sum(
        1
        for line in output.splitlines()
        if VARBIND.match(line) and not any(marker in line for marker in NO_VALUE)
    )


def timed_walk(command):
    started = time.monotonic()
    done = subprocess.run(command, capture_output=True)
    seconds = time.monotonic() - started
    if done.returncode:
        raise SystemExit(
            "%s failed: %s" % (command[0], done.stderr.decode(errors="replace"))
        )
    return count_oids(done.stdout), seconds


def responder_command(args, cache_dir):
    command = [args.python]
    if args.profile:
        command += ["-m", "cProfile", "-o", os.path.abspath(args.profile)]
    command += [
        "-m",
        RESPONDERS[args.responder],
        f"--data-dir={os.path.abspath(args.data_dir)}",
        f"--cache-dir={cache_dir}",
        f"--agent-udpv4-endpoint=127.0.0.1:{args.port}",
        "--log-level=error",
    ]
    return command + list(args.responder_option)


def check_port_free(port):
    """Fail unless nobody listens on the port.

    Whoever answers there would answer the walks, and a responder that could
    not bind would go unnoticed: the numbers would be somebody else's.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as exc:
            raise SystemExit(f"port {port} is in use, nothing measured: {exc}")


def said(log):
    log.seek(0)
    text = log.read().decode(errors="replace").strip()
    return "\n" + text[-4000:] if text else ""


def wait_until_answering(args, responder, log):
    probe = [
        "snmpget",
        "-v2c",
        "-c",
        args.community,
        "-t",
        "1",
        "-r",
        "0",
        f"127.0.0.1:{args.port}",
        "1.3.6.1.2.1.1.1.0",
    ]
    deadline = time.monotonic() + args.start_timeout
    while time.monotonic() < deadline:
        if responder.poll() is not None:
            raise SystemExit(
                f"the responder exited with {responder.returncode}" + said(log)
            )
        # any answer will do, noSuchObject included: it is serving
        if not subprocess.run(probe, capture_output=True).returncode:
            return
        time.sleep(0.2)
    raise SystemExit(
        f"no answer in {args.start_timeout} s; a community that selects no "
        f"recording (--community={args.community}) gets none either" + said(log)
    )


def stop(responder, interrupted=False):
    # after Ctrl-C the responder has had its SIGINT already, and a second one
    # could cut short cProfile writing its file
    if not interrupted and responder.poll() is None:
        responder.send_signal(signal.SIGINT)
    try:
        responder.wait(timeout=120)
    except subprocess.TimeoutExpired:
        responder.kill()
        responder.wait()


def package_split(profile_file):
    """Busy seconds by package, from a cProfile file."""
    import pstats

    busy = collections.Counter()
    for (filename, _, name), stat in pstats.Stats(profile_file).stats.items():
        # the event loop waiting for a datagram is not work
        if name.startswith("<method 'control' of 'select.") or name.startswith(
            "<method 'poll' of 'select."
        ):
            continue
        path = filename.replace("\\", "/")
        if "/site-packages/" in path:
            top = path.split("/site-packages/", 1)[1].split("/", 1)[0]
            package = (
                top if top in ("pyasn1", "pysnmp", "snmpsim") else "other packages"
            )
        elif "/snmpsim/" in path:
            package = "snmpsim"
        elif filename == "~":
            package = "builtins"
        else:
            package = "stdlib and the rest"
        busy[package] += stat[2]
    return dict(busy)


def run(args):
    missing = [tool for tool in TOOLS if not shutil.which(tool)]
    if missing:
        raise SystemExit("net-snmp tools missing: " + ", ".join(missing))

    env = dict(os.environ)
    if not args.installed:
        env["PYTHONPATH"] = os.pathsep.join(
            [CHECKOUT] + [p for p in [env.get("PYTHONPATH")] if p]
        )

    check_port_free(args.port)

    with tempfile.TemporaryDirectory() as scratch, tempfile.TemporaryFile() as log:
        cache_dir = os.path.abspath(args.cache_dir or os.path.join(scratch, "cache"))

        started = time.monotonic()
        responder = subprocess.Popen(
            responder_command(args, cache_dir),
            env=env,
            # `-m` puts the working directory first on the import path: a
            # checkout there would be measured instead of the one asked for
            cwd=scratch,
            stdout=subprocess.DEVNULL,
            stderr=log,
            # a SIGINT ends it the way Ctrl-C does, so that cProfile writes
            # its file; a shell that started this script in the background
            # may have left SIGINT ignored, and that would be inherited
            preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL),
        )
        interrupted = False
        try:
            wait_until_answering(args, responder, log)
            start_seconds = time.monotonic() - started

            getnext = ["snmpwalk"] + snmp_args(args) + [args.getnext_oid]
            for _ in range(args.warmup):
                timed_walk(getnext)

            bulk_oids, bulk_seconds = timed_walk(
                ["snmpbulkwalk"]
                + snmp_args(args, f"-Cr{args.repetitions}")
                + [args.bulk_oid]
            )
            getnext_oids, getnext_seconds = timed_walk(getnext)

            # one that died on the way was not what answered at the end
            if responder.poll() is not None:
                raise SystemExit(
                    f"the responder exited with {responder.returncode} during "
                    "the walks" + said(log)
                )

        except KeyboardInterrupt:
            interrupted = True
            raise

        finally:
            stop(responder, interrupted)

    result = {
        "python": subprocess.run(
            [
                args.python,
                "-c",
                "import platform; print(platform.python_implementation(), platform.python_version())",
            ],
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "responder": args.responder,
        "start_seconds": round(start_seconds, 1),
        "bulk": {
            "oids": bulk_oids,
            "seconds": round(bulk_seconds, 2),
            "oids_per_second": round(bulk_oids / bulk_seconds) if bulk_seconds else 0,
            "repetitions": args.repetitions,
        },
        "getnext": {
            "oids": getnext_oids,
            "seconds": round(getnext_seconds, 2),
            "oids_per_second": (
                round(getnext_oids / getnext_seconds) if getnext_seconds else 0
            ),
        },
    }

    if args.profile:
        result["busy_seconds_by_package"] = {
            k: round(v, 2) for k, v in package_split(args.profile).items()
        }

    return result


def report(result):
    lines = [
        f"{result['python']}, {result['responder']} responder",
        f"  start (indexes and bind): {result['start_seconds']} s"
        + (
            " - under cProfile, rates included"
            if "busy_seconds_by_package" in result
            else ""
        ),
        "  bulk walk:    {oids} OIDs in {seconds} s = {oids_per_second} OIDs/s"
        " (-Cr{repetitions})".format(**result["bulk"]),
        "  GETNEXT walk: {oids} OIDs in {seconds} s = {oids_per_second} OIDs/s".format(
            **result["getnext"]
        ),
    ]
    busy = result.get("busy_seconds_by_package")
    if busy:
        total = sum(busy.values()) or 1
        lines.append(f"  busy {total:.2f} s:")
        for package, seconds in sorted(busy.items(), key=lambda kv: -kv[1]):
            lines.append(
                f"    {package:22s} {seconds:7.2f} s {100 * seconds / total:5.1f}%"
            )
    return "\n".join(lines)


def main(argv=None):
    args = parse_args(argv)
    result = run(args)
    print(json.dumps(result, indent=2) if args.json else report(result))


if __name__ == "__main__":
    main()
