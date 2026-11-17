#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# Copyright (c) 2022-2025, LeXtudio Inc. <support@lextudio.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
# SNMP Agent Simulator: the command line of the lightweight SNMP v1/v2c
# command responder, kept for the systems that run it
#
"""`snmpsim-command-responder-lite`, served by `snmpsim-command-responder`.

The lite responder was a command responder of its own for SNMPv1/v2c, which
answered without pysnmp's SNMPv3 engine. The full responder answers SNMPv1/v2c
that way too, faster and with all it does besides, so there is one responder
now and this is its old name: it takes the options the lite responder took,
as it took them - `--args-from-file` read ahead of the command line, one
endpoint family - and starts `snmpsim-command-responder` with them.

What the lite responder was is kept: it answers SNMPv1 and SNMPv2c only, and
SIGHUP ends it rather than rescanning the recordings. `--v2c-arch` and
`--v3-only`, which it took and did nothing with, are taken and do nothing.
"""
import argparse
import os
import sys
import traceback

from pyasn1 import debug as pyasn1_debug
from pysnmp import debug as pysnmp_debug

from snmpsim import datafile
from snmpsim import log
from snmpsim import utils
from snmpsim.commands import responder
from snmpsim.reporting.manager import ReportingManager

DESCRIPTION = (
    "Lightweight SNMP agent simulator: responds to SNMP v1/v2c requests, "
    "variate responses based on transport addresses, SNMP community name "
    "or via variation modules."
)


def build_parser(raw=False):
    """The lite responder's command line.

    With `raw`, every value is kept as the string it was given and an option
    not given is None (or empty): what the full responder is handed.
    """
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    if raw:
        add_argument = parser.add_argument

        def raw_argument(*flags, **kwargs):
            for key in ("type", "choices"):
                kwargs.pop(key, None)

            if kwargs.get("action") not in ("append", "store_true", "version"):
                if "--pid-file" not in flags:
                    kwargs["default"] = None

            return add_argument(*flags, **kwargs)

        parser.add_argument = raw_argument

    parser.add_argument("-v", "--version", action="version", version=utils.TITLE)

    parser.add_argument(
        "--quiet", action="store_true", help="Do not print out informational messages"
    )

    parser.add_argument(
        "--debug",
        choices=pysnmp_debug.FLAG_MAP,
        action="append",
        type=str,
        default=[],
        help="Enable one or more categories of SNMP debugging.",
    )

    parser.add_argument(
        "--debug-asn1",
        choices=pyasn1_debug.FLAG_MAP,
        action="append",
        type=str,
        default=[],
        help="Enable one or more categories of ASN.1 debugging.",
    )

    parser.add_argument(
        "--logging-method",
        type=lambda x: x.split(":"),
        metavar="=<%s[:args]>]" % "|".join(log.METHODS_MAP),
        default="stderr",
        help="Logging method.",
    )

    parser.add_argument(
        "--log-level",
        choices=log.LEVELS_MAP,
        type=str,
        default="info",
        help="Logging level.",
    )

    parser.add_argument(
        "--reporting-method",
        type=utils.parse_reporting_method,
        metavar="=<%s[:args]>]" % "|".join(ReportingManager.REPORTERS),
        default="null",
        help="Activity metrics reporting method.",
    )

    parser.add_argument(
        "--daemonize",
        action="store_true",
        help="Disengage from controlling terminal and become a daemon",
    )

    parser.add_argument(
        "--process-user",
        type=str,
        help="If run as root, switch simulator daemon to this user right "
        "upon binding privileged ports",
    )

    parser.add_argument(
        "--process-group",
        type=str,
        help="If run as root, switch simulator daemon to this group right "
        "upon binding privileged ports",
    )

    parser.add_argument(
        "--pid-file",
        metavar="<FILE>",
        type=str,
        default=f"/var/run/{__name__}/{os.getpid()}.pid",
        help="SNMP simulation data file to write records to",
    )

    parser.add_argument(
        "--cache-dir",
        metavar="<DIR>",
        type=str,
        help="Location for SNMP simulation data file indices to create",
    )

    parser.add_argument(
        "--force-index-rebuild",
        action="store_true",
        help="Rebuild simulation data files indices even if they seem up to date",
    )

    parser.add_argument(
        "--validate-data",
        action="store_true",
        help="Validate simulation data files on daemon start-up",
    )

    parser.add_argument(
        "--variation-modules-dir",
        metavar="<DIR>",
        type=str,
        action="append",
        default=[],
        help="Variation modules search path(s)",
    )

    parser.add_argument(
        "--variation-module-options",
        metavar="<module[=alias][:args]>",
        type=str,
        action="append",
        default=[],
        help="Options for a specific variation module",
    )

    parser.add_argument(
        "--v2c-arch",
        action="store_true",
        help="Use lightweight, legacy SNMP architecture capable to support "
        "v1/v2c versions of SNMP",
    )

    parser.add_argument(
        "--v3-only",
        action="store_true",
        help="Trip legacy SNMP v1/v2c support to gain a little lesser memory footprint",
    )

    parser.add_argument(
        "--transport-id-offset",
        type=int,
        default=0,
        help="Start numbering the last sub-OID of transport endpoint OIDs "
        "starting from this ID",
    )

    parser.add_argument(
        "--max-var-binds",
        type=int,
        default=64,
        help="Maximum number of variable bindings to include in a single response",
    )

    parser.add_argument(
        "--max-message-size",
        type=int,
        default=utils.MAX_MESSAGE_SIZE,
        help="Maximum size (in octets) of an SNMP response message. GETBULK "
        "responses are cut short to stay within it, so that they are not sent "
        "as fragmented datagrams which managers may never receive whole. "
        "Raise it towards 65507 to let responses fill a whole datagram",
    )

    parser.add_argument(
        "--max-open-data-files",
        metavar="<N>",
        type=datafile.open_files_limit,
        default=datafile.DataFile.max_open_files,
        help="Keep at most this many data files open, closing the least "
        "recently used one to open another. Each open data file takes two "
        "file descriptors. Default is half of the descriptors the process "
        "may open less a reserve of 64, 256 at most (%(default)s here)",
    )

    parser.add_argument(
        "--data-dir",
        type=str,
        action="append",
        metavar="<DIR>",
        dest="data_dirs",
        help="SNMP simulation data recordings directory.",
    )

    endpoint_group = parser.add_mutually_exclusive_group(required=True)

    if raw:
        group_argument = endpoint_group.add_argument

        def raw_group_argument(*flags, **kwargs):
            kwargs.pop("type", None)
            return group_argument(*flags, **kwargs)

        endpoint_group.add_argument = raw_group_argument

    endpoint_group.add_argument(
        "--agent-udpv4-endpoint",
        type=str,
        action="append",
        metavar="<[X.X.X.X]:NNNNN>",
        dest="agent_udpv4_endpoints",
        default=[],
        help="SNMP agent UDP/IPv4 address to listen on (name:port)",
    )

    endpoint_group.add_argument(
        "--agent-udpv6-endpoint",
        type=str,
        action="append",
        metavar="<[X:X:..X]:NNNNN>",
        dest="agent_udpv6_endpoints",
        default=[],
        help="SNMP agent UDP/IPv6 address to listen on ([name]:port)",
    )

    parser.add_argument(
        "--args-from-file",
        metavar="<FILE>",
        type=str,
        help="Read command-line options from this file, as whitespace-separated "
        "--option=value items. Can be useful when command-line is too long. "
        "The file is read ahead of the command line: an option that takes "
        "one value is overridden by the command line, an option that can be "
        "given more than once (--data-dir, the endpoints) gets the values of "
        "both, and --agent-udpv4-endpoint in one with --agent-udpv6-endpoint "
        "in the other is an error, as it is on one command line. A switch "
        "the file turns on (--daemonize, --quiet and the like) cannot be "
        "turned off from the command line",
    )

    return parser


def args_file(argv):
    """The file `--args-from-file` names on the command line, or None."""
    file_helper = argparse.ArgumentParser(add_help=False)
    file_helper.add_argument("--args-from-file")

    return file_helper.parse_known_args(argv)[0].args_from_file


# options handed on as they are, by their name and dest
VALUE_OPTIONS = (
    ("--logging-method", "logging_method"),
    ("--log-level", "log_level"),
    ("--reporting-method", "reporting_method"),
    ("--process-user", "process_user"),
    ("--process-group", "process_group"),
    ("--pid-file", "pid_file"),
    ("--cache-dir", "cache_dir"),
    ("--transport-id-offset", "transport_id_offset"),
    ("--max-var-binds", "max_var_binds"),
    ("--max-message-size", "max_message_size"),
    ("--max-open-data-files", "max_open_data_files"),
)

SWITCHES = (
    ("--quiet", "quiet"),
    ("--daemonize", "daemonize"),
    ("--force-index-rebuild", "force_index_rebuild"),
    ("--validate-data", "validate_data"),
)

REPEATED = (
    ("--debug", "debug"),
    ("--debug-asn1", "debug_asn1"),
    ("--variation-modules-dir", "variation_modules_dir"),
    ("--variation-module-options", "variation_module_options"),
    # what the full responder reads in order, after its other options
    ("--data-dir", "data_dirs"),
    ("--agent-udpv4-endpoint", "agent_udpv4_endpoints"),
    ("--agent-udpv6-endpoint", "agent_udpv6_endpoints"),
)


def responder_arguments(args):
    """The command line of the full responder for the lite one's `args`."""
    argv = [flag for flag, dest in SWITCHES if getattr(args, dest)]

    argv += [
        f"{flag}={getattr(args, dest)}"
        for flag, dest in VALUE_OPTIONS
        if getattr(args, dest) is not None
    ]

    for flag, dest in REPEATED:
        argv += [f"{flag}={value}" for value in getattr(args, dest) or ()]

    return argv


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()

    # The file can hold the required options, so it has to be read before
    # the command line is checked for them. Its items go ahead of the
    # command line and the two are parsed as one: the last value wins for an
    # option that holds one, and the options that append collect both.
    path = args_file(argv)
    file_args = []

    if path:
        try:
            with open(path) as fl:
                file_args = fl.read().split()

        except Exception as exc:
            sys.stderr.write("ERROR: file %s opening failure: %s\r\n" % (path, exc))
            parser.print_usage(sys.stderr)
            return 1

    items = file_args + list(argv)

    # checked as the lite responder checked them, errors and all
    parser.parse_args(items)

    args = build_parser(raw=True).parse_args(items)

    return responder.main(responder_arguments(args), lite=True)


if __name__ == "__main__":
    try:
        rc = main()

    except KeyboardInterrupt:
        sys.stderr.write("shutting down process...")
        rc = 0

    except Exception as exc:
        sys.stderr.write("process terminated: %s" % exc)

        for line in traceback.format_exception(*sys.exc_info()):
            sys.stderr.write(line.replace("\n", ";"))
        rc = 1

    sys.exit(rc)
