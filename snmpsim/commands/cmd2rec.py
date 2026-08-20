#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
# SNMP Snapshot Data Recorder
#
import argparse
import asyncio
import functools
import os
import sys
import time
import traceback

from pyasn1 import debug as pyasn1_debug
from pyasn1.type import univ
from pysnmp import debug as pysnmp_debug
from pysnmp.entity import config
from pysnmp.error import PySnmpError
from pysnmp.hlapi.v3arch.asyncio import CommunityData
from pysnmp.hlapi.v3arch.asyncio import ContextData
from pysnmp.hlapi.v3arch.asyncio import SnmpEngine
from pysnmp.hlapi.v3arch.asyncio import Udp6TransportTarget
from pysnmp.hlapi.v3arch.asyncio import UdpTransportTarget
from pysnmp.hlapi.v3arch.asyncio import UsmUserData
from pysnmp.hlapi.v3arch.asyncio import bulk_walk_cmd
from pysnmp.hlapi.v3arch.asyncio import walk_cmd
from pysnmp.proto import rfc1902
from pysnmp.proto import rfc1905
from pysnmp.smi import compiler
from pysnmp.smi import view
from pysnmp.smi.rfc1902 import ObjectIdentity
from pysnmp.smi.rfc1902 import ObjectType

from snmpsim import confdir
from snmpsim import error
from snmpsim import log
from snmpsim import utils
from snmpsim import variation
from snmpsim import endpoints

AUTH_PROTOCOLS = {
    "MD5": config.USM_AUTH_HMAC96_MD5,
    "SHA": config.USM_AUTH_HMAC96_SHA,
    "SHA224": config.USM_AUTH_HMAC128_SHA224,
    "SHA256": config.USM_AUTH_HMAC192_SHA256,
    "SHA384": config.USM_AUTH_HMAC256_SHA384,
    "SHA512": config.USM_AUTH_HMAC384_SHA512,
    "NONE": config.USM_AUTH_NONE,
}

PRIV_PROTOCOLS = {
    "DES": config.USM_PRIV_CBC56_DES,
    "3DES": config.USM_PRIV_CBC168_3DES,
    "AES": config.USM_PRIV_CFB128_AES,
    "AES128": config.USM_PRIV_CFB128_AES,
    "AES192": config.USM_PRIV_CFB192_AES,
    "AES192BLMT": config.USM_PRIV_CFB192_AES_BLUMENTHAL,
    "AES256": config.USM_PRIV_CFB256_AES,
    "AES256BLMT": config.USM_PRIV_CFB256_AES_BLUMENTHAL,
    "NONE": config.USM_PRIV_NONE,
}

VERSION_MAP = {"1": 0, "2c": 1, "3": 3}

DESCRIPTION = "SNMP simulation data recorder. Pull simulation data from SNMP agent"


def _parse_mib_object(arg, last=False):
    if "::" in arg:
        return ObjectIdentity(*arg.split("::", 1), last=last)

    else:
        return univ.ObjectIdentifier(arg)


def _parse_sized_string(arg, min_length=8):
    if len(arg) < min_length:
        raise argparse.ArgumentTypeError(
            f'Value "{arg}" must be {min_length}+ chars of length'
        )

    return arg


def main():
    variation_module = None

    parser = argparse.ArgumentParser(description=DESCRIPTION)

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

    v1arch_group = parser.add_argument_group("SNMPv1/v2c parameters")

    v1arch_group.add_argument(
        "--protocol-version",
        choices=["1", "2c"],
        default="2c",
        help="SNMPv1/v2c protocol version",
    )

    v1arch_group.add_argument(
        "--community", type=str, default="public", help="SNMP community name"
    )

    v3arch_group = parser.add_argument_group("SNMPv3 parameters")

    v3arch_group.add_argument(
        "--v3-user",
        metavar="<STRING>",
        type=functools.partial(_parse_sized_string, min_length=1),
        help="SNMPv3 USM user (security) name",
    )

    v3arch_group.add_argument(
        "--v3-auth-key",
        type=_parse_sized_string,
        help="SNMPv3 USM authentication key (must be > 8 chars)",
    )

    v3arch_group.add_argument(
        "--v3-auth-proto",
        choices=AUTH_PROTOCOLS,
        type=lambda x: x.upper(),
        default="NONE",
        help="SNMPv3 USM authentication protocol",
    )

    v3arch_group.add_argument(
        "--v3-priv-key",
        type=_parse_sized_string,
        help="SNMPv3 USM privacy (encryption) key (must be > 8 chars)",
    )

    v3arch_group.add_argument(
        "--v3-priv-proto",
        choices=PRIV_PROTOCOLS,
        type=lambda x: x.upper(),
        default="NONE",
        help="SNMPv3 USM privacy (encryption) protocol",
    )

    v3arch_group.add_argument(
        "--v3-context-engine-id",
        type=lambda x: univ.OctetString(hexValue=x[2:]),
        help="SNMPv3 context engine ID",
    )

    v3arch_group.add_argument(
        "--v3-context-name", type=str, default="", help="SNMPv3 context engine ID"
    )

    parser.add_argument(
        "--use-getbulk",
        action="store_true",
        help="Use SNMP GETBULK PDU for mass SNMP managed objects retrieval",
    )

    parser.add_argument(
        "--getbulk-repetitions",
        type=int,
        default=25,
        help="Use SNMP GETBULK PDU for mass SNMP managed objects retrieval",
    )

    endpoint_group = parser.add_mutually_exclusive_group(required=True)

    endpoint_group.add_argument(
        "--agent-udpv4-endpoint",
        type=endpoints.parse_endpoint,
        metavar="<[X.X.X.X]:NNNNN>",
        help="SNMP agent UDP/IPv4 address to pull simulation data from (name:port)",
    )

    endpoint_group.add_argument(
        "--agent-udpv6-endpoint",
        type=functools.partial(endpoints.parse_endpoint, ipv6=True),
        metavar="<[X:X:..X]:NNNNN>",
        help="SNMP agent UDP/IPv6 address to pull simulation data from ([name]:port)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=3,
        help="SNMP command response timeout (in seconds)",
    )

    parser.add_argument("--retries", type=int, default=3, help="SNMP command retries")

    parser.add_argument(
        "--start-object",
        metavar="<MIB::Object|OID>",
        type=_parse_mib_object,
        default=univ.ObjectIdentifier("1.3.6"),
        help="Drop all simulation data records prior to this OID specified "
        "as MIB object (MIB::Object) or OID (1.3.6.)",
    )

    parser.add_argument(
        "--stop-object",
        metavar="<MIB::Object|OID>",
        type=functools.partial(_parse_mib_object, last=True),
        help="Drop all simulation data records after this OID specified "
        "as MIB object (MIB::Object) or OID (1.3.6.)",
    )

    parser.add_argument(
        "--mib-source",
        dest="mib_sources",
        metavar="<URI|PATH>",
        action="append",
        type=str,
        default=["https://mibs.pysnmp.com/asn1/@mib@"],
        help="One or more URIs pointing to a collection of ASN.1 MIB files."
        'Optional "@mib@" token gets replaced with desired MIB module '
        "name during MIB search.",
    )

    parser.add_argument(
        "--destination-record-type",
        choices=variation.RECORD_TYPES,
        default="snmprec",
        help="Produce simulation data with record of this type",
    )

    parser.add_argument(
        "--output-file",
        metavar="<FILE>",
        type=str,
        help="SNMP simulation data file to write records to",
    )

    parser.add_argument(
        "--continue-on-errors",
        metavar="<tolerance-level>",
        type=int,
        default=0,
        help="Keep on pulling SNMP data even if intermittent errors occur",
    )

    variation_group = parser.add_argument_group("Simulation data variation options")

    parser.add_argument(
        "--variation-modules-dir",
        action="append",
        type=str,
        help="Search variation module by this path",
    )

    variation_group.add_argument(
        "--variation-module",
        type=str,
        help="Pass gathered simulation data through this variation module",
    )

    variation_group.add_argument(
        "--variation-module-options",
        type=str,
        default="",
        help="Variation module options",
    )

    args = parser.parse_args()

    if args.debug:
        pysnmp_debug.set_logger(pysnmp_debug.Debug(*args.debug))

    if args.debug_asn1:
        pyasn1_debug.setLogger(pyasn1_debug.Debug(*args.debug_asn1))

    if args.output_file:
        ext = os.path.extsep
        ext += variation.RECORD_TYPES[args.destination_record_type].ext

        if not args.output_file.endswith(ext):
            args.output_file += ext

        record = variation.RECORD_TYPES[args.destination_record_type]
        args.output_file = record.open(args.output_file, "wb")

    else:
        args.output_file = sys.stdout

        if sys.version_info >= (3, 0, 0):
            # binary mode write
            args.output_file = sys.stdout.buffer

        elif sys.platform == "win32":
            import msvcrt

            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    # Catch missing params

    if args.protocol_version == "3":
        if not args.v3_user:
            sys.stderr.write("ERROR: --v3-user is missing\r\n")
            parser.print_usage(sys.stderr)
            return 1

        if args.v3_priv_key and not args.v3_auth_key:
            sys.stderr.write("ERROR: --v3-auth-key is missing\r\n")
            parser.print_usage(sys.stderr)
            return 1

        if AUTH_PROTOCOLS[args.v3_auth_proto] == config.USM_AUTH_NONE:
            if args.v3_auth_key:
                args.v3_auth_proto = "MD5"

        else:
            if not args.v3_auth_key:
                sys.stderr.write("ERROR: --v3-auth-key is missing\r\n")
                parser.print_usage(sys.stderr)
                return 1

        if PRIV_PROTOCOLS[args.v3_priv_proto] == config.USM_PRIV_NONE:
            if args.v3_priv_key:
                args.v3_priv_proto = "DES"

        else:
            if not args.v3_priv_key:
                sys.stderr.write("ERROR: --v3-priv-key is missing\r\n")
                parser.print_usage(sys.stderr)
                return 1

    proc_name = os.path.basename(sys.argv[0])

    try:
        log.set_logger(proc_name, *args.logging_method, force=True)

        if args.log_level:
            log.set_level(args.log_level)

    except error.SnmpsimError as exc:
        sys.stderr.write("%s\r\n" % exc)
        parser.print_usage(sys.stderr)
        return 1

    if args.use_getbulk and args.protocol_version == "1":
        log.info("will be using GETNEXT with SNMPv1!")
        args.use_getbulk = False

    # Load variation module

    if args.variation_module:
        for variation_modules_dir in args.variation_modules_dir or confdir.variation:
            log.info(
                'Scanning "%s" directory for variation '
                "modules..." % variation_modules_dir
            )

            if not os.path.exists(variation_modules_dir):
                log.info('Directory "%s" does not exist' % variation_modules_dir)
                continue

            mod = os.path.join(variation_modules_dir, args.variation_module + ".py")
            if not os.path.exists(mod):
                log.info('Variation module "%s" not found' % mod)
                continue

            ctx = {"path": mod, "moduleContext": {}}

            try:
                with open(mod) as fl:
                    exec(compile(fl.read(), mod, "exec"), ctx)

            except Exception as exc:
                log.error('Variation module "%s" execution failure: %s' % (mod, exc))
                return 1

            variation_module = ctx
            log.info('Variation module "%s" loaded' % args.variation_module)
            break

        else:
            log.error('variation module "%s" not found' % args.variation_module)
            return 1

    # SNMP configuration

    # pysnmp builds its transports around the event loop of the calling
    # thread, and Python 3.10+ does not hand out one which was never created
    # (or was closed by someone else)
    try:
        event_loop = asyncio.get_event_loop()

    except RuntimeError:
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)

    snmp_engine = SnmpEngine()

    if args.protocol_version == "3":
        if args.v3_priv_key is None and args.v3_auth_key is None:
            sec_level = "noAuthNoPriv"

        elif args.v3_priv_key is None:
            sec_level = "authNoPriv"

        else:
            sec_level = "authPriv"

        auth_data = UsmUserData(
            args.v3_user,
            authKey=args.v3_auth_key,
            authProtocol=AUTH_PROTOCOLS[args.v3_auth_proto],
            privKey=args.v3_priv_key,
            privProtocol=PRIV_PROTOCOLS[args.v3_priv_proto],
        )

        log.info(
            "SNMP version 3, Context EngineID: %s Context name: %s, SecurityName: %s, "
            "SecurityLevel: %s, Authentication key/protocol: %s/%s, Encryption "
            "(privacy) key/protocol: "
            "%s/%s"
            % (
                args.v3_context_engine_id
                and args.v3_context_engine_id.prettyPrint()
                or "<default>",
                args.v3_context_name and args.v3_context_name.prettyPrint() or '""',
                args.v3_user,
                sec_level,
                args.v3_auth_key is None and "<NONE>" or args.v3_auth_key,
                args.v3_auth_proto,
                args.v3_priv_key is None and "<NONE>" or args.v3_priv_key,
                args.v3_priv_proto,
            )
        )

    else:
        auth_data = CommunityData(
            args.community, mpModel=VERSION_MAP[args.protocol_version]
        )

        log.info(
            "SNMP version %s, Community name: "
            "%s" % (args.protocol_version, args.community)
        )

    context_data = ContextData(args.v3_context_engine_id, args.v3_context_name)

    if args.agent_udpv6_endpoint:
        log.info("Querying UDP/IPv6 agent at [%s]:%s" % args.agent_udpv6_endpoint)

    elif args.agent_udpv4_endpoint:
        log.info("Querying UDP/IPv4 agent at %s:%s" % args.agent_udpv4_endpoint)

    log.info(
        "Agent response timeout: %d secs, retries: %s" % (args.timeout, args.retries)
    )

    if isinstance(args.start_object, ObjectIdentity) or isinstance(
        args.stop_object, ObjectIdentity
    ):
        compiler.add_mib_compiler(
            snmp_engine.get_mib_builder(), sources=args.mib_sources
        )

        mib_view_controller = view.MibViewController(snmp_engine.get_mib_builder())

        try:
            if isinstance(args.start_object, ObjectIdentity):
                args.start_object.resolve_with_mib(mib_view_controller)

            if isinstance(args.stop_object, ObjectIdentity):
                args.stop_object.resolve_with_mib(mib_view_controller)

        except PySnmpError as exc:
            sys.stderr.write("ERROR: %s\r\n" % exc)
            return 1

    # Variation module initialization

    if variation_module:
        log.info("Initializing variation module...")

        for x in ("init", "record", "shutdown"):
            if x not in variation_module:
                log.error(
                    'missing "%s" handler at variation module '
                    '"%s"' % (x, args.variation_module)
                )
                return 1

        try:
            handler = variation_module["init"]

            handler(
                snmpEngine=snmp_engine,
                options=args.variation_module_options,
                mode="recording",
                startOID=args.start_object,
                stopOID=args.stop_object,
            )

        except Exception as exc:
            log.error(
                'Variation module "%s" initialization FAILED: '
                "%s" % (args.variation_module, exc)
            )

        else:
            log.info('Variation module "%s" initialization OK' % args.variation_module)

    data_file_handler = variation.RECORD_TYPES[args.destination_record_type]

    # SNMP worker

    state = {
        "total": 0,
        "count": 0,
        "errors": 0,
        "iteration": 0,
        "reqTime": time.time(),
        "retries": args.continue_on_errors,
        "lastOID": args.start_object,
    }

    def oid_after_error(var_binds):
        """Guess where to resume a walk which the agent broke off"""
        try:
            next_oid = var_binds[-1][0]

        except IndexError:
            next_oid = state["lastOID"]

        else:
            log.error("Failed OID: %s" % next_oid)

        # fuzzy logic of walking a broken OID
        if len(next_oid) < 4:
            pass

        elif (
            args.continue_on_errors - state["retries"]
        ) * 10 / args.continue_on_errors > 5:
            next_oid = next_oid[:-2] + (next_oid[-2] + 1,)

        elif next_oid[-1]:
            next_oid = next_oid[:-1] + (next_oid[-1] + 1,)

        else:
            next_oid = next_oid[:-2] + (next_oid[-2] + 1, 0)

        return next_oid

    def record(var_binds):
        """Write one response worth of var-binds into the data file

        Returns whether the walk is over, and whether a variation module has
        asked for a fresh iteration of it.
        """
        stop_flag = False
        restarted = False

        # Walk var-binds
        for oid, value in var_binds:
            # EOM
            if args.stop_object and oid >= args.stop_object:
                stop_flag = True  # stop on out of range condition

            elif value is None or value.tagSet in (
                rfc1905.NoSuchObject.tagSet,
                rfc1905.NoSuchInstance.tagSet,
                rfc1905.EndOfMibView.tagSet,
            ):
                stop_flag = True

            # remove value enumeration
            if value.tagSet == rfc1902.Integer32.tagSet:
                value = rfc1902.Integer32(value)

            if value.tagSet == rfc1902.Unsigned32.tagSet:
                value = rfc1902.Unsigned32(value)

            if value.tagSet == rfc1902.Bits.tagSet:
                value = rfc1902.OctetString(value)

            # Build .snmprec record

            context = {
                "origOid": oid,
                "origValue": value,
                "count": state["count"],
                "total": state["total"],
                "iteration": state["iteration"],
                "reqTime": state["reqTime"],
                "args.start_object": args.start_object,
                "stopOID": args.stop_object,
                "stopFlag": stop_flag,
                "variationModule": variation_module,
            }

            try:
                line = data_file_handler.format(oid, value, **context)

            except error.MoreDataNotification as exc:
                state["count"] = 0
                state["iteration"] += 1

                more_data_notification = exc

                if "period" in more_data_notification:
                    log.info(
                        "%s OIDs dumped, waiting %.2f sec(s)"
                        "..." % (state["total"], more_data_notification["period"])
                    )

                    time.sleep(more_data_notification["period"])

                # the caller starts another walk from the beginning
                restarted = True
                stop_flag = True  # stop current iteration

            except error.NoDataNotification:
                pass

            except error.SnmpsimError as exc:
                log.error(exc)
                continue

            else:
                args.output_file.write(line)

                state["count"] += 1
                state["total"] += 1

                if state["count"] % 100 == 0:
                    log.info(
                        "OIDs dumped: %s/%s" % (state["iteration"], state["count"])
                    )

        # Next request time
        state["reqTime"] = time.time()

        return stop_flag, restarted

    async def walk_agent():
        """Walk the agent from the start OID, restarting where asked to

        pysnmp hands over one response per request and does not walk on its
        own (lextudio/pysnmp#251), so the walking is the caller's business.
        """
        if args.agent_udpv6_endpoint:
            transport = await Udp6TransportTarget.create(
                args.agent_udpv6_endpoint, timeout=args.timeout, retries=args.retries
            )

        else:
            transport = await UdpTransportTarget.create(
                args.agent_udpv4_endpoint, timeout=args.timeout, retries=args.retries
            )

        start_oid = args.start_object

        while start_oid is not None:
            log.info(
                "Sending %s request for %s (stop at %s)"
                "...."
                % (
                    args.use_getbulk and "GETBULK" or "GETNEXT",
                    start_oid,
                    args.stop_object or "<end-of-mib>",
                )
            )

            if args.use_getbulk:
                walk = bulk_walk_cmd(
                    snmp_engine,
                    auth_data,
                    transport,
                    context_data,
                    0,
                    args.getbulk_repetitions,
                    ObjectType(ObjectIdentity(start_oid)),
                    lexicographicMode=True,
                    lookupMib=False,
                )

            else:
                walk = walk_cmd(
                    snmp_engine,
                    auth_data,
                    transport,
                    context_data,
                    ObjectType(ObjectIdentity(start_oid)),
                    lexicographicMode=True,
                    lookupMib=False,
                )

            start_oid = None

            async for (
                error_indication,
                error_status,
                error_index,
                var_binds,
            ) in walk:
                if error_indication and not state["retries"]:
                    state["errors"] += 1
                    log.error("SNMP Engine error: %s" % error_indication)
                    return

                # SNMPv1 response may contain noSuchName error *and* SNMPv2c
                # exception, so we ignore noSuchName error here
                if error_status and error_status != 2 or error_indication:
                    log.error(
                        "Remote SNMP error %s"
                        % (error_indication or error_status.prettyPrint())
                    )

                    state["errors"] += 1

                    if not state["retries"]:
                        return

                    start_oid = oid_after_error(var_binds)

                    state["retries"] -= 1
                    state["lastOID"] = start_oid

                    log.info(
                        "Retrying with OID %s (%s retries left)"
                        "..." % (start_oid, state["retries"])
                    )

                    break

                if args.continue_on_errors != state["retries"]:
                    state["retries"] += 1

                if var_binds and var_binds[-1]:
                    state["lastOID"] = var_binds[-1][0]

                stop_flag, restarted = record(var_binds)

                if restarted:
                    start_oid = args.start_object
                    break

                if stop_flag:
                    return

    started = time.time()

    try:
        event_loop.run_until_complete(walk_agent())

    except KeyboardInterrupt:
        log.info("Shutting down process...")

    finally:
        if variation_module:
            log.info("Shutting down variation module %s..." % args.variation_module)

            try:
                handler = variation_module["shutdown"]

                handler(
                    snmpEngine=snmp_engine,
                    options=args.variation_module_options,
                    mode="recording",
                )

            except Exception as exc:
                log.error(
                    "Variation module %s shutdown FAILED: "
                    "%s" % (args.variation_module, exc)
                )

            else:
                log.info("Variation module %s shutdown OK" % args.variation_module)

        if snmp_engine.transport_dispatcher:
            snmp_engine.transport_dispatcher.close_dispatcher()

        started = time.time() - started

        log.info(
            "OIDs dumped: %s, elapsed: %.2f sec, rate: %.2f OIDs/sec, errors: "
            "%d"
            % (
                state["total"],
                started,
                started and state["count"] // started or 0,
                state["errors"],
            )
        )

        args.output_file.flush()
        args.output_file.close()

        return state.get("errors", 0) and 1 or 0


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
