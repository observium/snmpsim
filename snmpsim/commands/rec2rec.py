#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
# SNMP Simulator data file management tool
#
import argparse
import functools
import os
import sys
import traceback

from pyasn1.type import univ
from pysnmp.error import PySnmpError
from pysnmp.smi import builder
from pysnmp.smi import compiler
from pysnmp.smi import rfc1902
from pysnmp.smi import view

from snmpsim import error
from snmpsim import utils
from snmpsim.record import dump
from snmpsim.record import mvc
from snmpsim.record import sap
from snmpsim.record import snmprec
from snmpsim.record import walk


class SnmprecRecordMixIn:
    def evaluateValue(self, oid, tag, value, **context):
        # Variation module reference
        if ":" in tag:
            context["backdoor"]["textTag"] = tag
            return oid, "", value

        else:
            return snmprec.SnmprecRecord.evaluate_value(self, oid, tag, value)

    def formatValue(self, oid, value, **context):
        if "textTag" in context["backdoor"]:
            return self.formatOid(oid), context["backdoor"]["textTag"], value

        else:
            return snmprec.SnmprecRecord.format_value(self, oid, value, **context)


class SnmprecRecord(SnmprecRecordMixIn, snmprec.SnmprecRecord):
    pass


class CompressedSnmprecRecord(SnmprecRecordMixIn, snmprec.CompressedSnmprecRecord):
    pass


# data file types and parsers
RECORD_TYPES = {
    dump.DumpRecord.ext: dump.DumpRecord(),
    mvc.MvcRecord.ext: mvc.MvcRecord(),
    sap.SapRecord.ext: sap.SapRecord(),
    walk.WalkRecord.ext: walk.WalkRecord(),
    SnmprecRecord.ext: SnmprecRecord(),
    CompressedSnmprecRecord.ext: CompressedSnmprecRecord(),
}

DESCRIPTION = (
    "SNMP simulation data management and repair tool. Online "
    "documentation at https://www.pysnmp.com/snmpsim"
)


def _parse_mib_object(arg, last=False):
    if "::" in arg:
        return rfc1902.ObjectIdentity(*arg.split("::", 1), last=last)

    else:
        return univ.ObjectIdentifier(arg)


def main():
    lost_comments = False
    written_count = skipped_count = duplicate_count = 0
    broken_count = variation_count = 0

    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument("-v", "--version", action="version", version=utils.TITLE)

    parser.add_argument(
        "--quiet", action="store_true", help="Do not print out informational messages"
    )

    parser.add_argument(
        "--sort-records",
        action="store_true",
        help="Order simulation data records by OID",
    )

    parser.add_argument(
        "--ignore-broken-records",
        action="store_true",
        help="Drop malformed simulation data records rather than bailing out",
    )

    parser.add_argument(
        "--deduplicate-records",
        action="store_true",
        help="Drop duplicate simulation data records",
    )

    parser.add_argument(
        "--escaped-strings",
        action="store_true",
        help='Produce Python-style escaped strings (e.g. "\x00") in '
        "simulation data values rather than hexify such non-ASCII "
        "values",
    )

    parser.add_argument(
        "--start-object",
        dest="start_oid",
        metavar="<MIB::Object|OID>",
        type=_parse_mib_object,
        help="Drop all simulation data records prior to this OID specified "
        "as MIB object (MIB::Object) or OID (1.3.6.)",
    )

    parser.add_argument(
        "--stop-object",
        dest="stop_oid",
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
        help="One or more URIs pointing to a collection of ASN.1 MIB files."
        'Optional "@mib@" token gets replaced with desired MIB module '
        "name during MIB search.",
    )

    parser.add_argument(
        "--source-record-type",
        choices=RECORD_TYPES,
        default="snmprec",
        help="Treat input as simulation data of this record type",
    )

    parser.add_argument(
        "--destination-record-type",
        choices=RECORD_TYPES,
        default="snmprec",
        help="Produce simulation data with record of this type",
    )

    parser.add_argument(
        "--input-file",
        dest="input_files",
        metavar="<FILE>",
        action="append",
        type=str,
        required=True,
        help="SNMP simulation data file to read records from",
    )

    parser.add_argument(
        "--output-file",
        metavar="<FILE>",
        type=str,
        help="SNMP simulation data file to write records to",
    )

    args = parser.parse_args()

    if not args.mib_sources:
        args.mib_sources = ["https://mibs.pysnmp.com/asn1/@mib@"]

    args.input_files = [
        RECORD_TYPES[args.source_record_type].open(x) for x in args.input_files
    ]

    if args.output_file and args.output_file != "-":
        ext = os.path.extsep + RECORD_TYPES[args.destination_record_type].ext

        if not args.output_file.endswith(ext):
            args.output_file += ext

        args.output_file = RECORD_TYPES[args.destination_record_type].open(
            args.output_file, "wb"
        )

    else:
        args.output_file = sys.stdout

        if sys.version_info >= (3, 0, 0):
            # binary mode write
            args.output_file = sys.stdout.buffer

        elif sys.platform == "win32":
            import msvcrt

            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    if not args.input_files:
        args.input_files.append(sys.stdin)

    if isinstance(args.start_oid, rfc1902.ObjectIdentity) or isinstance(
        args.stop_oid, rfc1902.ObjectIdentity
    ):
        mib_builder = builder.MibBuilder()

        mib_view_controller = view.MibViewController(mib_builder)

        compiler.add_mib_compiler(mib_builder, sources=args.mib_sources)

        try:
            if isinstance(args.start_oid, rfc1902.ObjectIdentity):
                args.start_oid.resolve_with_mib(mib_view_controller)

            if isinstance(args.stop_oid, rfc1902.ObjectIdentity):
                args.stop_oid.resolve_with_mib(mib_view_controller)

        except PySnmpError as exc:
            sys.stderr.write("ERROR: %s\r\n" % exc)
            return 1

    # Sorting is the only thing that takes all the records at once. Without
    # it each record is written as soon as it is read, so that the size of
    # a conversion is not bound by memory. Dropping duplicates only takes
    # remembering the OIDs seen so far.
    records_list = []
    unique_indices = set()
    write_failed = False

    def write_record(oid, value, backdoor):
        """Write one record out; False once the output cannot be written."""
        nonlocal written_count, duplicate_count, variation_count

        if args.deduplicate_records:
            if oid in unique_indices:
                if not args.quiet:
                    sys.stderr.write("# Skipping duplicate record " "<%s>\r\n" % oid)

                duplicate_count += 1

                return True

            unique_indices.add(oid)

        try:
            args.output_file.write(
                RECORD_TYPES[args.destination_record_type].format(
                    oid, value, backdoor=backdoor, nohex=args.escaped_strings
                )
            )

        except Exception as exc:
            sys.stderr.write("ERROR: record not written: %s\r\n" % exc)
            return False

        written_count += 1

        if backdoor:
            variation_count += 1

        return True

    for input_file in args.input_files:
        if write_failed:
            break

        if not args.quiet:
            sys.stderr.write(
                "# Input file #%s, processing records from %s till "
                "%s\r\n"
                % (
                    args.input_files.index(input_file),
                    args.start_oid or "the beginning",
                    args.stop_oid or "the end",
                )
            )

        line_no = 0

        while True:
            # the record type knows how many lines a record of it takes
            line, rec_line_no, _ = RECORD_TYPES[args.source_record_type].read_record(
                input_file, line_no
            )

            if not line:
                break

            if rec_line_no != line_no + 1:
                if not args.quiet:
                    sys.stderr.write(
                        "# Losing comment at lines %s..%s (input file #"
                        "%s)\r\n"
                        % (
                            line_no + 1,
                            rec_line_no - 1,
                            args.input_files.index(input_file),
                        )
                    )

                line_no = rec_line_no

                lost_comments += 1

            backdoor = {}

            try:
                oid, value = RECORD_TYPES[args.source_record_type].evaluate(
                    line, backdoor=backdoor
                )

            except error.SnmpsimError as exc:
                if args.ignore_broken_records:
                    if not args.quiet:
                        sys.stderr.write(
                            "# Skipping broken record <%s>: " "%s\r\n" % (line, exc)
                        )
                    broken_count += 1
                    continue

                else:
                    # what stopped the conversion is said even to --quiet
                    sys.stderr.write(
                        "ERROR: broken record <%s>: " "%s\r\n" % (line, exc)
                    )

                    # what was written ahead of it stays written
                    args.output_file.flush()

                    return 1

            if (
                args.start_oid
                and args.start_oid > oid
                or args.stop_oid
                and args.stop_oid < oid
            ):
                skipped_count += 1
                continue

            if args.sort_records:
                records_list.append((oid, value, backdoor))

            elif not write_record(oid, value, backdoor):
                write_failed = True
                break

    records_list.sort(key=lambda x: x[0])

    for record in records_list:
        if not write_record(*record):
            break

    if not args.quiet:
        sys.stderr.write(
            "# Records: written %s, filtered out %s, de-duplicated %s, ignored "
            "%s, broken %s, variated %s\r\n"
            % (
                written_count,
                skipped_count,
                duplicate_count,
                lost_comments,
                broken_count,
                variation_count,
            )
        )

    args.output_file.flush()
    args.output_file.close()

    return 0


if __name__ == "__main__":
    try:
        rc = main()

    except KeyboardInterrupt:
        sys.stderr.write("shutting down process...")
        rc = 0

    except Exception:
        sys.stderr.write("process terminated: %s" % sys.exc_info()[1])

        for line in traceback.format_exception(*sys.exc_info()):
            sys.stderr.write(line.replace("\n", ";"))
        rc = 1

    sys.exit(rc)
