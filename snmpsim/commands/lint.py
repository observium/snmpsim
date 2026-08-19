#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
# SNMP simulation data validation tool
#
import argparse
import os
import sys

from pyasn1.codec.ber import encoder
from pyasn1.type import univ

from snmpsim import utils
from snmpsim.record import dump
from snmpsim.record import mvc
from snmpsim.record import sap
from snmpsim.record import snmprec
from snmpsim.record import walk
from snmpsim.record.search.file import get_record

# data file types and parsers
RECORD_TYPES = {
    dump.DumpRecord.ext: dump.DumpRecord(),
    mvc.MvcRecord.ext: mvc.MvcRecord(),
    sap.SapRecord.ext: sap.SapRecord(),
    walk.WalkRecord.ext: walk.WalkRecord(),
    snmprec.SnmprecRecord.ext: snmprec.SnmprecRecord(),
    snmprec.CompressedSnmprecRecord.ext: snmprec.CompressedSnmprecRecord(),
}

DESCRIPTION = (
    "SNMP simulation data validation tool. Reports every record whose value "
    "cannot be served to SNMP clients, along with the records the simulator "
    "has to repair before serving them. Online documentation at "
    "https://www.pysnmp.com/snmpsim"
)

ERROR = "ERROR"
WARNING = "WARNING"


def get_record_type(path):
    """Return record parser suitable for the given file, `None` if unknown"""
    for ext in sorted(RECORD_TYPES, key=len, reverse=True):
        if path.endswith(os.path.extsep + ext):
            return RECORD_TYPES[ext]


def check_record(parser, line):
    """Check a single record, return a list of (severity, message) tuples"""
    try:
        oid, tag, value = parser.grammar.parse(line)

    except Exception as exc:
        return [(ERROR, "broken record: %s" % exc)]

    # variation module records are computed at run time - nothing to check
    if ":" in tag:
        return []

    try:
        oid = parser.evaluate_oid(oid)

    except Exception as exc:
        return [(ERROR, "broken OID: %s" % exc)]

    try:
        _, _, val = parser.evaluate_value(oid, tag, value)

    except Exception as exc:
        return [(ERROR, "%s" % exc)]

    try:
        encoder.encode(val)

    except Exception as exc:
        return [(ERROR, "value %r can not be encoded: %s" % (value, exc))]

    if isinstance(val, univ.ObjectIdentifier):
        served = val.prettyPrint()

        if value.strip().strip(".") != served:
            return [
                (
                    WARNING,
                    "short OID value %r is served as %s" % (value.strip(), served),
                )
            ]

    return []


def check_file(path, parser, quiet=False):
    """Check a single data file, return (errors, warnings, records) counts"""
    errors = warnings = records = 0

    try:
        text = parser.open(path)

    except OSError as exc:
        sys.stdout.write("%s: %s: %s\r\n" % (path, ERROR, exc))
        return 1, 0, 0

    try:
        line_no = 0
        offset = 0

        while True:
            line, line_no, offset = get_record(text, line_no, offset)

            if not line:
                break

            offset += len(line)
            records += 1

            for severity, message in check_record(parser, line):
                if severity == ERROR:
                    errors += 1

                else:
                    warnings += 1

                if not quiet or severity == ERROR:
                    sys.stdout.write(
                        "%s:%d: %s: %s\r\n" % (path, line_no, severity, message)
                    )

    finally:
        text.close()

    return errors, warnings, records


def get_files(paths):
    """Expand the given paths into a sorted list of (path, parser) tuples"""
    files = []

    for path in paths:
        if os.path.isdir(path):
            for dir_name, _, file_names in os.walk(path):
                for file_name in file_names:
                    full_path = os.path.join(dir_name, file_name)
                    parser = get_record_type(full_path)

                    if parser:
                        files.append((full_path, parser))

        else:
            parser = get_record_type(path)

            if not parser:
                parser = RECORD_TYPES[snmprec.SnmprecRecord.ext]

            files.append((path, parser))

    return sorted(files)


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument("-v", "--version", action="version", version=utils.TITLE)

    parser.add_argument(
        "--quiet", action="store_true", help="Report errors, but not warnings"
    )

    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings (such as repaired values) as errors",
    )

    parser.add_argument(
        "paths",
        metavar="<FILE|DIR>",
        nargs="*",
        default=["."],
        help="Simulation data files or directories to check (default: .)",
    )

    args = parser.parse_args()

    files = get_files(args.paths)

    if not files:
        sys.stderr.write("No simulation data files found\r\n")
        return 1

    errors = warnings = records = 0

    for path, record_type in files:
        file_errors, file_warnings, file_records = check_file(
            path, record_type, quiet=args.quiet
        )

        errors += file_errors
        warnings += file_warnings
        records += file_records

    if not args.quiet:
        sys.stdout.write(
            "# Checked %d record(s) in %d file(s): %d error(s), "
            "%d warning(s)\r\n" % (records, len(files), errors, warnings)
        )

    if errors or args.strict and warnings:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
