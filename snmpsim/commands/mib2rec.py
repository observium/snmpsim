#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
# SNMP Simulator MIB to data file converter
#
import argparse
import functools
import math
import os
import random
import re
import sys
import traceback

from pyasn1.error import PyAsn1Error
from pyasn1.type import constraint
from pyasn1.type import univ
from pysnmp import debug
from pysnmp.error import PySnmpError
from pysnmp.proto import rfc1902
from pysnmp.smi import builder
from pysnmp.smi import compiler
from pysnmp.smi import error
from pysnmp.smi import view
from pysnmp.smi.rfc1902 import ObjectIdentity

from snmpsim import utils
from snmpsim.error import SnmpsimError
from snmpsim.record import dump
from snmpsim.record import mvc
from snmpsim.record import sap
from snmpsim.record import snmprec
from snmpsim.record import walk

RECORD_TYPES = {
    dump.DumpRecord.ext: dump.DumpRecord(),
    mvc.MvcRecord.ext: mvc.MvcRecord(),
    sap.SapRecord.ext: sap.SapRecord(),
    walk.WalkRecord.ext: walk.WalkRecord(),
    snmprec.SnmprecRecord.ext: snmprec.SnmprecRecord(),
    snmprec.CompressedSnmprecRecord.ext: snmprec.CompressedSnmprecRecord(),
}

DESCRIPTION = (
    "Converts MIB modules into SNMP simulation data files. "
    "Chooses random values the MIB permits, or asks interactively. "
    "Fills SNMP conceptual tables with consistent indices."
)


# What a constraint leaves of the numbers, as a list of (first, last)
EVERYTHING = [(-math.inf, math.inf)]

# The types that go on the wire, by tag: what a MIB makes of them (textual
# conventions, enumerations, refinements) stays in the MIB
INTEGER_TYPES = {
    syntax.tagSet: syntax
    for syntax in (
        rfc1902.Integer32,
        rfc1902.Unsigned32,
        rfc1902.Counter32,
        rfc1902.TimeTicks,
        rfc1902.Counter64,
    )
}

# Octets of a string that is not text, where the MIB leaves the size open
BINARY_SIZE = 6

MAX_STRING_SIZE = 65535


def _intersect(these, those):
    return [
        (max(this[0], that[0]), min(this[1], that[1]))
        for this in these
        for that in those
        if max(this[0], that[0]) <= min(this[1], that[1])
    ]


def _permitted(spec, kind):
    """Tell what a subtype specification leaves of the numbers.

    The numbers are the values of an object (`kind` is `ValueRangeConstraint`)
    or the sizes of its values (`ValueSizeConstraint`). A constraint that is
    not understood permits everything here: the value is still checked
    against the whole specification once it is drawn.
    """
    if isinstance(spec, constraint.ConstraintsIntersection):
        permitted = EVERYTHING

        for member in spec:
            permitted = _intersect(permitted, _permitted(member, kind))

        return permitted

    if isinstance(spec, constraint.ConstraintsUnion):
        permitted = []

        for member in spec:
            permitted.extend(_permitted(member, kind))

        return permitted if len(spec) else EVERYTHING

    # ValueSizeConstraint is a ValueRangeConstraint, PermittedAlphabetConstraint
    # is a SingleValueConstraint: the very class is what tells them apart
    if type(spec) is kind:
        return [(spec.start, spec.stop)]

    if (
        type(spec) is constraint.SingleValueConstraint
        and kind is constraint.ValueRangeConstraint
    ):
        values = [value for value in spec if isinstance(value, int)]

        if values:
            return [(value, value) for value in sorted(values)]

    return EVERYTHING


def _pick(permitted):
    first, last = random.choice(permitted)

    return random.randint(first, last)


def _nearest(permitted, wanted):
    """Return the permitted number nearest to the wanted one, from below first."""
    below = [min(last, wanted) for first, last in permitted if first <= wanted]

    if below:
        return max(below)

    return min(first for first, last in permitted)


def _guess_integer(syntax, wanted):
    """Draw a number the syntax permits, from the wanted range where it can."""
    permitted = _intersect(
        _permitted(syntax.subtypeSpec, constraint.ValueRangeConstraint),
        _permitted(
            INTEGER_TYPES[syntax.tagSet].subtypeSpec, constraint.ValueRangeConstraint
        ),
    )

    members = [
        (member, member)
        for member in sorted(set(getattr(syntax, "namedValues", {}).values()))
    ]

    if members:
        # an enumeration: the range on the command line is not about it
        return _pick(_intersect(members, permitted) or members)

    if not permitted:
        raise SnmpsimError("its constraints permit no value")

    return _pick(_intersect(permitted, [wanted]) or permitted)


def _is_text(syntax):
    """Tell if the octets of a string are characters to read.

    A string is text unless its DISPLAY-HINT shows octets as numbers, the
    way `1x:` shows a MAC address and `2d-1d-1d,1d:1d:1d.1d,1a1d:1d` a date.
    """
    hint = getattr(syntax, "displayHint", None) or ""

    return not re.search(r"\d[xdo]", hint)


def _guess_string(syntax, words):
    """Make up a string of a size the syntax permits."""
    sizes = _intersect(
        _permitted(syntax.subtypeSpec, constraint.ValueSizeConstraint),
        [(0, MAX_STRING_SIZE)],
    )

    if not sizes:
        raise SnmpsimError("its constraints permit no size")

    if not _is_text(syntax):
        return bytes(random.randrange(256) for _ in range(_nearest(sizes, BINARY_SIZE)))

    text = " ".join(random.choice(words) for _ in range(random.randrange(1, 10)))
    text = text.encode("utf-8")

    size = _nearest(sizes, len(text))

    while len(text) < size:
        text += b" " + random.choice(words).encode("utf-8")

    return text[:size]


def _guess_bits(syntax):
    """Set some of the bits the syntax names."""
    names = list(syntax.namedValues)

    if not names:
        return bytes([random.randrange(256)])

    return random.sample(names, random.randint(1, len(names)))


def _parse_mib_object(arg, last=False):
    if "::" in arg:
        return ObjectIdentity(*arg.split("::", 1), last=last)

    else:
        return univ.ObjectIdentifier(arg)


def _parse_range(arg):
    try:
        minimum, maximum = (int(x) for x in arg.split(","))

    except Exception as exc:
        raise SnmpsimError(f"Malformed integer range {arg}: {exc}")

    return minimum, maximum


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument("-v", "--version", action="version", version=utils.TITLE)

    parser.add_argument(
        "--quiet", action="store_true", help="Do not print out informational messages"
    )

    parser.add_argument(
        "--debug",
        choices=debug.FLAG_MAP,
        action="append",
        type=str,
        default=[],
        help="Enable one or more categories of SNMP debugging.",
    )

    parser.add_argument(
        "--row-hint",
        dest="row_hint",
        action="store_true",
        help="With --manual-values, do not name a scalar and its type before "
        "asking for its value; table rows, indexes and columns are named "
        "all the same, unless --quiet",
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
        "--mib-module",
        dest="mib_modules",
        action="append",
        type=str,
        required=True,
        help="MIB module to generate simulation data from",
    )

    parser.add_argument(
        "--start-object",
        metavar="<MIB::Object|OID>",
        type=_parse_mib_object,
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
        "--manual-values",
        action="store_true",
        help="Fill all managed objects values interactively. Objects are "
        "left out once the input ends",
    )

    parser.add_argument(
        "--automatic-values",
        type=int,
        default=5000,
        help="Probe for suitable managed object value this many times "
        "prior to reporting the object and leaving it out",
    )

    parser.add_argument(
        "--table-size",
        type=int,
        default=10,
        help="Generate SNMP conceptual tables with this many rows",
    )

    parser.add_argument(
        "--destination-record-type",
        choices=RECORD_TYPES,
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
        "--string-pool",
        metavar="<words>",
        action="append",
        help="Words to use for simulated string values",
    )

    parser.add_argument(
        "--string-pool-file",
        metavar="<FILE>",
        type=str,
        help="File containing the words for simulating SNMP string values",
    )

    parser.add_argument(
        "--integer32-range",
        metavar="<min,max>",
        type=_parse_range,
        default=(0, 32),
        help="Range of values used to populate simulated Integer32 values",
    )

    parser.add_argument(
        "--unsigned-range",
        metavar="<min,max>",
        type=_parse_range,
        default=(0, 65535),
        help="Range of values used to populate simulated Unsigned values",
    )

    parser.add_argument(
        "--counter-range",
        metavar="<min,max>",
        type=_parse_range,
        default=(0, 0xFFFFFFFF),
        help="Range of values used to populate simulated Counter values",
    )

    parser.add_argument(
        "--counter64-range",
        metavar="<min,max>",
        type=_parse_range,
        default=(0, 0xFFFFFFFFFFFFFFFF),
        help="Range of values used to populate simulated Counter64 values",
    )

    parser.add_argument(
        "--gauge-range",
        metavar="<min,max>",
        type=_parse_range,
        default=(0, 0xFFFFFFFF),
        help="Range of values used to populate simulated Gauge values",
    )

    parser.add_argument(
        "--timeticks-range",
        metavar="<min,max>",
        type=_parse_range,
        default=(0, 0xFFFFFFFF),
        help="Range of values used to populate simulated Timeticks values",
    )

    args = parser.parse_args()

    if args.debug:
        debug.setLogger(debug.Debug(*args.debug))

    if args.manual_values:
        args.automatic_values = 0

    if args.string_pool_file:
        # UTF-8 whatever the locale, the words go into the values as UTF-8
        try:
            with open(args.string_pool_file, encoding="utf-8") as fl:
                args.string_pool = fl.read().split()

        except (OSError, ValueError) as exc:
            sys.stderr.write(
                "ERROR: cannot read --string-pool-file %s: %s\r\n"
                % (args.string_pool_file, exc)
            )
            return 1

        if not args.string_pool:
            sys.stderr.write(
                "ERROR: --string-pool-file %s holds no words\r\n"
                % args.string_pool_file
            )
            return 1

    elif not args.string_pool:
        args.string_pool = [
            "Jaded",
            "zombies",
            "acted",
            "quaintly",
            "but",
            "kept",
            "driving",
            "their",
            "oxen",
            "forward",
        ]

    if args.output_file:
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

    def plain_value(syntax, val):
        # remove value enumeration

        if syntax.tagSet == rfc1902.Integer32.tagSet:
            return rfc1902.Integer32(syntax.clone(val))

        if syntax.tagSet == rfc1902.Unsigned32.tagSet:
            return rfc1902.Unsigned32(syntax.clone(val))

        if syntax.tagSet == rfc1902.Bits.tagSet:
            return rfc1902.OctetString(syntax.clone(val))

        return syntax.clone(val)

    def guess_value(syntax):
        if isinstance(syntax, rfc1902.IpAddress):
            return syntax.clone(
                ".".join([str(random.randrange(1, 256)) for x in range(4)])
            )

        if syntax.tagSet in INTEGER_TYPES:
            if isinstance(syntax, rfc1902.TimeTicks):
                wanted = args.timeticks_range

            elif isinstance(syntax, rfc1902.Gauge32):
                wanted = args.gauge_range

            elif isinstance(syntax, rfc1902.Counter32):
                wanted = args.counter_range

            elif isinstance(syntax, rfc1902.Unsigned32):
                wanted = args.unsigned_range

            elif isinstance(syntax, rfc1902.Counter64):
                wanted = args.counter64_range

            else:
                wanted = args.integer32_range

            val = _guess_integer(syntax, wanted)

            # The number is the one that goes on the wire: `clone()` of a
            # textual convention would read it the way its DISPLAY-HINT
            # shows it, "d-2" turning 40 into 4000
            syntax.subtypeSpec(val)

            return INTEGER_TYPES[syntax.tagSet](val)

        if isinstance(syntax, rfc1902.Bits):
            return plain_value(syntax, _guess_bits(syntax))

        if isinstance(syntax, univ.OctetString):
            # octets, not text, for the same reason: no DISPLAY-HINT parsing
            return plain_value(syntax, _guess_string(syntax, args.string_pool))

        if isinstance(syntax, univ.ObjectIdentifier):
            return syntax.clone(
                ".".join(
                    ["1", "3", "6", "1", "3"]
                    + [
                        "%d" % random.randrange(0, 255)
                        for x in range(random.randrange(0, 10))
                    ]
                )
            )

        raise SnmpsimError("no way to make up a value of this type")

    def ask_value(syntax, hint):
        val = None

        while True:
            sys.stderr.write(
                "%s# Value ['%s'] ? "
                % (
                    hint,
                    (val is None and "<none>" or val),
                )
            )
            sys.stderr.flush()

            line = sys.stdin.readline()

            if not line:
                # nobody is there to answer
                return None, "no value given"

            line = line.strip()

            try:
                if line:
                    if line[:4] == "0x0x":
                        val = line[2:]

                    elif line[:2] == "0x":
                        if isinstance(syntax, univ.OctetString):
                            val = syntax.clone(hexValue=line[2:])

                        else:
                            val = int(line[2:], 16)

                    else:
                        val = line

                if val is not None:
                    return plain_value(syntax, val), None

            except (PyAsn1Error, PySnmpError, ValueError) as exc:
                sys.stderr.write(
                    "*** Inconsistent value: %s\r\n*** See constraints and "
                    "suggest a better one for:\r\n" % exc
                )

    def get_value(syntax, hint=""):
        """Return a value for the object, or None and why there is none."""
        if not args.automatic_values:
            return ask_value(syntax, hint)

        reason = None

        for _ in range(args.automatic_values):
            try:
                return guess_value(syntax), None

            except SnmpsimError as exc:
                return None, str(exc)

            except (PyAsn1Error, PySnmpError) as exc:
                reason = "no value fits its constraints (%s)" % exc

        return None, reason

    skipped = set()

    def skip(what, mib_name, sym_name, syntax, reason):
        # once for an object, not for every row of its table
        if (mib_name, sym_name) in skipped:
            return

        skipped.add((mib_name, sym_name))

        sys.stderr.write(
            "WARNING: skipping %s %s::%s (type %s): %s\r\n"
            % (what, mib_name, sym_name, syntax.__class__.__name__, reason)
        )

    data_file_handler = snmprec.SnmprecRecord()

    mib_builder = builder.MibBuilder()

    # Load MIB tree foundation classes
    (MibScalar, MibTable, MibTableRow, MibTableColumn) = mib_builder.import_symbols(
        "SNMPv2-SMI", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn"
    )

    mib_view_controller = view.MibViewController(mib_builder)

    compiler.add_mib_compiler(mib_builder, sources=args.mib_sources)

    try:
        if isinstance(args.start_object, ObjectIdentity):
            args.start_object.resolve_with_mib(mib_view_controller)

        if isinstance(args.stop_object, ObjectIdentity):
            args.stop_object.resolve_with_mib(mib_view_controller)

    except error.PySnmpError as exc:
        sys.stderr.write("ERROR: %s\r\n" % exc)
        return 1

    output = []

    # Indexes of the rows generated so far, by the columns that index them
    shared_rows = {}

    # MIBs walk
    for modName in args.mib_modules:
        if not args.quiet:
            sys.stderr.write(
                "# MIB module: %s, from %s till "
                "%s\r\n"
                % (
                    modName,
                    args.start_object or "the beginning",
                    args.stop_object or "the end",
                )
            )

        try:
            oid = ObjectIdentity(modName).resolve_with_mib(mib_view_controller)

        except error.PySnmpError as exc:
            sys.stderr.write("ERROR: failed on MIB %s: " "%s\r\n" % (modName, exc))
            return 1

        hint = row_hint = ""
        row_oid = None
        suffix = ()
        this_table_size = 0

        while True:
            try:
                oid, label, _ = mib_view_controller.get_next_node_name(oid)

            except error.NoSuchObjectError:
                break

            if row_oid and not row_oid.isPrefixOf(oid):
                this_table_size += 1

                if args.automatic_values:
                    if this_table_size < args.table_size:
                        oid = tuple(row_oid)
                        if not args.quiet:
                            sys.stderr.write(
                                "# Synthesizing row #%d of table %s\r\n"
                                % (this_table_size, row_oid)
                            )

                    else:
                        if not args.quiet:
                            sys.stderr.write(
                                "# Finished table %s (%d rows)\r\n"
                                % (row_oid, this_table_size)
                            )

                        row_oid = None

                else:
                    while True:
                        sys.stderr.write(
                            "# Synthesize row #%d for table %s (y/n)? "
                            % (this_table_size, row_oid)
                        )
                        sys.stderr.flush()

                        line = sys.stdin.readline()

                        # nobody is there to answer: no more rows
                        line = line.strip() if line else "n"

                        if line:
                            if line[0] in ("y", "Y"):
                                oid = tuple(row_oid)
                                break

                            elif line[0] in ("n", "N"):
                                if not args.quiet:
                                    sys.stderr.write(
                                        "# Finished table %s (%d rows)\r\n"
                                        % (row_oid, this_table_size)
                                    )
                                row_oid = None
                                break

            if args.start_object and oid < args.start_object:
                continue  # skip on premature OID

            if args.stop_object and oid > args.stop_object:
                break  # stop on out of range condition

            mib_name, sym_name, _ = mib_view_controller.get_node_location(oid)
            (node,) = mib_builder.import_symbols(mib_name, sym_name)

            if isinstance(node, MibTable):
                hint = f"# Table {mib_name}::{sym_name}\r\n"
                if not args.quiet:
                    sys.stderr.write(
                        "# Starting table %s::%s (%s)\r\n"
                        % (mib_name, sym_name, univ.ObjectIdentifier(oid))
                    )
                continue

            elif isinstance(node, MibTableRow):
                if row_oid is None:
                    this_table_size = 0

                index_names = tuple(node.getIndexNames())

                # Rows of the tables indexed by the same columns (AUGMENTS
                # or a repeated INDEX clause) describe the same things, so
                # the n-th row of each of them gets the same index
                table_rows = shared_rows.setdefault(index_names, [])

                row_hint = hint + f"# Row {mib_name}::{sym_name}\r\n"

                if index_names and this_table_size < len(table_rows):
                    row_indices, suffix = table_rows[this_table_size]

                else:
                    row_indices = {}
                    suffix = ()

                    for implied_flag, idx_mod_name, idx_sym_name in index_names:
                        (idxNode,) = mib_builder.import_symbols(
                            idx_mod_name, idx_sym_name
                        )

                        row_hint += "# Index {}::{} (type {})\r\n".format(
                            idx_mod_name,
                            idx_sym_name,
                            idxNode.syntax.__class__.__name__,
                        )

                        val, reason = get_value(
                            idxNode.syntax, not args.quiet and row_hint or ""
                        )

                        if val is None:
                            skip(
                                "the rows of",
                                mib_name,
                                sym_name,
                                idxNode.syntax,
                                "index %s::%s: %s"
                                % (idx_mod_name, idx_sym_name, reason),
                            )
                            row_indices = None
                            break

                        row_indices[idxNode.name] = val

                        suffix = suffix + node.getAsName(val, implied_flag)

                    if row_indices is None:
                        # no index, no row: the columns that follow are
                        # passed over, and the table ends here
                        row_oid = None
                        continue

                    table_rows.append((row_indices, suffix))

                if not row_indices:
                    if not args.quiet:
                        sys.stderr.write(
                            "# WARNING: %s::%s table has no index!\r\n"
                            % (mib_name, sym_name)
                        )

                row_oid = univ.ObjectIdentifier(oid)
                continue

            elif isinstance(node, MibTableColumn):
                if row_indices is None:
                    continue

                oid = node.name
                if oid in row_indices:
                    val = row_indices[oid]

                else:
                    hint = ""
                    if not args.quiet:
                        hint += row_hint
                        hint += "# Column %s::%s (type" " %s)\r\n" % (
                            mib_name,
                            sym_name,
                            node.syntax.__class__.__name__,
                        )

                    val, reason = get_value(node.syntax, hint)

                    if val is None:
                        skip("column", mib_name, sym_name, node.syntax, reason)
                        continue

            elif isinstance(node, MibScalar):
                hint = ""
                if not args.row_hint:
                    hint += "# Scalar %s::%s (type %s)" "\r\n" % (
                        mib_name,
                        sym_name,
                        node.syntax.__class__.__name__,
                    )
                oid = node.name
                suffix = (0,)
                val, reason = get_value(node.syntax, hint)

                if val is None:
                    skip("scalar", mib_name, sym_name, node.syntax, reason)
                    continue

            else:
                hint = ""
                continue

            output.append((oid + suffix, val))

        output.sort(key=lambda x: univ.ObjectIdentifier(x[0]))

        unique = set()

        for oid, val in output:
            if oid in unique:
                if not args.quiet:
                    sys.stderr.write(
                        "# Dropping duplicate OID %s\r\n"
                        % (univ.ObjectIdentifier(oid),)
                    )
            else:
                try:
                    args.output_file.write(data_file_handler.format(oid, val))

                except SnmpsimError as exc:
                    sys.stderr.write(f"ERROR: {exc}\r\n")

                else:
                    unique.add(oid)

        if not args.quiet:
            sys.stderr.write(f"# End of {modName}, {len(unique)} OID(s) dumped\r\n")

    args.output_file.flush()
    args.output_file.close()

    return 0


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
