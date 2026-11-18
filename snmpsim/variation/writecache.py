#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
# SNMP Simulator, https://www.pysnmp.com/snmpsim
#
# Managed value variation module: simulate a writable Agent
#
import shelve

from pysnmp.smi import error

from snmpsim import log
from snmpsim.grammar.snmprec import SnmprecGrammar
from snmpsim.record.snmprec import SnmprecRecord
from snmpsim.utils import split

ERROR_TYPES = {
    "generror": error.GenError,
    "noaccess": error.NoAccessError,
    "wrongtype": error.WrongTypeError,
    "wrongvalue": error.WrongValueError,
    "nocreation": error.NoCreationError,
    "inconsistentvalue": error.InconsistentValueError,
    "resourceunavailable": error.ResourceUnavailableError,
    "commitfailed": error.CommitFailedError,
    "undofailed": error.UndoFailedError,
    "authorizationerror": error.AuthorizationError,
    "notwritable": error.NotWritableError,
    "inconsistentname": error.InconsistentNameError,
    "nosuchobject": error.NoSuchObjectError,
    "nosuchinstance": error.NoSuchInstanceError,
    "endofmib": error.EndOfMibViewError,
}


RECORD = SnmprecRecord()


def evaluate(tag, value):
    """Build SNMP value from its text as the tag of the record tells.

    The tag may carry an encoding flag: `x` for hex digits, `e` for a
    string with Python escapes - just like on a plain .snmprec record.
    """
    return RECORD.evaluate_value(None, tag, value)[2]


def init(**context):
    moduleContext["settings"] = {}

    if context["options"]:
        moduleContext["settings"].update(
            dict([split(x, ":") for x in split(context["options"], ",")])
        )

    if "file" in moduleContext["settings"]:
        moduleContext["cache"] = shelve.open(moduleContext["settings"]["file"])

    else:
        moduleContext["cache"] = {}


def variate(oid, tag, value, **context):
    if not context["nextFlag"] and not context["exactMatch"]:
        return context["origOid"], tag, context["errorStatus"]

    if "settings" not in recordContext:
        recordContext["settings"] = dict([split(x, "=") for x in split(value, ",")])

        if "vlist" in recordContext["settings"]:
            vlist = {}

            recordContext["settings"]["vlist"] = split(
                recordContext["settings"]["vlist"], ":"
            )

            while recordContext["settings"]["vlist"]:
                o, v, e = recordContext["settings"]["vlist"][:3]

                # the names of the errors are not case-sensitive
                e = e.lower()

                vl = recordContext["settings"]["vlist"][3:]
                recordContext["settings"]["vlist"] = vl

                v = evaluate(tag, v)

                if o not in vlist:
                    vlist[o] = {}

                if o == "eq":
                    vlist[o][v] = e

                elif o in ("lt", "gt"):
                    vlist[o] = v, e

                else:
                    log.info(
                        "writecache: bad vlist syntax: "
                        "%s" % recordContext["settings"]["vlist"]
                    )

            recordContext["settings"]["vlist"] = vlist

        if "status" in recordContext["settings"]:
            st = recordContext["settings"]["status"].lower()
            recordContext["settings"]["status"] = st

    if oid not in moduleContext:
        moduleContext[oid] = {}

        type_tag, _ = SnmprecRecord.unpack_tag(tag)

        moduleContext[oid]["type"] = SnmprecGrammar.TAG_MAP[type_tag]()

    text_oid = str(oid)

    # whether the variable is writable at all comes first, then the type of
    # the value, then the value itself, as net-snmp's snmpd checks a SET
    if "status" in recordContext["settings"]:
        if (
            "op" not in recordContext["settings"]
            or recordContext["settings"]["op"] == "any"
            or recordContext["settings"]["op"] == "set"
            and context["setFlag"]
            or recordContext["settings"]["op"] == "get"
            and not context["setFlag"]
        ):
            e = recordContext["settings"]["status"]

            if e in ERROR_TYPES:
                raise ERROR_TYPES[e](name=oid, idx=position(context))

    if context["setFlag"]:
        # the record's type is unconstrained, to serve what a device sent
        # outside its range; the value written has the range of its type.
        # They are the same type all the same. A value of another type is
        # wrongType (RFC 3416, 4.2.5)
        if not moduleContext[oid]["type"].isSameTypeWith(
            context["origValue"], matchConstraints=False
        ):
            raise error.WrongTypeError(name=oid, idx=position(context))

        if "vlist" in recordContext["settings"]:
            if (
                "eq" in recordContext["settings"]["vlist"]
                and context["origValue"] in recordContext["settings"]["vlist"]["eq"]
            ):
                e = recordContext["settings"]["vlist"]["eq"][context["origValue"]]

            elif (
                "lt" in recordContext["settings"]["vlist"]
                and context["origValue"] < recordContext["settings"]["vlist"]["lt"][0]
            ):
                e = recordContext["settings"]["vlist"]["lt"][1]

            elif (
                "gt" in recordContext["settings"]["vlist"]
                and context["origValue"] > recordContext["settings"]["vlist"]["gt"][0]
            ):
                e = recordContext["settings"]["vlist"]["gt"][1]

            else:
                e = None

            if e in ERROR_TYPES:
                raise ERROR_TYPES[e](name=oid, idx=position(context))

        write(text_oid, context["origValue"], context.get("setUndo"))

    if text_oid in moduleContext["cache"]:
        return oid, tag, moduleContext["cache"][text_oid]

    elif "hexvalue" in recordContext["settings"]:
        return (
            oid,
            tag,
            moduleContext[oid]["type"].clone(
                hexValue=recordContext["settings"]["hexvalue"]
            ),
        )

    elif "value" in recordContext["settings"]:
        return oid, tag, evaluate(tag, recordContext["settings"]["value"])

    else:
        return oid, tag, context["errorStatus"]


def position(context):
    """The place of the variable in the request, counted from 0."""
    return max(0, context["varsTotal"] - context["varsRemaining"] - 1)


def write(text_oid, value, undo):
    """Write `value`, and add to `undo` what takes it back."""
    cache = moduleContext["cache"]

    if undo is not None:
        if text_oid in cache:
            previous = cache[text_oid]
            undo.append(lambda: cache.__setitem__(text_oid, previous))

        else:
            undo.append(lambda: cache.pop(text_oid, None))

    cache[text_oid] = value


def shutdown(**context):
    if "file" in moduleContext["settings"]:
        moduleContext["cache"].close()
