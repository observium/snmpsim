#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
from pysnmp.proto import rfc1905
from pysnmp.proto.proxy import rfc2576
from pysnmp.smi import error

from snmpsim import log
from snmpsim.grammar.snmprec import SnmprecGrammar
from snmpsim.record.snmprec import SnmprecRecord
from snmpsim.utils import split

ERROR_TYPES = {
    "toobig": error.TooBigError,
    "nosuchname": error.NoSuchNameError,
    "badvalue": error.BadValueError,
    "readonly": error.ReadOnlyError,
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
    # These are raised on SET only, see EXCEPTION_VALUES
    "nosuchobject": error.NoSuchObjectError,
    "nosuchinstance": error.NoSuchInstanceError,
    "endofmib": error.EndOfMibViewError,
}

# SNMPv2 has no error-status for these three: on a read they are the value of
# the variable, the response is otherwise a success and carries the values of
# its other variables. For an SNMPv1 manager pysnmp turns such a response into
# noSuchName pointing at the variable (RFC 3584, 4.2.2.1).
#
# The values are made here rather than taken from pysnmp.smi.exval: the data
# file reader takes that very endOfMib object for "nothing at this record,
# try the next one", which is not what the recording asks for.
EXCEPTION_VALUES = {
    "nosuchobject": rfc1905.NoSuchObject(),
    "nosuchinstance": rfc1905.NoSuchInstance(),
    "endofmib": rfc1905.EndOfMibView(),
}


# SNMPv1 error-status codes which SNMPv2 has kept for proxies only: noSuchName,
# badValue and readOnly
V1_ONLY_STATUSES = (2, 3, 4)


def init(**context):
    # pysnmp builds every response as SNMPv2 PDU and translates it for SNMPv1
    # manager through this map. The map holds what RFC 3584 lists, that is the
    # codes an SNMPv2 agent may produce on its own. The three SNMPv1 codes are
    # not among them, so they would turn into genErr on their way to exactly
    # the manager they are meant for.
    for status in V1_ONLY_STATUSES:
        rfc2576.V2_TO_V1_ERROR_MAP.setdefault(status, status)


def variate(oid, tag, value, **context):
    if not context["nextFlag"] and not context["exactMatch"]:
        return context["origOid"], tag, context["errorStatus"]

    if "settings" not in recordContext:
        recordContext["settings"] = dict([split(x, "=") for x in split(value, ",")])

        if "hexvalue" in recordContext["settings"]:
            recordContext["settings"]["value"] = [
                int(recordContext["settings"]["hexvalue"][x : x + 2], 16)
                for x in range(0, len(recordContext["settings"]["hexvalue"]), 2)
            ]

        if "status" in recordContext["settings"]:
            recordContext["settings"]["status"] = recordContext["settings"][
                "status"
            ].lower()

        if "op" not in recordContext["settings"]:
            recordContext["settings"]["op"] = "any"

        if "vlist" in recordContext["settings"]:
            vlist = {}

            recordContext["settings"]["vlist"] = split(
                recordContext["settings"]["vlist"], ":"
            )

            while recordContext["settings"]["vlist"]:
                o, v, e = recordContext["settings"]["vlist"][:3]

                # the names of the errors are not case-sensitive
                e = e.lower()

                recordContext["settings"]["vlist"] = recordContext["settings"]["vlist"][
                    3:
                ]

                typeTag, _ = SnmprecRecord.unpack_tag(tag)

                v = SnmprecGrammar.TAG_MAP[typeTag](v)

                if o not in vlist:
                    vlist[o] = {}

                if o == "eq":
                    vlist[o][v] = e

                elif o in ("lt", "gt"):
                    vlist[o] = v, e

                else:
                    log.info(
                        "error: bad vlist syntax: %s"
                        % recordContext["settings"]["vlist"]
                    )

            recordContext["settings"]["vlist"] = vlist

    e = None

    if context["setFlag"]:
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

        elif recordContext["settings"]["op"] in ("set", "any"):
            if "status" in recordContext["settings"]:
                e = recordContext["settings"]["status"]

    else:
        if recordContext["settings"]["op"] in ("get", "any"):
            if "status" in recordContext["settings"]:
                e = recordContext["settings"]["status"]

    if e and e in EXCEPTION_VALUES and not context["setFlag"]:
        log.info(f"error: reporting {e} for {oid}")

        # GETNEXT is answered with the name of the record it has arrived at
        return (
            oid if context["nextFlag"] else context["origOid"],
            tag,
            EXCEPTION_VALUES[e],
        )

    if e and e in ERROR_TYPES:
        log.info(f"error: reporting {e} for {oid}")
        raise ERROR_TYPES[e](
            name=oid, idx=max(0, context["varsTotal"] - context["varsRemaining"] - 1)
        )

    if context["setFlag"]:
        settings = recordContext["settings"]
        undo = context.get("setUndo")

        # what takes the write back, should a variable after this one fail
        # the SET
        if undo is not None:
            if "value" in settings:
                previous = settings["value"]
                undo.append(lambda: settings.__setitem__("value", previous))

            else:
                undo.append(lambda: settings.pop("value", None))

        settings["value"] = context["origValue"]

    return oid, tag, recordContext["settings"].get("value", context["errorStatus"])


def shutdown(**context):
    pass
