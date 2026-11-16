#
# This file is part of snmpsim software.
#
# License: https://www.pysnmp.com/snmpsim/license.html
#
"""What a command responder answers, shared by both ways of answering.

SNMPv1 and SNMPv2c requests are answered either through pysnmp's SNMPv3
engine or by the simulator itself (`--v1-v2c-path`). What goes back must not
depend on which: the rules both of them follow live here.
"""
from pysnmp.entity.rfc3413 import cmdrsp

# error-status by the SMI error a variation module or a controller raised
SMI_ERROR_MAP = cmdrsp.CommandResponderBase.SMI_ERROR_MAP


def error_response(exc, var_binds, offset=0):
    """Return error-status, error-index and var-binds answering `exc`.

    `var_binds` are those of the request. An error which names the variable
    it is about gets that variable's place in the request; `offset` is added
    to it when what raised was given a part of the request only (the
    repetitions of a GETBULK). An error which names none, or a place outside
    the request, is answered the way pysnmp's command responder does: with
    the index it names, but 1 where that is not the last variable.
    """
    error_status = SMI_ERROR_MAP.get(exc.__class__, "genErr")

    try:
        error_index = exc["idx"] + offset + 1

    except (KeyError, TypeError):
        error_index = None

    if error_index is None or not 0 < error_index <= len(var_binds):
        try:
            error_index = exc["idx"] + 1

        # a bare SmiError names nothing and cannot even be asked
        except (KeyError, TypeError):
            error_index = 1

        if len(var_binds) > error_index:
            error_index = 1

    # RFC 3416, 4.2.1: tooBig comes with no index and no variables
    if error_status == "tooBig":
        return error_status, 0, []

    return error_status, error_index, var_binds
