#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
import asyncio
import importlib
import sys
import threading

import pysnmp
import pysmi
import pyasn1
import snmpsim

from pyasn1.codec.ber import encoder

TITLE = """\
SNMP Simulator version {}, written by Ilya Etingof <etingof@gmail.com>
Using foundation libraries: pysmi {}, pysnmp {}, pyasn1 {}.
Python interpreter: {}
Documentation and support at https://www.pysnmp.com/snmpsim
""".format(
    snmpsim.__version__,
    pysmi.__version__,
    pysnmp.__version__,
    pyasn1.__version__,
    sys.version,
)


# An SNMP response travels as a single UDP datagram: once it outgrows the
# smallest MTU on the path it gets IP-fragmented, and a lost fragment reads as
# a request timeout at the manager. Real agents dodge that by never filling a
# datagram past the Ethernet MTU less the IP and UDP headers -- this is what
# net-snmp calls SNMP_MAX_MSG_SIZE.
MAX_MESSAGE_SIZE = 1472

# Octets held back for what wraps the var-bind list of an SNMPv1/v2c response:
# the message header, the PDU header and the var-bind list header. Same slack
# pysnmp itself keeps.
MESSAGE_ENVELOPE_SIZE = 128

# The same for an SNMPv3 response, where the envelope also carries
# msgGlobalData, the USM parameters (engine ID, user name, authentication and
# privacy parameters), the scopedPDU header and the encryption padding.
USM_MESSAGE_ENVELOPE_SIZE = 200


def try_load(module, package=None):
    """Try to load given module, return `None` on failure"""
    try:
        return importlib.import_module(module, package)

    except ImportError:
        return


def split(val, sep):
    """Split a string into a list based on a separator"""
    for x in (3, 2, 1):
        if val.find(sep * x) != -1:
            return val.split(sep * x)

    return [val]


def run_in_new_loop(coroutine):
    """Run a coroutine in a new event loop and return its result"""
    result = None

    def run():
        nonlocal result
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        try:
            result = new_loop.run_until_complete(coroutine)
        finally:
            new_loop.close()

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()

    return result


def var_bind_size(var_bind):
    """Return the number of octets given var-bind takes on the wire"""
    name, value = var_bind

    # plus the tag and the length of the var-bind SEQUENCE itself
    return len(encoder.encode(name)) + len(encoder.encode(value)) + 4


def get_bulk_var_binds(
    read_next_vars,
    req_var_binds,
    non_repeaters,
    max_repetitions,
    max_var_binds,
    max_response_size,
):
    """Produce var-binds for a GETBULK response.

    Repetitions stop once `max_var_binds` var-binds are collected or the
    var-bind list grows past `max_response_size` octets, whichever comes
    first. Cutting the repetitions short is what RFC 3416 prescribes for a
    response which would not otherwise fit, and what real agents do -- the
    manager simply resumes the walk from the last var-bind it got.
    """
    N = min(max(int(non_repeaters), 0), len(req_var_binds))
    M = max(int(max_repetitions), 0)
    R = max(len(req_var_binds) - N, 0)

    if R:
        M = min(M, max_var_binds // R)

    if N:
        rsp_var_binds = list(read_next_vars(*req_var_binds[:N]))

    else:
        rsp_var_binds = []

    size = sum(var_bind_size(var_bind) for var_bind in rsp_var_binds)

    var_binds = req_var_binds[-R:]

    while M and R:
        for var_bind in read_next_vars(*var_binds):
            size += var_bind_size(var_bind)

            # never come back empty-handed, the first var-bind always goes in
            if size > max_response_size and rsp_var_binds:
                return rsp_var_binds

            rsp_var_binds.append(var_bind)

        var_binds = rsp_var_binds[-R:]
        M -= 1

    return rsp_var_binds
