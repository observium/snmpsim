#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# Copyright (c) 2022-2025, LeXtudio Inc. <support@lextudio.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
# SNMP Agent Simulator: fully-fledged SNMP v1/v2c/v3 command responder
#
import argparse
import asyncio
import functools
import os
import signal
import sys
import traceback
from hashlib import md5

from pyasn1 import debug as pyasn1_debug
from pyasn1.type import univ
from pysnmp import debug as pysnmp_debug
from pysnmp import error
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.carrier.asyncio.dgram import udp6
from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
from pysnmp.entity import config
from pysnmp.entity import engine
from pysnmp.entity.rfc3413 import cmdrsp
from pysnmp.entity.rfc3413 import context
from pysnmp.proto.api import v2c
from pysnmp.smi import error as smi_error

from snmpsim import confdir
from snmpsim import controller
from snmpsim import daemon
from snmpsim import datafile
from snmpsim import endpoints
from snmpsim import fastpath
from snmpsim import log
from snmpsim import responding
from snmpsim import utils
from snmpsim import variation
from snmpsim.error import NoDataNotification
from snmpsim.error import SnmpsimError
from snmpsim.reporting.manager import ReportingManager

# securityModel of the User-based Security Model, RFC 3411 section 5
USM_SECURITY_MODEL = 3

# msgVersion on the wire, which is also the ID of the message processing
# model handling it, to the name the version goes by
SNMP_VERSIONS = {0: "1", 1: "2c", 3: "3"}

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

USM_KEY_TYPES = {
    "passphrase": config.USM_KEY_TYPE_PASSPHRASE,
    "master": config.USM_KEY_TYPE_MASTER,
    "localized": config.USM_KEY_TYPE_LOCALIZED,
}

# What the hash of an authentication protocol gives out, in octets: the size
# of a master key and of a localized authentication key.
USM_HASH_SIZES = {
    "MD5": 16,
    "SHA": 20,
    "SHA224": 28,
    "SHA256": 32,
    "SHA384": 48,
    "SHA512": 64,
}

DESCRIPTION = (
    "SNMP agent simulator: responds to SNMP v1/v2c/v3 requests, variate "
    "responses based on transport addresses, SNMP community name, SNMPv3 "
    "context or via variation modules."
)

V3_OPTIONS = "SNMPv3 options"


def probe_hash_context(responder, snmp_engine):
    """v3arch SNMP context name searcher"""
    execCtx = snmp_engine.observer.get_execution_context(
        "rfc3412.receiveMessage:request"
    )

    (transport_domain, transport_address, context_engine_id, context_name) = (
        execCtx["transportDomain"],
        execCtx["transportAddress"],
        execCtx["contextEngineId"],
        execCtx["contextName"].prettyPrint(),
    )

    if context_engine_id == snmp_engine.snmpEngineID:
        context_engine_id = datafile.SELF_LABEL

    else:
        context_engine_id = context_engine_id.prettyPrint()

    for candidate in datafile.probe_context(
        transport_domain, transport_address, context_engine_id, context_name
    ):
        if len(candidate) > 32:
            probed_context_name = md5(candidate).hexdigest()

        else:
            probed_context_name = candidate

        try:
            mib_instrum = responder.snmpContext.get_mib_instrum(probed_context_name)

        except error.PySnmpError:
            pass

        else:
            log.info(
                "Using %s selected by candidate %s; transport ID %s, "
                "source address %s, context engine ID %s, "
                "community name "
                '"%s"'
                % (
                    mib_instrum,
                    candidate,
                    univ.ObjectIdentifier(transport_domain),
                    transport_address[0],
                    context_engine_id,
                    probed_context_name,
                )
            )
            context_name = probed_context_name
            break
    else:
        mib_instrum = responder.snmpContext.get_mib_instrum(context_name)
        log.info(
            'Using %s selected by contextName "%s", transport ID %s, '
            "source address %s"
            % (
                mib_instrum,
                context_name,
                univ.ObjectIdentifier(transport_domain),
                transport_address[0],
            )
        )

    if not isinstance(
        mib_instrum,
        (controller.MibInstrumController, controller.DataIndexInstrumController),
    ):
        log.error("LCD access denied (contextName does not match any data file)")
        raise NoDataNotification()

    return context_name


class ErrorReporter:
    """Report a failed variable by its own place in the request.

    pysnmp's command responder answers an error raised for a variable with
    error-index 1 unless the variable is the last one of the request, so a
    manager which asked for three variables and got the second one refused
    blames the first. The responders below catch the error before pysnmp
    does and send the error response themselves.
    """

    def report_error(self, snmp_engine, state_reference, pdu, exc, offset=0):
        """Send the error response for `exc`, or raise `exc` for pysnmp.

        `exc` goes back to pysnmp when it asks for a REPORT, which only
        pysnmp is able to produce. What is sent otherwise is what
        `responding.error_response()` makes of it, the fast path's answer
        to the same error. `offset` is added to the place the error names:
        what read the variables may have been given a part of the request.
        """
        # a REPORT goes back for SNMPv3 instead, only pysnmp can send it; a
        # bare SmiError cannot be asked and asks for none
        try:
            wants_report = "oid" in exc

        except TypeError:
            wants_report = False

        if wants_report:
            raise exc

        error_status, error_index, var_binds = responding.error_response(
            exc, v2c.apiPDU.get_varbinds(pdu), offset
        )

        self.send_varbinds(
            snmp_engine, state_reference, error_status, error_index, var_binds
        )
        self.release_state_information(state_reference)


class GetCommandResponder(ErrorReporter, cmdrsp.GetCommandResponder):
    """v3arch GET command handler"""

    def handle_management_operation(
        self, snmp_engine, state_reference, context_name, pdu
    ):
        try:
            cmdrsp.GetCommandResponder.handle_management_operation(
                self,
                snmp_engine,
                state_reference,
                probe_hash_context(self, snmp_engine),
                pdu,
            )

        except NoDataNotification:
            self.release_state_information(state_reference)

        except smi_error.SmiError as exc:
            self.report_error(snmp_engine, state_reference, pdu, exc)


class SetCommandResponder(ErrorReporter, cmdrsp.SetCommandResponder):
    """v3arch SET command handler"""

    def handle_management_operation(
        self, snmp_engine, state_reference, context_name, pdu
    ):
        try:
            cmdrsp.SetCommandResponder.handle_management_operation(
                self,
                snmp_engine,
                state_reference,
                probe_hash_context(self, snmp_engine),
                pdu,
            )

        except NoDataNotification:
            self.release_state_information(state_reference)

        except smi_error.SmiError as exc:
            self.report_error(snmp_engine, state_reference, pdu, exc)


class NextCommandResponder(ErrorReporter, cmdrsp.NextCommandResponder):
    """v3arch GETNEXT command handler"""

    def handle_management_operation(
        self, snmp_engine, state_reference, context_name, pdu
    ):
        try:
            cmdrsp.NextCommandResponder.handle_management_operation(
                self,
                snmp_engine,
                state_reference,
                probe_hash_context(self, snmp_engine),
                pdu,
            )

        except NoDataNotification:
            self.release_state_information(state_reference)

        except smi_error.SmiError as exc:
            self.report_error(snmp_engine, state_reference, pdu, exc)


class BulkCommandResponder(ErrorReporter, cmdrsp.BulkCommandResponder):
    """v3arch GETBULK command handler.

    Unlike the pysnmp responder it derives from, this one keeps the response
    within `max_message_size` octets, dropping the repetitions which would not
    fit. An oversized response leaves the simulator as a fragmented datagram
    which the manager often never sees whole, so the walk stalls with a
    timeout on the very recordings which hold the longest values.

    A manager may ask for less than that: every SNMPv3 message carries
    msgMaxSize, the largest message its sender is able to receive. pysnmp
    refuses to send a response past it and drops the response without a word,
    so the repetitions are cut to what the manager takes as well.
    """

    max_message_size = utils.MAX_MESSAGE_SIZE

    # Octets held back for what wraps the var-bind list inside a scopedPDU:
    # the scopedPDU header, contextEngineID (32 octets at most), the header
    # of contextName, the PDU header, request-id, error-status, error-index
    # and the var-bind list header.
    scoped_pdu_envelope_size = 64

    # the largest scopedPDU the manager takes in response to the request
    # being handled, as the message processing model made it out of the
    # request: msgMaxSize less the message header and the security
    # parameters for SNMPv3, the engine's own limit for SNMPv1/v2c
    _max_size_response_scoped_pdu = None

    def process_pdu(
        self,
        snmp_engine,
        message_processing_model,
        security_model,
        security_name,
        security_level,
        context_engine_id,
        context_name,
        pdu_version,
        pdu,
        max_size_response_scoped_pdu,
        state_reference,
    ):
        # pysnmp keeps this to itself, handle_management_operation() below
        # is not told
        self._max_size_response_scoped_pdu = max_size_response_scoped_pdu

        try:
            cmdrsp.BulkCommandResponder.process_pdu(
                self,
                snmp_engine,
                message_processing_model,
                security_model,
                security_name,
                security_level,
                context_engine_id,
                context_name,
                pdu_version,
                pdu,
                max_size_response_scoped_pdu,
                state_reference,
            )

        finally:
            self._max_size_response_scoped_pdu = None

    def handle_management_operation(
        self, snmp_engine, state_reference, context_name, pdu
    ):
        try:
            context_name = probe_hash_context(self, snmp_engine)

        except NoDataNotification:
            self.release_state_information(state_reference)
            return

        mib_instrum = self.snmpContext.get_mib_instrum(context_name)

        read_next_vars = functools.partial(
            mib_instrum.read_next_variables,
            snmpEngine=snmp_engine,
            acFun=self.verify_access,
            cbCtx=self.cbCtx,
        )

        exec_ctx = snmp_engine.observer.get_execution_context(
            "rfc3412.receiveMessage:request"
        )

        if exec_ctx["securityModel"] == USM_SECURITY_MODEL:
            envelope_size = utils.USM_MESSAGE_ENVELOPE_SIZE

        else:
            envelope_size = utils.MESSAGE_ENVELOPE_SIZE

        # the context name travels back in the response as well: as the
        # community name for SNMPv1/v2c, as contextName for SNMPv3
        max_response_size = self.max_message_size - envelope_size

        if self._max_size_response_scoped_pdu is not None:
            max_response_size = min(
                max_response_size,
                int(self._max_size_response_scoped_pdu) - self.scoped_pdu_envelope_size,
            )

        max_response_size -= len(context_name)

        req_var_binds = v2c.apiPDU.get_varbinds(pdu)
        non_repeaters = v2c.apiBulkPDU.get_non_repeaters(pdu)

        # how many times the variables have been read
        takes = []

        try:
            rsp_var_binds = utils.get_bulk_var_binds(
                lambda *var_binds: takes.append(None) or read_next_vars(*var_binds),
                req_var_binds,
                non_repeaters,
                v2c.apiBulkPDU.get_max_repetitions(pdu),
                self.max_varbinds,
                max_response_size,
            )

        except smi_error.SmiError as exc:
            # The non-repeaters are read in one take, the repeaters in the
            # takes which follow, and an error counts the variables of its
            # take, while error-index is a place in the request (RFC 3416,
            # 4.2.3).
            non_repeaters = min(max(int(non_repeaters), 0), len(req_var_binds))

            self.report_error(
                snmp_engine,
                state_reference,
                pdu,
                exc,
                offset=non_repeaters if len(takes) > 1 else 0,
            )
            return

        if not rsp_var_binds:
            raise smi_error.SmiError()

        self.send_varbinds(snmp_engine, state_reference, 0, 0, rsp_var_binds)
        self.release_state_information(state_reference)


def _parse_sized_string(arg, min_length=8):
    if len(arg) < min_length:
        raise argparse.ArgumentTypeError(
            f'Value "{arg}" must be {min_length}+ chars of length'
        )

    return arg


def parse_usm_key(key, key_type, auth_proto, priv_proto=None):
    """Turn a USM key off the command line into what pysnmp is to be given.

    A passphrase is passed as it is. A master key (the hashed passphrase) and
    a localized key (the master key hashed with the engine ID) are octets
    written in hex, with or without the leading 0x, and come back as bytes.

    `auth_proto` and `priv_proto` are our names of the protocols; the latter
    is given for a privacy key, which is made by the hash of the
    authentication protocol as well.

    Raises ValueError saying what is wrong with a key that cannot be one: a
    key of a wrong size would be taken at start-up and then fail every
    request of that user.
    """
    if key_type == "passphrase":
        return key

    digits = key[2:] if key[:2].lower() == "0x" else key

    try:
        octets = bytes.fromhex(digits)

    except ValueError:
        octets = b""

    # bytes.fromhex() lets white space through
    if not octets or len(octets) * 2 != len(digits):
        raise ValueError(
            f'{key_type} key "{key}" is not hexadecimal (an even number of '
            f"hex digits, with or without the leading 0x)"
        )

    hash_size = USM_HASH_SIZES[auth_proto]

    if priv_proto and key_type == "localized":
        # the cipher takes the leading octets of the key and agents differ
        # in how many of the rest they show
        proto, takes = (
            priv_proto,
            config.PRIV_SERVICES[PRIV_PROTOCOLS[priv_proto]].KEY_SIZE,
        )
        fits = len(octets) >= takes

    else:
        proto, takes = auth_proto, hash_size
        fits = len(octets) == takes

    if not fits:
        raise ValueError(
            f'{key_type} key "{key}" is {len(octets)} octets long, '
            f"{proto} takes {takes}"
        )

    return octets


class Recordings:
    """The recordings of one SNMP context engine, as they are served.

    A recording is served under a community name, and under SNMPv3 context
    names made of it. `rescan()` looks into the data directories and brings
    what is served in line with what is found there: a recording which
    appeared is indexed and registered, one which is gone is unregistered and
    its files are closed. A recording which is still there is not touched,
    not even when its contents changed: that is noticed by the data file
    itself when it is asked next.
    """

    def __init__(
        self,
        data_dirs,
        variation_modules,
        snmp_engine,
        snmp_context,
        data_index,
        communities=True,
        force_index_rebuild=False,
        validate_data=False,
        indexed=None,
        on_change=None,
    ):
        self.data_dirs = list(data_dirs)
        self.snmp_engine = snmp_engine
        self.snmp_context = snmp_context
        self.data_index = data_index

        self._variation_modules = variation_modules
        self._communities = communities
        self._force_index_rebuild = force_index_rebuild
        self._validate_data = validate_data

        # called whenever a community name is added or removed
        self._on_change = on_change

        # what `datafile.index_data_files()` has just built, the error or
        # None by data file; emptied by its owner once the start is over
        self._indexed = {} if indexed is None else indexed

        # community name to what was registered for it
        self._served = {}

        # path of a data file to its controller and the number of community
        # names it is served under
        self._mib_instrums = {}

    def scan(self):
        """Return what the data directories hold now.

        Community names to the data files which claim them, each a path and
        a parser, in the order they are found. Nothing is changed, so this
        may run aside from the event loop.
        """
        found = {}

        for data_dir in self.data_dirs:
            log.info(
                'Scanning "%s" directory for %s data '
                "files..."
                % (
                    data_dir,
                    ",".join(
                        [
                            f" *{os.path.extsep}{x.ext}"
                            for x in variation.RECORD_TYPES.values()
                        ]
                    ),
                )
            )

            if not os.path.exists(data_dir):
                log.info('Directory "%s" does not exist' % data_dir)
                continue

            for full_path, text_parser, community_name in datafile.get_data_files(
                data_dir
            ):
                candidates = found.setdefault(community_name, [])

                if full_path not in [candidate[0] for candidate in candidates]:
                    candidates.append((full_path, text_parser))

        return found

    def changes(self, found):
        """Return the community names to drop and the recordings to add.

        Of several data files claiming a community name the one which is
        served stays, otherwise the first one found is taken.
        """
        wanted = {}

        for community_name, candidates in found.items():
            chosen = candidates[0]

            if community_name in self._served:
                for candidate in candidates:
                    if candidate[0] == self._served[community_name][0]:
                        chosen = candidate

            for full_path, _ in candidates:
                if full_path != chosen[0]:
                    log.error(
                        'ignoring duplicate Community/ContextName "%s" for data '
                        "file %s (%s already loaded)"
                        % (community_name, full_path, chosen[0])
                    )

            wanted[community_name] = chosen

        removed = [
            community_name
            for community_name, served in self._served.items()
            if community_name not in wanted or wanted[community_name][0] != served[0]
        ]

        added = [
            (community_name, full_path, text_parser)
            for community_name, (full_path, text_parser) in wanted.items()
            if community_name not in self._served
            or self._served[community_name][0] != full_path
        ]

        return removed, added

    def load(self, full_path, text_parser):
        """Index a data file, return its controller.

        Nothing is registered, so this may run aside from the event loop.
        """
        data_file = datafile.DataFile(full_path, text_parser, self._variation_modules)
        data_file.index_text(
            # one that has just been built is not built again
            self._force_index_rebuild and self._indexed.get(full_path, True),
            self._validate_data,
        )

        return controller.MIB_CONTROLLERS[data_file.layout](data_file)

    def serves(self, community_name):
        """Tell if a community name is served."""
        return community_name in self._served

    def loaded(self, full_path):
        """Return the controller of a data file which is served, or None."""
        if full_path in self._mib_instrums:
            return self._mib_instrums[full_path][0]

    def add(self, community_name, full_path, mib_instrum):
        """Serve a data file under a community name."""
        if full_path in self._mib_instrums:
            mib_instrum = self._mib_instrums[full_path][0]
            log.info(f"Configuring *shared* {mib_instrum}")

        else:
            log.info(f"Configuring {mib_instrum}")

        log.info(f"SNMPv1/2c community name: {community_name}")

        agent_name = md5(univ.OctetString(community_name).asOctets()).hexdigest()

        context_name = agent_name
        context_names = []

        try:
            self.snmp_context.register_context_name(context_name, mib_instrum)
            context_names.append(context_name)

            if len(community_name) <= 32:
                self.snmp_context.register_context_name(community_name, mib_instrum)
                context_names.append(community_name)

            # snmpCommunityTable::snmpCommunityIndex can't be > 32
            if self._communities and self.snmp_engine:
                config.add_v1_system(
                    self.snmp_engine,
                    agent_name,
                    community_name,
                    contextName=context_name,
                )

        except Exception:
            # nothing half-registered is left behind
            for name in context_names:
                self.snmp_context.unregister_context_name(name)

            raise

        row = self.data_index.add_data_file(full_path, community_name, context_name)

        self._mib_instrums.setdefault(full_path, [mib_instrum, 0])[1] += 1
        self._served[community_name] = full_path, agent_name, context_names, row

        if self._on_change:
            self._on_change()

        log.info(
            "SNMPv3 Context Name: %s"
            "%s"
            % (
                context_name,
                len(community_name) <= 32 and " or %s" % community_name or "",
            )
        )

    def remove(self, community_name):
        """Stop serving a community name, close the data file nobody uses."""
        full_path, agent_name, context_names, row = self._served.pop(community_name)

        log.info(f"Removing community name {community_name}, data file {full_path}")

        if self._communities and self.snmp_engine:
            config.delete_v1_system(self.snmp_engine, agent_name)

        for context_name in context_names:
            self.snmp_context.unregister_context_name(context_name)

        self.data_index.remove_data_file(row)

        if self._on_change:
            self._on_change()

        usage = self._mib_instrums[full_path]
        usage[1] -= 1

        if not usage[1]:
            del self._mib_instrums[full_path]

            log.info(f"Closing {usage[0]}")

            usage[0].close()

    def rescan(self, strict=False):
        """Serve what the data directories hold now.

        Returns how many community names were added, removed and left as
        they were. A data directory which cannot be read fails the rescan
        before anything is changed. A recording which cannot be indexed or
        registered is reported and left out, unless `strict` is set.
        """
        removed, added = self.changes(self.scan())

        log.msg.inc_ident()

        try:
            for community_name in removed:
                self.remove(community_name)

            unchanged = len(self._served)
            failed = 0

            for community_name, full_path, text_parser in added:
                try:
                    self.add(
                        community_name,
                        full_path,
                        self.loaded(full_path) or self.load(full_path, text_parser),
                    )

                except Exception as exc:
                    if strict:
                        raise

                    failed += 1
                    self.report_failure(community_name, full_path, exc)

        finally:
            log.msg.dec_ident()

        return len(added) - failed, len(removed), unchanged

    async def rescan_aside(self, loop):
        """Do what `rescan()` does while requests are being served.

        Directories are read and data files are indexed in a thread, so the
        event loop is held up only for registering a recording, which takes
        no time. Recordings are served or dropped one by one as the rescan
        goes on.
        """
        removed, added = self.changes(await loop.run_in_executor(None, self.scan))

        for community_name in removed:
            self.remove(community_name)

        unchanged = len(self._served)
        failed = 0

        for community_name, full_path, text_parser in added:
            try:
                mib_instrum = self.loaded(full_path)

                if mib_instrum is None:
                    mib_instrum = await loop.run_in_executor(
                        None, self.load, full_path, text_parser
                    )

                self.add(community_name, full_path, mib_instrum)

            except Exception as exc:
                failed += 1
                self.report_failure(community_name, full_path, exc)

        return len(added) - failed, len(removed), unchanged

    @staticmethod
    def report_failure(community_name, full_path, exc):
        log.error(
            f"data file {full_path} is not served, community name "
            f"{community_name}: {exc}"
        )


class Rescanner:
    """Rescans the data directories when asked to, one rescan at a time.

    Asked while a rescan is running, it rescans once more when that one is
    over: what was changed in a directory already read would be missed.
    """

    def __init__(self, loop):
        self.recordings = []

        self._loop = loop
        self._task = None
        self._asked_again = False

    def request(self):
        if self._task is not None:
            self._asked_again = True
            return

        self._task = self._loop.create_task(self._rescan())

    async def _rescan(self):
        try:
            while True:
                self._asked_again = False

                log.info("Rescanning data directories...")

                for recordings in list(self.recordings):
                    try:
                        counts = await recordings.rescan_aside(self._loop)

                    except Exception as exc:
                        log.error(
                            "rescan failed, recordings of %s are served as "
                            "before: %s" % (", ".join(recordings.data_dirs), exc)
                        )

                    else:
                        log.info(
                            "Rescan finished: %d added, %d removed, "
                            "%d unchanged" % counts
                        )

                if not self._asked_again:
                    break

        finally:
            self._task = None


def wait_for_endpoints(bound_endpoints):
    """Wait until every endpoint is bound, return those which are not.

    pysnmp 7 binds a UDP endpoint in a task of the event loop, which has not
    run yet when `open_server_mode()` returns, and nobody looks at how that
    task ended: a port in use, or an address the host does not have, left a
    responder which logged "Listening" and served nothing.

    Takes (name, transport) pairs, returns a (name, error) pair for every
    endpoint that could not be bound.
    """
    failed = []

    for name, transport in bound_endpoints:
        # the task pysnmp keeps for its own use; a transport without one has
        # nothing to wait for
        bind = getattr(transport, "_lport", None)

        if bind is None:
            continue

        if not bind.done():
            try:
                bind.get_loop().run_until_complete(asyncio.wait([bind]))

            except Exception as exc:
                failed.append((name, exc))
                continue

        if bind.cancelled():
            failed.append((name, "binding was cancelled"))

        elif bind.exception() is not None:
            failed.append((name, bind.exception()))

    return failed


def main():
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("-v", "--version", action="version", version=utils.TITLE)

    parser.add_argument(
        "-h", action="store_true", dest="usage", help="Brief usage message"
    )

    parser.add_argument("--help", action="store_true", help="Detailed help message")

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
        help="Rebuild simulation data files indices even if they seem " "up to date",
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

    # at most one of these: each of them leaves a single way to be asked
    version_group = parser.add_mutually_exclusive_group()

    version_group.add_argument(
        "--v3-only",
        action="store_true",
        help="Trip legacy SNMP v1/v2c support to gain a little lesser memory "
        "footprint",
    )

    version_group.add_argument(
        "--v1-only",
        action="store_true",
        help="Answer SNMPv1 requests only. SNMPv2c and SNMPv3 requests get no "
        "response, as from an agent configured for SNMPv1 alone",
    )

    version_group.add_argument(
        "--v2c-only",
        action="store_true",
        help="Answer SNMPv2c requests only. SNMPv1 and SNMPv3 requests get no "
        "response, as from an agent configured for SNMPv2c alone",
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
        help="Maximum number of variable bindings to include in a single " "response",
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
        "--v1-v2c-path",
        choices=("fast", "engine"),
        default="fast",
        help="How SNMPv1 and SNMPv2c requests are answered: by the simulator "
        "itself (the default), or through pysnmp's SNMPv3 engine, as releases "
        "before 2026.11.4 did, which is slower. SNMPv3 always goes through "
        "the engine",
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
        "--index-workers",
        metavar="<N>",
        type=datafile.index_workers,
        default=datafile.default_index_workers(),
        help="Build missing and out of date data file indices in this many "
        "processes at once before the SNMP engines are configured. 1 builds "
        "them one by one. Default is the number of CPUs the process may use, "
        "8 at most (%(default)s here)",
    )

    parser.add_argument(
        "--args-from-file",
        metavar="<FILE>",
        type=str,
        help="Read SNMP engine(s) command-line configuration from this "
        "file. Can be useful when command-line is too long",
    )

    # We do not parse SNMP params with argparse, but we want its -h/--help
    snmp_helper = argparse.ArgumentParser(
        description=DESCRIPTION, add_help=False, parents=[parser]
    )

    v3_usage = """\
Configure one or more independent SNMP engines. Each SNMP engine has a
distinct engine ID, its own set of SNMP USM users, one or more network
transport endpoints to listen on and its own simulation data directory.

Each SNMP engine configuration starts with `--v3-engine-id <arg>` parameter
followed by other configuration options up to the next `--v3-engine-id`
option or end of command line

Example
-------

$ snmp-command-responder \\
    --v3-engine-id auto \\
        --data-dir ./data --agent-udpv4-endpoint=127.0.0.1:1024 \\
    --v3-engine-id auto \\
        --data-dir ./data --agent-udpv4-endpoint=127.0.0.1:1025 \\
        --data-dir ./data --agent-udpv4-endpoint=127.0.0.1:1026

Besides network endpoints, simulated agents can be addressed by SNMPv1/v2c
community name or SNMPv3 context engine ID/name. These parameters are
configured automatically based on simulation data file paths relative to
`--data-dir`.
"""
    v3_group = snmp_helper.add_argument_group(v3_usage)

    v3_group.add_argument(
        "--v3-engine-id",
        type=str,
        metavar="<HEX|auto>",
        default="auto",
        help="SNMPv3 engine ID",
    )

    v3_group.add_argument(
        "--v3-user",
        metavar="<STRING>",
        type=functools.partial(_parse_sized_string, min_length=1),
        help="SNMPv3 USM user (security) name",
    )

    v3_group.add_argument(
        "--v3-auth-key",
        type=_parse_sized_string,
        help="SNMPv3 USM authentication key (must be > 8 chars)",
    )

    v3_group.add_argument(
        "--v3-auth-proto",
        choices=AUTH_PROTOCOLS,
        type=lambda x: x.upper(),
        default="NONE",
        help="SNMPv3 USM authentication protocol",
    )

    v3_group.add_argument(
        "--v3-auth-key-type",
        choices=USM_KEY_TYPES,
        type=lambda x: x.lower(),
        default="passphrase",
        help="What --v3-auth-key holds: a passphrase, or the master key made "
        "of it (the hashed passphrase), or that key localized to the SNMP "
        "engine ID. Master and localized keys are given in hex, with or "
        "without the leading 0x; a localized key only fits the "
        "--v3-engine-id it was made for",
    )

    v3_group.add_argument(
        "--v3-priv-key",
        type=_parse_sized_string,
        help="SNMPv3 USM privacy (encryption) key (must be > 8 chars)",
    )

    v3_group.add_argument(
        "--v3-priv-key-type",
        choices=USM_KEY_TYPES,
        type=lambda x: x.lower(),
        default="passphrase",
        help="What --v3-priv-key holds: a passphrase, a master key or a "
        "localized key, as with --v3-auth-key-type",
    )

    v3_group.add_argument(
        "--v3-priv-proto",
        choices=PRIV_PROTOCOLS,
        type=lambda x: x.upper(),
        default="NONE",
        help="SNMPv3 USM privacy (encryption) protocol",
    )

    v3_group.add_argument(
        "--v3-context-engine-id",
        type=lambda x: univ.OctetString(hexValue=x[2:]),
        help="SNMPv3 context engine ID",
    )

    v3_group.add_argument(
        "--v3-context-name", type=str, default="", help="SNMPv3 context engine ID"
    )

    v3_group.add_argument(
        "--agent-udpv4-endpoint",
        type=endpoints.parse_endpoint,
        metavar="<[X.X.X.X]:NNNNN>",
        help="SNMP agent UDP/IPv4 address to listen on (name:port)",
    )

    v3_group.add_argument(
        "--agent-udpv6-endpoint",
        type=functools.partial(endpoints.parse_endpoint, ipv6=True),
        metavar="<[X:X:..X]:NNNNN>",
        help="SNMP agent UDP/IPv6 address to listen on ([name]:port)",
    )

    v3_group.add_argument(
        "--data-dir",
        type=str,
        metavar="<DIR>",
        help="SNMP simulation data recordings directory.",
    )

    v3_group.add_argument(
        "--timeout",
        type=float,
        default=0,
        help="SNMP simulation process timeout",
    )

    args, unparsed_args = parser.parse_known_args()

    if args.usage:
        snmp_helper.print_usage(sys.stderr)
        return 1

    if args.help:
        snmp_helper.print_help(sys.stderr)
        return 1

    _, unknown_args = snmp_helper.parse_known_args(unparsed_args)
    if unknown_args:
        sys.stderr.write(
            "ERROR: Unknown command-line parameter(s) "
            "%s\r\n" % " ".join(unknown_args)
        )
        snmp_helper.print_usage(sys.stderr)
        return 1

    # Reformat unparsed args into a list of (option, value) tuples
    snmp_args = []
    name = None

    for opt in unparsed_args:
        if "=" in opt:
            snmp_args.append(opt.split("="))

        elif name:
            snmp_args.append((name, opt))
            name = None

        else:
            name = opt

    if name:
        sys.stderr.write(
            "ERROR: Non-paired command-line key-value parameter " "%s\r\n" % name
        )
        snmp_helper.print_usage(sys.stderr)
        return 1

    if args.args_from_file:
        try:
            with open(args.args_from_file) as fl:
                snmp_args.extend(
                    [handler.split("=", 1) for handler in fl.read().split()]
                )

        except Exception as exc:
            sys.stderr.write(
                "ERROR: file %s opening failure: " "%s\r\n" % (args.args_from_file, exc)
            )
            snmp_helper.print_usage(sys.stderr)
            return 1

    if args.daemonize:
        # The daemon changes into "/". Whatever was given relative to the
        # directory we are started from has to be found from there as well.
        # No pid file is written for an empty name, which has to stay empty.
        if args.pid_file:
            args.pid_file = os.path.abspath(args.pid_file)

        if args.cache_dir:
            args.cache_dir = os.path.abspath(args.cache_dir)

        args.variation_modules_dir = [
            os.path.abspath(path) for path in args.variation_modules_dir
        ]

        # The log file is open by then, the reports are written later on.
        if len(args.reporting_method) > 1:
            args.reporting_method[1] = os.path.abspath(args.reporting_method[1])

        snmp_args = [
            (opt[0], os.path.abspath(opt[1])) if opt[0] == "--data-dir" else opt
            for opt in snmp_args
        ]

    if args.debug:
        pysnmp_debug.set_logger(pysnmp_debug.Debug(*args.debug))

    if args.debug_asn1:
        pyasn1_debug.setLogger(pyasn1_debug.Debug(*args.debug_asn1))

    if args.cache_dir:
        confdir.cache = args.cache_dir

    if args.variation_modules_dir:
        confdir.variation = args.variation_modules_dir

    variation_modules_options = variation.parse_modules_options(
        args.variation_module_options
    )

    with daemon.PrivilegesOf(args.process_user, args.process_group):
        proc_name = os.path.basename(sys.argv[0])

        try:
            log.set_logger(proc_name, *args.logging_method, force=True)

            if args.log_level:
                log.set_level(args.log_level)

        except SnmpsimError as exc:
            sys.stderr.write("%s\r\n" % exc)
            snmp_helper.print_usage(sys.stderr)
            return 1

        datafile.set_max_open_files(args.max_open_data_files)

        log.info("Data files kept open at most: %s" % args.max_open_data_files)

        try:
            ReportingManager.configure(*args.reporting_method)

        except SnmpsimError as exc:
            sys.stderr.write("%s\r\n" % exc)
            snmp_helper.print_usage(sys.stderr)
            return 1

    startup = None

    if args.daemonize:
        try:
            startup = daemon.daemonize(args.pid_file, wait=True)

        except Exception as exc:
            sys.stderr.write("ERROR: cant daemonize process: %s\r\n" % exc)
            snmp_helper.print_usage(sys.stderr)
            return 1

    # Python 3.14+ no longer auto-creates a default event loop. Create it only
    # now: an event loop does not survive the fork() done by --daemonize, the
    # daemon would inherit descriptors which are already invalid there.
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    rescanner = Rescanner(asyncio.get_event_loop())

    if hasattr(signal, "SIGHUP"):
        # Takes the place of what --daemonize does on SIGHUP, which is to
        # exit, and of dying of it in the foreground. The event loop calls
        # this once it runs: a SIGHUP which comes while the responder is
        # still starting is a rescan right after the start.
        try:
            asyncio.get_event_loop().add_signal_handler(
                signal.SIGHUP, rescanner.request
            )

        except (NotImplementedError, RuntimeError, ValueError) as exc:
            log.info("SIGHUP will not rescan the data directories: %s" % exc)

    if not os.path.exists(confdir.cache):
        try:
            with daemon.PrivilegesOf(args.process_user, args.process_group):
                os.makedirs(confdir.cache)

        except OSError as exc:
            log.error(
                'failed to create cache directory "%s": ' "%s" % (confdir.cache, exc)
            )
            return 1

        else:
            log.info('Cache directory "%s" created' % confdir.cache)

    variation_modules = variation.load_variation_modules(
        confdir.variation, variation_modules_options
    )

    with daemon.PrivilegesOf(args.process_user, args.process_group):
        variation.initialize_variation_modules(variation_modules, mode="variating")

    # Bind transport endpoints
    bound_endpoints = []

    for idx, opt in enumerate(snmp_args):
        if opt[0] == "--agent-udpv4-endpoint":
            snmp_args[idx] = (opt[0], endpoints.IPv4TransportEndpoints().add(opt[1]))
            bound_endpoints.append(
                (f"UDP/IPv4 endpoint {opt[1]}", snmp_args[idx][1][0])
            )

        elif opt[0] == "--agent-udpv6-endpoint":
            snmp_args[idx] = (opt[0], endpoints.IPv6TransportEndpoints().add(opt[1]))
            bound_endpoints.append(
                (f"UDP/IPv6 endpoint {opt[1]}", snmp_args[idx][1][0])
            )

    # The binding itself is done by the event loop. See to its end here: this
    # is the last place where the process has the privileges it was started
    # with, and nothing has been said to be listening yet.
    failed_endpoints = wait_for_endpoints(bound_endpoints)

    if failed_endpoints:
        for name, exc in failed_endpoints:
            log.error(f"failed to bind {name}: {exc}")

        for _, transport in bound_endpoints:
            try:
                transport.close_transport()

            except Exception:
                pass

        return 1

    # Start configuring SNMP engine(s)

    transport_dispatcher = AsyncioDispatcher()

    # SNMPv1/v2c answered by the simulator itself; there are no communities
    # to answer them under with --v3-only
    fast_path = None

    if args.v1_v2c_path == "fast" and not args.v3_only:
        fast_path = fastpath.FastPath()

        transport_dispatcher.register_routing_callback(fast_path.route)
        transport_dispatcher.register_recv_callback(fast_path.receive, fastpath.RECV_ID)

    else:
        transport_dispatcher.register_routing_callback(lambda td, t, d: td)

    if not snmp_args or snmp_args[0][0] != "--v3-engine-id":
        snmp_args.insert(0, ("--v3-engine-id", "auto"))

    if snmp_args and snmp_args[-1][0] != "end-of-options":
        snmp_args.append(("end-of-options", ""))

    if args.v1_only:
        served_versions = {"1"}

    elif args.v2c_only:
        served_versions = {"2c"}

    else:
        # --v3-only keeps its meaning: no community is configured for the
        # recordings, the processing models stay
        served_versions = None

    # Build the indices the engines are going to ask for, several at a time
    with daemon.PrivilegesOf(args.process_user, args.process_group):
        indexed = datafile.index_data_files(
            datafile.find_data_files(
                datafile.configured_data_dirs(snmp_args, confdir.data)
            ),
            args.index_workers,
            args.force_index_rebuild,
            args.validate_data,
        )

    snmp_engine = None
    timeout = 0  # Initialize timeout before the loop

    transport_index = {
        "udpv4": args.transport_id_offset,
        "udpv6": args.transport_id_offset,
    }

    for opt in snmp_args:
        if opt[0] in ("--v3-engine-id", "end-of-options"):
            if snmp_engine:
                log.info("--- SNMP Engine configuration")

                log.info(
                    "SNMPv3 EngineID: "
                    "%s"
                    % (
                        hasattr(snmp_engine, "snmpEngineID")
                        and snmp_engine.snmpEngineID.prettyPrint()
                        or "<unknown>",
                    )
                )

                if not v3_context_engine_ids:
                    v3_context_engine_ids.append((None, []))

                log.msg.inc_ident()

                log.info("--- Simulation data recordings configuration")

                for v3_context_engine_id, ctx_data_dirs in v3_context_engine_ids:
                    snmp_context = context.SnmpContext(
                        snmp_engine, v3_context_engine_id
                    )
                    # unregister default context
                    snmp_context.unregister_context_name(b"")

                    log.info(
                        "SNMPv3 Context Engine ID: "
                        "%s" % snmp_context.contextEngineId.prettyPrint()
                    )

                    data_index_instrum_controller = (
                        controller.DataIndexInstrumController()
                    )

                    recordings = Recordings(
                        ctx_data_dirs or data_dirs or confdir.data,
                        variation_modules,
                        snmp_engine,
                        snmp_context,
                        data_index_instrum_controller,
                        communities=not args.v3_only,
                        force_index_rebuild=args.force_index_rebuild,
                        validate_data=args.validate_data,
                        indexed=indexed,
                        on_change=fast_path and fast_path.forget_selections,
                    )

                    with daemon.PrivilegesOf(args.process_user, args.process_group):
                        recordings.rescan(strict=True)

                    rescanner.recordings.append(recordings)

                # Configure access to data index

                config.add_v1_system(snmp_engine, "index", "index", contextName="index")

                log.info("--- SNMPv3 USM configuration")

                if not v3_users:
                    v3_users = ["simulator"]
                    v3_auth_keys[v3_users[0]] = "auctoritas"
                    v3_auth_protos[v3_users[0]] = "MD5"
                    v3_priv_keys[v3_users[0]] = "privatus"
                    v3_priv_protos[v3_users[0]] = "DES"

                for v3User in v3_users:
                    if v3User in v3_auth_keys:
                        if v3User not in v3_auth_protos:
                            v3_auth_protos[v3User] = "MD5"

                    elif v3User in v3_auth_protos:
                        log.error(
                            "auth protocol configured without key for user "
                            "%s" % v3User
                        )
                        return 1

                    else:
                        v3_auth_keys[v3User] = None
                        v3_auth_protos[v3User] = "NONE"

                    if v3User in v3_priv_keys:
                        if v3User not in v3_priv_protos:
                            v3_priv_protos[v3User] = "DES"

                    elif v3User in v3_priv_protos:
                        log.error(
                            "privacy protocol configured without key for user "
                            "%s" % v3User
                        )
                        return 1

                    else:
                        v3_priv_keys[v3User] = None
                        v3_priv_protos[v3User] = "NONE"

                    if (
                        AUTH_PROTOCOLS[v3_auth_protos[v3User]] == config.USM_AUTH_NONE
                        and PRIV_PROTOCOLS[v3_priv_protos[v3User]]
                        != config.USM_PRIV_NONE
                    ):
                        log.error(
                            "privacy impossible without authentication for USM user "
                            "%s" % v3User
                        )
                        return 1

                    if v3User in v3_auth_key_types and v3_auth_keys[v3User] is None:
                        log.error(
                            "auth key type configured without key for user "
                            "%s" % v3User
                        )
                        return 1

                    if v3User in v3_priv_key_types and v3_priv_keys[v3User] is None:
                        log.error(
                            "privacy key type configured without key for user "
                            "%s" % v3User
                        )
                        return 1

                    v3_auth_key_type = v3_auth_key_types.get(v3User, "passphrase")
                    v3_priv_key_type = v3_priv_key_types.get(v3User, "passphrase")

                    try:
                        config.add_v3_user(
                            snmp_engine,
                            v3User,
                            AUTH_PROTOCOLS[v3_auth_protos[v3User]],
                            v3_auth_keys[v3User]
                            and parse_usm_key(
                                v3_auth_keys[v3User],
                                v3_auth_key_type,
                                v3_auth_protos[v3User],
                            ),
                            PRIV_PROTOCOLS[v3_priv_protos[v3User]],
                            v3_priv_keys[v3User]
                            and parse_usm_key(
                                v3_priv_keys[v3User],
                                v3_priv_key_type,
                                v3_auth_protos[v3User],
                                v3_priv_protos[v3User],
                            ),
                            authKeyType=USM_KEY_TYPES[v3_auth_key_type],
                            privKeyType=USM_KEY_TYPES[v3_priv_key_type],
                        )

                    except ValueError as exc:
                        log.error("bad USM key for user %s: %s" % (v3User, exc))
                        return 1

                    except error.PySnmpError as exc:
                        log.error("bad USM values for user %s: " "%s" % (v3User, exc))
                        return 1

                    log.info("SNMPv3 USM SecurityName: %s" % v3User)

                    if AUTH_PROTOCOLS[v3_auth_protos[v3User]] != config.USM_AUTH_NONE:
                        log.info(
                            "SNMPv3 USM authentication key: %s, "
                            "authentication protocol: "
                            "%s" % (v3_auth_keys[v3User], v3_auth_protos[v3User])
                        )

                        if v3_auth_key_type != "passphrase":
                            log.info(
                                "SNMPv3 USM authentication key type: "
                                "%s" % v3_auth_key_type
                            )

                    if PRIV_PROTOCOLS[v3_priv_protos[v3User]] != config.USM_PRIV_NONE:
                        log.info(
                            "SNMPv3 USM encryption (privacy) key: %s, "
                            "encryption protocol: "
                            "%s" % (v3_priv_keys[v3User], v3_priv_protos[v3User])
                        )

                        if v3_priv_key_type != "passphrase":
                            log.info(
                                "SNMPv3 USM encryption (privacy) key type: "
                                "%s" % v3_priv_key_type
                            )

                snmp_context.register_context_name(
                    "index", data_index_instrum_controller
                )

                log.info(
                    "Maximum number of variable bindings in SNMP response: "
                    "%s" % local_max_var_binds
                )

                log.info(
                    "Maximum size of SNMP response message: %s octets"
                    % local_max_message_size
                )

                log.info(
                    "SNMP versions served: %s"
                    % ", ".join(
                        sorted(
                            SNMP_VERSIONS[int(model_id)]
                            for model_id in snmp_engine.message_processing_subsystems
                        )
                    )
                )

                log.info("--- Transport configuration")

                if not agent_udpv4_endpoints and not agent_udpv6_endpoints:
                    log.error(
                        "agent endpoint address(es) not specified for SNMP "
                        "engine ID %s" % v3_engine_id
                    )
                    return 1

                # the endpoints of this engine, for the fast path
                engine_domains = []

                for agent_udpv4_endpoint in agent_udpv4_endpoints:
                    transport_domain = udp.DOMAIN_NAME + (transport_index["udpv4"],)
                    transport_index["udpv4"] += 1
                    engine_domains.append(transport_domain)

                    snmp_engine.register_transport_dispatcher(
                        transport_dispatcher, transport_domain
                    )

                    config.add_transport(
                        snmp_engine, transport_domain, agent_udpv4_endpoint[0]
                    )

                    endpoints.remember_local_address(
                        transport_domain, agent_udpv4_endpoint[2]
                    )

                    log.msg(
                        "Listening at UDP/IPv4 endpoint %s, transport ID "
                        "%s"
                        % (
                            agent_udpv4_endpoint[1],
                            ".".join([str(handler) for handler in transport_domain]),
                        )
                    )

                for agent_udpv6_endpoint in agent_udpv6_endpoints:
                    transport_domain = udp6.DOMAIN_NAME + (transport_index["udpv6"],)
                    transport_index["udpv6"] += 1
                    engine_domains.append(transport_domain)

                    snmp_engine.register_transport_dispatcher(
                        transport_dispatcher, transport_domain
                    )

                    config.add_transport(
                        snmp_engine, transport_domain, agent_udpv6_endpoint[0]
                    )

                    endpoints.remember_local_address(
                        transport_domain, agent_udpv6_endpoint[2]
                    )

                    log.msg(
                        "Listening at UDP/IPv6 endpoint %s, transport ID "
                        "%s"
                        % (
                            agent_udpv6_endpoint[1],
                            ".".join([str(handler) for handler in transport_domain]),
                        )
                    )

                # SNMP applications
                GetCommandResponder(snmp_engine, snmp_context)
                SetCommandResponder(snmp_engine, snmp_context)
                NextCommandResponder(snmp_engine, snmp_context)
                bulk_command_responder = BulkCommandResponder(snmp_engine, snmp_context)
                bulk_command_responder.max_varbinds = local_max_var_binds
                bulk_command_responder.max_message_size = local_max_message_size

                # v1/v2c are served from the context the engine's own command
                # responders are given, as on the engine path. A message of
                # v1/v2c names the engine's own context engine ID, which the
                # engine finds no responder for when --v3-context-engine-id
                # gave the context another one: it answers none, nor do we
                if (
                    fast_path
                    and snmp_context.contextEngineId == snmp_engine.snmpEngineID
                ):
                    for transport_domain in engine_domains:
                        fast_path.add_endpoint(
                            transport_domain,
                            snmp_engine,
                            snmp_context,
                            recordings,
                            local_max_var_binds,
                            local_max_message_size,
                        )

                log.msg.dec_ident()

                if opt[0] == "end-of-options":
                    # Load up the rest of MIBs while running privileged
                    (
                        snmp_engine.message_dispatcher.mib_instrum_controller.get_mib_builder().load_modules()
                    )
                    break

            # Prepare for next engine ID configuration

            v3_context_engine_ids = []
            data_dirs = []
            local_max_var_binds = args.max_var_binds
            local_max_message_size = args.max_message_size
            v3_users = []
            v3_auth_keys = {}
            v3_auth_protos = {}
            v3_priv_keys = {}
            v3_priv_protos = {}
            v3_auth_key_types = {}
            v3_priv_key_types = {}
            agent_udpv4_endpoints = []
            agent_udpv6_endpoints = []
            # timeout = 0  <- Remove initialization from here

            try:
                v3_engine_id = opt[1]
                if not v3_engine_id or v3_engine_id.lower() == "auto":
                    snmp_engine = engine.SnmpEngine()

                else:
                    snmp_engine = engine.SnmpEngine(
                        snmpEngineID=univ.OctetString(hexValue=v3_engine_id)
                    )

            except Exception as exc:
                log.error(
                    'SNMPv3 Engine initialization failed, EngineID "%s": '
                    "%s" % (v3_engine_id, exc)
                )
                return 1

            config.add_context(snmp_engine, "")

            if served_versions:
                # A message of a version the engine has no processing model
                # for is counted in snmpInBadVersions and dropped, nothing
                # goes back to the manager.
                for model_id in list(snmp_engine.message_processing_subsystems):
                    if SNMP_VERSIONS[int(model_id)] not in served_versions:
                        del snmp_engine.message_processing_subsystems[model_id]

        elif opt[0] == "--v3-context-engine-id":
            v3_context_engine_ids.append((univ.OctetString(hexValue=opt[1]), []))

        elif opt[0] == "--data-dir":
            if v3_context_engine_ids:
                v3_context_engine_ids[-1][1].append(opt[1])

            else:
                data_dirs.append(opt[1])

        # --max-varbinds is the name this option had in a file of
        # --args-from-file, the command line never took it
        elif opt[0] in ("--max-var-binds", "--max-varbinds"):
            local_max_var_binds = int(opt[1])

        elif opt[0] == "--max-message-size":
            local_max_message_size = int(opt[1])

        elif opt[0] == "--v3-user":
            v3_users.append(opt[1])

        elif opt[0] == "--v3-auth-key":
            if not v3_users:
                log.error("--v3-user should precede %s" % opt[0])
                return 1

            if v3_users[-1] in v3_auth_keys:
                log.error(f"repetitive {opt[0]} option for user {v3_users[-1]}")
                return 1

            v3_auth_keys[v3_users[-1]] = opt[1]

        elif opt[0] == "--v3-auth-proto":
            if opt[1].upper() not in AUTH_PROTOCOLS:
                log.error("bad v3 auth protocol %s" % opt[1])
                return 1

            else:
                if not v3_users:
                    log.error("--v3-user should precede %s" % opt[0])
                    return 1

                if v3_users[-1] in v3_auth_protos:
                    log.error(f"repetitive {opt[0]} option for user {v3_users[-1]}")
                    return 1

                v3_auth_protos[v3_users[-1]] = opt[1].upper()

        elif opt[0] == "--v3-priv-key":
            if not v3_users:
                log.error("--v3-user should precede %s" % opt[0])
                return 1

            if v3_users[-1] in v3_priv_keys:
                log.error(f"repetitive {opt[0]} option for user {v3_users[-1]}")
                return 1

            v3_priv_keys[v3_users[-1]] = opt[1]

        elif opt[0] == "--v3-priv-proto":
            if opt[1].upper() not in PRIV_PROTOCOLS:
                log.error("bad v3 privacy protocol %s" % opt[1])
                return 1

            else:
                if not v3_users:
                    log.error("--v3-user should precede %s" % opt[0])
                    return 1

                if v3_users[-1] in v3_priv_protos:
                    log.error(f"repetitive {opt[0]} option for user {v3_users[-1]}")
                    return 1

                v3_priv_protos[v3_users[-1]] = opt[1].upper()

        elif opt[0] in ("--v3-auth-key-type", "--v3-priv-key-type"):
            # options of --args-from-file do not pass through argparse
            if opt[1].lower() not in USM_KEY_TYPES:
                log.error("bad v3 key type %s" % opt[1])
                return 1

            if not v3_users:
                log.error("--v3-user should precede %s" % opt[0])
                return 1

            key_types = (
                v3_auth_key_types
                if opt[0] == "--v3-auth-key-type"
                else v3_priv_key_types
            )

            if v3_users[-1] in key_types:
                log.error(f"repetitive {opt[0]} option for user {v3_users[-1]}")
                return 1

            key_types[v3_users[-1]] = opt[1].lower()

        elif opt[0] == "--agent-udpv4-endpoint":
            agent_udpv4_endpoints.append(opt[1])

        elif opt[0] == "--agent-udpv6-endpoint":
            agent_udpv6_endpoints.append(opt[1])

        elif opt[0] == "--timeout":
            timeout = opt[1]

    # a recording found by a rescan later on is indexed as the options say
    indexed.clear()

    transport_dispatcher.job_started(1)  # server job would never finish

    with daemon.PrivilegesOf(args.process_user, args.process_group, final=True):
        try:
            if startup:
                # indexes are built and endpoints are bound: whoever started
                # the daemon may go on and talk to it
                startup.ready()

            transport_dispatcher.run_dispatcher(float(timeout))

        except KeyboardInterrupt:
            log.info("Shutting down process...")

        finally:
            if variation_modules:
                log.info("Shutting down variation modules:")

                for name, contexts in variation_modules.items():
                    body = contexts[0]
                    try:
                        body["shutdown"](options=body["args"], mode="variation")

                    except Exception as exc:
                        log.error(
                            'Variation module "%s" shutdown FAILED: ' "%s" % (name, exc)
                        )

                    else:
                        log.info('Variation module "%s" shutdown OK' % name)

            transport_dispatcher.close_dispatcher()

            log.info("Process terminated")

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
