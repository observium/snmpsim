#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# Copyright (c) 2022-2025, LeXtudio Inc. <support@lextudio.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
# Managed value variation module
# Send SNMP Notification
#
import asyncio
import threading

from pysnmp.hlapi.asyncio import *  # Import all necessary modules

from snmpsim import log
from snmpsim.commands.responder import AUTH_PROTOCOLS, PRIV_PROTOCOLS
from snmpsim.grammar.snmprec import SnmprecGrammar
from snmpsim.record.snmprec import SnmprecRecord
from snmpsim.utils import split


def init(**context):
    pass


TYPE_MAP = {
    "s": OctetString,
    "h": lambda x: OctetString(hexValue=x),
    "i": Integer32,
    "o": ObjectIdentifier,
    "a": IpAddress,
    "u": Unsigned32,
    "g": Gauge32,
    "t": TimeTicks,
    "b": Bits,
    "I": Counter64,
}

MODULE_OPTIONS = (
    ("op", "set"),
    ("community", "public"),
    ("authkey", None),
    ("authproto", "md5"),
    ("privkey", None),
    ("privproto", "des"),
    ("proto", "udp"),
    ("port", "162"),
    ("ntftype", "trap"),
    ("trapoid", "1.3.6.1.6.3.1.1.5.1"),
)

TRANSPORT_TARGETS = {
    "udp": UdpTransportTarget,
    "udp6": Udp6TransportTarget,
}


def get_protocol(protocols, name):
    """Look up a USM protocol by the name the responder options call it.

    The responder takes the names in any case, so do `authproto` and
    `privproto`. Returns `None` for a name the responder would refuse.
    """
    return protocols.get(name.upper())


class Originator:
    """Sends notifications from SNMP engines of its own.

    Sending through the engine that answers the managers would configure the
    notification's credentials on it. A USM user of the same name would get
    the notification's keys and protocols, and the managers polling under
    the original ones would fail authentication from then on.

    Each responder engine gets a twin carrying the same engine ID, so that a
    receiver sees the notification coming from the agent it knows. The twins
    live on an event loop of their own, in a thread started on first use.
    """

    def __init__(self):
        self._engines = {}
        self._bind_addresses = []
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run, name="notification", daemon=True
        )
        self._thread.start()

    def _run(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def send(self, engine_id, auth_data, endpoint, notify_type, notification, tag):
        """Queue a notification, log the failure if it comes to one.

        The caller is the responder serving a request: it does not wait for
        the name to resolve or for an INFORM to be acknowledged.
        """
        future = asyncio.run_coroutine_threadsafe(
            self._send(engine_id, auth_data, endpoint, notify_type, notification),
            self._loop,
        )
        future.add_done_callback(lambda future: self._report(future, tag))

    @staticmethod
    def _report(future, tag):
        try:
            error_indication, error_status, error_index, var_binds = future.result()

        except Exception as exc:
            log.info("notification: for %s failed: %s" % (tag, exc))
            return

        if error_indication or error_status:
            log.info(
                "notification: for %s failed with errorIndication %s, "
                "errorStatus %s" % (tag, error_indication, error_status)
            )

    async def _send(self, engine_id, auth_data, endpoint, notify_type, notification):
        proto, host, port, bind_address = endpoint

        if engine_id not in self._engines:
            # must be born on this loop: its dispatcher sticks to the loop
            # that is current when the first transport is added
            self._engines[engine_id] = SnmpEngine(snmpEngineID=engine_id)

        target = await TRANSPORT_TARGETS[proto].create((host, port))

        if bind_address:
            target.set_local_address((bind_address, 0))

            # one socket per local address: without a domain of its own the
            # target would reuse the socket of whichever address came first
            if bind_address not in self._bind_addresses:
                self._bind_addresses.append(bind_address)

            target.TRANSPORT_DOMAIN = target.TRANSPORT_DOMAIN + (
                self._bind_addresses.index(bind_address) + 1,
            )

        return await send_notification(
            self._engines[engine_id],
            auth_data,
            target,
            ContextData(),
            notify_type,
            notification,
        )

    def close(self):
        def stop():
            for snmp_engine in self._engines.values():
                snmp_engine.close_dispatcher()

            self._loop.stop()

        self._loop.call_soon_threadsafe(stop)
        self._thread.join()
        self._loop.close()


def variate(oid, tag, value, **context):
    if not context["nextFlag"] and not context["exactMatch"]:
        return context["origOid"], tag, context["errorStatus"]

    if "settings" not in recordContext:
        recordContext["settings"] = dict([split(x, "=") for x in split(value, ",")])

        for k, v in MODULE_OPTIONS:
            recordContext["settings"].setdefault(k, v)

        if "hexvalue" in recordContext["settings"]:
            recordContext["settings"]["value"] = [
                int(recordContext["settings"]["hexvalue"][x : x + 2], 16)
                for x in range(0, len(recordContext["settings"]["hexvalue"]), 2)
            ]

        if "vlist" in recordContext["settings"]:
            vlist = {}

            recordContext["settings"]["vlist"] = split(
                recordContext["settings"]["vlist"], ":"
            )

            while recordContext["settings"]["vlist"]:
                o, v = recordContext["settings"]["vlist"][:2]

                vlist = recordContext["settings"]["vlist"][2:]
                recordContext["settings"]["vlist"] = vlist

                typeTag, _ = SnmprecRecord.unpack_tag(tag)

                v = SnmprecGrammar.TAG_MAP[typeTag](v)

                if o not in vlist:
                    vlist[o] = set()

                if o == "eq":
                    vlist[o].add(v)

                elif o in ("lt", "gt"):
                    vlist[o] = v

                else:
                    log.info(
                        "notification: bad vlist syntax: "
                        "%s" % recordContext["settings"]["vlist"]
                    )

            recordContext["settings"]["vlist"] = vlist

    args = recordContext["settings"]

    if context["setFlag"] and "vlist" in args:
        if "eq" in args["vlist"] and context["origValue"] in args["vlist"]["eq"]:
            pass

        elif "lt" in args["vlist"] and context["origValue"] < args["vlist"]["lt"]:
            pass

        elif "gt" in args["vlist"] and context["origValue"] > args["vlist"]["gt"]:
            pass

        else:
            return oid, tag, context["origValue"]

    if args["op"] not in ("get", "set", "any", "*"):
        log.info(
            "notification: unknown SNMP request type configured: " "%s" % args["op"]
        )
        return context["origOid"], tag, context["errorStatus"]

    if (
        args["op"] == "get"
        and not context["setFlag"]
        or args["op"] == "set"
        and context["setFlag"]
        or args["op"] in ("any", "*")
    ):
        version = args.get("version")

        if version in ("1", "2c"):
            authData = CommunityData(
                args["community"], mpModel=version == "2c" and 1 or 0
            )

        elif version == "3":
            if "user" not in args:
                log.info("notification: USM user not configured for OID %s" % (oid,))
                return context["origOid"], tag, context["errorStatus"]

            authProtocol = get_protocol(AUTH_PROTOCOLS, args["authproto"])
            if authProtocol is None:
                log.info("notification: unknown auth proto " "%s" % args["authproto"])
                return context["origOid"], tag, context["errorStatus"]

            privProtocol = get_protocol(PRIV_PROTOCOLS, args["privproto"])
            if privProtocol is None:
                log.info(
                    "notification: unknown privacy proto " "%s" % args["privproto"]
                )
                return context["origOid"], tag, context["errorStatus"]

            authData = UsmUserData(
                args["user"],
                args["authkey"],
                args["privkey"],
                authProtocol=authProtocol,
                privProtocol=privProtocol,
            )

        else:
            log.info("notification: unknown SNMP version %s" % version)
            return context["origOid"], tag, context["errorStatus"]

        if "host" not in args:
            log.info(
                "notification: target hostname not configured for " "OID %s" % (oid,)
            )
            return context["origOid"], tag, context["errorStatus"]

        if args["proto"] not in TRANSPORT_TARGETS:
            log.info("notification: unknown transport %s" % args["proto"])
            return context["origOid"], tag, context["errorStatus"]

        localAddress = args.get("bindaddr")

        if localAddress:
            log.info("notification: binding to local address %s" % localAddress)

        varBinds = []

        if "uptime" in args:
            varBinds.append(
                (ObjectIdentifier("1.3.6.1.2.1.1.3.0"), TimeTicks(args["uptime"]))
            )

        if version == "1":
            if "agentaddress" in args:
                varBinds.append(
                    (
                        ObjectIdentifier("1.3.6.1.6.3.18.1.3.0"),
                        IpAddress(args["agentaddress"]),
                    )
                )

            if "enterprise" in args:
                varBinds.append(
                    (
                        ObjectIdentifier("1.3.6.1.6.3.1.1.4.3.0"),
                        ObjectIdentifier(args["enterprise"]),
                    )
                )

        if "varbinds" in args:
            vbs = split(args["varbinds"], ":")
            while vbs:
                varBinds.append((ObjectIdentifier(vbs[0]), TYPE_MAP[vbs[1]](vbs[2])))
                vbs = vbs[3:]

        notificationType = NotificationType(
            ObjectIdentity(args["trapoid"])
        ).add_varbinds(*varBinds)

        # the notification goes out under the engine ID of the agent that
        # is being simulated, yet not through its engine
        snmpEngine = context.get("snmpEngine")
        snmpEngineID = snmpEngine and snmpEngine.snmpEngineID or None

        if "originator" not in moduleContext:
            moduleContext["originator"] = Originator()

        log.info(
            "notification: sending SNMPv%s %s to %s:%s"
            % (version, args["ntftype"], args["host"], args["port"])
        )

        moduleContext["originator"].send(
            snmpEngineID,
            authData,
            (args["proto"], args["host"], int(args["port"]), localAddress),
            args["ntftype"],
            notificationType,
            "%s=%r" % (oid, value),
        )

    if context["setFlag"] or "value" not in args:
        return oid, tag, context["origValue"]

    else:
        return oid, tag, args["value"]


def shutdown(**context):
    if "originator" in moduleContext:
        moduleContext.pop("originator").close()
