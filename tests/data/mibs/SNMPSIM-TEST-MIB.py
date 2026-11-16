#
# This file is part of snmpsim software.
#
# SNMPSIM-TEST-MIB in the pysnmp data model, written by hand for the tests of
# snmpsim-record-mibs: tables that are indexed by the same columns, and
# objects whose values are constrained. pysnmp loads it with `mibBuilder` in
# its globals; nothing is compiled or fetched.
#
#   portTable       INDEX    { portIndex }
#   portExtTable    AUGMENTS { portEntry }
#   portStatsTable  INDEX    { portIndex }
#   portQueueTable  INDEX    { portIndex, portQueueIndex }
#   slotTable       INDEX    { slotIndex }, a column per kind of constraint
#   voidTable       INDEX    { voidIndex }, which no value fits
#   voidSetting     a scalar no value fits
#
(
    ConstraintsUnion,
    SingleValueConstraint,
    ValueRangeConstraint,
    ValueSizeConstraint,
) = mibBuilder.import_symbols(  # noqa: F821
    "ASN1-REFINEMENT",
    "ConstraintsUnion",
    "SingleValueConstraint",
    "ValueRangeConstraint",
    "ValueSizeConstraint",
)

(NamedValues,) = mibBuilder.import_symbols(  # noqa: F821
    "ASN1-ENUMERATION", "NamedValues"
)

(OctetString,) = mibBuilder.import_symbols("ASN1", "OctetString")  # noqa: F821

(
    Bits,
    Counter32,
    Gauge32,
    Integer32,
    ModuleIdentity,
    MibScalar,
    MibTable,
    MibTableRow,
    MibTableColumn,
) = mibBuilder.import_symbols(  # noqa: F821
    "SNMPv2-SMI",
    "Bits",
    "Counter32",
    "Gauge32",
    "Integer32",
    "ModuleIdentity",
    "MibScalar",
    "MibTable",
    "MibTableRow",
    "MibTableColumn",
)

(
    DateAndTime,
    DisplayString,
    MacAddress,
    TextualConvention,
) = mibBuilder.import_symbols(  # noqa: F821
    "SNMPv2-TC", "DateAndTime", "DisplayString", "MacAddress", "TextualConvention"
)

MIB = "SNMPSIM-TEST-MIB"
ROOT = (1, 3, 6, 1, 3, 9999)


class Number(Integer32):
    subtypeSpec = Integer32.subtypeSpec + ValueRangeConstraint(1, 2147483647)


# what the MIB compiler writes for INTEGER { standby(40), active(50), failed(60) }
class SlotState(Integer32):
    subtypeSpec = Integer32.subtypeSpec + SingleValueConstraint(40, 50, 60)
    namedValues = NamedValues(("standby", 40), ("active", 50), ("failed", 60))


# an enumeration that only names its members, as hand-written MIB code has it
class SlotKind(Integer32):
    namedValues = NamedValues(("fan", 1), ("power", 2), ("line", 3))


class SlotPower(Integer32):
    subtypeSpec = Integer32.subtypeSpec + ValueRangeConstraint(1000, 2000)


class SlotOffset(Integer32):
    subtypeSpec = Integer32.subtypeSpec + ConstraintsUnion(
        ValueRangeConstraint(-20, -10), ValueRangeConstraint(100, 110)
    )


class SlotSpeed(Gauge32):
    subtypeSpec = Gauge32.subtypeSpec + ValueRangeConstraint(4000000000, 4000000010)


# Integer32 (4000..5000) with DISPLAY-HINT "d-2": the hint is for people, the
# value on the wire is the plain number
class SlotLoad(TextualConvention, Integer32):
    displayHint = "d-2"
    subtypeSpec = Integer32.subtypeSpec + ValueRangeConstraint(4000, 5000)


class SlotSerial(OctetString):
    subtypeSpec = OctetString.subtypeSpec + ValueSizeConstraint(6, 6)


class SlotTag(DisplayString):
    subtypeSpec = DisplayString.subtypeSpec + ValueSizeConstraint(0, 2)


class SlotLabel(DisplayString):
    subtypeSpec = DisplayString.subtypeSpec + ValueSizeConstraint(100, 120)


class SlotKey(OctetString):
    subtypeSpec = OctetString.subtypeSpec + ConstraintsUnion(
        ValueSizeConstraint(16, 16), ValueSizeConstraint(20, 20)
    )


class SlotFlags(Bits):
    namedValues = NamedValues(("present", 0), ("powered", 1), ("faulty", 9))


# no number is both between 1 and 5 and equal to 9
class Void(Integer32):
    subtypeSpec = (
        Integer32.subtypeSpec + ValueRangeConstraint(1, 5) + SingleValueConstraint(9)
    )


def column(oid, syntax, access="read-only"):
    return MibTableColumn(oid, syntax).set_max_access(access)


snmpsimTestMIB = ModuleIdentity(ROOT)

portTable = MibTable(ROOT + (1,))
portEntry = MibTableRow(ROOT + (1, 1)).set_index_names((0, MIB, "portIndex"))
portIndex = column(ROOT + (1, 1, 1), Number())
portName = column(ROOT + (1, 1, 2), DisplayString())

portExtTable = MibTable(ROOT + (2,))
portExtEntry = MibTableRow(ROOT + (2, 1))
portExtAlias = column(ROOT + (2, 1, 1), DisplayString())

# what the MIB compiler writes for AUGMENTS { portEntry }
portEntry.register_augmentions((MIB, "portExtEntry"))
portExtEntry.set_index_names(*portEntry.get_index_names())

portStatsTable = MibTable(ROOT + (3,))
portStatsEntry = MibTableRow(ROOT + (3, 1)).set_index_names((0, MIB, "portIndex"))
portStatsErrors = column(ROOT + (3, 1, 1), Counter32())

portQueueTable = MibTable(ROOT + (4,))
portQueueEntry = MibTableRow(ROOT + (4, 1)).set_index_names(
    (0, MIB, "portIndex"), (0, MIB, "portQueueIndex")
)
portQueueIndex = column(ROOT + (4, 1, 1), Number(), "not-accessible")
portQueueDrops = column(ROOT + (4, 1, 2), Counter32())

slotTable = MibTable(ROOT + (5,))
slotEntry = MibTableRow(ROOT + (5, 1)).set_index_names((0, MIB, "slotIndex"))
slotIndex = column(ROOT + (5, 1, 1), Number(), "not-accessible")
slotState = column(ROOT + (5, 1, 2), SlotState())
slotKind = column(ROOT + (5, 1, 3), SlotKind())
slotPower = column(ROOT + (5, 1, 4), SlotPower())
slotOffset = column(ROOT + (5, 1, 5), SlotOffset())
slotSpeed = column(ROOT + (5, 1, 6), SlotSpeed())
slotLoad = column(ROOT + (5, 1, 7), SlotLoad())
slotSerial = column(ROOT + (5, 1, 8), SlotSerial())
slotTag = column(ROOT + (5, 1, 9), SlotTag())
slotLabel = column(ROOT + (5, 1, 10), SlotLabel())
slotKey = column(ROOT + (5, 1, 11), SlotKey())
slotMac = column(ROOT + (5, 1, 12), MacAddress())
slotBuilt = column(ROOT + (5, 1, 13), DateAndTime())
slotFlags = column(ROOT + (5, 1, 14), SlotFlags())
slotVoid = column(ROOT + (5, 1, 15), Void())
slotErrors = column(ROOT + (5, 1, 16), Counter32())

voidTable = MibTable(ROOT + (6,))
voidEntry = MibTableRow(ROOT + (6, 1)).set_index_names((0, MIB, "voidIndex"))
voidIndex = column(ROOT + (6, 1, 1), Void(), "not-accessible")
voidName = column(ROOT + (6, 1, 2), DisplayString())

voidSetting = MibScalar(ROOT + (7,), Void()).set_max_access("read-only")
lastSetting = MibScalar(ROOT + (8,), SlotPower()).set_max_access("read-only")

mibBuilder.export_symbols(  # noqa: F821
    MIB,
    snmpsimTestMIB=snmpsimTestMIB,
    portTable=portTable,
    portEntry=portEntry,
    portIndex=portIndex,
    portName=portName,
    portExtTable=portExtTable,
    portExtEntry=portExtEntry,
    portExtAlias=portExtAlias,
    portStatsTable=portStatsTable,
    portStatsEntry=portStatsEntry,
    portStatsErrors=portStatsErrors,
    portQueueTable=portQueueTable,
    portQueueEntry=portQueueEntry,
    portQueueIndex=portQueueIndex,
    portQueueDrops=portQueueDrops,
    slotTable=slotTable,
    slotEntry=slotEntry,
    slotIndex=slotIndex,
    slotState=slotState,
    slotKind=slotKind,
    slotPower=slotPower,
    slotOffset=slotOffset,
    slotSpeed=slotSpeed,
    slotLoad=slotLoad,
    slotSerial=slotSerial,
    slotTag=slotTag,
    slotLabel=slotLabel,
    slotKey=slotKey,
    slotMac=slotMac,
    slotBuilt=slotBuilt,
    slotFlags=slotFlags,
    slotVoid=slotVoid,
    slotErrors=slotErrors,
    voidTable=voidTable,
    voidEntry=voidEntry,
    voidIndex=voidIndex,
    voidName=voidName,
    voidSetting=voidSetting,
    lastSetting=lastSetting,
)
