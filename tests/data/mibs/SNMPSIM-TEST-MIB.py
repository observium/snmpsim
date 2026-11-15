#
# This file is part of snmpsim software.
#
# SNMPSIM-TEST-MIB in the pysnmp data model, written by hand for the tests of
# snmpsim-record-mibs: tables that are indexed by the same columns. pysnmp
# loads it with `mibBuilder` in its globals; nothing is compiled or fetched.
#
#   portTable       INDEX    { portIndex }
#   portExtTable    AUGMENTS { portEntry }
#   portStatsTable  INDEX    { portIndex }
#   portQueueTable  INDEX    { portIndex, portQueueIndex }
#
(ValueRangeConstraint,) = mibBuilder.import_symbols(  # noqa: F821
    "ASN1-REFINEMENT", "ValueRangeConstraint"
)

(
    Counter32,
    Integer32,
    ModuleIdentity,
    MibTable,
    MibTableRow,
    MibTableColumn,
) = mibBuilder.import_symbols(  # noqa: F821
    "SNMPv2-SMI",
    "Counter32",
    "Integer32",
    "ModuleIdentity",
    "MibTable",
    "MibTableRow",
    "MibTableColumn",
)

(DisplayString,) = mibBuilder.import_symbols("SNMPv2-TC", "DisplayString")  # noqa: F821

MIB = "SNMPSIM-TEST-MIB"
ROOT = (1, 3, 6, 1, 3, 9999)


class Number(Integer32):
    subtypeSpec = Integer32.subtypeSpec + ValueRangeConstraint(1, 2147483647)


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
)
