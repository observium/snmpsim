.. include:: /includes/_links.rst

Quick Start
===========

.. toctree::
   :maxdepth: 2

Installation
------------

SNMP Simulator is written in Python and depends on other Python libraries.
The easiest way to deploy SNMP Simulator is by downloading it from PyPI.

Below we quickly set up a Python 3.12 virtual environment and install SNMP
Simulator into it.

.. code-block:: bash

   $ pyenv local 3.12
   $ pip install pipenv
   $ pipenv --python 3.12
   $ pipenv install snmpsim

.. note::

   You might want to use some existing data files to get started quickly. Then,
   you can install ``snmpsim-data`` package as well. You can learn more
   about it in the `SNMP Simulator Data`_.

Run SNMP Simulator
------------------

Once installed, invoke ``snmpsim-command-responder`` daemon and point it to a
directory containing simulation data:

.. code-block:: bash

   $ pipenv run snmpsim-command-responder --data-dir=./data/UPS \
        --agent-udpv4-endpoint=127.0.0.1:1611

This command starts the Simulator on UDP/IPv4 port 1611. It will
respond to SNMP queries with simulation data stored in ``./data/UPS`` directory.

Test the Setup
--------------

Depending on how many data files are loaded, the Simulator initializes a number
of agents. You can then try them out with Net-SNMP's command-line tools which
are usually shipped along with your operating system:

.. code-block:: bash

   $ snmpwalk -v2c -c apc-8932 127.0.0.1:1611 system
   SNMPv2-MIB::sysDescr.0 = STRING: APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.7.2 PN:apc_hw05_aos_672.bin AF1:v6.7.2 AN1:apc_hw05_rpdu2g_672.bin MN:AP8932 HR:02 SN: 3F503A169043 MD:01/23/2019)
   SNMPv2-MIB::sysObjectID.0 = OID: SNMPv2-SMI::enterprises.318.1.3.4.6
   DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (165328680) 19 days, 3:14:46.80
   SNMPv2-MIB::sysContact.0 = STRING: Unknown
   SNMPv2-MIB::sysName.0 = STRING: pwr-dc01-pdu-rack3-01
   SNMPv2-MIB::sysLocation.0 = STRING: Unknown
   SNMPv2-MIB::sysServices.0 = INTEGER: 72
   SNMPv2-MIB::sysORLastChange.0 = Timeticks: (0) 0:00:00.00
   SNMPv2-MIB::sysORID.1 = OID: SNMPv2-MIB::snmpMIB
   SNMPv2-MIB::sysORID.2 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
   SNMPv2-MIB::sysORID.3 = OID: SNMP-MPD-MIB::snmpMPDCompliance
   SNMPv2-MIB::sysORID.4 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
   SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmMIBCompliance
   SNMPv2-MIB::sysORDescr.1 = STRING: The MIB Module from SNMPv2 entities
   SNMPv2-MIB::sysORDescr.2 = STRING: SNMP Management Architecture MIB
   SNMPv2-MIB::sysORDescr.3 = STRING: Message Processing and Dispatching MIB
   SNMPv2-MIB::sysORDescr.4 = STRING: USM User MIB
   SNMPv2-MIB::sysORDescr.5 = STRING: VACM MIB
   SNMPv2-MIB::sysORUpTime.1 = Timeticks: (0) 0:00:00.00
   SNMPv2-MIB::sysORUpTime.2 = Timeticks: (0) 0:00:00.00
   SNMPv2-MIB::sysORUpTime.3 = Timeticks: (0) 0:00:00.00
   SNMPv2-MIB::sysORUpTime.4 = Timeticks: (0) 0:00:00.00
   SNMPv2-MIB::sysORUpTime.5 = Timeticks: (0) 0:00:00.00

Simulation data are simple plain-text file, with ``.snmprec`` (or other) file
extensions. Each line in represents a single SNMP object in form of
pipe-separated fields ``OID|TYPE|VALUE``.

.. code-block:: bash

   $ cat ./data/UPS/apc-8932.snmprec
   1.3.6.1.2.1.1.1.0|4x|415043205765622f534e4d50204d616e6167656d656e74204361726420284d423a76342e312e302050463a76362e372e3220504e3a6170635f687730355f616f735f3637322e62696e204146313a76362e372e3220414e313a6170635f687730355f7270647532675f3637322e62696e204d4e3a4150383933322048523a303220534e3a20334635303341313639303433204d443a30312f32332f3230313929
   1.3.6.1.2.1.1.2.0|6|1.3.6.1.4.1.318.1.3.4.6
   1.3.6.1.2.1.1.3.0|67|165328680
   1.3.6.1.2.1.1.4.0|4|Unknown
   1.3.6.1.2.1.1.5.0|4x|7077722d646330312d7064752d7261636b332d3031
   1.3.6.1.2.1.1.6.0|4|Unknown
   1.3.6.1.2.1.1.7.0|2|72
   1.3.6.1.2.1.1.8.0|67|0
   1.3.6.1.2.1.1.9.1.2.1|6|1.3.6.1.6.3.1
   1.3.6.1.2.1.1.9.1.2.2|6|1.3.6.1.6.3.10.3.1.1
   1.3.6.1.2.1.1.9.1.2.3|6|1.3.6.1.6.3.11.3.1.1
   1.3.6.1.2.1.1.9.1.2.4|6|1.3.6.1.6.3.15.2.1.1
   1.3.6.1.2.1.1.9.1.2.5|6|1.3.6.1.6.3.16.2.1.1
   1.3.6.1.2.1.1.9.1.3.1|4x|546865204d4942204d6f64756c652066726f6d20534e4d50763220656e746974696573
   1.3.6.1.2.1.1.9.1.3.2|4x|534e4d50204d616e6167656d656e7420417263686974656374757265204d4942
   1.3.6.1.2.1.1.9.1.3.3|4x|4d6573736167652050726f63657373696e6720616e64204469737061746368696e67204d4942
   1.3.6.1.2.1.1.9.1.3.4|4x|55534d2055736572204d4942
   1.3.6.1.2.1.1.9.1.3.5|4x|5641434d204d4942
   1.3.6.1.2.1.1.9.1.4.1|67|0
   1.3.6.1.2.1.1.9.1.4.2|67|0
   1.3.6.1.2.1.1.9.1.4.3|67|0
   1.3.6.1.2.1.1.9.1.4.4|67|0
   1.3.6.1.2.1.1.9.1.4.5|67|0
   ...

The Simulator analyzes the parameters (such as SNMP community name or SNMPv3
context name and/or IP address) of SNMP query to determine which agent (whose
data from a specific ``.snmprec`` file) to respond with.

Simulate Existing SNMP Agent
----------------------------

Besides creating simulation data by hand, you can generate it from some
existing SNMP agent. Here we use publicly available SNMP Simulator instance
as a donor device:

.. code-block:: bash

   $ pipenv run snmpsim-record-commands --agent-udpv4-endpoint=demo.pysnmp.com \
        --output-file=./data/public.snmprec
   SNMP version 2c, Community name: public
   Querying UDP/IPv4 agent at 195.218.195.228:161
   Agent response timeout: 3.00 secs, retries: 3
   Sending initial GETNEXT request for 1.3.6 (stop at <end-of-mib>)....
   OIDs dumped: 182, elapsed: 11.97 sec, rate: 15.20 OIDs/sec, errors: 0

.. note::

   We host many simulation data files in ``snmpsim-data`` package.
   You can learn more about them in the `SNMP Simulator Data`_.

Simulate from MIB
-----------------

Alternatively, you could build simulation data from a MIB file:

.. code-block:: bash

   $ pipenv run snmpsim-record-mibs --output-file=./data/public.snmprec \
        --mib-module=IF-MIB
   # MIB module: IF-MIB, from the beginning till the end
   # Starting table IF-MIB::ifTable (1.3.6.1.2.1.2.2)
   # Synthesizing row #1 of table 1.3.6.1.2.1.2.2.1
   ...
   # Finished table 1.3.6.1.2.1.2.2.1 (10 rows)
   # End of IF-MIB, 177 OID(s) dumped

You can even sniff network traffic on the wire recovering SNMP messages there
and building simulation data from it.

Besides static files, SNMP simulator can be configured to call its plugin
modules for simulation data. We ship plugins to interface SQL and NOSQL
databases, file-based key-value stores and other sources of information.

Related Resources
-----------------

- `Support Options`_
- :doc:`/documentation/index`
- :doc:`/license`
