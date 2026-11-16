.. include:: /includes/_links.rst

Quick Start
===========

.. toctree::
   :maxdepth: 2

Installation
------------

snmpsim-ng is written in Python and depends on other Python libraries.
It is not on PyPI yet, so it is installed straight from git. The package
named ``snmpsim`` on PyPI is a different release line; if that one, or an
earlier version of this project, is installed already, remove it first as
described in :doc:`/migrating`.

Below we quickly set up a Python virtual environment and install snmpsim-ng
into it.

.. code-block:: bash

   $ python3 -m venv venv
   $ . venv/bin/activate
   $ pip install "git+https://github.com/observium/snmpsim.git@master"

On Windows the environment is made and activated differently, the rest is
the same:

.. code-block:: bat

   > py -m venv venv
   > venv\Scripts\activate
   > pip install "git+https://github.com/observium/snmpsim.git@master"

It runs on PyPy 3.11 as well, which serves about twice as many requests per
second as CPython. ``uv`` fetches PyPy itself:

.. code-block:: bash

   $ uv tool install --python pypy3.11 "git+https://github.com/observium/snmpsim.git@master"

Install the gdbm library first (``brew install gdbm`` on macOS; most Linux
systems have it). PyPy has the gdbm module only where the library is there,
and without it the indexes land in ``dbm.ndbm``, which ``dbm.whichdb()``
does not recognise, so every start of the Simulator builds them all again,
or, where there is no ``dbm.ndbm`` either, in the much slower ``dbm.dumb``.

.. note::

   A few sample recordings come with the package, in its ``data``
   directory, and the Simulator serves them when it is started without
   ``--data-dir``. The ``snmpsim-data`` package on PyPI is not a way to get
   more: it requires ``snmpsim`` 1.x, so installing it puts the other
   release line over this one.

Run SNMP Simulator
------------------

Simulation data are plain-text files with the ``.snmprec`` (or other) file
extension. Each line represents a single SNMP object as pipe-separated
fields ``OID|TYPE|VALUE``. Make a directory called ``data`` and put a small
file of your own into it:

.. code-block:: text
   :caption: data/demo.snmprec

   1.3.6.1.2.1.1.1.0|4|Demo agent served by snmpsim-ng
   1.3.6.1.2.1.1.3.0|67|12345
   1.3.6.1.2.1.1.4.0|4|admin@example.com
   1.3.6.1.2.1.1.5.0|4|demo.example.com
   1.3.6.1.2.1.1.6.0|4|Rack 3

Then invoke the ``snmpsim-command-responder`` daemon and point it to that
directory:

.. code-block:: bash

   $ snmpsim-command-responder --data-dir=./data \
        --agent-udpv4-endpoint=127.0.0.1:1611

This command starts the Simulator on UDP/IPv4 port 1611. It will
respond to SNMP queries with simulation data stored in ``./data`` directory.

Test the Setup
--------------

Depending on how many data files are loaded, the Simulator initializes a number
of agents. Each is addressed by the name of its file: ``data/demo.snmprec``
answers to the community name ``demo``. You can try it out with Net-SNMP's
command-line tools which are usually shipped along with your operating system:

.. code-block:: bash

   $ snmpwalk -v2c -c demo 127.0.0.1:1611 system
   SNMPv2-MIB::sysDescr.0 = STRING: Demo agent served by snmpsim-ng
   DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (12345) 0:02:03.45
   SNMPv2-MIB::sysContact.0 = STRING: admin@example.com
   SNMPv2-MIB::sysName.0 = STRING: demo.example.com
   SNMPv2-MIB::sysLocation.0 = STRING: Rack 3

The Simulator analyzes the parameters (such as SNMP community name or SNMPv3
context name and/or IP address) of SNMP query to determine which agent (whose
data from a specific ``.snmprec`` file) to respond with.

Simulate Existing SNMP Agent
----------------------------

Besides creating simulation data by hand, you can generate it from some
existing SNMP agent. Here the donor device answers at 192.0.2.1, an address
reserved for documentation - put the address of your own agent in its place:

.. code-block:: bash

   $ snmpsim-record-commands --agent-udpv4-endpoint=192.0.2.1 \
        --output-file=./data/public.snmprec
   SNMP version 2c, Community name: public
   Querying UDP/IPv4 agent at 192.0.2.1:161
   Agent response timeout: 3 secs, retries: 3
   Sending initial GETNEXT request for 1.3.6 (stop at <end-of-mib>)....
   OIDs dumped: 182, elapsed: 11.97 sec, rate: 15.20 OIDs/sec, errors: 0

Simulate from MIB
-----------------

Alternatively, you could build simulation data from a MIB file:

.. code-block:: bash

   $ snmpsim-record-mibs --output-file=./data/public.snmprec \
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

- :doc:`/documentation/index`
- :doc:`/migrating`
- :doc:`/license`
