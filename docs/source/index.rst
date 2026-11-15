.. include:: /includes/_links.rst

snmpsim-ng
==========

Simulation plays a crucial role in the network management tool ecosystem as it
allows developers and network administrators to test and validate their
applications and systems in a controlled environment. By simulating various
SNMP speaking devices, it becomes possible to replicate real-world scenarios
and evaluate the behavior of network management tools under different
conditions.

snmpsim-ng is a maintained line of SNMP Simulator, the tool Ilya Etingof
wrote on top of PySNMP. With it, users can easily create virtual SNMP devices
that mimic the behavior of actual devices on the network. This enables
comprehensive testing of SNMP-based applications, including monitoring,
configuration management, and performance analysis.

The software is free, open source, and immediately available to anyone for
whatever purpose, making it an accessible and valuable tool for network
management professionals.

How to Use SNMP Simulator
-------------------------

Try the fast lane if you are fluent with network management matters.

.. toctree::
   :maxdepth: 2

   /quick-start

Coming from snmpsim
-------------------

snmpsim-ng has a package name and a version line of its own. If you have
an installation named ``snmpsim``, read this first.

.. toctree::
   :maxdepth: 2

   /migrating

SNMP Simulator Suite
--------------------

Detailed documentation explaining the entire work flow and SNMP simulator tool
set.

.. toctree::
   :maxdepth: 2

   /documentation/index

Source Code
-----------

Project source code is hosted in the `GitHub repository`_.
Everyone is welcome to fork and contribute back!

We maintain a detailed log of changes:

.. toctree::
   :maxdepth: 1

   /changelog
   /development

Download
--------

snmpsim-ng is not on PyPI yet, so install it straight from git:

.. code-block:: bash

   $ pipx install "git+https://github.com/observium/snmpsim.git@master"

``pip install snmpsim`` fetches a different release line instead, which does
not contain the changes made here.

License
-------

The SNMP Simulator software is distributed under 2-clause BSD license

.. toctree::
   :maxdepth: 1

   /license

Contact
-------

In case of questions or troubles using snmpsim-ng, please open up a
new `GitHub issue`_.
