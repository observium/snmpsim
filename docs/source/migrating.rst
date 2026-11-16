.. include:: /includes/_links.rst

.. _migrating:

Migrating from snmpsim
======================

snmpsim-ng is installed under a name of its own and numbered differently
from the snmpsim it continues. The simulator itself is used as before: the
Python module is still ``snmpsim``, the commands are still ``snmpsim-*``,
and the recordings need no conversion. This page is for those who have an
installation named ``snmpsim`` - of the other release line, or of this
project before it was renamed - and are moving to snmpsim-ng.

The name
--------

The distribution is called ``snmpsim-ng``. The name ``snmpsim`` on PyPI
belongs to another release line, which does not have the changes described
below, so:

* ``pip install snmpsim`` does not install snmpsim-ng and never will;
* snmpsim-ng is not on PyPI yet and is installed from its
  `GitHub repository`_, see :doc:`/quick-start`;
* the ``snmpsim-data`` package on PyPI requires ``snmpsim`` 1.x, so
  installing it puts the other release line over this one.

To tell which of the two an environment has, ask for the package by both
names. Only one of them should answer:

.. code-block:: bash

   $ pip show snmpsim-ng
   $ pip show snmpsim

Removing the old installation
-----------------------------

Until 2026.11.0 this project was installed as ``snmpsim`` too. Installing
snmpsim-ng does not replace a package of that name: to the installer they
are two different packages, though both bring the same ``snmpsim`` module
and the same commands. ``pip`` would leave the two writing over each
other's files, and ``pipx`` would not touch the ``snmpsim-*`` commands
already on the ``PATH``, which would go on running the old environment.

So the package named ``snmpsim`` has to be removed first, with the tool it
was installed with:

.. code-block:: bash

   $ pipx uninstall snmpsim

.. code-block:: bash

   $ pip uninstall snmpsim

.. code-block:: bash

   $ uv tool uninstall snmpsim

and snmpsim-ng installed after that:

.. parsed-literal::

   $ pipx install "git+https://github.com/observium/snmpsim.git@\ |release|"

``pipx uninstall`` drops what was added to the environment with
``pipx inject`` as well. ``pysmi`` and ``cryptography``, which used to be
injected by hand because the simulator would not start without them, are
dependencies of snmpsim-ng and arrive with it; anything else - a database
driver for the ``sql`` variation module, ``redis``, ``pylibpcap`` - has to
be injected into the new environment again.

A responder that is running keeps the code it was started with, so restart
it once the new package is in. The indices in ``--cache-dir`` may have been
written by another dbm backend than the one snmpsim-ng uses (see
:ref:`below <migrating-behaviour>`); empty that directory before the first
start and they are built anew.

Version numbers
---------------

Releases are numbered by the calendar, ``YYYY.M.N``: the year, the month
and the number of the release within that month, counted from zero.
``2026.11.0`` is the first release under the new name, ``2026.11.1`` the
one after it.

The project did not go on with the ``1.2.x`` series it was forked from,
because its next release would have been ``1.2.3`` - the number the other
release line is most likely to give its own next release, and two different
packages under one name and one version cannot be told apart by anything.
A calendar version sorts above any ``1.x`` or ``2.x``, so a requirement
like ``snmpsim-ng>=2026.11.0`` means what it says.

An installation from git or from a wheel has no package index to compare
itself against, so nothing is upgraded by itself. To move to a newer
release, install it over the one that is there:

.. parsed-literal::

   $ pipx install --force "git+https://github.com/observium/snmpsim.git@\ |release|"

.. parsed-literal::

   $ pip install --upgrade --force-reinstall "git+https://github.com/observium/snmpsim.git@\ |release|"

What each release changed is in the :doc:`/changelog`.

.. _migrating-behaviour:

What behaves differently
------------------------

Most of what snmpsim-ng changed is something that did not work and now
does. Where the simulator now answers differently from snmpsim 1.2.2 with
the same recordings and the same command line, it is listed here, each
item with the place it is documented at.

The responders
++++++++++++++

* A *GETBULK* response is cut to fit into 1472 octets, one unfragmented
  datagram, where it used to grow as large as the repetitions asked for
  made it. A manager gets fewer repetitions per response and asks again.
  The limit is :ref:`--max-message-size <response-size>`;
  ``--max-var-binds``, which had no effect, limits the response again.
* A record whose value cannot be encoded is answered with
  *noSuchInstance* on GET and stepped over on GETNEXT and GETBULK. It used
  to leave the request unanswered and the walk cut off at that OID. A
  single-arc OID value such as ``6|0`` is served as ``0.0``, and an integer
  outside the range of its type is served with the octets the device sent.
  See :ref:`snmpsim-lint-records`, the new tool that finds such records.
* A recording filed under the source address of the manager is chosen
  again, see :ref:`addressing-simulation-data`. With snmpsim on pysnmp 7
  every manager was served the plain recording.
* ``--daemonize``, ``--reporting-method`` and
  ``snmpsim-command-responder-lite`` work, which they did not on pysnmp 7.
  ``--reporting-method`` takes a directory with a drive letter, and the
  lite responder takes ``--args-from-file``. See
  :doc:`/documentation/command-line-options`.
* ``snmpsim-command-responder --daemonize`` returns when the daemon serves,
  not right after the fork, and exits with status 1 if the daemon did not
  come up; it used to exit with 0 whatever happened next. A script that
  started the daemon and went on at once now waits for the indices to be
  built. Relative paths are taken from the directory the responder was
  started in, where the daemon used to look for them under ``/``. See
  *--daemonize* in :doc:`/documentation/command-line-options`.
* SIGHUP makes ``snmpsim-command-responder`` read its data directories
  again. It used to end a daemon and kill a responder in the foreground:
  whatever stops the responder with ``kill -HUP`` has to send SIGTERM. See
  :ref:`rescanning-data-directories`.
* The error-index of an error response points at the variable that failed.
  It used to point at the first variable of the request unless the failed
  one was the last.
* Data files and variation modules are also looked for under
  ``/usr/local/share/snmpsim`` on Linux, and under the real profile
  directory of the user on Windows. A recording left in one of these
  directories is now served.
* Indices are built with gdbm where Python has it, so the files in
  ``--cache-dir`` may be of another kind than those an earlier
  installation left there.

The recorders
+++++++++++++

* ``snmpsim-record-commands`` records, where on pysnmp 7 it hung without
  writing anything, and it records over SNMPv3: ``--v3-user`` makes it ask
  over version 3, where it used to go on asking over v2c with the community
  *public*. ``--v3-user`` together with ``--protocol-version=1`` or ``2c``
  is an error now. See :ref:`recorder-options`.
* Its progress and summary lines count the OIDs recorded:
  ``OIDs dumped: 300`` instead of ``0/300``. A script that reads these
  lines has to follow.
* Recording through a variation module (``numeric``, ``multiplex``,
  ``sql``, ``redis``) produces what the module was asked for, where it used
  to fail on the first OID or silently write plain values. See
  :ref:`recording-with-variation-modules`.
* ``snmpsim-record-traffic`` reads capture files without any capture
  library installed, and only the classic pcap format. See
  :ref:`snmpsim-record-traffic`.

Converting data files
+++++++++++++++++++++

* ``snmpsim-manage-records`` converts more of a walk and converts it
  differently: values wrapped onto several lines become one record,
  strings keep their non-ASCII octets, the escaping of quotes is taken off,
  *Opaque* floats and doubles are written as net-snmp sends them. A
  *.snmprec* made from the same walk by snmpsim may therefore differ, and
  is worth converting again. See :ref:`snmpwalk-dump`.
* A line that cannot be converted is a broken record, skipped under
  ``--ignore-broken-records`` and otherwise ending the run with exit
  status 1 and a message, also under ``--quiet``; such lines used to end
  it with a traceback. The records ahead of the broken one are in the
  output file by then, which used to be left empty. See
  :ref:`snmpsim-manage-records`.

Variation modules
+++++++++++++++++

* :ref:`subprocess <variate-subprocess>` drops the line ending of the
  program's output. ``4:subprocess|echo hello`` answers five octets, not
  six. A record written with ``echo -n`` answers what it did.
* :ref:`writecache <variate-writecache>` reads ``value=`` by the modifier
  of the tag. ``4x:writecache|value=414243`` serves ``ABC``; it used to
  serve the six characters ``414243``.
* :ref:`error <variate-error>` answers SNMPv1 managers with *noSuchName*,
  *badValue* and *readOnly* where these are configured, not with *genErr*.
  ``status=noSuchObject``, ``noSuchInstance`` and ``endOfMib`` are no
  longer *genErr* either: on GET, GETNEXT and GETBULK an SNMPv2c or SNMPv3
  manager gets error-status 0 with the exception as the value of that
  variable, next to the values of the others, and an SNMPv1 manager gets
  *noSuchName*. On SET they are still *genErr*.
* :ref:`numeric <variate-numeric>` cuts ``deviation`` to a whole number,
  and its documentation states the formula the module computes. On Python
  3.12 and later a record with a ``deviation`` used to fail every request.
  ``wrap=0``, ``cumulative=0`` and ``atime=0`` switch the feature off; any
  value, ``0`` included, used to switch it on. A recording made with
  ``--variation-module=numeric`` and no options has its integers, counters,
  gauges and time ticks written as ``numeric`` records with
  ``initial=<value>`` (time ticks with ``rate=100`` and integers with
  ``rate=0`` added), where it used to come out as plain values. See
  :ref:`record-numeric`.
* :ref:`multiplex <variate-multiplex>` names the snapshots it records
  ``00000.snmprec``, not ``00000..snmprec``, and serves them in the order
  of their numbers. Snapshots under the old names are still served.
* :ref:`notification <variate-notification>` sends from an SNMP engine of
  its own, so a notification sent as the USM user the agent answers under
  no longer replaces that user's keys. ``authproto`` and ``privproto`` take
  all the names the responder does.
* :ref:`sql <variate-sql>` connects again when the database has dropped
  the connection, and rolls a failed request back.
