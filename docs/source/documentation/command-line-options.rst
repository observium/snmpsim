
Command-line options
====================

.. toctree::
   :maxdepth: 2

The SNMP Simulator suite consists of a handful of command-line tools that
take command-line options.

Common options
--------------

**--debug**
++++++++++++++++

The *--debug* option makes the daemon emitting detailed log of SNMP
protocol related debugging. Debugging can be enabled for all or for just
some of the SNMP engine subsystems by adding their names to the
*--debug* option.

Recognized SNMP debugging options include:

* *io* -- report raw network traffic
* *msgproc* -- report SNMP message processing
* *secmod* -- report SNMP security module operations
* *mibbuild* -- report on MIB loading and processing
* *mibinstrum* -- report agent MIB operations
* *acl* -- report MIB access access control operations
* *proxy* -- report on SNMP version translation operations
* *app* -- application-specific debugging
* *all* -- enable full SNMP debugging

SNMP debugging is fully disabled by default.

**--debug-asn1**
++++++++++++++++

SNMP is backed by the
`ASN.1 <https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One>`_
for data representation and serialization purposes. The *--debug-asn1* option
makes the tools emitting detailed log of ASN.1 data de/serialization. Debugging
can be enabled for either encoder or decoder, or for everything ASN.1 related
by adding their names to the *--debug-asn1* option.

Recognized ASN.1 debugging options include:

* *encoder* -- debug data serialization
* *decoder* -- debug data deserialization
* *all* -- enable full ASN.1 debugging

ASN.1 debugging is fully disabled by default.

**--logging-method**
++++++++++++++++++++

Some of the SNMP Simulator tools can log using one of the following methods.
The default is *stderr*.

**--logging-method=syslog**
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The *syslog* logging method requires the following sub-options:

.. code-block:: bash

    --logging-method=syslog:facility[:address[:port:[tcp|udp]]]]

Where:

* *facility* -- one of the recognized syslog service
  `facilities <https://en.wikipedia.org/wiki/Syslog#Facility>`_
* *address* -- can be either an absolute path to a local socket or network
  address where syslog service is listening (optional)
* *port* -- if network address of the syslog service is used for *address*,
  *port* be a TCP or UDP port number (optional)
* *tcp* or *udp* -- TCP (stream) or UDP (datagram) protocol to use for
  syslog service communication (optional)

**--logging-method=file**
~~~~~~~~~~~~~~~~~~~~~~~~~

The *file* logging method redirects daemon logging into a local file. The
log file could be made automatically rotated based on time or size criteria.

The following sub-options are supported:

.. code-block:: bash

    --logging-method=file:path[:criterion]

Where:

* *path* -- path to a log file
* *criterion* -- should consist of a number followed by one of the specifiers:

  - *k* -- rotate when file size exceeds N kilobytes
  - *m* -- rotate when file size exceeds N megabytes
  - *g* -- rotate when file size exceeds N gigabytes
  - *S* -- rotate when file age exceeds N seconds
  - *M* -- rotate when file age exceeds N minutes
  - *H* -- rotate when file age exceeds N hours
  - *D* -- rotate when file age exceeds N days

**--logging-method=stdout/stderr**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When *stdout* or *stderr* logging methods are used, daemon log messages are
directed to either process standard output or standard error stream.

**--logging-method=null**
~~~~~~~~~~~~~~~~~~~~~~~~~

The *null* logging method completely inhibits all daemon logging.

**--log-level**
+++++++++++++++

The *--log-level* option limits the minimum severity of the log messages
to actually log.

Recognized log levels are:

* *debug* -- log at all levels
* *info* - log informational and error messages only
* *error* - log error messages only

SNMP command responders
-----------------------

SNMP Simulator runs as *snmpsim-command-responder*. It answers every SNMP
version, SNMPv1 and SNMPv2c without pysnmp's SNMPv3 engine (see
*--v1-v2c-path*).

*snmpsim-command-responder-lite* is the name of what used to be a
lightweight command responder of its own, for SNMPv1 and SNMPv2c. Since
2026.11.5 it is *snmpsim-command-responder* under that name, kept for the
systems that run it: it takes the options the lightweight version took and
no others, as it took them, and answers as *snmpsim-command-responder*
answers - with request counters in its activity reports, with *--daemonize*
waiting for the daemon to serve. What the lightweight version was it stays:
it answers SNMPv1 and SNMPv2c only, a SNMPv3 request goes unanswered, and
SIGHUP ends it rather than rescanning the data directories. *--v2c-arch*
and *--v3-only*, which it took and did nothing with, are taken and do
nothing.

Common command responders options
---------------------------------

The following options are respected by both SNMP command responder
applications.

**--daemonize**
+++++++++++++++

Unless *--daemonize* option is given, the daemon will remain an interactive
process. With the *--daemonize* option, the daemon will detach itself from
user terminal, close down standard I/O streams etc.

*snmpsim-command-responder* tells whoever started it whether the daemon came
up. The process that was started stays until the daemon has built its indices
and bound its endpoints, and exits with status 0 then. If the daemon ends
before that - a port in use, a PID file that cannot be written, a broken
recording - the process exits with status 1. Until it is ready the daemon
keeps the standard output and error it was started with, so the error is
seen where the command was given, unless *--logging-method* sends it
elsewhere; after that it holds neither, and a script that reads the output
of the command through a pipe is not kept waiting.

.. code-block:: bash

   $ snmpsim-command-responder --daemonize --pid-file=responder.pid \
       --data-dir=./data --agent-udpv4-endpoint=127.0.0.1:1161 || echo "not started"

The daemon changes its working directory to `/`. In
*snmpsim-command-responder* relative *--data-dir*,
*--cache-dir*, *--variation-modules-dir*, *--pid-file* and the reports
directory of *--reporting-method* are resolved before that, against the
directory the responder was started in.

*snmpsim-command-responder-lite* does the same since 2026.11.5; before,
its process exited with status 0 right after the fork, whatever became of
the daemon, and it did not resolve relative paths.

Not available on Windows.

**--process-user** & **--process-group**
++++++++++++++++++++++++++++++++++++++++

It is generally safer to run daemons under a non-privileged user. However,
it may be necessary to, at least, start SNMP Simulator parts as root
to let the process bind to privileged ports (161/udp for SNMP by default).

In this case it may make sense to drop process privileges upon
initialization by becoming *--process-user* belonging to *--process-group*.

**--pid-file**
++++++++++++++

Especially when running in *--daemonize* mode, it might be handy to keep
track of UNIX process ID allocated to the running daemon. Primarily, this
can be used for killing or restarting the process.

The *--pid-file* option can be used to specify a disk file where daemon
would store its PID.

Default is not to create PID file.

**--cache-dir**
+++++++++++++++

Specifies path to directory for temporary indices used for fast simulation
data lookup. The indices for all .snmprec files will be built on process
start unless they already exist and not outdated.

Default is `$TEMPDIR/snmpsim`.

The indices are built with *gdbm* where the Python interpreter has it, as
the *dbm.sqlite3* backend that Python 3.13 made its default writes every
entry to the disk on its own and takes about twice as long. On Debian and
Ubuntu gdbm comes in the *python3-gdbm* package. Without it the indices are
built with whatever backend Python picks, and nothing else changes.

**--reporting-method**
++++++++++++++++++++++

SNMP command responder applications can collect and periodically emit
various activity metrics.

The default is *null* that disables activity collection and reporting.

**--reporting-method=fulljson**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The *fulljson* activity reporting method collects and reports highly
detailed activity metrics. It may become expensive when simulating thousands
of transport endpoints or SNMP agents.

The *fulljson* reporting method supports the following sub-options:

.. code-block:: bash

    --reporting-method=fulljson:reports-dir[:dumping-period]

Where:

* *reports-dir* -- location on the filesystem where this reporting module
  should dump collected metrics. The dumps go into its *fulljson*
  subdirectory, one file per period, named after the UNIX time it was
  written at: *reports-dir/fulljson/1763200000.json*.
* *dumping-period* -- how often to dump, in seconds (optional). The default
  is 300.

Only a number at the very end of the option is taken for the period, so
the directory may hold colons of its own, as a Windows path does:

.. code-block:: bat

    > snmpsim-command-responder --agent-udpv4-endpoint=127.0.0.1:1611 ^
        --reporting-method=fulljson:C:\snmpsim\reports:60

A period with nothing to report writes no file. A dump is written under a
temporary name in the same directory and then renamed, so a reader never
sees half a file; when it cannot be written, the error is logged and the
counters are kept for the next period.

**--reporting-method=minimaljson**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The *minimaljson* activity reporting method collects and reports minimal
activity metrics. Essentially, it collapses individual metrics for transport
endpoints, agents, data files into one.

The *minimaljson* reporting method supports the following sub-options:

.. code-block:: bash

    --reporting-method=minimaljson:reports-dir[:dumping-period]

Where:

* *reports-dir* -- location on the filesystem where this reporting module
  should dump collected metrics, into its *minimaljson* subdirectory.
* *dumping-period* -- how often to dump, in seconds (optional). The default
  is 300.

**--variation-modules-dir**
+++++++++++++++++++++++++++

Specifies path to the directory where SNMP simulator should look for variation
modules. All modules found there will be imported and initialized for
further use from the .snmprec files.

Default search path is dependent on the platform. On Linux, macOS and
other UNIX systems it is:

* `$HOME/.snmpsim/variation`
* `/usr/local/share/snmpsim/variation`
* `<Python prefix>/snmpsim/variation`
* `<Python prefix>/share/snmpsim/variation`
* `<snmpsim package>/variation`

where *<Python prefix>* is `/usr` for the system Python and the root of the
virtual environment otherwise. On Windows it is:

* `%USERPROFILE%\\SNMP Simulator\\Variation`
* `%APPDATA%\\SNMP Simulator\\Variation`
* `%PROGRAMFILES%\\SNMP Simulator\\Variation`
* `<snmpsim package>\\variation`

The Windows home directory is `USERPROFILE`, or `HOMEDRIVE` and `HOMEPATH`
put together when that is not set. On any system a directory that hangs
off an environment variable which is not set - as happens to `HOME` or
`USERPROFILE` under a service account - is left out of the search path.

**--variation-module-options**
++++++++++++++++++++++++++++++

Some variation modules accept configuration options. These options could be
given in the form of `:`-separated positional arguments:

.. code-block:: bash

   --variation-module-options=<module[=alias][:args]

If the same variation module needs to be used with different set of
configuration parameters, one or more aliases could be created. Each instance
of the variation module could then be referenced from the .snmprec files
by alias.

Example:

.. code-block:: bash

    --variation-module-options=sql=mydb:dbtype:sqlite3,database:/tmp/snmpsim.db

**--force-index-rebuild**
+++++++++++++++++++++++++

Force rebuilding indices for all the .snmprec files regardless of their age and
status. With this option, the rebuild happens on every *snmpsim-command-responder*
process startup.

The default is off.

**--validate-data**
+++++++++++++++++++

Normally, SNMP simulator does not evaluate simulation values configured in the
.snmprec files (however it evaluates the OIDs when building look up indices).
With this option SNMP simulator will also evaluate simulation data on process
startup.

The default is off.

**--max-var-binds**
+++++++++++++++++++

Maximum number of SNMP objects to serve in response to the *GETBULK* command
per each requested variable-binding.

The default is *64*.

In a file given to *snmpsim-command-responder* by *--args-from-file*, the
option sets the limit of one SNMP engine, the same way *--max-message-size*
does there: of the engine whose *--v3-engine-id* comes before it, or else of
the last engine of the command line. The other engines keep the value of the
command line. Such a file may still call the option *--max-varbinds*, the
name it used to be read by.

**--max-message-size**
++++++++++++++++++++++

Maximum size, in octets, of an SNMP response message. A *GETBULK* response is
served with fewer repetitions than asked for, rather than growing past this
limit, the way a real agent behaves. Beyond it a response no longer fits into
a single UDP datagram, and once the reply is fragmented at the IP layer, a
manager which does not receive every fragment sees the request time out.

The default is *1472* - the Ethernet MTU less the IP and UDP headers. Raise it
towards *65507* to let responses fill a whole datagram.

**--max-open-data-files**
+++++++++++++++++++++++++

How many data files the responder keeps open at once. When one more has to be
opened, the one that has not been asked for the longest is closed; it is
reopened, index included, on the next request for it. Each open data file
takes two file descriptors, the recording and its index, so the number has to
stay below half of what the system lets the process open (``ulimit -n``).

The default is half of the soft limit on open files (``RLIMIT_NOFILE``) less
a reserve of 64 descriptors, *256* at most: 256 with a limit of 1024, 96 with
a limit of 256, and 256 where there is no such limit, as on Windows. Raise the
limit and this option together when more recordings than that are polled in
turn.

**--transport-id-offset**
+++++++++++++++++++++++++

With SNMP, transport endpoints (network addresses and ports) are identified by
OIDs. Each kind of network transport (e.g. IPv4-over-UDP) has its own OID
prefix, while the instances of it are identified by a longer OID.

When *snmpsim-command-responder* is asked to initialize a transport endpoint,
it will take the prefix OID and append a single sub-OID number starting from
this offset.

The default is one.

**--data-dir**
++++++++++++++

Specifies path to the directory where SNMP simulator should look for simulation
data in form of *.snmprec*, *.snmprec.bz2*, *.snmpwalk* or *.sapwalk* files.
All files found beneath *--data-dir* will be considered as sources of SNMP
simulation data and their paths will be used for SNMP configuration purposes.

*snmpsim-command-responder* reads the directories at startup and again each
time it receives SIGHUP, see :ref:`rescanning-data-directories`.

The default search path is the one of *--variation-modules-dir* with `data`
(`Data` on Windows) in place of `variation`. On Linux, macOS and other UNIX
systems it is:

* `$HOME/.snmpsim/data`
* `/usr/local/share/snmpsim/data`
* `<Python prefix>/snmpsim/data`
* `<Python prefix>/share/snmpsim/data`
* `<snmpsim package>/data`

**--agent-udpv4-endpoint**
++++++++++++++++++++++++++

Bind SNMP agent to the given UDP-over-IPv4 transport endpoint in the form of
*IP:port*.

Each occurrence of this option creates a new transport endpoint. All SNMP
engines created afterwards (by *--v3-engine-id* option) up to the next
*--agent-* option will reside behind this transport endpoint.

.. code-block:: bash

   $ snmpsim-command-responder --agent-udpv4-endpoint=127.0.0.1:161

.. note::

   Binding ports less than 1024 on UNIX requires superuser privileges.

**--agent-udpv6-endpoint**
++++++++++++++++++++++++++

Bind SNMP agent to the given UDP-over-IPv6 transport endpoint in the form of
*[IP]:port*.

Each occurrence of this option creates a new transport endpoint. All SNMP
engines created afterwards (by *--v3-engine-id* option) up to the next
*--agent-* option will reside behind this transport endpoint.

.. code-block:: bash

   $ snmpsim-command-responder --agent-udpv6-endpoint=[::1]:161

.. note::

   Binding ports less than 1024 on UNIX requires superuser privileges.

.. _args-from-file:

**--args-from-file**
++++++++++++++++++++

Command-line options could be stored in a file and passed through this
option. File could be easier to manage, and does not impose any limit on the
length of the command line.

The file holds *--option=value* items separated by spaces or line breaks:

.. code-block:: bash

   $ cat responder.args
   --data-dir=/usr/local/share/snmpsim/data
   --agent-udpv4-endpoint=127.0.0.1:1024
   --agent-udpv4-endpoint=127.0.0.1:1025
   $ snmpsim-command-responder-lite --args-from-file=responder.args

*snmpsim-command-responder-lite* reads any of its options from the file,
as if they stood ahead of those of the command line. An option that takes
a single value (*--log-level*, *--cache-dir* and the like) is overridden
by the command line. An option that can be given more than once
(*--data-dir*, *--agent-udpv4-endpoint*, *--agent-udpv6-endpoint*,
*--variation-modules-dir*, *--variation-module-options*, *--debug*,
*--debug-asn1*) is not: the values of the file and of the command line
add up. *--agent-udpv4-endpoint* and *--agent-udpv6-endpoint* exclude
each other, so one of them in the file and the other on the command line
is an error. The on/off switches (*--daemonize*, *--quiet*, *--v2c-arch*,
*--v3-only*, *--v1-only*, *--v2c-only*, *--force-index-rebuild*,
*--validate-data*) have no "off"
form, so one that the file sets cannot be switched off from the command
line.
*snmpsim-command-responder* reads from the file the options that configure
its SNMP engines (*--v3-engine-id*, *--data-dir*, *--agent-udpv4-endpoint*
and the like) and adds them after those of the command line.

Full version command responder options
--------------------------------------

Full version of SNMP command responder is based on SNMPv3 architecture,
it is capable of handling all SNMP versions i.e. 1, 2c qnd 3.

*snmpsim-command-responder* understands all options of
*snmpsim-command-responder-lite*, plus the following ones.

**--v3-only**
+++++++++++++

SNMP simulator serves simulation data over both SNMP v1/v2c and SNMPv3
protocols. With the *--v3-only* flag in effect, SNMPv1/v2c agents will
not be configured what saves a bit of memory and startup time.

Default is to configure SNMPv1/v2c and SNMPv3.

**--v1-only** & **--v2c-only**
++++++++++++++++++++++++++++++

Make the responder speak a single SNMP version, the way an agent configured
for that version alone does. With *--v1-only* only SNMPv1 requests are
answered, with *--v2c-only* only SNMPv2c ones. A request of any other version
gets no response at all - no error and no SNMPv3 report - so the manager
times out.

.. code-block:: bash

   snmpsim-command-responder --v2c-only --data-dir=./data \
       --agent-udpv4-endpoint=127.0.0.1:1161

*--v1-only*, *--v2c-only* and *--v3-only* exclude each other: giving two of
them is a command-line error. The versions each SNMP engine serves are logged
at startup.

Default is to answer SNMPv1, SNMPv2c and SNMPv3.


**--v1-v2c-path**
+++++++++++++++++

How SNMPv1 and SNMPv2c requests are answered. With *fast*, the default, the
simulator answers them itself; with *engine* they go through pysnmp's SNMPv3
engine, as every release before 2026.11.4 did. SNMPv3 always goes through
the engine.

Both answer alike: the same values, error-status and error-index, the same
SNMPv1 translation, the same *GETBULK* cut, and the same call context for
variation modules and activity reports. *fast* skips the message processing,
security and access control models of the engine, encodes and decodes
SNMPv1 and SNMPv2c reads itself rather than in pyasn1, and serves a bulk walk about
2.2 times as fast, a GETNEXT walk about 4.4 times (CPython 3.14). It also chooses the
recording as :ref:`addressing-simulation-data` describes, by community,
transport and source address; *engine* serves only a recording named exactly
like the community. *engine* is there for one release, in case something
answers differently after all.

With *--v3-only* there is nothing to answer SNMPv1/v2c with, and the option
makes no difference.

**--index-workers**
+++++++++++++++++++

How many processes build data file indices at startup. Before the SNMP
engines are configured, the responder looks through all its data directories
and builds the indices that are missing or out of date in this many processes
at once. A recording that fails to index is reported and the other indices
are still built, but the responder does not start without it: once they are
done it stops at that recording with exit status 1, as it does with
*--index-workers=1*. With *--index-workers=1* indices are built one by one,
each when its data file is set up.

The default is the number of CPUs the process may use, *8* at most.

**--v3-engine-id**
++++++++++++++++++

SNMP engine identifier that creates a new, independent instance of SNMP
engine. All the following *--v3-* options up to another *--v3-engine-id*
option apply to the SNMP engine being configured.

.. code-block:: bash

   snmpsim-command-responder --v3-engine-id=0102030405070809 ...

.. note::

   The *-v3-engine-id* option expects a hex string or `auto` for automatic
   value.

The default is an autogenerated value.

**--v3-context-engine-id**
++++++++++++++++++++++++++

SNMP entity can have access to many instances of the same collection of
MIB objects. Each such collection is called *context*. A context is identified
by the Context Engine ID and a Context Name that identifies the specific
context.

In other words, to identify an individual item of SNMP management information,
four elements are required:

1. a ContextEngineID
2. a ContextName
3. an object type, and
4. its instance identification

The default for *--v3-context-engine-id* option is the same value
as *--v3-engine-id*.

**--v3-user**
+++++++++++++

SNMP USM user name to use for SNMPv3 authentication and authorization purposes.

**--v3-auth-key**
+++++++++++++++++

SNMP USM message authentication key.

.. note::

    Must be 8 or more characters.

.. _usm-key-types:

**--v3-auth-key-type**
++++++++++++++++++++++

What *--v3-auth-key* holds:

* *passphrase* - the passphrase of the user, 8 or more characters. The
  responder hashes it into the key and localizes the key to its SNMP engine
  ID.
* *master* - the master key, that is the passphrase already hashed with the
  authentication protocol, but not yet localized.
* *localized* - the master key hashed with the SNMP engine ID, as it stands
  in the configuration of a device. A localized key only fits the
  *--v3-engine-id* it was made for, so give that option as well.

Master and localized keys are given in hex, with or without the leading
*0x*, and must be of the size the protocol takes (16 octets for MD5, 20 for
SHA and so on). A key that is not hexadecimal or of another size stops the
responder with a message naming the user.

.. code-block:: bash

   snmpsim-command-responder --v3-engine-id=80004fb805736e6d7073696d01 \
       --v3-user=wallace --v3-auth-proto=SHA --v3-auth-key-type=localized \
       --v3-auth-key=0x6fa2b85a0b067e30a4d2ee88afb33bb3f05da1e4 \
       --data-dir=./data --agent-udpv4-endpoint=127.0.0.1:1161

The default is *passphrase*.

**--v3-auth-proto**
+++++++++++++++++++

SNMPv3 message authentication protocol to use. Valid values are:

+--------+----------------+-------------+
| *ID*   |  *Algorithm*   | *Reference* |
+--------+----------------+-------------+
| NONE   | -              | RFC3414     |
+--------+----------------+-------------+
| MD5    | HMAC MD5       | RFC3414     |
+--------+----------------+-------------+
| SHA    | HMAC SHA-1 128 | RFC3414     |
+--------+----------------+-------------+
| SHA224 | HMAC SHA-2 224 | RFC7860     |
+--------+----------------+-------------+
| SHA256 | HMAC SHA-2 256 | RFC7860     |
+--------+----------------+-------------+
| SHA384 | HMAC SHA-2 384 | RFC7860     |
+--------+----------------+-------------+
| SHA512 | HMAC SHA-2 512 | RFC7860     |
+--------+----------------+-------------+

**--v3-priv-key**
+++++++++++++++++

SNMP USM message encryption key.

.. note::

    Must be 8 or more characters.

**--v3-priv-key-type**
++++++++++++++++++++++

What *--v3-priv-key* holds: *passphrase* (the default), *master* or
*localized*, with the same meaning and the same hex notation as
:ref:`--v3-auth-key-type <usm-key-types>`. A master privacy key is made by
the hash of the user's authentication protocol and has its size; a localized
one must be at least as long as the key the privacy protocol takes (16 octets
for AES, for instance).

**--v3-priv-proto**
+++++++++++++++++++

SNMPv3 message encryption protocol to use. Valid values are:

+------------+------------------------+----------------------+
| *ID*       | *Algorithm*            | *Reference*          |
+------------+------------------------+----------------------+
| NONE       | -                      | RFC3414              |
+------------+------------------------+----------------------+
| DES        | DES                    | RFC3414              |
+------------+------------------------+----------------------+
| AES        | AES CFB 128            | RFC3826              |
+------------+------------------------+----------------------+
| AES192     | AES CFB 192            | RFC Draft            |
+------------+------------------------+----------------------+
| AES256     | AES CFB 256            | RFC Draft            |
+------------+------------------------+----------------------+
| AES192BLMT | AES CFB 192 Blumenthal | RFC Draft            |
+------------+------------------------+----------------------+
| AES256BLMT | AES CFB 256 Blumenthal | RFC Draft            |
+------------+------------------------+----------------------+
| 3DES       | Triple DES EDE         | RFC Draft            |
+------------+------------------------+----------------------+

.. _recorder-options:

SNMP agent recorder options
---------------------------

The *snmpsim-record-commands* tool walks a live SNMP agent and writes what
it answers into a data file, as shown in :ref:`building-simulation-data`.
Besides the common options it takes the following ones.

**--agent-udpv4-endpoint** & **--agent-udpv6-endpoint**
+++++++++++++++++++++++++++++++++++++++++++++++++++++++

The agent to record, as *address:port* or *[address]:port*. One of the two
is required. The port can be left out, it is 161 then.

**--protocol-version**
++++++++++++++++++++++

SNMP version to talk to the agent: *1*, *2c* or *3*.

When the option is left out, the version follows from the credentials
given: *3* if there is a *--v3-user*, *2c* otherwise. So naming a USM user
is enough to record over SNMPv3:

.. code-block:: bash

    $ snmpsim-record-commands --agent-udpv4-endpoint=192.0.2.1 \
        --v3-user=recorder --v3-auth-key=auctoritas --v3-auth-proto=SHA256 \
        --v3-priv-key=privatus --v3-priv-proto=AES \
        --output-file=data/switch.snmprec

A *--v3-user* together with an explicit *--protocol-version=1* or *2c* is
refused, and so is *--protocol-version=3* with no *--v3-user*. The command
line is checked before the output file is opened: a recording that is
there already is not emptied by a command that was not going to run.

**--community**
+++++++++++++++

SNMP community name to ask with, for SNMPv1 and v2c. The default is
*public*.

**--v3-user**, **--v3-auth-key**, **--v3-auth-proto**, **--v3-priv-key**, **--v3-priv-proto**
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

The USM user to ask as, and its keys and protocols. They take the same
values as the :ref:`options of the command responder <auth-algos>` with
the same names.

The security level follows from the keys: no key at all asks with
*noAuthNoPriv*, an authentication key alone with *authNoPriv*, both keys
with *authPriv*. A privacy key needs an authentication key. A key given
without its protocol is used with *MD5* or *DES* respectively; a protocol
given without its key is an error.

**--v3-context-engine-id** & **--v3-context-name**
++++++++++++++++++++++++++++++++++++++++++++++++++

The SNMPv3 context to record. The engine ID is written in hex with *0x* in
front (*0x80004fb805636c6f75644dab22cc*) and defaults to the engine ID of
the agent; the name is an empty one by default.

**--use-getbulk** & **--getbulk-repetitions**
+++++++++++++++++++++++++++++++++++++++++++++

Walk the agent with *GETBULK* instead of *GETNEXT*, asking for this many
repetitions at once (25 by default). SNMPv1 has no *GETBULK*, so with
*--protocol-version=1* the recorder says so and falls back to *GETNEXT*.

**--timeout** & **--retries**
+++++++++++++++++++++++++++++

For how many seconds to wait for a response, and how many times to repeat
a request which got none. Both default to 3.

**--start-object** & **--stop-object**
++++++++++++++++++++++++++++++++++++++

Where the recording begins and where it ends, as an OID (*1.3.6.1.2.1.2*)
or as a MIB object (*IF-MIB::ifTable*). By default the walk starts at
*1.3.6* and goes on to the end of the MIB. MIB objects are resolved with
the MIB files found at *--mib-source*.

**--output-file** & **--destination-record-type**
+++++++++++++++++++++++++++++++++++++++++++++++++

The file to write and the format of its records, *snmprec* by default.
The extension of the format is appended to the file name unless it is
there already. Without *--output-file* the records go to the standard
output.

**--continue-on-errors**
++++++++++++++++++++++++

How many times in a row the recorder may step over an OID the agent
failed on and carry on with the walk. The default is 0: the first error
ends the recording.

**--variation-module**, **--variation-module-options** & **--variation-modules-dir**
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Pass the recorded values through a variation module, as described in
:ref:`recording-with-variation-modules`.

The run ends with a summary line. It counts the OIDs recorded, in all the
passes of a variation module that walks the agent more than once, against
the whole time taken:

.. code-block:: bash

    OIDs dumped: 362, elapsed: 71.18 sec, rate: 5.09 OIDs/sec, errors: 0

.. _data-tools-options:

Data file tools options
-----------------------

**snmpsim-manage-records**
++++++++++++++++++++++++++

The :ref:`snmpsim-manage-records <snmpsim-manage-records>` tool converts,
sorts and cuts data files. Its options are:

* *--input-file* -- a data file to read. Can be given more than once;
  */dev/stdin* reads a pipe.
* *--source-record-type* -- the format of the input: *snmprec* (the
  default), *snmprec.bz2*, *snmpwalk*, *sapwalk*, *dump* or *MVC*.
* *--output-file* -- the file to write; the standard output by default.
* *--destination-record-type* -- the format to write, *snmprec* by default.
* *--start-object* and *--stop-object* -- keep the records between these
  two OIDs (or MIB objects) only.
* *--sort-records* -- order the records by OID. This is the one option
  that makes the tool hold the whole input in memory; without it records
  are written as they are read, and a file larger than the memory of the
  machine can be converted.
* *--deduplicate-records* -- drop a record whose OID was seen already.
* *--ignore-broken-records* -- skip the records which cannot be converted,
  reporting each one, instead of stopping at the first.
* *--escaped-strings* -- write strings which are not plain text as Python
  string literals (tag modifier *e*) rather than in hex (tag modifier *x*).
* *--quiet* -- do not print the informational messages. Errors are
  printed all the same.

The exit status is 0 when the conversion went through and 1 when it was
stopped by a broken record.

**snmpsim-lint-records**
++++++++++++++++++++++++

The :ref:`snmpsim-lint-records <snmpsim-lint-records>` tool takes data
files and directories as its arguments (the current directory by default)
and checks every record in them. Its options are:

* *--quiet* -- report errors, but not warnings.
* *--strict* -- count warnings as errors.

The exit status is 1 when errors were found, or when there was no data
file to check, and 0 otherwise.
