.. current-version: 2026.11.5 (managed by bump2version)

Revision 2026.11.5, unreleased
------------------------------

Changes carried by snmpsim-ng.

- Answered SNMPv1 GET and GETNEXT on the fast path without pyasn1 as well,
  as SNMPv2c reads are: ``ber.decode_read_request()`` takes their plain
  shape, and the response is translated as pysnmp's ``rfc2576.v2_to_v1()``
  translates it (RFC 3584) - noSuchName for the first variable without a
  value, a Counter64 refused to a GET and read past on a GETNEXT, the
  SNMPv2 error-status mapped, the request's var-binds sent back with an
  error. Tests hold it to the engine path on GETs and GETNEXTs of several
  variables with Counter64s and missing ones in every order, on the error
  module, on odd communities and on hand-made messages. An SNMPv1 GETNEXT
  walk is served about four times as fast on CPython, as fast as SNMPv2c.
- Answered an SNMPv1 request whose request-id does not fit an Integer32 on
  the fast path, as the engine path answers it, rather than dropping it.
  pysnmp's message processing puts a request-id of its own in place of an
  SNMPv1 one, which may be any INTEGER, before the PDU is turned into an
  SNMPv2 one, and the original back into the response; the fast path,
  new in 2026.11.4, turned the PDU with the request-id it came with.
- Decoded the SNMPv2c GET, GETNEXT and GETBULK requests of the fast path
  without pyasn1, which had become most of what a request cost once the
  responses were encoded without it. ``ber.decode_read_request()`` takes
  the plain shape of such a request only - one-octet tags, definite
  lengths in their shortest form, NULL values, nothing left over - and
  leaves everything else, SET among it, to pyasn1 as before. It
  keeps the limits pyasn1 added for crafted input since 0.6.2, the 20
  continuation octets of an OID arc among them, and works in linear time.
  Tests hold it to pyasn1 on the vectors of pyasn1's own decoder tests,
  on the inputs its security fixes are about, on fields out of range, and
  on random requests and thousands of mutations of them: whatever is
  decoded here, pyasn1 decodes alike, and what pyasn1 refuses is left to
  it. A GETNEXT walk is served about twice as fast again on CPython.
- Encoded the SNMPv2c responses of the fast path, and the var-bind sizes
  every responder cuts GETBULK by, without building them in pyasn1:
  ``snmpsim.ber`` puts the octets together straight from the values, the
  same octets pyasn1 makes, and hands pyasn1 any kind of value it does not
  know. A GETBULK var-bind is encoded once, where it used to be encoded to
  be measured and again for the message. A bulk walk and a GETNEXT walk are
  served about 1.8 times as fast as with 2026.11.4 on CPython. Tests hold
  the encoding to pyasn1's on edge values, random integers and OIDs, whole
  responses, and the vectors of pyasn1's own encoder tests.
- Required pyasn1 0.6.5 or later, and pysnmp 7.1.31 or later. pyasn1 was
  not named at all, though the simulator imports it, and pysnmp 7.1.26 let
  pyasn1 0.6.3 in, which decodes a crafted OBJECT IDENTIFIER in quadratic
  time (CVE-2026-59885) and has the other decoder faults fixed in 0.6.4
  and 0.6.5. ``uv.lock`` has pyasn1 0.6.5, and pysnmp 7.1.31 for Python
  3.10, the last release that runs on it, 7.1.33 elsewhere.

Revision 2026.11.4, released on Nov 17, 2026
--------------------------------------------

Changes carried by snmpsim-ng.

- Stepped over the noSuchObject, noSuchInstance and endOfMibView a
  recording holds (tags 128, 129 and 130) on GETNEXT and GETBULK. They were
  sent as the value of the variable, which RFC 3416 does not allow in an
  answer to GETNEXT or GETBULK, and a manager's walk stopped there: net-snmp
  ended at the first one with the rest of the table unread. They are still
  the answer to a GET of the variable, and an ``error`` variation module
  record asked for one still has it sent. A test serves every type a
  ``.snmprec`` holds, on both ways of answering SNMPv1/v2c.
- Answered SNMPv1 and SNMPv2c in ``snmpsim-command-responder`` without
  pysnmp's SNMPv3 engine. Every message went through its message
  processing, security and access control models, which is most of what an
  answer cost; the transport dispatcher now reads the version off each
  message and hands SNMPv1/v2c ones to the simulator's own fast path, and
  SNMPv3 to the engine as before. The answers are the same, octet for octet,
  which a test checks by sending the same requests to both paths: values,
  error-status and error-index, pysnmp's own SNMPv1 translation (RFC 3584),
  the GETBULK cut, and the call context variation modules get, down to the
  types of ``contextName`` and ``securityName``, so that activity reports
  count the same dimensions. One thing changed on purpose: a recording is
  chosen as the documentation always said, by community, transport and the
  manager's address, the most specific one first, where the engine served
  only a recording named exactly like the community. ``--v1-v2c-path=engine``
  sends SNMPv1/v2c through the engine as before, for one release.
- Added ``scripts/bench_responder.py``, which starts a command responder,
  full or lite, with any interpreter on a recording of one's choice and
  times its start, a bulk walk and a GETNEXT walk with net-snmp's tools,
  optionally under cProfile with the busy time split by package. The
  README's "Performance" numbers come from it.
- Added PyPy 3.11 to the Tests workflow, which runs on Linux. The whole
  suite passed on PyPy 3.11 on macOS, with ``cryptography`` and gdbm, before
  it went in. The package declares CPython and PyPy, and Python 3.10 to
  3.15, in its classifiers.
- Documented running on PyPy, which serves two to two and a half times as
  many requests per second as CPython, and added a "Performance" section to
  the README: index build, bulk walk and GETNEXT walk of a 188 MB recording
  on CPython with gdbm and with ``dbm.sqlite3``, on the lite responder and on
  PyPy.
- Took macOS out of the CI workflow for now, Linux and Windows keep all six
  Python versions. GitHub's macOS runners were not to be had: jobs waited
  for one and were cancelled without having run, which failed the workflow
  on code that was fine, first with six versions on macOS, then with the
  oldest and the newest only. The matrix keeps macOS commented out, to be
  put back once runners are available again.

Revision 2026.11.3, released on Nov 16, 2026
--------------------------------------------

Changes carried by snmpsim-ng.

- Summed up the changes in the README's "What snmpsim-ng adds" as a table
  of how many each release made in each area, with the release notes and
  the changelog linked, instead of a list of 66 entries that had grown to
  half the README. The details are kept here.
- Stopped building the documentation site for a change to ``CHANGES.rst``
  alone, which nearly every commit makes. The changelog page is brought up
  to date by the next change to ``docs/``, ``LICENSE.txt`` or
  ``pyproject.toml``, or by running the workflow by hand after a release.
- Fixed ``--max-var-binds`` being passed over in a file of
  ``--args-from-file``. ``snmpsim-command-responder`` reads the engine
  options of such a file itself, and looked for this one as
  ``--max-varbinds``, a name no command line takes: the documented name in
  the file was ignored without a word, and the engine answered GETBULK with
  the limit of the command line, 64 variable bindings per requested one if
  none was given there. Both names are read
  now, and set the limit of the engine they are given for, as
  ``--max-message-size`` does there.
- Made ``snmpsim-record-mibs --string-pool-file`` report a file it cannot
  use. A file that was missing ended the tool with a traceback, and one with
  no words in it with an ``IndexError`` at the first string to make up. Both
  are an error message and exit status 1 now. So is a file that is not
  UTF-8: the file is read as UTF-8 whatever the locale, since the words go
  into the values as UTF-8 anyway. The help of ``--row-hint`` says what the
  switch does - with ``--manual-values``, it leaves out the lines naming a
  scalar and its type before the question for its value - instead of "Hint
  for MIBs Type".
- Documented ``--string-pool-file`` and ``--row-hint`` of
  ``snmpsim-record-mibs`` and ``--promiscuous-mode`` of
  ``snmpsim-record-traffic``, which the reference pages did not mention.
- Read the strings of a walk taken with ``snmpwalk -OQ``. Without types, a
  line like ``.1.3.6.1.2.1.1.5.0 = "switch"`` fell to the TimeTicks guess
  made for untagged values and was a broken record, and a quoted value with
  a line break inside cost two records. A value in quotes is a STRING now,
  read over several lines the way a quoted ``STRING:`` is. An untagged
  number is still taken for TimeTicks, since nothing tells what it is.
- Stopped the responders logging an error for the ``sql`` and ``redis``
  variation modules when nobody configured them. Every module found is
  initialized at start, and these two cannot work without options naming
  their database, so every start of a responder without a database printed
  ``ERROR ... load FAILED: database type not specified`` and the same for
  Redis, burying the errors that matter. A module given no options at all
  is reported in an ordinary line as not configured, and the records that
  refer to it fail as before; options that do not name a database are still
  an error.

Revision 2026.11.2, released on Nov 16, 2026
--------------------------------------------

Changes carried by snmpsim-ng.

- Added Python 3.15 to both test workflows, which now run the suite on
  Python 3.10 to 3.15.
- Published the documentation at https://observium.github.io/snmpsim/. A
  workflow builds it with ``sphinx-build -W`` on every change to
  ``docs/``, ``CHANGES.rst``, ``LICENSE.txt`` or ``pyproject.toml`` on
  ``master`` and publishes it on GitHub Pages; pull requests only build
  it, so a page that does not build is seen before it is merged. The
  package metadata and the README point at the site.
- Made ``snmpsim-command-responder`` stop when it cannot bind an endpoint.
  pysnmp 7 binds a UDP endpoint in a task of the event loop, and the
  responder never looked at how that task ended: with the port taken by
  another process, or an address the host does not have, it logged
  ``Listening at UDP/IPv4 endpoint 127.0.0.1:1161`` all the same, kept
  running and answered nothing. The responder now waits for every bind
  before it says it is listening; an endpoint that failed is logged by name
  with the error of the system, e.g. ``failed to bind UDP/IPv4 endpoint
  127.0.0.1:1161: [Errno 48] Address already in use``, and the process exits
  with status 1.
- Added the ``--v1-only`` and ``--v2c-only`` options to the command responder.
  The responder answered SNMPv1, SNMPv2c and SNMPv3 on every endpoint whatever
  device it simulated, so an agent that speaks one version could not be
  simulated: a manager falling back from v2c to v1 got an answer either way.
  With ``--v1-only`` only SNMPv1 requests are answered, with ``--v2c-only``
  only SNMPv2c ones; a request of any other version gets no response at all
  (no error and no SNMPv3 report), the manager times out as it does with a
  real single-version agent. The two options and ``--v3-only`` are mutually
  exclusive, giving two of them is a command-line error. The versions each
  SNMP engine serves are logged at startup.
- Added the ``--v3-auth-key-type`` and ``--v3-priv-key-type`` options to the
  command responder. It took every ``--v3-auth-key`` and ``--v3-priv-key``
  for a passphrase, so a USM user of which only the key is known (as it
  stands in a device configuration) could not be simulated: the key was
  hashed once more and no manager could authenticate. The new options take
  ``passphrase`` (the default), ``master`` (the hashed passphrase) or
  ``localized`` (the master key hashed with the engine ID); master and
  localized keys are given in hex, with or without the leading ``0x``, e.g.
  ``--v3-engine-id=80004fb805736e6d7073696d01 --v3-user=wallace
  --v3-auth-proto=SHA --v3-auth-key-type=localized
  --v3-auth-key=0x6fa2b85a0b067e30a4d2ee88afb33bb3f05da1e4``. A localized
  key only fits the ``--v3-engine-id`` it was made for. A key that is not
  hexadecimal or not of the size the protocol takes (16 octets where SHA
  takes 20) stops the responder with a message naming the user.
- Fixed SNMPv3 GETBULK responses ignoring the message size the manager is
  able to receive. Every SNMPv3 request carries ``msgMaxSize``, but the
  responder filled the response up to its own ``--max-message-size`` (1472
  octets by default) and pysnmp then silently dropped whatever was larger
  than the manager had asked for: a manager announcing 484 octets, the
  smallest size the protocol allows, got nothing but timeouts from a table
  of 200-octet rows. The repetitions are now cut to the smaller of
  ``--max-message-size`` and the manager's ``msgMaxSize``, so that manager
  gets one row in a 353-octet message and walks the whole table. SNMPv1 and
  SNMPv2c responses, which carry no such field, are unchanged.
- Fixed the error-index of a request in which a variable other than the last
  one fails. pysnmp's command responder points error-index at the first
  variable unless the failed one is the last of the request, so
  ``snmpget -v2c ... OID1 OID2 OID3`` with ``OID2`` served by the ``error``
  variation module (``status=noSuchName``) reported ``Failed object: OID1``.
  The responder now sends the error response itself and error-index is 2;
  the same holds for GETNEXT, SET and GETBULK (where the index counts from
  the start of the request) over SNMPv1, SNMPv2c and SNMPv3.
- Fixed ``noSuchObject``, ``noSuchInstance`` and ``endOfMib`` of the ``error``
  variation module, which came out as ``genErr`` on every SNMP version.
  SNMPv2 has no such error-status, these are values of a variable: on GET,
  GETNEXT and GETBULK an SNMPv2c or SNMPv3 manager now gets error-status 0,
  the exception in the var-bind of that variable and the values of the other
  variables, and an SNMPv1 manager gets ``noSuchName`` pointing at the
  variable. On SET they are reported as before (``notWritable`` for the
  first two).
- ``--daemonize`` of ``snmpsim-command-responder`` reports whether the daemon
  started: the process which was started stays until the daemon has built its
  indexes and bound its endpoints, and exits with 0 then, or with 1 if the
  daemon ended before that (a port in use, a pid file which cannot be
  written). Until it is ready the daemon keeps the standard error it was
  started with, so the reason is seen by whoever started it. Before, the
  parent exited with 0 right after ``fork()`` whatever happened next.
  Relative ``--data-dir``, ``--cache-dir``, ``--variation-modules-dir``,
  ``--pid-file`` and the reports directory of ``--reporting-method`` are taken
  from the directory the responder was started in, not from ``/`` where the
  daemon changes to. An empty ``--pid-file=`` still means no pid file.
  ``snmpsim-command-responder-lite --daemonize`` is unchanged: its parent
  exits right after the fork. Once it is ready the daemon holds neither the
  standard output nor the standard error it was started with, and nor does
  the resource tracker that Python starts when indexes are built in several
  processes, so ``$(...)``, ``| tee`` or ``ssh host snmpsim-command-responder
  --daemonize ...`` return when the parent exits.
- The command responder rescans its data directories on SIGHUP. A recording
  put into a data directory used to be served after a restart only, and one
  taken away kept its community name, every request for it failing at the
  file which was not there; SIGHUP itself ended a daemon and killed a
  responder running in the foreground. Now a recording which appeared is
  indexed and gets its community and context names, one which is gone loses
  them and has its files closed, the others are not touched and are served
  all the while: with an index of 400000 records being built, the slowest
  answer from another recording took 140 ms. A recording which cannot be
  indexed is reported and left out, a directory which cannot be read leaves
  everything as it was. POSIX only; ``snmpsim-command-responder-lite`` is
  unchanged.
- Fixed the responder serving a changed recording from a stale index left
  in the cache by another DBM backend. The dbm modules keep an index of the
  same name in different files (``<name>.dbm`` for gdbm and sqlite3,
  ``<name>.dbm.db`` or ``.dir``/``.pag`` for ndbm, ``.dat``/``.dir``/``.bak``
  for dumb), and ``dbm.open()`` looks for ndbm's first: with an old
  ``<name>.dbm.db`` in the cache the recording was re-indexed into
  ``<name>.dbm`` on every start and still answered from the old file, so new
  OIDs were missing. Building an index now removes every file any backend
  could take for that name, the index is opened with the backend that built
  it, and an index found next to another backend's files is rebuilt once.
- The responder keeps the most recently used data files open. Open files
  were held in a queue of 31 and the one opened first was closed, however
  recently it had been asked for: polled in turn, A, B, C, A, D with room
  for three closed A and left B open, so with some 1300 recordings polled
  round-robin nearly every request closed one data file and reopened
  another, index included. A recording that failed to open was queued
  again on every request and each time pushed a good file out, and the
  "Closing" log line named the file being opened rather than the one
  closed. Now the file closed is the one nobody asked for the longest, each
  file is counted once, a file that cannot be opened closes nobody, and the
  log names the file that was closed. The new ``--max-open-data-files``
  option of ``snmpsim-command-responder`` and
  ``snmpsim-command-responder-lite`` sets how many are kept; the default is
  half of the soft ``RLIMIT_NOFILE`` less a reserve of 64 descriptors, 256
  at most (256 with a limit of 1024, 96 with macOS's 256, and 256 where
  there is no such limit, as on Windows).
- The responder no longer formats request and response var-binds for log
  lines that are not printed, and no longer calls ``stat()`` on the data file
  for every request. With ``--log-level error`` or ``--logging-method null``
  every request still had each of its values and OIDs turned into text for
  the two INFO lines ("Request var-binds: ...", "Response var-binds: ..."),
  which were then dropped; they are now built only when INFO is printed, and
  read the same as before. An open data file is checked for changes at most
  once a second instead of on every lookup, so 100 requests within a second
  cost one ``stat()``, not 100. An edited recording is still reopened and
  reindexed, up to a second later than before.
- The responder builds missing and out of date indexes in several processes
  before it configures its SNMP engines, so a start over an empty cache no
  longer indexes some 1300 recordings one after another. The new
  ``--index-workers N`` option of ``snmpsim-command-responder`` sets how many
  (default: the CPUs the process may use, 8 at most; 1 builds them one by
  one as before). A recording that fails to index is reported and the other
  indexes are still built; the responder then stops at it with exit status 1,
  as it did before. An index is now built as ``<name>.dbm.part`` and renamed
  once complete, so a build cut short by a kill, Ctrl-C or a dead worker no
  longer leaves half an index that is served as up to date.
- Fixed ``snmpsim-record-commands`` exiting with 0 after a failed recording.
  ``main()`` returned from inside a ``finally`` block, which dropped whatever
  the walk had raised: a variation module whose ``record`` handler raised left
  a short recording and exit code 0, and Python 3.14 printed
  ``SyntaxWarning: 'return' in a 'finally' block`` on every start. An
  exception from the walk is now logged as ``Recording FAILED`` and the exit
  code is 1. The exit code is 1 as well when a variation module fails to
  initialize (the recorder stops before the walk instead of walking the agent
  with a module that refuses every record), when a module refuses a record
  with an error, and when a module fails to shut down.
- Fixed ``snmpsim-record-commands`` never telling a variation module that a
  walk had reached the end of the MIB. The module was told that a pass was
  over only when the walk ran into ``--stop-object``, so without that option
  ``--variation-module=multiplex`` with ``iterations:3`` made one snapshot
  instead of three, and ``numeric`` with ``iterations`` wrote an empty
  recording, both with exit code 0. The recorder now reports the end of the
  walk to the module itself and walks again for as many iterations as were
  asked for.
- Fixed the end of a recording made by ``snmpsim-record-traffic``. The last
  OID of every recording was written twice: a capture of ``sysDescr.0`` and
  ``sysName.0`` gave three records, ``sysName.0`` being there two times. The
  record that marks the end of a pass was never flagged as such either, so
  the ``iterations`` of the ``numeric`` and ``multiplex`` variation modules
  never moved on to the next time window of the capture. A UDP payload that
  is not BER made pysnmp raise a ``TypeError``, which was taken for a request
  to shut down: the conversion stopped at that packet, wrote what it had and
  exited with code 0; a truncated frame, an ARP frame or an empty datagram
  ended it with a traceback. Packets that are not SNMP are now counted as
  bad packets and passed over, an unexpected error is reported with the
  number of the packet and exit code 1 after writing what was read before
  it, and a context whose OIDs all fall outside the range of
  ``--start-object`` and ``--stop-object`` no longer ends the run with an
  ``IndexError``.
- An empty value is told from a missing one in every data file format. In a
  ``.dump`` or ``.MVC`` file a record such as ``1.3.6.1.2.1.1.5.0|6|`` ran
  into an IndexError and was reported as broken, so an empty string was
  lost; an empty OBJECT IDENTIFIER (``|5|``) passed and was converted into a
  record no responder can serve. In a ``.snmprec`` file an empty hex number
  (``|2x|``, ``|65x|``, ``|66x|``, ``|67x|``, ``|70x|``) built a value with
  nothing in it, and ``snmpsim-manage-records`` stopped with ``record not
  written: Attempted "__hash__" operation on ASN.1 schema object`` even
  under ``--ignore-broken-records``. Now an empty value of a string type is
  a zero-length string, and an empty value of any other type is a broken
  record: reported, and skipped under ``--ignore-broken-records``.
- Fixed the line numbers reported by ``snmpsim-manage-records``. The line
  counter moved only when a comment was met, so every record without a
  comment ahead of it was taken to start on line 1 again: a comment on
  line 2 of a ``.snmprec`` was reported as "Losing comment at lines 1..1",
  later ones were off by the number of records read in between, and the
  lines a wrapped snmpwalk value continues on were not counted at all.
  Every line is counted now, and the "Skipping broken record" and
  "ERROR: broken record" messages name the line the record starts on,
  e.g. "at line 7 (input file #0)".
- The ``numeric`` variation module applied its recording defaults only when
  some other option was given: ``--variation-module=numeric`` on its own left
  the settings empty and the recording came out as plain values, as if the
  module was not there. The defaults (``period`` of 10 seconds, ``taglist`` of
  ``2-65-66-67-70``) now apply with or without other options. While
  simulating, ``atime``, ``wrap`` and ``cumulative`` were switched on by the
  key being present, so ``wrap=0`` wrapped and ``cumulative=0`` accumulated;
  a flag set to ``0`` is now off and any other number is on. A record with an
  empty value field (``65:numeric|``) raised ``ValueError`` instead of running
  on the defaults. The documentation of the ``iterations`` recording option
  now says what the module does: ``0``, the default, is a single walk
  recording initial values, any other number is two walks with the rate
  computed between them, however large the number.
- Fixed ``snmpsim-record-mibs`` giving unrelated rows to tables that describe
  the same things. Every table got its own random indexes, so a table that
  ``AUGMENTS`` another one, or repeats its ``INDEX`` clause, did not line up
  with it: IF-MIB came out with ``ifTable`` rows 3, 4, 12, ... and ``ifXTable``
  rows 4, 6, 11, ..., that is interfaces with counters and no names next to
  interfaces with names and no counters. Tables indexed by the same columns
  now reuse the indexes generated for the first of them, also across the MIB
  modules given in one run; tables with a different set of index columns
  still get rows of their own.
- Fixed ``snmpsim-record-mibs`` generating values the MIB does not permit and
  then asking for them at the terminal. The tool made up a number from
  ``--integer32-range`` (0..32 by default) or a few words from the string
  pool, tried it against the object's constraints up to 5000 times and then
  prompted, so ``INTEGER { standby(40), active(50), failed(60) }``,
  ``Integer32 (1000..2000)``, ``OCTET STRING (SIZE (6))``, ``MacAddress`` and
  any ``BITS`` object never got a value: IF-MIB stopped at ``ifPhysAddress``
  to ask, and with stdin closed the question was printed for ever. Values
  are now drawn from the constraints: a member of the enumeration, a number
  from the permitted ranges (narrowed to the range given on the command line
  where the two overlap), a string of a permitted size, random octets where
  the DISPLAY-HINT shows numbers, a set of the named bits. A number is
  written as it goes on the wire, a ``d-2`` DISPLAY-HINT no longer multiplies
  it by 100. An object no value can be made for is reported once on stderr
  and left out, a table whose index has no value is left out as a whole, and
  the rest of the MIB is generated; nothing is asked unless
  ``--manual-values`` is given, and there the end of the input ends the
  questions.
- Made the documentation sources describe snmpsim-ng. They were still set up
  for the release line this project was forked from: published at its
  address, naming its company as the author, opening with an announcement of
  another product, linking its repository and tracker, loading its analytics
  and advertising on every page, and buildable only with its fork of
  sphinx-sitemap. The examples no longer record from a public demo agent but
  from the documentation address 192.0.2.1. The quick start installs from
  git, on POSIX and on Windows, and serves a five-line data file the reader
  writes, instead of a recording from the ``snmpsim-data`` package, which
  requires ``snmpsim`` 1.x and so installs the other release line. The Sphinx
  packages moved from the ``dev`` extra to a ``docs`` extra of their own.
- Documented what snmpsim-ng changed in the reference pages, not only here
  and in the README. The command-line reference had no word on the
  recorder's ``--protocol-version`` and SNMPv3 options, gave
  ``--reporting-method`` without its dumping period, and listed search paths
  such as ``/usr/snmpsim/data`` and ``\Document and Settings`` that are not
  searched; the page on ``snmpwalk`` files still said multi-line values are
  not coped with. It now has sections for ``snmpsim-record-commands``,
  ``snmpsim-manage-records`` and ``snmpsim-lint-records``, and the pages on
  data files show a recording over SNMPv3, a converted walk with wrapped
  values, non-ASCII strings and Opaque floats, and what a broken record ends
  a conversion with. A new page, "Migrating from snmpsim", covers the package
  name, removing an installation named ``snmpsim`` first, the calendar
  version numbers, and what answers differently from snmpsim 1.2.2. Options
  the pages named but no command takes were put right: ``--start-oid`` and
  ``--stop-oid`` are ``--start-object`` and ``--stop-object``,
  ``--max-varbinds`` is ``--max-var-binds``, ``--manual-value`` is
  ``--manual-values``, and ``--agent-udpv4-endpoints-list`` never existed -
  it is ``--args-from-file``. The options this release adds are described
  there as well: ``--v1-only``, ``--v2c-only``, ``--v3-auth-key-type``,
  ``--v3-priv-key-type``, ``--index-workers`` and ``--max-open-data-files``.

Revision 2026.11.1, released on Nov 15, 2026
--------------------------------------------

Changes carried by snmpsim-ng.

- Pointed the README, the licence and the package metadata at this project.
  The README explains why the package is called ``snmpsim-ng``, installs
  from tagged releases rather than from ``master``, and no longer sends
  readers to the other release line's site, pull requests or bug tracker;
  ``LICENSE.txt`` keeps the earlier copyright notices, as the BSD licence
  requires, and adds the current one. Removed what was left over from that
  line: the sponsorship link (``.github/FUNDING.yml``), editor settings
  (``.vscode``), an outdated ``TODO.txt``, the setuptools ``MANIFEST.in``,
  which hatchling does not read, and a pre-commit configuration whose
  formatter disagreed with the ``black`` the CI checks against.
- Told variation modules which OID a recording starts at.
  ``snmpsim-record-commands`` handed the start OID to a module's ``record``
  handler under a name none of them reads, so
  ``--variation-module=multiplex``, ``sql`` and ``redis`` failed on the first
  OID, the failure was only logged, and the recording came out empty. The
  handler now gets it as ``startOID``, the name those modules and
  ``snmpsim-record-traffic`` already use.
- Made the ``multiplex`` variation module close the snapshot it is recording
  when the recorder shuts it down. It closed a snapshot only on a stop
  record, which a walk to the end of the MIB never produces, so the only
  snapshot of such a recording stayed open, and whether what was written to
  it reached the disk was left to the interpreter exiting: at times the
  snapshot came out empty next to a recording that looked fine.
- Fixed the name ``multiplex`` gives to a snapshot: it was
  ``00000..snmprec``, with two dots, which the responder could not turn into
  a number, so a recording made by the module was not served by it. Snapshots
  are named ``00000.snmprec`` now, as documented, and those already recorded
  under the old name are served as well - unless the directory was recorded
  into again and has the snapshot under both names, where the new one is
  served and the old one is logged as ignored.
- Fixed the ``multiplex`` variation module serving the wrong snapshot. It
  kept the snapshot numbers as the system happened to list the files, not in
  ascending order, while the snapshot whose turn it is by time is found in
  them by bisection, and the one chosen through the control OID by its
  position. With several snapshots another one could be served, depending on
  the file system. The numbers are sorted now.
- Fixed ``snmpsim-record-commands`` not being able to record over SNMPv3. It
  took ``--v3-user`` and the other USM options, but ``--protocol-version``
  accepted only ``1`` and ``2c``, so they were never used: given a v3 user the
  recorder went on asking over v2c with the ``public`` community, and an agent
  answering only SNMPv3 timed out with 0 OIDs dumped. ``--protocol-version``
  now takes ``3`` as well; when it is left out it is ``3`` if ``--v3-user`` is
  given and ``2c`` otherwise, and ``--v3-user`` together with an explicit
  ``1`` or ``2c`` is rejected. ``--v3-context-name`` is sent as an octet
  string, which the line logging the SNMPv3 settings can print. The command
  line is now checked before the output file is opened, so a rejected one no
  longer empties an existing recording.
- Fixed conversion of Opaque Float and Double values from snmpwalk output. The
  ``Float:`` prefix was cut off twice, so ``Opaque: Float: 100.000000`` was
  recorded as zero and ``Opaque: Float: 12.5`` failed the conversion; what did
  get recorded was a BER Real, which agents do not send inside an Opaque.
  ``Opaque: Double:`` was not recognised at all. Both are now written as
  net-snmp puts them on the wire, the way UInt64 and Int64 already were:
  ``Opaque: Float: 100.000000`` becomes ``68x|9f780442c80000`` (sub-tag
  ``9f78``, four octets of IEEE 754 single precision) and
  ``Opaque: Double: 1.5`` becomes ``68x|9f79083ff8000000000000`` (sub-tag
  ``9f79``, eight octets of double precision).
- Kept the non-ASCII octets of strings read from ``snmpwalk`` output. The walk
  grammar decoded each line as ASCII and ignored what did not fit, so every
  octet from 0x80 up was deleted before the value was read: a ``sysName`` of
  ``Привет``, in UTF-8 or in cp1251, was converted to an empty string, and
  ``Zürich`` lost two of its seven octets. Lines are now read octet for octet,
  and white space is stripped by its ASCII list only, as ``0x85`` and ``0xa0``
  end many UTF-8 and code page strings. The ``sapwalk`` grammar lost such a
  trailing octet from an unquoted value the same way and is fixed with it. A
  UTF-8 byte order mark at the start of a walk saved on Windows is skipped.
- Read the values ``snmpwalk`` wraps onto several lines when converting a walk
  with ``snmpsim-manage-records``. ``snmpwalk`` starts a new line after every
  sixteen octets of a ``Hex-STRING`` and prints the newlines inside a quoted
  ``STRING`` as they are, but every line of a walk was taken for a record: a
  40-octet ``Hex-STRING`` came out 16 octets long with its other two lines
  reported as broken records, and ``"first\nsecond"`` became the value
  ``"first`` with the opening quote still on it. A line is now joined to the
  record before it when that record is a quoted ``STRING`` whose closing quote
  has not come yet, or a ``Hex-STRING`` and the line holds nothing but hex
  octets (with the text column of ``-OT``, if any). A line that starts a
  record of its own - with a numeric OID or a name, as ``-Os`` and ``-Of``
  print them - is never joined, so a string that was cut short costs that one
  value and not the rest of the walk. The backslash ``snmpwalk`` puts before
  every quote and backslash of a quoted ``STRING`` is no longer recorded as
  part of the value: ``"C:\\Temp \"x\""`` used to come out three octets longer
  than what the device sent. A walk read from a pipe
  (``--input-file=/dev/stdin``) is converted the same way, on Windows too,
  where a pipe claims it can be moved back and the record after a wrapped
  value was lost: only a regular file is moved back. The ``.snmprec``
  reader and the line reader of the responder are not changed.
- Fixed ``snmpsim-manage-records`` crashing on walk and sapwalk lines it
  cannot convert. A walk taken without ``-On`` has names for OIDs, and
  ``SNMPv2-MIB::sysName.0 = STRING: switch`` ended the conversion with a
  ``PyAsn1Error`` traceback; a sapwalk line with a bad hex value,
  ``1.3.6.1.2.1.1.5.0, OctetString, 0x73ZZ``, did the same with a
  ``ValueError``, as did the walk values ``Opaque: Float: n/a``,
  ``BITS: ZZ 01`` and ``Network Address: ZZ:00:00:01``.
  ``--ignore-broken-records`` made no difference. Such lines are broken
  records now: skipped and counted with ``--ignore-broken-records``, otherwise
  the command exits with status 1 and a message that quotes the line and says
  what is wrong with it (for a walk with names, that ``snmpwalk -On`` prints
  OIDs in numbers; MIB names are not resolved). That message is printed under
  ``--quiet`` as well, where the command used to exit with status 1 and not a
  word.
- Fixed ``snmpsim-manage-records`` holding a whole conversion in memory. Every
  record was kept in a list until the last input line had been read, whether
  or not ``--sort-records`` was given, so a 37 MB walk of 600000 lines took
  742 MB and a 221 MB one ran out of memory. Records are now written as they
  are read unless they are to be sorted (the same walk takes 48 MB);
  ``--deduplicate-records`` streams as well. The output is byte for byte what
  it was. A broken record met without ``--ignore-broken-records`` still ends
  the conversion with exit status 1, but the records ahead of it are now
  already in the output file, which used to be left empty.
- Fixed recording with ``--variation-module=numeric``: any
  ``--variation-module-options`` failed to parse ("too many values to
  unpack"), so the run silently wrote plain values instead of numeric records.
  Options are now cut at the first colon (a value may contain colons),
  repeated ``addon`` options accumulate, and the options are applied all or
  nothing: an option with no colon, or an ``iterations``/``period`` that is
  not a number, is reported by name and the recording then proceeds with plain
  values instead of half of the options.
- Fixed the ``numeric`` variation module failing every request for a record
  with a ``deviation`` on Python 3.12 and later. The module reads its settings
  as floats and passed the deviation to ``random.randrange()``, which no
  longer accepts them, so ``66:numeric|initial=100,deviation=2`` and the
  COUNTER example of the documentation answered with a data error
  (``'float' object cannot be interpreted as an integer``). The deviation is
  now cut to a whole number first: ``deviation=2`` adds one of -2, -1, 0, 1.
- Fixed the ``writecache`` variation module ignoring the encoding flag of the
  record's tag. The text after ``value=`` was always taken as plain text, so
  ``64x:writecache|value=c0000219`` failed with "Bad IP address syntax" on
  every request and the record vanished from walks, while
  ``4x:writecache|value=414243`` served the six characters ``414243``.
  ``value=`` and the constants of ``vlist`` are now read the way a plain
  record reads its value: hex digits under the ``x`` flag (the records above
  serve ``192.0.2.25`` and ``ABC``), a string with Python escapes under the
  ``e`` flag. ``hexvalue=`` works as before.
- Fixed the ``subprocess`` variation module returning the line ending of the
  program's output as a part of the value. ``4:subprocess|echo hello``
  answered the six octets of ``hello\n``, and ``4x:subprocess|echo 07e30307``
  decoded into five octets instead of four, the only way around being
  ``echo -n``. One trailing line feed, with the carriage return in front of it
  if there is one, is dropped now. Nothing else is trimmed: a program printing
  ``a\n\n`` still returns ``a\n``, and trailing spaces stay.
- Fixed the ``error`` variation module reporting ``genErr`` to SNMPv1 managers
  for the three errors only SNMPv1 has. A record like
  ``4:error|status=noSuchName`` answered an SNMPv1 GET with error-status 5
  instead of 2, and ``status=badValue`` or ``status=readOnly`` answered a SET
  with 5 instead of 3 or 4, because pysnmp has no SNMPv1 translation for these
  codes. They now reach an SNMPv1 manager as configured; other errors
  translate as before and SNMPv2c responses are unchanged.
- Fixed the ``notification`` variation module rekeying the agent's own USM
  users. Notifications were sent through the engine that answers the managers,
  so a record sending a v3 trap as user ``simulator`` with keys of its own
  replaced that user's keys and protocols: the trap went out and every v3 GET
  after it failed with a wrong digest until the responder was restarted.
  Notifications now leave through a separate SNMP engine carrying the agent's
  engine ID, and no longer hold up the response that triggered them.
  ``authproto`` and ``privproto`` take every name ``--v3-auth-proto`` and
  ``--v3-priv-proto`` take (``sha224`` to ``sha512``, ``3des``, ``aes192``,
  ``aes256`` and the Blumenthal variants) instead of only ``md5``, ``sha``,
  ``des`` and ``aes``; a record asking for ``sha256`` used to answer
  noSuchInstance. The module also works under
  ``snmpsim-command-responder-lite`` now.
- Fixed the search path for data and variation modules. On Windows the
  per-user ``SNMP Simulator`` directories were built from ``HOMEPATH``, which
  holds no drive letter, so ``\Users\name`` resolved against whatever drive
  the simulator was started from; a service account with no ``HOMEPATH`` at
  all could not start any command, they died with ``KeyError: 'HOMEPATH'`` on
  import. The home directory is now taken from ``USERPROFILE``, then from
  ``HOMEDRIVE`` and ``HOMEPATH`` together, and a directory whose environment
  variable (``APPDATA``, ``PROGRAMFILES``, ``HOME`` included) is not set is
  left out of the search path. Linux now also searches
  ``/usr/local/share/snmpsim/variation`` and
  ``/usr/local/share/snmpsim/data``, as macOS always did.
- Made the ``sql`` variation module reconnect when the database drops its
  connection. The connection was opened once, at start, and used for every
  request from then on, so after a database server restart - or after MySQL
  closed a connection idle for its ``wait_timeout``, eight hours by default -
  every request for a database-backed OID failed until the simulator itself
  was restarted. When a request fails, the module now checks the connection
  with a ``select 1``. If the connection is gone, the request is repeated
  once on a new one made with the same parameters; if that fails too the
  error is reported as before and the next request tries again, so the
  database is picked up as soon as it is back. If the connection answers, the
  statement itself was refused (no such table, bad SQL): the error is
  reported on the connection the module has and nothing is reconnected. The
  same goes for a passing error on a connection that is alive - sqlite's
  "database is locked", a MySQL deadlock or lock wait timeout: it is
  reported, not retried on a new connection.
  Whatever the database error, the transaction of the failed request is
  rolled back, so that PostgreSQL does not refuse everything that follows;
  the earlier variable bindings of the same SET message, answered already
  but not committed, are discarded with it.
- Made the lite responder read its options from a file. Only
  ``snmpsim-command-responder`` had ``--args-from-file``;
  ``snmpsim-command-responder-lite --args-from-file=ips.txt`` stopped with
  "unrecognized arguments", so a list of endpoints too long for a command line
  could not be served by it. The lite responder now takes the same option and
  the same file format, ``--option=value`` items separated by whitespace. Any
  of its options can be kept in the file, the required endpoints included.
  The file is read as if its items stood ahead of the command line: for an
  option that takes one value the command line wins, while the options that
  can be given more than once (``--data-dir``, ``--agent-udpv4-endpoint``,
  ``--agent-udpv6-endpoint``, ``--variation-modules-dir``,
  ``--variation-module-options``, ``--debug``, ``--debug-asn1``) get the
  values of both. IPv4 endpoints in the file with IPv6 ones on the command
  line, or the other way round, are refused the way they are on a single
  command line. A switch the file sets (``--daemonize``, ``--quiet``,
  ``--v2c-arch``, ``--v3-only``, ``--force-index-rebuild``,
  ``--validate-data``) cannot be switched off from the command line. A file
  that cannot be read is reported and the responder exits with status 1.
- Switched the lite responder and ``snmpsim-record-traffic`` to decoding the
  SNMP message version through
  ``pysnmp.proto.api.verdec.decode_message_version`` instead of the camelCase
  ``api.decodeMessageVersion``. They were the last two callers of that pre-7
  name, which pysnmp keeps only as an alias; without it the lite responder
  answers no request and the converter writes no recording and reports no
  error.
- Made the documentation of the ``numeric`` variation module state the formula
  the module actually computes. The old one showed ``offset`` as a plain
  addend, while with ``cumulative`` it is multiplied by ``rate`` and by the
  seconds since the previous request, and ``min``, ``max`` and ``wrap`` apply
  after the previous value is added. It also said ``atime``, ``wrap`` and
  ``cumulative`` act "if non-zero" (the module only looks for the key, so
  ``wrap=0`` wraps) and gave the default ``max`` as ``2**32`` instead of
  ``2**32 - 1``. The section now warns that a cumulative value grows by the
  whole function value on every request, so a counter polled twice as often
  grows about twice as fast, and shows ``scale=0,offset=100,cumulative=1`` for
  a counter with a steady pace. A test executes the documented formula against
  the module.

Revision 2026.11.0, released on Nov 15, 2026
----------------------------------------------

Changes carried by the Observium fork. Where a change was also sent to the
upstream project, its pull request is given.

- Renamed the distribution to ``snmpsim-ng``. The name ``snmpsim`` on PyPI
  belongs to the upstream release, so the fork could not be published under it,
  and an installation of either could not tell which one it had. The ``snmpsim``
  module and the ``snmpsim-*`` commands are unchanged; an existing installation
  under the old name has to be removed before installing the new one.
- Numbered releases by the calendar, ``YYYY.M.N``, instead of continuing the
  upstream ``1.2.x`` series. The fork's next release would otherwise have been
  ``1.2.3``, the number upstream is most likely to give its own next release, and
  two different packages under one version is something no installer can tell
  apart. A calendar version sorts above any upstream ``1.x`` or ``2.x``.
- Switched the remaining calls to pysnmp's pre-7 camelCase names -
  ``importSymbols``, ``resolveWithMib``, ``addMibCompiler``,
  ``getNextNodeName``, ``getNodeLocation``, ``flagMap`` and the index context's
  ``nextKey`` - to their current spelling. pysnmp keeps the old names only as
  deprecated aliases, which warn on every call and go away once it drops them.
- Kept the integers a device sent outside the range of their type, instead of
  dropping the record over them. ``.1.3.6.1.2.1.6.4.0 = INTEGER: 4294967295`` -
  a ``tcpMaxConn`` of ``-1`` put on the wire unsigned - failed to convert and
  could not be served, as pyasn1 refuses to build an ``Integer32`` above
  2147483647. Such a value is now recorded and answered with the very octets
  the device sent, ``02 05 00 ff ff ff ff``, and ``snmpsim-lint-records``
  reports it as a warning. ``Counter32``, ``Gauge32``, ``Unsigned32``,
  ``TimeTicks`` and ``Counter64`` values above their maximum are kept the same
  way.
- Dropped the ``scripts`` git submodule, which came from a third-party repository
  and was used only to invoke ``uv`` and ``pytest`` from CI. The workflow calls
  them directly, so a plain clone is enough to build and test.
- Removed the references to the third-party control plane from the documentation.
  That project's last functional commit was in April 2020 and its dependencies no
  longer import on a current Python.
- Fixed ``--reporting-method`` on Windows, where splitting the argument on
  every colon cut the reports directory in half at its drive letter and left
  the responder trying to read a path as the dumping period. Only a trailing
  run of digits is taken for the period now.
- Fixed ``RecordIndex.close()``, which raised ``AttributeError`` on an index
  that had been built but never opened, and on a second close. Building an
  index without opening it is what ``create()`` does, so closing one - as the
  ``multiplex`` variation module does between files, and as anything warming a
  cache ahead of a restart does - died on a handle that was never there.
- Made ``fulljson`` activity reporting work at all. Its counters are indexed
  by the endpoint which received the request, and the pysnmp 7 port had
  commented that endpoint out - ``getLocalAddress()`` was renamed, and pysnmp
  never sets a local address on an incoming datagram anyway - so every counter
  update was dropped on a ``KeyError`` and the dumps carried nothing but their
  header. The responder now remembers what each transport domain listens on.
  In the same path, the transport protocol was decided by the class of the
  peer address, which pysnmp 7 passes as a plain tuple, so every request was
  filed under ``unknown``; it now comes from the transport domain, and a plain
  address tuple no longer ends up as a JSON key it cannot be.
- Fixed the JSON activity reporting (``--reporting-method``), which wrote no
  file at all wherever ``/tmp`` is a filesystem of its own: the document went
  into a temporary file there and was then renamed into the reports directory,
  which fails with ``EXDEV``. The temporary file is now created beside its
  destination, which is what makes the rename atomic in the first place, and a
  failed dump keeps its counters for the next period instead of discarding
  them.
- Cut GETBULK responses short so they fit into a single, unfragmented UDP
  datagram, as real agents do. Recordings holding long values could otherwise
  answer with several kilobytes at once, and managers which never received the
  fragmented reply whole saw the walk stall with a timeout. The limit is
  ``--max-message-size``, 1472 octets by default. The same change makes
  ``--max-var-binds`` work again: it was assigned to an attribute pysnmp 7 no
  longer reads (lextudio/snmpsim#21).
- Serve OID values made of a single arc, such as ``6|0``, instead of dropping
  the response. BER has no representation for such an OID, so ``0`` and ``0.0``
  are the same octets and the missing arc is restored (lextudio/snmpsim#14).
- Answer ``noSuchInstance`` on GET, and step over the record on GETNEXT and
  GETBULK, for values which cannot be encoded at all. One broken record no
  longer truncates the rest of the walk (lextudio/snmpsim#14).
- Added ``snmpsim-lint-records``, which checks data files, or whole directories
  of them, by encoding every value, and exits non-zero on errors
  (lextudio/snmpsim#14).
- Preserve trailing spaces in escaped values, so an ``IpAddress`` whose last
  octet is 32 is no longer cut short and dropped (lextudio/snmpsim#12).
- Fixed ``--daemonize``: the event loop was created before ``fork()`` and did
  not survive it, so the daemon died moments after opening its socket
  (lextudio/snmpsim#15).
- Declared ``pysmi`` and ``cryptography`` as dependencies. Both are imported at
  run time, and without them a fresh installation cannot start
  (lextudio/snmpsim#16).
- Fixed ``snmpsim-command-responder-lite``, which aborted at startup on pysnmp
  7, along with the request paths behind that crash: var-binds passed to the
  MIB controllers as a list rather than positionally, the IPv6 endpoint built
  from the IPv4 class, and the data files index context
  (lextudio/snmpsim#17).
- Fixed ``snmpsim-record-commands``, which recorded nothing and hung. pysnmp 7
  hands over one response per request and no longer continues a walk by
  itself - deliberately, per lextudio/pysnmp#251 - so the recorder now walks
  agents through ``hlapi``, the supported way to do it. It also creates an
  event loop of its own, which Python no longer provides implicitly, and no
  longer counts every OID twice. The pull request sent upstream
  (lextudio/snmpsim#18) carries the smaller fix against the low-level API.
- Fixed ``snmpsim-record-traffic``, which could not start at all: it required
  a capture library which has not been installable for years, and behind that
  parsed packet headers with Python 2 byte semantics, overwrote its own
  arguments with a packet mid-loop and could not create its output directory.
  Capture files are now read without an extension module; ``pylibpcap`` is
  needed only for live capture off an interface (lextudio/snmpsim#18).
- Fixed ``--debug`` in the recorder and the lite responder, which died on a
  pysnmp function renamed years ago.
- Fixed selection of a recording by source address in the full responder. Its
  four command responder classes hooked into ``handleMgmtOperation``, which
  pysnmp 7 renamed and no longer calls, so the hooks - and the address probing,
  the "LCD access denied" guard and the ``NoDataNotification`` handling inside
  them - had been dead since the pysnmp 7 port (lextudio/snmpsim#20).
- Moved off the pysnmp names which survive only as deprecated aliases
  (``udp6.domainName``, ``config.addV1System`` and its neighbours, the
  ``usm*Protocol`` constants). Their removal is what killed the lite responder.
- Build data file indexes with gdbm where the interpreter has it. Python 3.13
  made ``dbm.sqlite3`` the default backend, which fsyncs every write and builds
  indexes twice as slowly; interpreters without gdbm are unaffected
  (lextudio/snmpsim#19).
- Added a test workflow running the suite on every supported Python version,
  without the retries which let a failing test pass in the existing one.
  Neither workflow runs for changes which touch documentation only.

Revision 1.2.2, released on Apr 26, 2026
----------------------------------------

- Updated pysnmp to 7.1.26.
- Fixed a bug in cmd2rec.py.

Revision 1.2.1, released on Nov 19, 2025
----------------------------------------

- Fixed Python 3.14 compatibility issues.

Revision 1.2.0, released on Nov 19, 2025
----------------------------------------

- Upgraded pysnmp to 7.1.

Revision 1.1.7, released on Sep 13, 2024
----------------------------------------

- Removed pyasn1.compat dependency.

Revision 1.1.6, released on Sep 12, 2024
----------------------------------------

- Removed pyasn1.compat dependency.

Revision 1.1.5, released on Aug 09, 2024
----------------------------------------

- Implemented the arguments "--debug" and "--debug-asn1" in responders
  to enable debugging mode.

Revision 1.1.4, released on Aug 01, 2024
----------------------------------------

- Added SNMP_ALLOW_ROOT environment variable to allow running SNMP simulator
  as root. This is a security risk and should be used with caution.

Revision 1.1.3, released on Jul 23, 2024
----------------------------------------

- Fixed notification variation module.

Revision 1.1.2, released on Jul 16, 2024
----------------------------------------

- Removed package postfix.

Revision 1.1.1, released on Jun 28, 2024
----------------------------------------

- Fixed a file path bug.

Revision 1.1.0, released on Mar 30, 2024
----------------------------------------

- Upgraded pysnmp-lextudio to 6.1.

Revision 1.0.6, released on Mar 05, 2024
----------------------------------------

- Locked pysnmp-lextudio to 5.0 to avoid breaking changes in 6.0.

Revision 1.0.5, released on Oct 15, 2023
----------------------------------------

- Fixed IPv6 endpoint support (by kbaikov).

Revision 1.0.4, released on Sep 16, 2023
----------------------------------------

- Merged walk.py patches from inexio.

Revision 1.0.3, released on Sep 16, 2023
----------------------------------------

- Merged other pull requests on upstream.

Revision 1.0.2, released on Sep 16, 2023
----------------------------------------

- Fixed a few bugs in snmpsim-record-mibs.

Revision 1.0.1, released on Jan 26, 2023
----------------------------------------

- Added data and variation folders back to package.

Revision 1.0.0, released on Nov 13, 2022
----------------------------------------

- Command-line tools refactored into entry-points and renamed for better
  clarity and name spacing for the upcoming tools:

  * snmpsimd.py -> snmpsim-command-responder
  * snmprec.py -> snmpsim-record-commands
  * mib2dev.py -> snmpsim-record-mibs
  * pcap2dev.py -> snmpsim-record-traffic
  * datafile.py -> snmpsim-manage-records

- Python 2.4-2.6 support has been dropped.

- Converted integration tests from depending on @snmplabs.com to local,
  autonomous test suite.

- Replace `getopt` with `argparse` in all CLI tools The latter is way more
  advanced and Pythonic.

  Due to differences in `getopt` vs `argparse` usage model, slight changes
  in tools' behavior is not impossible.

  Some legacy, backward compatibility CLI options have been dropped by
  way of this change.

- Remove `execfile` use on Py2.

- Split monolithic command responder onto many specialized modules and
  two command responder applications: one implementing fully-fledged
  SNMPv3 architecture (supporting all SNMP versions) and the other
  implementing just v1 and v2c. The second one is lighter on the
  resources.

  So we now have two daemons:

  * snmpsim-command-responder
  * snmpsim-command-responder-lite

- Add activity reporting feature

  On every query, SNMP simulator command responder calls its
  "reporting" subsystem. If configured, it invokes one of the
  "modules" responsible for doing something with request
  information.

  Included modules ("fulljson" and "minimaljson" reporters) accumulate
  and periodically dump JSON documents containing request counters scoped
  by SNMP command processing steps.

  Future modules may just send out the information to external
  collectors e.g. Graphite/Carbon or store it in some other format
  e.g. Prometheus.

Revision 0.4.9, released on XX-11-2022
----------------------------------------

- Changed web site to pysnmp.com.

Revision 0.4.8, released on XX-08-2019
----------------------------------------

- Code base PEP8'ed
- Added support for SNMP Context Engine ID mapping to the file system paths.
  This feature allows for every single SNMP engine to simulate multiple
  SNMP contexts based on different .snmprec files. On top of that, this
  feature simplifies the mapping of empty SNMP community and context names
  to .snmprec files.
- Added support for simulation based on compressed .snmprec files using
  bzip2 compression algorithm (.snmprec.bz2), as well as recording straight
  into this compressed format.
  By way of implementing this change, all snmpsim tools have been generalized
  to variate and record using any of the supported simulation file formats (for
  as long as chosen format supports variation or recording).
- Run snmpsimd variation modules initialization under non-privileged user
- MIB resolution failure handling improved in `mib2dev`
- Rearranged documentation, removed public SNMP simulator page
- Fixed crash caused by pysnmp failing to load up the rest of its MIBs when
  snmpsimd is switched into non-privileged user
- Fixed wrong cache directory and files ownership when switching snmpsimd from
  privileged into non-privileged user
- Fixed .snmpwalk hex string parser
- Fixed hex value evaluation error on Python 3 when produced in bytes
  by a variation modules
- Fixed '\\' evaluation in escaped strings (tag 4e)
- Fixed `redis` variation module to run under Py3
- Fixed broken indices clean-up, especially on Mac OS
- Fixed broken `multiplex` module initialization
- Fixed broken NULL value parsing in .snmpwalk files

Revision 0.4.7, released on Feb 09, 2019
----------------------------------------

- Added missing SNMP PDU error-status values to the `error`
  variation module
- Fix to define `PrivilegesOf` on Windows

Revision 0.4.6, released on Jan 25, 2019
----------------------------------------

- The `--log-level` option added
- Default daemon syslog service destination to a local socket
- Fixed timed log file rotation to respect log file creation time
  when computing next rotation time
- Fixed possible file permission issues by initializing pysnmp modules,
  logger and variation modules subsystems under reduced user privileges
- Improve error reporting in `notification` variation module

Revision 0.4.5, released on Dec 30, 2018
----------------------------------------

- Copyright notice bumped up to year 2019
- Bumped upper Python version to 3.7
- Use absolute paths of Simulator data files and variation modules
  and reflect that in the log -- that should ease troubleshooting
- Optional .snmprec tag modifier is ignored by the *error*,
  *delay*, *writecache* and *notification* variation modules
- Fixed DBM file index detection code to operate correctly
- Fixed pysnmp/pyasn1 debugging flags print out in `--help` to work
  with newer pyasn1/pysnmp

Revision 0.4.4, released on Feb 20, 2018
----------------------------------------

- Fixed regression to non-snmprec format evaluator when
  called in a non-simulation context (e.g. datafile.py)
- Fixed non-functional SQL isolation level setup at the
  `sql` variation module

Revision 0.4.3, released on Feb 12, 2018
----------------------------------------

- Copyright notice bumped up to year 2018
- Fix to strip labels from enumerations when producing .snmprec
  file
- Fix to SNMP GET command processing by the non-snmprec storage
  backends - it used to return next OID instead of noSuchObject

Revision 0.4.2, released on Dec 22, 2017
----------------------------------------

- Python literal string representation added as a new flavor of .snmprec
  string type field (4e)
- Migrated references from SourceForge
- Integer and enumerations parsing of snmpwalk output improved
- Added strong AES privacy algorithms with Blumenthal key localization
- Fixed SNMP crypto algorithm identifiers to be named consistently after
  key length rather than MAC length

Revision 0.4.1, released on Oct 29, 2017
----------------------------------------

- SHA2 authentication protocol suite added.
- Sphinx documentation added based on the original web-site
  user manual
- Simulator's SNMPv3 command line option processing hardened to
  make easier to understand.
- Notification variation module now accepts hex strings in var-binds
- Fixes to Windows path to log file handling.
- Fixes to MIB objects command-line parsing.
- Source code PEP8'ed

Revision 0.3.1, released on Jan 21, 2017
----------------------------------------
- Fix to __doc__ use in setup.py to make -O0 installation mode working.
- Copyright notes added to source code files.
- Per-OID access control added to 'writecache' variation module.
- Data file binary search performance improved
- Option --string-pool-file for mib2dev.py tool implemented
- Default string pool for mib2dev.py tool changed to a pangram
- Author's e-mail changed, copyright extended to year 2017
- Fix to PID file creation when running Python 3.
- Fix to datafile.py tool that apparently stopped working.
- Fix to snmpwalk Timeticks parser
- Fix to mib2dev.py stopping prematurely iterating over OIDs in MIB
- Fix to accidentally expanded shebang in console scripts (hopefully)

Revision 0.3.0, released on Sep 28, 2015
----------------------------------------

- Simulator now depends on the latest pysnmp features introduced in
  pysnmp version 4.3.0
- Introducing initial MIB compiler (PySMI) integration. Most command-line
  tools can now be given MIB symbols rather than OIDs. Requested
  MIBs will be automatically downloaded from http://mibs.snmplabs.com/ .
- New Redis-backed variation module implemented to let users record into
  and replay simulation data from noSQL key-value store optionally
  involving server-side Lua scripting.
- Full-line comments (#-based) and empty lines are now allowed in data files.
- When recording .snmprec data, hex everything if a non-alpha/numeric
  literal is present in a value. This eliminates possible issues with
  unescaped contents in a SQL-based recorder.
- New --max-varbinds option can now be used for limiting the number
  of variable bindings in SNMP response message on a per-engine-id
  basis. Global default is now 64 variable bindings.
- Multiple SNMP ContextEngineID can now be configured per each of possibly
  many SNMP Engine IDs.
- SNMP configuration logging reworked for better clarity.
- The notification module now binds to the same local interface through
  which Simulator received CommandRequest triggering notification.
  Also it supports 'bindaddr' option to override the above behaviour on
  a per-OID basis.
- The sql variation module not switches default SQL transaction isolation
  level to 'READ COMMITTED'. Isolation level (0-3) could now be specified
  on per-instance basis through 'isolationlevel' option.
- The subprocess variation module improved to expose more SNMP engine
  parameters to user process.
- Switched to the latest pysnmp's requestObserver facility for getting
  request details from pysnmp core.
- Numeric module's 'function' parameter now accepts optional arguments.
- The snmprec.py tool improved to optionally survive SNMP PDU-level errors
  and keep walking remote Agent using an OID derived from the failed one.
- Configurable SNMP request timeout and retry count settings now supported
  by the snmprec.py tool.
- The --context-engine-id option support added to snmprec.py tool.
- Hex values can now be passed to --v3-context-\* options to snmprec.py tool
- Variation modules options separators can now be escaped by doubling or
  tripling them.
- All logging moved to Python logging framework. Some more log targets (such
  as remote syslog) added.
- Low-level SNMP and ASN.1 debugging implemented for all relevant scripts.
- Configure both plain-text and hashed versions of snmpCommunityName,
  contextName whenever its length does not exceed 32 chars. That might ease
  ContextName usage for Agent addressing.
- Wheel distribution format now supported.
- Fix to log file autorotation feature.
- Fix to pcap2dev.py not to loose the last trailing OID in capture.
- Fix to variation module recordContexts isolation to make it dedicated
  to each Variation Module+Agent instance.
- Fix to snmpEngine configuration code at notification.py variation module.
- Fixes to --logging-method formatting in --help output.
- Fix to numeric.py module value wrapping feature.
- Fix to MIB selection code to prevent (and report) LCD access.
- Multiple comma-separated debug options now supported.
- PostgreSQL is now supported by sql variation module.
- Fix to sql.py variation module to work with Python older than 2.5.
- Fix to sql.py variation module to avoid 'Unread result found' MySQL error.
- The snmpwalk OPAQUE: Float: syntax is now supported.
- Fix to HEX value handling in snmpwalk format handler.
- Fix to absolute file log path on Windows.
- Fix to off-by-one errorIndex as reported by error.py and writecache.py
  variation modules.
- Fix to record parsers/builders to fail on empty values.
- Fix to snmprec.py & pcap2dev.py in part of processed OIDs counting.

Revision 0.2.4, released on Oct 04, 2013
----------------------------------------

- A tool for building SNMP Simulator data files from network
  packet captures added.
- Automatic online data file index rebuild on data file timestamp
  change implemented.
- The sql variation module tweaked to be better compliant with
  Python DB API 2.0 so that it can now work with MySQL out of
  the box. Module options also reworked to support named
  DB connect() parameters.
- Simulator can now run many independent SNMP engines each with its
  own set of data files listening at dedicated transport endpoints.
  At least pysnmp 4.2.5 is required for this feature to work.
- Simulator now accepts the --transport-id-offset command-line parameter
  to specify the initial transport ID instance for each transport domain
  configured.
- Variation module API changed to allow recording module to communicate
  to its host time of the next probe to occur.
- Variation module API changed so that SNMP engine ID is only available
  in variate() context. This is due to the new multi-engine ID design.
- New --args-from-file command-line parameter added to snmpsimd.py to
  allow a large number of SNMP engines configured to Simulator. The
  --agent-endpoint\*-list= family of options discontinued in favor of
  multiple --agent-\*-endpoint options read from args file.
- Distribute is gone, switching to setuptools completely.
- Default logging destination for all tools is now stderr.
- The --version option of snmprec.py renamed into --protocol-version.
- New command-line option --pid-file added.
- Daemonization under a non-root user now works.
- Fixes to time-based log file rotation implementation.
- Fixes to numeric variation module. Also, taglist parameter is now
  defaulted into all numerical types.
- Fix to PID file creation on daemonization.
- Fixes to stdio binary mode write to work with Python 3.

Revision 0.2.3, released on Aug 01, 2013
----------------------------------------

- Simulator now supports a list of interfaces to listen on through
  the --agent-endpoint\*-list=<file> family of options. It's intended
  for simulation a very large pool of devices.
- Introducing new command-line utility "datafile.py" designed to manage data
  files. Features include: merging, splitting, sorting, de-duplicating,
  conversion between data file formats.
- Automatic log file rotation feature implemented.
- A number of improvement to the mib2dev.py tool:

  * Columnar objects for table indices are now automatically populated
    from index values
  * Tables are can now be populated with arbitrary number of rows
  * Hex values can now be given at the prompt using the 0x syntax
  * Default automatic value ranges for integers are now much smaller
    to increase a chance of automatic selection.
  * Values ranges can now be set for each SNMP type separately.
  * When generating values, make N probes choosing random values for
    better automation
  * Produced values are sorted and de-duplicated.
  * Fix to OID range checking when specified at the command-line.

- Help messages made more readable and complete.
- Data file search code fixed (not to crash Simulator in corner cases)
  and simplified.
- Variable conflict fixed that broke --v2c-arch option operations.
- Fix to OIDs ordering in --v2c-arch GETBULK responder.
- Fix subprocess variation module to work with old Python(s).
- Source code linted and improved.

Revision 0.2.2, released on May 13, 2013
----------------------------------------

- Multiple USM user entries with potentially different auth&priv settings
  can now be configured to snmpsimd.py.
- Centralized logging facility added. Logging into syslog or file is
  now supported.
- Simulator process daemonization and privileges drop implemented.
- More logging added into snmpsimd.py, snmprec.py and variation modules
  to ease the understanding of their operation.
- The --quiet flag of snmprec.py now deprecated in favor of "null"
  logging method.
- Variation modules execution environment extended to provide contexts
  for three scopes: record, agent and module. This simplifies modules
  implementation in terms of storing and managing state/configuration
  information on per-OID/per-Agent and global basis.
- The snmprec.py tool now supports DNS names in c/l target parameter.
- New 'cumulative' flag added to the numeric.py variation module.
- The multiplex module improved to allow .snmprec file selection via
  SNMP SET.
- Fatal exceptions are now fully logged.
- Type checking is now performed on SET operation at writecache module.
- Fix to community names '/'-normalization at transport address based
  variation logic. It appeared broken on Windows only since 0.2.1.
- Fix to snmprec.py behaviour on missing variation module directory.
- Fix to .snmpwalk grammar parser to support Network Address type tag.
- Fix to multiplex.py module to let its multiple instances working
  independently (each for a subtree).
- Multiple fixes and re-work of the numeric.py module
- Fix to snmprec.py tool to write snmprec data to stderr in binary mode.
- Fix to OID search in a .snmprec in case of a subtree configured
  on the last line of .snmprec file.
- Fix to line separator character used in file logger -- now it's
  platform-dependent.

Revision 0.2.1, released on Apr 07, 2013
----------------------------------------

- WARNING: this release brings some backward incompatibilities in

    * variation modules names and options
    * snmpsimd.py community names (in Windows platform)
    * stock variation modules installation location
    * sql module OID format stored in database

  Please read the changes below for more information.

- License updated to vanilla BSD 2-Clause
  (http://opensource.org/licenses/BSD-2-Clause).
- Variation modules can now participate in .snmprec production what
  can be used for capturing additional information about SNMP Agent
  being snapshotted in .snmprec files.
  The following changes have been made to the system:

  * the snmprec.py tool can be passed variation module name.
  * variation modules can now define the 'record' callable which
    will be given a chance to influence snmprec record being written.
  * existing 'process' callable in variation modules renamed into
    'variate' for clarity.
  * variation modules' init() and shutdown() methods accept \*\*context,
    'mode' parameter being passed indicating current operation mode.
  * variation modules running in recording mode can communicate to
    the upper levels that they either won't produce any data on the
    current invocation or request another round of SNMP Agent walk.

- Variation modules options now take shape of a key-value pairs. This
  might break backward compatibility with 0.2.0!
- The counter.py and gauge.py variation modules merged into a single
  numeric.py module which also supports INTEGER&TIMETICKS values as
  well as recording feature.
- The involatilecache.py and volatilecache.py modules merged into a
  single writecache.py module which also supports SET value verification
  against per-OID access list.
- The error.py variation module extended to support variation based on
  SET value.
- The delay.py variation module extended to support variation based on
  SET value and time of date.
- Format of the OID stored in SQL database changed in a backward incompatible
  manner.
- Recording functionality added to the delay.py and numeric.py modules.
- The new "multiplex" variation module added to be able to record
  and replay a sequence of .snmprec files ordered by time.
- SNMP GETBULK operation is now supported by snmprec.py.
- Redesign of grammar objects -- the new concept is that they
  are only responsible for basic record layout, fields normalization.
  and SNMP types resolution. However complex field formatting (such
  as grammar-specific tag modifiers) is now up to higher-level
  'Record' objects.
- Simulator-generated community names now uses '/' as path separator
  regardless of the platform. This allows for unified Simulator view
  in terms of community and context names across the platforms.
- Snapshot files recording now works under Python3.
- Install data and variation modules into package root to make easy_install
  work again. Search these directories at runtime as a last resort - prefer
  system or home locations as it is more natural to keep changing data there.
- Simulator is now more tolerant to duplicate variation modules (just ignores
  recently found) and catches duplicate data files (also ignores more recent).
- On Windows, search both data and variation modules into %PROGRAMFILES%

Revision 0.2.0, released on Mar 12, 2013
----------------------------------------

- Major overhaul aimed at adding value variation features to the Simulator
  core:

  * data files may now hold not only terminal OIDs but also OID subtrees
  * pluggable value variation modules interfaces and basic modules added
  * write support added through the use of appropriate variation modules
  * SQL backend for keeping and modifying SNMP snapshots added in form of
    a value variation module
  * subprocess execution variation module added what could be used
    for external process invocation on SNMP request to Simulator
  * SNMP Notification Originator variation module added what could be
    used for sending SNMP TRAP/INFORM messages to SNMP entities
    on SNMP requests to Simulator

- SNMP snapshots now being called 'data files' rather than 'device files'
  which is a legacy term.
- Data files and variation modules are now installed into platform-specific
  directories.
- Data files and variation modules are now looked up at several,
  platform-specific, locations including $HOME/.snmpsim
- Simulator data files indices are now created and kept in a dedicated
  temporary directory which is also configurable though snmpsimd command-line.
- Example data files simplified, more native and foreign snapshots added.
- Fix to snmprec.py not to record end-of-mib.
- Fix to py2exe settings of setup.py

Revision 0.1.6, released on Jan 30, 2013
----------------------------------------

- Net-SNMP's .snmpwalk files created with the "snmpwalk -ObentU" command
  can now be used by the Simulator directly.
- SimpleAgentPro's .sapwalk files support added to Simulator.
- Fixes to --start-oid & --stop-oid params to make the working again.
- Simulator reports supported device files types on startup.
- Shared device files now supported. Snapshots can now be indicated
  as shared through a symbolic link. Managers can use different
  credentials to access and modify the same set of Managed Objects.

Revision 0.1.5, released on Aug 23, 2012
----------------------------------------

- Simulator device file selection by a combination of ContextName,
  Transport ID and source address implemented.
- Rudimentary MIB write support added (snmpset now works). Still need to
  support MIB-defined constraints.
- Fix to snmpsimd.py to ignore possibly missing .dbm file on failed
  index rebuild.
- Fix to OID search code what used to always pick the first OID in file
  while looking for EOL (Python3 only).

Revision 0.1.4, released on Jul 25, 2012
----------------------------------------

- Simulator device file selection by a combination of Community,
  Transport ID and source address implemented (for --v2c-arch mode).
- UDP/IPv6 and UNIX domain socket transports support added to
  snmpsimd.py and snmprec.py tools.
- The snmpsimd.py and snmprec.py tools now support additional SNMPv3
  authentication (SHA) and encryption (3DES, AES192, AES256) algorithms
  provided by pysnmp.
- Simulator now supports binding to and listening at multiple local
  endpoints. The --agent-address & --agent-port options are now obsolete.
- The snmprec.py tool Agent address specification syntax unified with that
  of snmpsimd.py.
- Multiple --device-dir c/l options are now supported by snmpsimd.py.
- Some runtime diagnostics added to snmprec.py.
- The snmpsimd.py tool unconditionally rebuilds existing indices of
  unknown format.
- Device files handling indexing made faster by not calling <fileobj>.tell().
  That also required opening files in 'binary' mode to make sure offset
  calculation will work correctly.
- Attempt to open DBM in "fast" and "unsync" modes when building indices
  to speed-up index generation.
- Package meta information updated.
- Fix to snmprec.py to make SNMP debugging working again.
- Fix to snmprec.py to properly support non-default SNMP context name.
- Fix to infinite loop possibly occurring at OID search routine.
- Fix to DBM key type (string vs byte issue)
- Fix to mib2dev.py MIB path handling.
- Fix to index object to make "snmpwalk -c index" work again.
- Fix to index object registration in --v2c-arch mode.
- Fix to SNMPv2 exception objects translation into SNMPv1 PDU in the
  --v2c-arch mode

Revision 0.1.3, released on Nov 12, 2011
----------------------------------------

- Initial revision of the mib2dev.py tool.
- Some more MIB-originated device files added.

Revision 0.1.2, released on Nov 09, 2011
----------------------------------------

- Some more py2k refactoring (some features did not work otherwise).
- Fix to values tags matching at snmpsimd.py (simulator did not work
  otherwise).
- Fixes to sys.exc_info invocation.

Revision 0.1.1, released on Nov 06, 2011
----------------------------------------

- Major overhaul for Python 2.4 -- 3.2 compatibility:
  + drop explicit long integer type use
  + map()/filter() replaced with list comprehension
  + apply() replaced with \*/\*\*args
  + dictionary operations made 2K/3K compatible
  + division operator made 2K/3K compatible
  + exception syntax made 2K/3K compatible
  + tuple function arguments resolved to scalars to become py3k compatible

Revision 0.0.10, released on Dec 31, 2010
-----------------------------------------

- --agent-port handling bug fixed in snmprec.py
- --v3-arch command-line flag added to save on large number of
  [expensive] addV1System() calls.
- setuptools dependencies improved

Revision 0.0.9, released on Dec 21, 2010
----------------------------------------

- Simulator now builds a table of loaded device files in a
  dedicated 'index' context.
- Use OS-specific file extension separator for better portability.
- Support .db extensions voluntarily added by gdbm on OS X.
- Fix to null-typed value read from .dump device file.
- Legacy SNMPv1/v2c community string generation policy dropped.
- SNMPv3 VACM initialization dropped altogether, as the specialized
  SMI backend used by Simulator does not implement access control.
- Fix to support zero-length device files.
- Ignore value syntax errors in device files occurred when responding.
- Optionally validate device file data while indexing.
- Allow forced device files re-indexing.
- Fix to broken IP address serialization code in recorder.

Revision 0.0.8, released on Dec 10, 2010
----------------------------------------

- Initial public release.
