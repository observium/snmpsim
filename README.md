# SNMP Simulator

[![GitHub license](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/observium/snmpsim/master/LICENSE.txt)

This is a pure-Python, open source and free implementation of SNMP agents simulator
distributed under the 2-clause [BSD license](LICENSE.txt).

> **snmpsim-ng** is a maintained line of snmpsim, the SNMP agent simulator, kept by the
> developers of [Observium](https://www.observium.org/). It carries fixes for recordings that
> the other release line refuses to serve, brings the recorders and the lite responder back to
> life, and adds a lint tool for recording repositories. The package named `snmpsim` on PyPI
> is a different release line, which does **not** contain these changes - see
> [Installation](#installation).

## Why the name snmpsim-ng

The project started as a fork of [lextudio/snmpsim](https://github.com/lextudio/snmpsim),
itself a continuation of Ilya Etingof's original. Until 2026.11.0 it was installed under the
same name, `snmpsim`, with the same version numbers, which made two different packages look
like one:

* the name `snmpsim` on PyPI belongs to the other release line, so this one could never be
  published there under it
* an installation could not tell which of the two it had - `snmpsim 1.2.2` was either
* the next version here would have been `1.2.3`, the number the other line is most likely to
  give its own next release

So it is distributed as `snmpsim-ng` and numbered by the calendar, `YYYY.M.N`, which sorts
above any `1.x` or `2.x`. The Python module and the `snmpsim-*` commands keep their names, so
scripts and recordings work unchanged.

## What snmpsim-ng adds

Compared with the release it was forked from:

* Tested on Python 3.15 as well: both CI workflows run the suite on Python 3.10 to 3.15, one
  of them on Linux, macOS and Windows
* Documentation of its own at <https://observium.github.io/snmpsim/>, built from
  `docs/source` and published on every change to it on `master`
* `snmpsim-command-responder` exits with status 1 and names the endpoint when it cannot bind it,
  e.g. `failed to bind UDP/IPv4 endpoint 127.0.0.1:1161: [Errno 48] Address already in use`.
  pysnmp 7 binds in a task nobody looked at, so with the port taken or an address the host does
  not have the responder logged "Listening", kept running and answered nothing
* `--v1-only` and `--v2c-only` make the responder speak a single SNMP version: requests of the
  other two versions get no response at all, so the manager times out exactly as with a real
  v1-only or v2c-only agent. Before, every endpoint answered v1, v2c and v3 alike, and a manager
  that wrongly fell back to another version was never caught; the two flags and `--v3-only` are
  mutually exclusive
* SNMPv3 users can be configured with the key itself instead of the passphrase:
  `--v3-auth-key-type` and `--v3-priv-key-type` take `passphrase` (default), `master` or
  `localized`, with master and localized keys given in hex (with or without `0x`). The responder
  used to hash every key as a passphrase, so a user known only by the 20-octet SHA key from a
  device configuration could never authenticate; a key of the wrong size (16 octets where SHA
  takes 20) now stops the responder at start-up
* SNMPv3 GETBULK responses fit the `msgMaxSize` the manager announces: the responder used to
  fill a response up to `--max-message-size` (1472 octets) whatever the manager could take, and
  the oversized response was then dropped without a word, so a manager asking for 484 octets
  only ever saw timeouts on a table of 200-octet rows; it now gets one row in 353 octets and the
  walk completes
* An error tells the manager which variable failed, and `noSuchObject`, `noSuchInstance` and
  `endOfMib` of the `error` variation module arrive as what they are: a GET of 3 OIDs with the
  2nd one failing reported error-index 1 unless the failed variable was the last of the request
  (GETNEXT, SET and GETBULK likewise), and the three statuses came out as `genErr` on every SNMP
  version; now error-index is 2, SNMPv2c and SNMPv3 managers get error-status 0 with the
  exception in the var-bind next to the values of the other variables, and SNMPv1 managers get
  `noSuchName` with the right index
* `--daemonize` of the full responder tells whether the daemon came up: the process you started
  waits until the daemon serves and exits with 0, or with 1 and the daemon's error if it died
  first (port in use, pid file not writable); relative `--data-dir`, `--cache-dir`,
  `--variation-modules-dir`, `--pid-file` and reports directory are taken from where it was
  started rather than from `/`. The lite responder daemonizes as before, without waiting
* `kill -HUP` makes the command responder rescan its data directories: new recordings are
  indexed and served, removed ones lose their community and have their files closed, the rest
  keeps answering meanwhile (slowest answer 140 ms while a 400000-record index was being built).
  Before, a new recording needed a restart, and SIGHUP ended a daemon and killed a foreground
  responder
* A changed recording is never served from an index left in the cache by another DBM backend:
  building an index removes all 9 file names the 4 dbm backends could use for it and the index
  is opened with the backend that built it. Before, a stale `<name>.dbm.db` from ndbm beside
  `<name>.dbm` made the responder re-index the recording on every start and still answer from
  the old file
* The responder keeps the most recently used data files open, up to `--max-open-data-files`
  (default: half of the soft `RLIMIT_NOFILE` less 64 descriptors, 256 at most); it used to hold
  31 in a first-in-first-out queue, so with ~1300 recordings polled in turn nearly every request
  closed one file and reopened another, a recording that failed to open pushed a good one out on
  every request, and the "Closing" log line named the wrong file
* Requests cost less when the log is turned down: with `--log-level error` or `--logging-method
  null` the request and response var-binds are no longer formatted for INFO lines that are then
  dropped, and an open data file is checked for changes at most once a second instead of on
  every lookup (100 requests within a second used to mean 100 `stat()` calls, now one); an
  edited recording is still picked up, at most a second later
* On start the responder builds missing and stale indexes in several processes
  (`--index-workers`, default one per usable CPU, 8 at most) instead of one by one, so a start
  over an empty cache no longer indexes ~1300 recordings one after another; each index is
  written under a temporary name until it is complete, so an interrupted build is never served
  from
* `snmpsim-record-commands` exits with 1 when a recording fails: `main()` returned from inside
  `finally`, so an exception raised during the walk was dropped and the exit code was 0, with a
  `SyntaxWarning` on every start under Python 3.14; a variation module that fails to initialize
  now stops the run before the walk, and a record it refuses or a failed shutdown counts as an
  error too
* Recording several passes with a variation module works without `--stop-object`: `multiplex`
  with `iterations:3` makes three snapshots `00000.snmprec`..`00002.snmprec` and `numeric` with
  `iterations` computes its rates; the module was never told that a walk had reached the end of
  the MIB, so multiplex stopped after one snapshot and numeric wrote an empty recording, both
  with exit code 0
* `snmpsim-record-traffic` writes each captured OID once and reads a capture to its end: the
  last OID of every recording used to be written twice (2 OIDs in the capture gave 3 records),
  the end-of-pass flag was never set so `numeric` and `multiplex` `iterations` never advanced,
  and the first UDP payload that was not BER stopped the conversion silently with exit code 0 -
  stray packets are now counted as bad and skipped, and a real error exits with 1 and names the
  packet
* An empty value is read as a zero-length string where the type is a string and reported as a
  broken record where it is not: `1.3.6.1.2.1.1.5.0|6|` in a `.dump` file used to hit an
  IndexError and lose the record, and an empty hex number such as `|2x|` in a `.snmprec` stopped
  `snmpsim-manage-records` with an ASN.1 schema error even under `--ignore-broken-records`
* `snmpsim-manage-records` says which line a broken record is on ("at line 7 (input file #0)")
  and reports lost comments at their real lines, also after walk values wrapped onto several
  lines; the line counter used to move only on comments, so a comment on line 2 was reported as
  "lines 1..1" and broken records carried no line number at all
* `numeric` options mean what they say: `--variation-module=numeric` with no options records
  with the defaults (`period` 10 s, `taglist` `2-65-66-67-70`), which used to apply only when
  some other option was given and otherwise left plain values; `wrap=0`, `cumulative=0` and
  `atime=0` switch the feature off instead of on; a record with an empty value field
  (`65:numeric|`) runs on the defaults instead of raising `ValueError`; and the docs say that
  `iterations` is 0 for one walk or anything else for exactly two
* `snmpsim-record-mibs` gives tables that share an index the same rows: `ifXTable` (and any
  table that `AUGMENTS` another or repeats its `INDEX` clause) now has exactly the row indexes
  of `ifTable`, also across the MIB modules of one run. Before, every table drew its own random
  indexes, so a generated IF-MIB had 10 interfaces with counters and 10 other interfaces with
  names
* `snmpsim-record-mibs` generates values the MIB permits and never stops to ask: enumeration
  members, numbers inside the value ranges, strings of a permitted size, 6 random octets for a
  `MacAddress`, named bits for `BITS`. It used to try a random 0..32 number or a few words
  against the constraints 5000 times and then prompt at the terminal, so IF-MIB stopped at
  `ifPhysAddress`, and with stdin closed the prompt was printed for ever; an object no value
  fits is now reported once and left out, and IF-MIB (519 records) generates unattended
* Documentation sources that describe this project: the Sphinx pages no longer publish to the
  other release line's address, name its company as author, announce its product, load its
  analytics and ad blocks or need its fork of sphinx-sitemap; examples use 192.0.2.1 instead of
  a public demo agent, the quick start installs from git on POSIX and Windows and serves a
  five-line data file the reader writes rather than a recording from `snmpsim-data` (which pulls
  in `snmpsim` 1.x), and the build needs only the new `docs` extra
* The documentation describes this project and not the one it was forked from: the command-line
  reference covers `snmpsim-record-commands` (with `--protocol-version 3` and the USM options),
  `snmpsim-manage-records` and `snmpsim-lint-records`, the dumping period of
  `--reporting-method` and the directories that are really searched, and a "Migrating from
  snmpsim" page explains the package name, the uninstall step, the calendar versions and what
  answers differently from snmpsim 1.2.2. The pages named 6 options no command takes
  (`--start-oid`, `--stop-oid`, `--max-varbinds`, `--manual-value`,
  `--agent-udpv4-endpoints-list`, `--agent-udpv6-endpoints-list`), listed search paths like
  `/usr/snmpsim/data` and `\Document and Settings`, and said nothing of recording over SNMPv3
* Recording through a variation module works again. `snmpsim-record-commands` handed the start
  OID to the module under a name none of them reads, so `--variation-module=multiplex`, `sql`
  and `redis` failed on the first OID and left an empty recording; it is passed as `startOID`
  now, the name the modules expect
* The `multiplex` module closes the snapshot it records when the recorder is done. It did so
  only on a stop record, which a walk to the end of the MIB never produces, so the only
  snapshot of such a recording was left open and could come out empty next to a recording
  that looked fine
* `multiplex` snapshots are named `00000.snmprec`, not `00000..snmprec`: the responder could
  not make a number of the two-dot name, so what the module recorded it would not serve.
  Snapshots already recorded under the old name are served as well, and give way to one
  recorded since under the new name
* `multiplex` serves the snapshot whose turn it is. It kept the snapshot numbers as the system
  listed the files, in no particular order, and looked them up as if they were sorted, so
  with several snapshots the wrong one could be served, depending on the file system
* `snmpsim-record-commands` records over SNMPv3: `--v3-user` alone now selects protocol version
  3 (noAuthNoPriv, authNoPriv and authPriv, GETNEXT or GETBULK), and a v3 recording of the test
  agent is byte-for-byte the v2c one. `--protocol-version` used to accept only `1` and `2c`, so
  every `--v3-*` option was dead code and the recorder kept asking over v2c with the `public`
  community, dumping 0 OIDs from a v3-only agent
* Opaque Float and Double values survive conversion from snmpwalk output:
  `Opaque: Float: 100.000000` is recorded as `68x|9f780442c80000` and `Opaque: Double: 1.5` as
  `68x|9f79083ff8000000000000`, the encoding net-snmp agents send. Before, the `Float:` prefix
  was stripped twice, so 100.000000 was recorded as 0 and 12.5 aborted the conversion, the
  stored value was a BER Real no manager reads as a float, and Double was not recognised at all
* Strings in `snmpwalk` output keep their non-ASCII octets. Every octet from 0x80 up used to be
  deleted on conversion, so a `sysName` of `Привет` in UTF-8 or cp1251 became an empty string.
  `sapwalk` values no longer lose a trailing `0x85` or `0xa0` octet, and a UTF-8 byte order
  mark at the start of a walk saved on Windows is skipped
* `snmpsim-manage-records` reads the values `snmpwalk` wraps onto several lines: a `Hex-STRING`
  continued after every sixteen octets and a quoted `STRING` with newlines inside each become
  one record, from a file or from a pipe. Every line of a walk used to be taken for a record,
  so a 40-octet `Hex-STRING` came out 16 octets long with its other two lines reported as
  broken, and `"first\nsecond"` became the value `"first` with the opening quote still on it. A
  string that never closes ends at the next record, whether its OID is numeric or a name,
  instead of swallowing the rest of the walk. The backslash `snmpwalk` puts before each quote
  and backslash of a quoted `STRING` is dropped as well: `"C:\\Temp \"x\""` was recorded three
  octets longer than what the device sent
* `snmpsim-manage-records` skips the walk and sapwalk lines it cannot convert under
  `--ignore-broken-records` and otherwise stops with a message that quotes the line: a walk
  taken without `-On` (`SNMPv2-MIB::sysName.0 = STRING: switch`) used to end in a `PyAsn1Error`
  traceback and a sapwalk value like `0x73ZZ` in a `ValueError`, with or without the option,
  and under `--quiet` a broken record made the command exit 1 without saying anything
* `snmpsim-manage-records` converts recordings larger than memory: records are written as they
  are read unless `--sort-records` is asked for. Every record used to be held in a list until
  the last line was read, so a 37 MB walk of 600000 lines took 742 MB (48 MB now) and a 221 MB
  one ran out of memory
* Recording with the `numeric` variation module accepts its options (`taglist`, `iterations`,
  `period`, `addon`) again; they used to fail to parse, so the recording came out as plain
  values. A malformed option is reported by name and none of the options are applied
* The `numeric` variation module answers records with a `deviation` again, and its
  documentation states the formula it really computes: on Python 3.12+ every request for e.g.
  `66:numeric|initial=100,deviation=2` failed with
  `'float' object cannot be interpreted as an integer` (the float setting went straight into
  `random.randrange()`), which broke the documentation's own COUNTER example; the documented
  formula showed `offset` as a plain addend although with `cumulative` it is multiplied by
  `rate` and the seconds since the previous request, said `wrap=0` freezes although it wraps,
  and gave the default `max` as `2**32` instead of `2**32 - 1`. A test now executes the formula
  from the docs against the module for 22 records
* `writecache` records can hold hex-encoded initial values: `64x:writecache|value=c0000219`
  serves the IP address 192.0.2.25 and `4x:writecache|value=414243` serves `ABC`. The module
  used to drop the `x` flag of the tag, so the first record failed on every request and
  vanished from walks and the second served the six characters `414243`; the `e` flag and the
  constants of `vlist` follow the flag too
* The `subprocess` variation module returns what the program printed without the line ending:
  `4:subprocess|echo hello` is the 5 octets of `hello` and `4x:subprocess|echo 07e30307` is 4
  octets; before, the string came back as 6 octets with a trailing `\n` and the hex value as 5,
  unless the command was `echo -n`. Exactly one trailing LF (or CRLF) is dropped, everything
  else the program printed is kept
* The `error` variation module returns `noSuchName`, `badValue` and `readOnly` to SNMPv1
  managers: `4:error|status=noSuchName` used to answer a v1 GET with error-status 5 (`genErr`)
  instead of 2, and `badValue`/`readOnly` on SET with 5 instead of 3 and 4, as pysnmp has no
  SNMPv1 translation for these three codes
* The `notification` module sends SNMPv3 traps and informs without breaking the agent: it has
  an SNMP engine of its own under the agent's engine ID, and accepts all 7 auth and 9 privacy
  protocol names the responder does (`sha256`, `aes256`, ...). Before, a trap sent as the
  agent's own user overwrote that user's keys and every v3 GET after it failed with a wrong
  digest until restart, and only `md5`/`sha` and `des`/`aes` were known
* Data and variation directories are found on Windows under the user's real profile
  (`USERPROFILE`, then `HOMEDRIVE` + `HOMEPATH`) and on Linux under
  `/usr/local/share/snmpsim/{variation,data}` as well; the Windows path came from `HOMEPATH`,
  which has no drive letter, and all 3 environment variables it read were mandatory, so a
  service account without them got `KeyError` from every command before it parsed its arguments
* The `sql` variation module survives a database restart: a request that fails because the
  connection is gone is repeated once on a new connection made with the same parameters, and if
  the database is still away the next request tries again. A request the database itself refuses
  (no such table, bad SQL) is reported without reconnecting: the module tells the two apart with
  a `select 1` on the connection it has. Every database error rolls the failed request's
  transaction back, the earlier variable bindings of the same SET message included. The module
  used to open one connection at start and keep it for good, so after a server restart, or after
  MySQL closed a connection idle for its `wait_timeout` (8 hours by default), every
  database-backed OID failed until the simulator was restarted
* `snmpsim-command-responder-lite` takes `--args-from-file`, with the same file format as the
  full responder (`--option=value` items separated by whitespace) and any of its options allowed
  in the file; the command line overrides the file for an option that takes one value and adds
  to it for a repeatable one such as `--data-dir`, and cannot switch off an on/off option such
  as `--daemonize` that the file sets; before, the option existed only in the full responder and
  the lite one rejected it as "unrecognized arguments", so hundreds of endpoints had to fit on
  one command line
* The lite responder and `snmpsim-record-traffic` no longer depend on pysnmp's last camelCase
  leftover: both called `api.decodeMessageVersion`, a pre-7 alias of
  `verdec.decode_message_version`, and without it the responder answers nothing and the
  converter writes no recording without saying why
* Its own package name and version line: it installs as `snmpsim-ng` and is numbered by the
  calendar, `2026.11.0` for the first release - see
  [Why the name snmpsim-ng](#why-the-name-snmpsim-ng). The `snmpsim` module and the
  `snmpsim-*` commands keep their names
* `snmpsim-record-commands` reports its progress as the number of OIDs recorded so far,
  `OIDs dumped: 300`, rather than `0/300` - the `0` was the pass of a variation module
  that walks repeatedly, and it is now shown only for one. The closing rate is every OID
  over the elapsed time: it used to floor-divide the count of the last pass only, so 362
  OIDs in 71.18 sec read as `5.00 OIDs/sec` and a multi-pass recording as `0.00`
* Only pysnmp 7's own names are called. `snmpsim-record-mibs`, `snmpsim-manage-records`,
  `snmpsim-record-traffic` and the index context of both responders still went through its
  pre-7 camelCase aliases (`importSymbols`, `resolveWithMib`, `nextKey` and others), which
  pysnmp keeps only as deprecated wrappers that warn on every call
* An integer a device sent outside the range of its type is recorded and served as it came
  off the wire. `.1.3.6.1.2.1.6.4.0 = INTEGER: 4294967295` - a `tcpMaxConn` of `-1` put on
  the wire unsigned - could not be converted at all (`value evaluation error ... at
  Integer`) and could not be answered either, since pyasn1 refuses to build an `Integer32`
  above 2147483647. The record now keeps the value and the responder puts back the very
  octets the device sent, `02 05 00 ff ff ff ff`; `snmpsim-lint-records` reports it as a
  warning. `Counter32`, `Gauge32`, `Unsigned32`, `TimeTicks` and `Counter64` values above
  their maximum are kept the same way
* A record whose value cannot be BER-encoded no longer silences the responder. A single-arc
  OID (`6|0`) is served as `0.0`, which is byte for byte what the device put on the wire;
  values which cannot be repaired answer `noSuchInstance` on GET and are stepped over on
  GETNEXT/GETBULK, so one broken line no longer truncates the rest of the walk
* `snmpsim-lint-records`, which checks a recording file or a whole directory by actually
  encoding every value, and exits non-zero on errors, so a broken recording is found before
  it turns into a mystery timeout
* `--daemonize` works again: the event loop is created after the fork rather than before it
* `pysmi` and `cryptography` are declared as dependencies - both are imported at runtime, and
  without them a fresh installation cannot start
* Trailing spaces are preserved in escaped values, so an `IpAddress` ending in `.32` (the
  byte `0x20`) is no longer cut short and dropped
* `snmpsim-command-responder-lite` runs again. It aborted at startup on pysnmp 7, and behind
  that crash every request path was broken as well, including the IPv6 endpoint and the
  index context shared with the full responder
* `snmpsim-record-commands` and `snmpsim-record-traffic` work again. The first one used to
  record nothing and hang; the second could not start at all, since it required a capture
  library which has not been installable for years - capture files are now read directly,
  and that library is needed only for live capture off an interface
* The recorder walks agents through pysnmp's `hlapi`, the supported way to walk one in
  pysnmp 7
* A recording filed under the requester's source address is served again. The command
  responders hooked into a pysnmp method which was renamed in 7.x, so the hook - and with it
  address-based selection - had been dead code, and every client got the plain recording
* A GETBULK response is cut short to fit into a single, unfragmented UDP datagram, the way
  real agents behave. Recordings with long values answered with several kilobytes at once -
  3171 octets for `-Cr64` on an EndRun Tempus LX - and where a fragment of that reply did not
  reach the manager, the walk stalled with a timeout at the same OID every time. The limit is
  `--max-message-size`, 1472 octets by default; the same change makes `--max-var-binds` work
  again
* No submodule to check out: the CI helper scripts lived in a third-party repository, and the
  workflow now runs `uv` and `pytest` directly, so a plain `git clone` is all it takes to
  build and test this
* An index can be closed whether or not it was ever opened. `RecordIndex.create()` builds
  an index without opening it, and closing one then died on a file handle that was never
  there - which is what the `multiplex` variation module does between files, and what
  anything building indexes ahead of a restart does
* Activity reporting (`--reporting-method=fulljson:<dir>`) produces something at all. Three
  faults sat on top of each other: the dump was built in a temporary file under `/tmp` and
  renamed into the reports directory, which fails wherever `/tmp` is a filesystem of its own;
  the endpoint the counters are indexed by had been commented out in the pysnmp 7 port, so
  every update died on a `KeyError` and left dumps carrying nothing but a header; and the
  transport protocol was read off the class of the peer address, which pysnmp 7 hands over as
  a plain tuple, so every request was filed under `unknown` - and that tuple could not be a
  JSON key either. Counters now also survive a dump that could not be written, instead of
  being cleared along with it
* `--reporting-method` accepts a Windows path. Splitting the argument on every colon cut the
  reports directory in half at its drive letter and left the responder reading the rest of
  the path as its dumping period, so it refused to start; only a trailing run of digits is
  taken for the period now
* Indexes are built with gdbm where the interpreter has it, instead of the `dbm.sqlite3`
  backend Python 3.13 made the default, which fsyncs every write: 5.0s against 10.9s for the
  index of a 35 MB recording, and a smaller index at that. On Debian and Ubuntu gdbm comes
  from the `python3-gdbm` package; without it nothing changes

## The original author

snmpsim was created by **Ilya Etingof**. He released the first version in December 2010 and
carried it, together with the whole Python SNMP stack it stands on — pysnmp, pysmi and
pyasn1 — through eight years and twenty-odd releases, the last of them in February 2019. The
original project is [etingof/snmpsim](https://github.com/etingof/snmpsim).

Everything this simulator is remains his design: the `.snmprec` format, recording a live
agent and replaying it, the variation modules, serving thousands of agents out of one
process. What came after him — the releases of other maintainers, and the work in
snmpsim-ng — is maintenance on top of that.

Ilya died in 2022. Thank you, Ilya, for a tool that a great many people still test their
monitoring against, years later.

## Features

* SNMPv1/v2c/v3 support
* SNMPv3 USM supports MD5/SHA/SHA224/SHA256/SHA384/SHA512 auth and
  DES/3DES/AES128/AES192/AES256 privacy crypto algorithms (including the Blumenthal
  AES192/AES256 variants)
* Runs over IPv4 and/or IPv6 transports
* Simulates many EngineID's, each with its own set of simulated objects
* Varies response based on SNMP Community, Context, source/destination addresses and ports
* Can gather and store snapshots of SNMP Agents for later simulation
* Can run simulation based on MIB files, snmpwalk and sapwalk output
* Can gather simulation data from network traffic or tcpdump snoops
* Can gather simulation data from external program invocation or a SQL database
* Can trigger SNMP TRAP/INFORMs on SET operations
* Capable to simultaneously simulate tens of thousands of Agents
* Gathers and reports extensive activity metrics
* Pure-Python, easy to deploy and highly portable
* Can be extended by loadable Python snippets

## Installation

Python 3.10 or newer is required.

### From a release

Releases are published on the [Releases](https://github.com/observium/snmpsim/releases) page,
each with a wheel and a source archive and tagged with its version. Install the current one
with `pipx`, which keeps the simulator in an environment of its own and puts its commands on
your `PATH`:

```bash
pipx install "git+https://github.com/observium/snmpsim.git@2026.11.1"
```

or from the release's wheel, without git:

```bash
pipx install https://github.com/observium/snmpsim/releases/download/2026.11.1/snmpsim_ng-2026.11.1-py3-none-any.whl
```

With `pip`, into the environment of your choice, or as a `uv` tool, the same specifiers work:

```bash
pip install "git+https://github.com/observium/snmpsim.git@2026.11.1"
```

```bash
uv tool install "git+https://github.com/observium/snmpsim.git@2026.11.1"
```

Replace `2026.11.1` with the release you want. snmpsim-ng is not on PyPI yet, and
`pip install snmpsim` installs the other release line, which has none of the changes listed
under [What snmpsim-ng adds](#what-snmpsim-ng-adds).

### The development version

`master` carries what is going into the next release; see the topmost section of
[CHANGES.rst](CHANGES.rst). Install it by naming the branch instead of a release:

```bash
pipx install "git+https://github.com/observium/snmpsim.git@master"
```

Any commit works the same way, for example `@8c804dc`.

### Updating

An installation from git or from a wheel has no package index to compare against, so nothing
upgrades by itself. Install the newer release over the top, with the flag which says "yes,
replace what is there" - in the commands below, put the release you are moving to in place of
`2026.11.1`; a wheel URL takes `--force` the same way:

```bash
pipx install --force "git+https://github.com/observium/snmpsim.git@2026.11.1"
```

```bash
pip install --upgrade --force-reinstall "git+https://github.com/observium/snmpsim.git@2026.11.1"
```

```bash
uv tool install --force "git+https://github.com/observium/snmpsim.git@2026.11.1"
```

`pipx` keeps packages added with `pipx inject` across a `--force` reinstall, and dependencies
are re-resolved, so a newer pysnmp arrives with it.

#### Coming from an installation named `snmpsim`

Before 2026.11.0 snmpsim-ng installed under the name `snmpsim`. A reinstall does not
replace that one: the new name is a different package, which ships the same `snmpsim` module
and the same commands. `pipx` would not touch the `snmpsim-*` links already on the `PATH`,
so they kept running the old environment, and `pip` would leave two packages writing over
each other's files. Remove the old one
first, then install as above:

```bash
pipx uninstall snmpsim
```

```bash
pip uninstall snmpsim
```

```bash
uv tool uninstall snmpsim
```

`pipx uninstall` also drops whatever was added with `pipx inject`; re-add it to the
`snmpsim-ng` environment afterwards.

#### After updating

A responder already running keeps serving the code it started with: restart it afterwards.
The same goes for changed recordings — the running process holds byte offsets into the files
it indexed at startup.

### For development

```bash
git clone https://github.com/observium/snmpsim.git
```

Install the package in editable mode along with its test dependencies:

```bash
pip install -e ".[dev]"
```

Run the test suite with `pytest tests`. Most of its wall clock is spent waiting: each
responder test starts a real agent and then waits out `SNMPSIM_TEST_TIMEOUT`, 15 seconds by
default. Lower it to keep the loop tight:

```bash
SNMPSIM_TEST_TIMEOUT=3 pytest tests
```

Two workflows run on every push to `master` and on pull requests, unless the change touches
documentation only. `build-test.yml` builds the package and runs the suite on Linux, macOS
and Windows on Python 3.10 to 3.15. `tests.yml` runs the same suite on Linux
only, but plainly - no coverage and, more to the point, no retries, which is how it catches
failures the retrying workflow lets through.


## Commands

Installing the package puts these commands on your `PATH`:

| Command | Purpose |
|---|---|
| `snmpsim-command-responder` | The simulator itself: serves recordings over SNMPv1/v2c/v3 |
| `snmpsim-command-responder-lite` | Lighter responder: SNMPv1/v2c only, no SNMPv3 |
| `snmpsim-lint-records` | Checks recordings for values which cannot be served (snmpsim-ng only) |
| `snmpsim-manage-records` | Converts, sorts, deduplicates, filters and repairs recording files |
| `snmpsim-record-commands` | Builds a recording by querying a live SNMP agent |
| `snmpsim-record-mibs` | Builds a recording from MIB files |
| `snmpsim-record-traffic` | Builds recordings from captured network traffic |

## How to use SNMP simulator

Once installed, invoke `snmpsim-command-responder` and point it to a directory
with simulation data:

``` bash
$ snmpsim-command-responder --data-dir=./data --agent-udpv4-endpoint=127.0.0.1:1024
```

Simulation data is stored in simple plain-text files having OID|TYPE|VALUE
format:

``` bash
$ cat ./data/public.snmprec
1.3.6.1.2.1.1.1.0|4|Linux 2.6.25.5-smp SMP Tue Jun 19 14:58:11 CDT 2007 i686
1.3.6.1.2.1.1.2.0|6|1.3.6.1.4.1.8072.3.2.10
1.3.6.1.2.1.1.3.0|67|233425120
1.3.6.1.2.1.2.2.1.6.2|4x|00127962f940
1.3.6.1.2.1.4.22.1.3.2.192.21.54.7|64x|c3dafe61
...
```

Simulator maps query parameters like SNMP community names, SNMPv3 contexts or
IP addresses into data files.

Before putting new recordings into service, check that every value in them can actually be
served:

``` bash
$ snmpsim-lint-records ./data
./data/huawei-s2326.snmprec:812: WARNING: short OID value '0' is served as 0.0
./data/huawei-s2326.snmprec:836: ERROR: value evaluation error for tag '6', value '': empty OID value
# Checked 3714 record(s) in 12 file(s): 1 error(s), 1 warning(s)
```

Warnings mark values the simulator repairs on the fly, errors mark records it cannot serve at
all. The exit status is non-zero when there are errors, so this works as a repository check;
`--quiet` reports errors only and `--strict` fails on warnings as well.

You can immediately generate simulation data file by querying existing SNMP agent:

``` bash
$ snmpsim-record-commands --agent-udpv4-endpoint=192.0.2.1 \
    --output-file=./data/public.snmprec
SNMP version 2c, Community name: public
Querying UDP/IPv4 agent at 192.0.2.1:161
Agent response timeout: 3.00 secs, retries: 3
Sending initial GETNEXT request for 1.3.6 (stop at <end-of-mib>)....
OIDs dumped: 182, elapsed: 11.97 sec, rate: 15.20 OIDs/sec, errors: 0
```

If you are recording a device so that Observium can support it, follow
[Requesting device support](https://snmpdump.observium.cloud/) — it describes which parts of
the tree to capture and where to send the result.

Alternatively, you could build simulation data from a MIB file:

``` bash
$ snmpsim-record-mibs --output-file=./data/public.snmprec \
    --mib-module=IF-MIB
# MIB module: IF-MIB, from the beginning till the end
# Starting table IF-MIB::ifTable (1.3.6.1.2.1.2.2)
# Synthesizing row #1 of table 1.3.6.1.2.1.2.2.1
...
# Finished table 1.3.6.1.2.1.2.2.1 (10 rows)
# End of IF-MIB, 177 OID(s) dumped
```

Or even sniff on the wire, recover SNMP traffic there and build simulation
data from it.

Besides static files, SNMP simulator can be configured to call its plugin modules
for simulation data. We ship plugins to interface SQL and noSQL databases, file-based
key-value stores and other sources of information.

## Documentation

The documentation is published at <https://observium.github.io/snmpsim/>: a quick start,
the command reference, the variation modules, a page on moving over
from `snmpsim`, and the changelog. It is built from [docs/source](docs/source) on `master`
each time the documentation changes there, so it describes `master` - where an option is
newer than the release you run, [CHANGES.rst](CHANGES.rst) says which release brought it,
and each command's `--help` lists what the installed version has.

## Who maintains this

snmpsim-ng is maintained by the developers of [Observium](https://www.observium.org/), the
network monitoring platform, who run it in production: a public simulator serving a
repository of about 1300 device recordings, which Observium is tested against. Fixes here
come from that use — every one of them was something a real recording of a real device ran
into.

So questions about snmpsim-ng, about `.snmprec` recordings, or about simulating a device you
are trying to monitor are welcome:

* [open an issue](https://github.com/observium/snmpsim/issues) in this repository
* ask on [Discord](https://discord.observium.cloud/), or through the other
  [Observium community channels](https://docs.observium.org/community/)
* capturing a device so that it can be supported:
  [Requesting device support](https://snmpdump.observium.cloud/) walks through what to
  record and where to send it
* [Observium documentation](https://docs.observium.org/) and [website](https://www.observium.org/)

## Feedback and collaboration

Bug reports, fixes, suggestions, improvements, and your pull requests are very
welcome!

Copyright (c) 2010-2019, [Ilya Etingof](mailto:etingof@gmail.com).
Copyright (c) 2022-2026, [LeXtudio Inc.](mailto:support@lextudio.com).
Copyright (c) 2026, Mikhail Stupalov.
All rights reserved.
