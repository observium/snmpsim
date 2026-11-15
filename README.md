# SNMP Simulator

[![GitHub license](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/observium/snmpsim/master/LICENSE.txt)

This is a pure-Python, open source and free implementation of SNMP agents simulator
distributed under 2-clause [BSD license](https://www.pysnmp.com/snmpsim/license.html).

> **This is Observium's fork of [lextudio/snmpsim](https://github.com/lextudio/snmpsim).**
> It carries fixes for recordings that the upstream responder refuses to serve, and adds a
> lint tool for recording repositories. It is distributed as **`snmpsim-ng`**; the package
> named `snmpsim` on PyPI is the upstream release, which does **not** contain these changes -
> see [Installation](#installation) for how to install this fork. Every code change here is also filed upstream; this README is not.

## What this fork adds

Most items were also filed upstream; those link to their pull request:

* Recording through a variation module works again. `snmpsim-record-commands` handed the start
  OID to the module under a name none of them reads, so `--variation-module=multiplex`, `sql`
  and `redis` failed on the first OID and left an empty recording; it is passed as `startOID`
  now, the name the modules expect
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
  connection is gone is repeated once on a new connection made with the same parameters, and
  if the database is still away the next request tries again. A request the database itself
  refuses (no such table, bad SQL) is reported without reconnecting: the module tells the two
  apart with a `select 1` on the connection it has. The module used to open one connection
  at start and keep it for good, so after a server restart, or after MySQL closed a connection
  idle for its `wait_timeout` (8 hours by default), every database-backed OID failed until the
  simulator was restarted
* `snmpsim-command-responder-lite` takes `--args-from-file`, with the same file format as the
  full responder (`--option=value` items separated by whitespace) and any of its options allowed
  in the file; the command line overrides the file for an option that takes one value and adds
  to it for a repeatable one such as `--data-dir`; before, the option existed only in the full
  responder and the lite one rejected it as "unrecognized arguments", so hundreds of endpoints
  had to fit on one command line
* The lite responder and `snmpsim-record-traffic` no longer depend on pysnmp's last camelCase
  leftover: both called `api.decodeMessageVersion`, a pre-7 alias of
  `verdec.decode_message_version`, and without it the responder answers nothing and the
  converter writes no recording without saying why
* Its own package name and version line: the fork installs as `snmpsim-ng` and is numbered
  by the calendar, `2026.11.0` for the first release. It used to call itself `snmpsim
  1.2.2`, the very name and number of the upstream release it no longer matches, and its
  next version would have been `1.2.3`, the number upstream is most likely to use next. The
  `snmpsim` module and the `snmpsim-*` commands keep their names
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
  ([#14](https://github.com/lextudio/snmpsim/pull/14))
* `snmpsim-lint-records`, which checks a recording file or a whole directory by actually
  encoding every value, and exits non-zero on errors, so a broken recording is found before
  it turns into a mystery timeout ([#14](https://github.com/lextudio/snmpsim/pull/14))
* `--daemonize` works again: the event loop is created after the fork rather than before it
  ([#15](https://github.com/lextudio/snmpsim/pull/15))
* `pysmi` and `cryptography` are declared as dependencies - both are imported at runtime, and
  without them a fresh installation cannot start
  ([#16](https://github.com/lextudio/snmpsim/pull/16))
* Trailing spaces are preserved in escaped values, so an `IpAddress` ending in `.32` (the
  byte `0x20`) is no longer cut short and dropped
  ([#12](https://github.com/lextudio/snmpsim/pull/12))
* `snmpsim-command-responder-lite` runs again. It aborted at startup on pysnmp 7, and behind
  that crash every request path was broken as well, including the IPv6 endpoint and the
  index context shared with the full responder
  ([#17](https://github.com/lextudio/snmpsim/pull/17))
* `snmpsim-record-commands` and `snmpsim-record-traffic` work again. The first one used to
  record nothing and hang; the second could not start at all, since it required a capture
  library which has not been installable for years - capture files are now read directly,
  and that library is needed only for live capture off an interface
  ([#18](https://github.com/lextudio/snmpsim/pull/18))
* Here the recorder walks agents through pysnmp's `hlapi`, which its maintainer confirmed is
  now the only supported way to walk one ([pysnmp#251](https://github.com/lextudio/pysnmp/issues/251)) -
  the pull request above carries the smaller fix, written against the low-level API, so that
  upstream has less to review
* A recording filed under the requester's source address is served again. The command
  responders hooked into a pysnmp method which was renamed in 7.x, so the hook - and with it
  address-based selection - had been dead code, and every client got the plain recording
  ([#20](https://github.com/lextudio/snmpsim/pull/20))
* A GETBULK response is cut short to fit into a single, unfragmented UDP datagram, the way
  real agents behave. Recordings with long values answered with several kilobytes at once -
  3171 octets for `-Cr64` on an EndRun Tempus LX - and where a fragment of that reply did not
  reach the manager, the walk stalled with a timeout at the same OID every time. The limit is
  `--max-message-size`, 1472 octets by default; the same change makes `--max-var-binds` work
  again ([#21](https://github.com/lextudio/snmpsim/pull/21))
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
  ([#19](https://github.com/lextudio/snmpsim/pull/19))

## The original author

snmpsim was created by **Ilya Etingof**. He released the first version in December 2010 and
carried it, together with the whole Python SNMP stack it stands on — pysnmp, pysmi and
pyasn1 — through eight years and twenty-odd releases, the last of them in February 2019. The
original project is [etingof/snmpsim](https://github.com/etingof/snmpsim).

Everything this simulator is remains his design: the `.snmprec` format, recording a live
agent and replaying it, the variation modules, serving thousands of agents out of one
process. What came after him — LeXtudio's releases upstream, and the fixes in this fork — is
maintenance on top of that.

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

### From this repository

This fork is distributed as `snmpsim-ng`. It is not on PyPI yet, so install it straight from
git. With `pipx`, which keeps
the simulator in its own environment and puts its commands on your `PATH`:

```bash
pipx install "git+https://github.com/observium/snmpsim.git@master"
```

With `pip`, into the environment of your choice:

```bash
pip install "git+https://github.com/observium/snmpsim.git@master"
```

Replace `@master` with any branch or commit to pin a particular revision, for example
`@8a244ea`.

If you use `uv`, the same specifier works as a tool install:

```bash
uv tool install "git+https://github.com/observium/snmpsim.git@master"
```

### Updating

git is not a package index, so an installation from it has no version to compare against and
nothing upgrades by itself. Install over the top instead — the same command, with the flag
which says "yes, replace what is there":

```bash
pipx install --force "git+https://github.com/observium/snmpsim.git@master"
```

```bash
pip install --upgrade --force-reinstall "git+https://github.com/observium/snmpsim.git@master"
```

```bash
uv tool install --force "git+https://github.com/observium/snmpsim.git@master"
```

`pipx` keeps packages added with `pipx inject` across a `--force` reinstall, and dependencies
are re-resolved, so a newer pysnmp arrives with it.

#### Coming from an installation named `snmpsim`

Before 2026.11.0 the fork installed under the upstream name, `snmpsim`. A reinstall does not
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

Two workflows run on every push. `build-test.yml`, inherited from upstream, builds the
package and runs the suite on Linux, macOS and Windows across all supported Python versions.
`tests.yml` runs the same suite on Linux only, but plainly - no coverage and, more to the
point, no retries, which is how it catches failures the retrying workflow lets through.

<details>
<summary>Installing the upstream release from PyPI instead</summary>

`pip install snmpsim` fetches the package LeXtudio publishes, which is **not** this fork
(`snmpsim-ng`): it
contains none of the fixes listed at the top of this file, so recordings which trip over any
of them behave there as they did before. Use it only if you specifically want the upstream
release.

</details>

## Commands

Installing the package puts these commands on your `PATH`:

| Command | Purpose |
|---|---|
| `snmpsim-command-responder` | The simulator itself: serves recordings over SNMPv1/v2c/v3 |
| `snmpsim-command-responder-lite` | Lighter responder: SNMPv1/v2c only, no SNMPv3 |
| `snmpsim-lint-records` | Checks recordings for values which cannot be served (fork only) |
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
$ snmpsim-record-commands --agent-udpv4-endpoint=demo.pysnmp.com \
    --output-file=./data/public.snmprec
SNMP version 2c, Community name: public
Querying UDP/IPv4 agent at 128.203.82.143:161
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

Detailed information on SNMP simulator usage could be found at
[snmpsim site](https://www.pysnmp.com/snmpsim/). It documents the upstream project; the
additions listed at the top of this file are covered by their pull requests and by
`--help` of the commands themselves.

## Who maintains this

This fork is maintained by the developers of [Observium](https://www.observium.org/), the
network monitoring platform, who run it in production: a public simulator serving a
repository of about 1300 device recordings, which Observium is tested against. Fixes here
come from that use — every one of them was something a real recording of a real device ran
into.

So questions about this fork, about `.snmprec` recordings, or about simulating a device you
are trying to monitor are welcome:

* [open an issue](https://github.com/observium/snmpsim/issues) in this repository
* ask on [Discord](https://discord.observium.cloud/), or through the other
  [Observium community channels](https://docs.observium.org/community/)
* capturing a device so that it can be supported:
  [Requesting device support](https://snmpdump.observium.cloud/) walks through what to
  record and where to send it
* [Observium documentation](https://docs.observium.org/) and [website](https://www.observium.org/)

## Getting help with the simulator itself

For the simulator in general, rather than this fork, the upstream project is
[lextudio/snmpsim](https://github.com/lextudio/snmpsim), and it asks for bug reports at
[lextudio/pysnmp](https://github.com/lextudio/pysnmp/issues).

## Feedback and collaboration

Bug reports, fixes, suggestions, improvements, and your pull requests are very
welcome!

Copyright (c) 2010-2019, [Ilya Etingof](mailto:etingof@gmail.com).
Copyright (c) 2022-2026, [LeXtudio Inc.](mailto:support@lextudio.com).
All rights reserved.
