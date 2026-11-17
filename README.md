# SNMP Simulator

[![Release](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fobservium%2Fsnmpsim%2Freleases%2Flatest&query=%24.tag_name&label=release&color=blue)](https://github.com/observium/snmpsim/releases/latest)
[![Tests](https://github.com/observium/snmpsim/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/observium/snmpsim/actions/workflows/tests.yml)
[![CI](https://github.com/observium/snmpsim/actions/workflows/build-test.yml/badge.svg?branch=master)](https://github.com/observium/snmpsim/actions/workflows/build-test.yml)
[![Docs](https://github.com/observium/snmpsim/actions/workflows/docs.yml/badge.svg?branch=master)](https://observium.github.io/snmpsim/)
[![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.15%20%7C%20PyPy%203.11-blue?logo=python&logoColor=white)](#installation)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue)](LICENSE.txt)

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

Compared with snmpsim 1.2.2, the release it was forked from, snmpsim-ng carries 92 changes.
Most of them are fixes: for what stopped working when pysnmp 7 renamed and reworked its API,
and for what never worked. Every change is described in [CHANGES.rst](CHANGES.rst), also
published as the [changelog](https://observium.github.io/snmpsim/changelog.html) of the
documentation, and in the notes of each release. What answers differently from snmpsim 1.2.2
is collected in [Migrating from snmpsim](https://observium.github.io/snmpsim/migrating.html).

| Area | [2026.11.0](https://github.com/observium/snmpsim/releases/tag/2026.11.0) | [2026.11.1](https://github.com/observium/snmpsim/releases/tag/2026.11.1) | [2026.11.2](https://github.com/observium/snmpsim/releases/tag/2026.11.2) | [2026.11.3](https://github.com/observium/snmpsim/releases/tag/2026.11.3) | [2026.11.4](https://github.com/observium/snmpsim/releases/tag/2026.11.4) | [next](CHANGES.rst) | Total |
|---|--:|--:|--:|--:|--:|--:|--:|
| Command responders | 11 | 1 | 11 | 1 | 2 | 7 | **33** |
| Recording tools | 3 | 2 | 5 | 1 | 0 | 0 | **11** |
| Data files and conversion | 3 | 5 | 2 | 1 | 0 | 0 | **11** |
| Variation modules | 0 | 10 | 2 | 1 | 0 | 0 | **13** |
| Python, platforms and packaging | 7 | 3 | 1 | 1 | 3 | 1 | **16** |
| Documentation | 1 | 1 | 3 | 2 | 1 | 0 | **8** |
| **All** | **25** | **22** | **24** | **7** | **6** | **8** | **92** |

Among them:

* **Command responders:** SNMPv1/v2c answered without pysnmp's SNMPv3 engine, works on pysnmp
  7, `--daemonize` survives the fork, GETBULK fits one datagram and the manager's `msgMaxSize`,
  `--v1-only` and `--v2c-only`, master and localized USM keys, rescan on SIGHUP, indexes built
  in parallel, exits when a port cannot be bound
* **Recording tools:** `snmpsim-record-commands` records again, over SNMPv3 too, and fails with
  a non-zero exit; `snmpsim-record-traffic` starts and reads pcap files; `snmpsim-record-mibs`
  makes values the MIB permits and shares rows between tables
* **Data files and conversion:** `snmpsim-lint-records`; walk conversion keeps non-ASCII
  octets, values wrapped onto several lines, Opaque Float and Double, `-OQ` strings, and
  streams instead of holding the file in memory
* **Variation modules:** `multiplex` snapshots named, closed and served right; `numeric`,
  `writecache`, `subprocess`, `error` and `notification` fixed; `sql` reconnects
* **Python, platforms and packaging:** Python 3.10 to 3.15 in CI on Linux and Windows, PyPy
  3.11, Windows search paths, the `snmpsim-ng` name and calendar versions, dependencies
  declared
* **Documentation:** [a site of its own](https://observium.github.io/snmpsim/) describing what
  snmpsim-ng does, the options of every command

| Release | Date | Changes | Details |
|---|---|--:|---|
| 2026.11.4 | Nov 17, 2026 | 6 | [release notes](https://github.com/observium/snmpsim/releases/tag/2026.11.4), [changelog](https://observium.github.io/snmpsim/changelog.html#revision-2026-11-4-released-on-nov-17-2026) |
| 2026.11.3 | Nov 16, 2026 | 7 | [release notes](https://github.com/observium/snmpsim/releases/tag/2026.11.3), [changelog](https://observium.github.io/snmpsim/changelog.html#revision-2026-11-3-released-on-nov-16-2026) |
| 2026.11.2 | Nov 16, 2026 | 24 | [release notes](https://github.com/observium/snmpsim/releases/tag/2026.11.2), [changelog](https://observium.github.io/snmpsim/changelog.html#revision-2026-11-2-released-on-nov-16-2026) |
| 2026.11.1 | Nov 15, 2026 | 22 | [release notes](https://github.com/observium/snmpsim/releases/tag/2026.11.1), [changelog](https://observium.github.io/snmpsim/changelog.html#revision-2026-11-1-released-on-nov-15-2026) |
| 2026.11.0 | Nov 15, 2026 | 25 | [release notes](https://github.com/observium/snmpsim/releases/tag/2026.11.0), [changelog](https://observium.github.io/snmpsim/changelog.html#revision-2026-11-0-released-on-nov-15-2026) |

"next" counts what is on `master` and not released yet: the topmost section of
[CHANGES.rst](CHANGES.rst).

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

Python 3.10 or newer is required, CPython or PyPy - see [On PyPy](#on-pypy).

### From a release

Releases are published on the [Releases](https://github.com/observium/snmpsim/releases) page,
each with a wheel and a source archive and tagged with its version. Install the current one
with `pipx`, which keeps the simulator in an environment of its own and puts its commands on
your `PATH`:

```bash
pipx install "git+https://github.com/observium/snmpsim.git@2026.11.4"
```

or from the release's wheel, without git:

```bash
pipx install https://github.com/observium/snmpsim/releases/download/2026.11.4/snmpsim_ng-2026.11.4-py3-none-any.whl
```

With `pip`, into the environment of your choice, or as a `uv` tool, the same specifiers work:

```bash
pip install "git+https://github.com/observium/snmpsim.git@2026.11.4"
```

```bash
uv tool install "git+https://github.com/observium/snmpsim.git@2026.11.4"
```

Replace `2026.11.4` with the release you want. snmpsim-ng is not on PyPI yet, and
`pip install snmpsim` installs the other release line, which has none of the changes summed up
under [What snmpsim-ng adds](#what-snmpsim-ng-adds).

### On PyPy

The simulator runs unchanged on [PyPy](https://pypy.org/) 3.11, which answers 1.4 to 1.9 times
as many requests per second as CPython does (see [Performance](#performance)); the test suite
passes on it, and CI runs it there. `uv` fetches PyPy by itself:

```bash
uv tool install --python pypy3.11 "git+https://github.com/observium/snmpsim.git@2026.11.4"
```

`pipx` takes a PyPy that is installed already, by name or path:

```bash
pipx install --python pypy3.11 "git+https://github.com/observium/snmpsim.git@2026.11.4"
```

Install the gdbm library before PyPy (`brew install gdbm` on macOS; most Linux systems have
it): PyPy has the gdbm module only where the library is there. Without it the indexes land in
`dbm.ndbm`, which `dbm.whichdb()` does not recognise, so every start of the simulator builds
every index again, or, where PyPy has no `dbm.ndbm` either, in the much slower `dbm.dumb`.
This prints which module the simulator will use:

```bash
python -c "from snmpsim.record.search import database; print(database.DBM_BACKEND.__name__)"
```

Run it with the interpreter of the environment the simulator is installed in; `dbm.gnu` is
gdbm.

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
`2026.11.4`; a wheel URL takes `--force` the same way:

```bash
pipx install --force "git+https://github.com/observium/snmpsim.git@2026.11.4"
```

```bash
pip install --upgrade --force-reinstall "git+https://github.com/observium/snmpsim.git@2026.11.4"
```

```bash
uv tool install --force "git+https://github.com/observium/snmpsim.git@2026.11.4"
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
documentation only. `build-test.yml` builds the package and runs the suite on Linux and Windows
on Python 3.10 to 3.15 (macOS is out for now: GitHub's runners for it are not to be had, see
the commented lines of the workflow). `tests.yml` runs the same suite on Linux only, on Python
3.10 to 3.15 and on PyPy 3.11, but plainly - no coverage and, more to the point, no retries,
which is how it catches failures the retrying workflow lets through.


## Performance

Measured with [`scripts/bench_responder.py`](scripts/bench_responder.py) on one recording of
a cable modem termination system, 188 MB with 3.29 million records, served by one process on
an Apple M3 Max: net-snmp's `snmpbulkwalk -Cr25` over the whole recording and `snmpwalk`
(one GETNEXT per OID) over its `.1.3.6.1.2.1.2` subtree, 27 thousand OIDs.

Against snmpsim 1.2.2, the release this fork started from, in OIDs per second, gdbm index:

| Interpreter | Walk | snmpsim 1.2.2 | snmpsim 1.2.2 lite | snmpsim-ng 2026.11.5 | Faster than 1.2.2 / lite |
|---|---|--:|--:|--:|--:|
| CPython 3.14 | bulk | 14,700 | 18,800 | 35,200 | 2.4× / 1.9× |
| CPython 3.14 | GETNEXT | 2,600 | 3,300 | 11,400 | 4.4× / 3.5× |
| PyPy 3.11 | bulk | 30,500 | 44,300 | 66,200 | 2.2× / 1.5× |
| PyPy 3.11 | GETNEXT | 6,500 | 8,700 | 16,000 | 2.5× / 1.8× |

The 1.2.2 figures were taken on snmpsim-ng 2026.11.3, which still answered every request the
way 1.2.2 does, through pysnmp's engine and pyasn1. In detail, with every way of running it:

| Interpreter, responder, index | Index build and start | Bulk walk | GETNEXT walk |
|---|--:|--:|--:|
| CPython 3.14, full responder, gdbm | 14 s | 35,200 OIDs/s | 11,400 OIDs/s |
| CPython 3.14, full responder through the engine, gdbm | 14 s | 15,700 OIDs/s | 2,600 OIDs/s |
| CPython 3.14, full responder through the engine, `dbm.sqlite3` | 159 s | 15,900 OIDs/s | 2,700 OIDs/s |
| PyPy 3.11, full responder, gdbm | 16 s | 66,200 OIDs/s | 16,000 OIDs/s |
| PyPy 3.11, full responder through the engine, gdbm | 16 s | 32,900 OIDs/s | 7,400 OIDs/s |

"Through the engine" is `--v1-v2c-path=engine`: SNMPv1/v2c sent through pysnmp's SNMPv3
engine, as releases before 2026.11.4 did.

* The dbm module decides how long an index takes to build, not how fast it is served: every
  record has its own key in the index, so a request for an OID in the recording costs one
  lookup and one read whatever the size of the recording. CPython 3.13 and later pick
  `dbm.sqlite3` when gdbm is missing, as it is from Homebrew's Python unless
  `python-gdbm@3.x` is installed for its version; PyPy picks `dbm.ndbm` or `dbm.dumb`, see
  [On PyPy](#on-pypy).
* Serving is bound by the CPU of a single core. Through the engine, the BER coding in pyasn1,
  the message processing in pysnmp and the simulator's own lookup share it; PyPy runs all of
  it two to three times as fast.
* The full responder answers SNMPv1/v2c without pysnmp's message processing, and encodes and
  decodes SNMPv1/v2c reads itself rather than in pyasn1 (`snmpsim.ber`), with the same answers:
  about 2.2 times as fast as through the engine on a bulk walk, 4.4 times on a GETNEXT walk.
  On PyPy it is 1.4 to 1.9 times as fast again. The lite responder is the same responder
  under its old name since 2026.11.5, serving SNMPv1/v2c only, and serves as fast.

To measure a recording of your own, with any interpreter and either responder:

```bash
python scripts/bench_responder.py --data-dir=/path/to/recordings --community=vendor/model
```

## Commands

Installing the package puts these commands on your `PATH`:

| Command | Purpose |
|---|---|
| `snmpsim-command-responder` | The simulator itself: serves recordings over SNMPv1/v2c/v3 |
| `snmpsim-command-responder-lite` | The responder under its old name, with the options it took: SNMPv1/v2c only |
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
