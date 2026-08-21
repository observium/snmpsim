# SNMP Simulator

[![Become a Sponsor](https://img.shields.io/badge/Become%20a%20Sponsor-lextudio-orange.svg?style=for-readme)](https://github.com/sponsors/lextudio)
[![PyPI](https://img.shields.io/pypi/v/snmpsim.svg)](https://pypi.python.org/pypi/snmpsim)
[![PyPI Downloads](https://img.shields.io/pypi/dd/snmpsim)](https://pypi.python.org/pypi/snmpsim/)
[![Python Versions](https://img.shields.io/pypi/pyversions/snmpsim.svg)](https://pypi.python.org/pypi/snmpsim/)
[![GitHub license](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/lextudio/snmpsim/master/LICENSE.txt)

This is a pure-Python, open source and free implementation of SNMP agents simulator
distributed under 2-clause [BSD license](https://www.pysnmp.com/snmpsim/license.html).

> **This is Observium's fork of [lextudio/snmpsim](https://github.com/lextudio/snmpsim).**
> It carries fixes for recordings that the upstream responder refuses to serve, and adds a
> lint tool for recording repositories. The badges above track the upstream PyPI release,
> which does **not** contain these changes - see [Installation](#installation) for how to
> install this fork. Every code change here is also filed upstream; this README is not.

## What this fork adds

Every item is also filed upstream; each links to its pull request:

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
* Offers REST API based [control plane](https://www.pysnmp.com/snmpsim-control-plane/)
* Gathers and reports extensive activity metrics
* Pure-Python, easy to deploy and highly portable
* Can be extended by loadable Python snippets

## Installation

Python 3.10 or newer is required.

### From this repository

This fork is not published to PyPI, so install it straight from git. With `pipx`, which keeps
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

A responder already running keeps serving the code it started with: restart it afterwards.
The same goes for changed recordings — the running process holds byte offsets into the files
it indexed at startup.

### For development

```bash
git clone --recurse-submodules https://github.com/observium/snmpsim.git
```

The `scripts/` directory is a git submodule ([lextudio/pysnmp-scripts](https://github.com/lextudio/pysnmp-scripts));
in an existing clone fetch it with `git submodule update --init`. Then install the package in
editable mode along with its test dependencies:

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

`pip install snmpsim` fetches the package LeXtudio publishes, which is **not** this fork: it
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
OIDs dumped: 182, elapsed: 11.97 sec, rate: 7.00 OIDs/sec, errors: 0
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

Besides stand-alone deployment described above, third-party
[SNMP Simulator control plane](https://github.com/lextudio/snmpsim-control-plane)
project offers REST API managed mass deployment of multiple `snmpsim-command-responder`
instances.

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
