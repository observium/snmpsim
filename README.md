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

Each item links to the upstream pull request carrying the same change:

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
* Offers REST API based [control plane](https://www.pysnmp.com/snmpsim-control-plane)
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
`@8a244ea`. To upgrade an existing installation, add `--force` (pipx) or
`--upgrade` (pip); pipx keeps packages added with `pipx inject` across a `--force` reinstall.

If you use `uv`, the same specifier works as a tool install:

```bash
uv tool install "git+https://github.com/observium/snmpsim.git@master"
```

### From PyPI

The published package is the upstream release and does **not** include the changes listed
above:

```bash
pip install snmpsim
```

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

## Getting help

For anything specific to this fork,
[open an issue](https://github.com/observium/snmpsim/issues) here. For the simulator in
general, [open an issue](https://github.com/lextudio/pysnmp/issues) upstream or
post your question [on Stack Overflow](https://stackoverflow.com/questions/ask).

## Feedback and collaboration

Bug reports, fixes, suggestions, improvements, and your pull requests are very
welcome!

Copyright (c) 2010-2019, [Ilya Etingof](mailto:etingof@gmail.com).
Copyright (c) 2022-2026, [LeXtudio Inc.](mailto:support@lextudio.com).
All rights reserved.
