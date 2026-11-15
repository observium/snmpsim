#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
import os
import sys
import tempfile


def _windows_home():
    """Return the home directory of the current Windows user, if there is one.

    `HOMEPATH` alone carries no drive letter, so it only counts together
    with `HOMEDRIVE`. Services may run with none of these set.
    """
    home = os.environ.get("USERPROFILE")
    if home:
        return home

    drive = os.environ.get("HOMEDRIVE")
    path = os.environ.get("HOMEPATH")
    if drive and path:
        return drive + path


def _search_path(kind):
    """Return the directories searched for `kind`: "variation" or "data".

    Directories hanging off an environment variable that is not set are
    left out rather than failing the import.
    """
    bundled = os.path.join(os.path.split(__file__)[0], kind)

    if sys.platform[:3] == "win":
        roots = [
            _windows_home(),
            os.environ.get("APPDATA"),
            os.environ.get("PROGRAMFILES"),
        ]
        dirs = [
            os.path.join(root, "SNMP Simulator", kind.capitalize())
            for root in roots
            if root
        ]

    else:
        home = os.environ.get("HOME")
        dirs = [os.path.join(home, ".snmpsim", kind)] if home else []
        dirs += [
            os.path.join("/", "usr", "local", "share", "snmpsim", kind),
            os.path.join(sys.prefix, "snmpsim", kind),
            os.path.join(sys.prefix, "share", "snmpsim", kind),
        ]

    return dirs + [bundled]


variation = _search_path("variation")
data = _search_path("data")

cache = os.path.join(tempfile.gettempdir(), "snmpsim")
