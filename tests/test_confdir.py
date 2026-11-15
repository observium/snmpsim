import importlib
import os
import sys

import pytest

from snmpsim import confdir

PACKAGE_DIR = os.path.dirname(confdir.__file__)

SHARED_DIR = os.path.join("/", "usr", "local", "share", "snmpsim")

WINDOWS_VARIABLES = (
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "PROGRAMFILES",
)


@pytest.fixture
def load_confdir():
    """Reload confdir for a made-up platform and environment.

    The module is reloaded once more with the real ones afterwards, so that
    the tests which follow see the directories of the machine they run on.
    """
    with pytest.MonkeyPatch.context() as patch:

        def load(platform, **environ):
            patch.setattr(sys, "platform", platform)

            for name in WINDOWS_VARIABLES + ("HOME",):
                patch.delenv(name, raising=False)

            for name, value in environ.items():
                patch.setenv(name, value)

            return importlib.reload(confdir)

        yield load

    importlib.reload(confdir)


def windows_dirs(kind, *roots):
    dirs = [os.path.join(root, "SNMP Simulator", kind) for root in roots]
    return dirs + [os.path.join(PACKAGE_DIR, kind.lower())]


def posix_dirs(kind, *roots):
    return [os.path.join(root, kind) for root in roots] + [
        os.path.join(sys.prefix, "snmpsim", kind),
        os.path.join(sys.prefix, "share", "snmpsim", kind),
        os.path.join(PACKAGE_DIR, kind),
    ]


def test_windows_takes_the_user_directory_from_userprofile(load_confdir):
    module = load_confdir(
        "win32",
        USERPROFILE=r"C:\Users\simulator",
        HOMEDRIVE="D:",
        HOMEPATH=r"\Elsewhere",
        APPDATA=r"C:\Users\simulator\AppData\Roaming",
        PROGRAMFILES=r"C:\Program Files",
    )

    roots = (
        r"C:\Users\simulator",
        r"C:\Users\simulator\AppData\Roaming",
        r"C:\Program Files",
    )

    assert module.variation == windows_dirs("Variation", *roots)
    assert module.data == windows_dirs("Data", *roots)


def test_windows_falls_back_to_homedrive_and_homepath(load_confdir):
    module = load_confdir(
        "win32",
        HOMEDRIVE="D:",
        HOMEPATH=r"\Users\simulator",
        APPDATA=r"D:\AppData",
        PROGRAMFILES=r"C:\Program Files",
    )

    roots = (r"D:\Users\simulator", r"D:\AppData", r"C:\Program Files")

    assert module.variation == windows_dirs("Variation", *roots)
    assert module.data == windows_dirs("Data", *roots)


def test_windows_does_not_guess_a_drive_for_a_lone_homepath(load_confdir):
    module = load_confdir(
        "win32",
        HOMEPATH=r"\Users\simulator",
        APPDATA=r"D:\AppData",
        PROGRAMFILES=r"C:\Program Files",
    )

    roots = (r"D:\AppData", r"C:\Program Files")

    assert module.variation == windows_dirs("Variation", *roots)
    assert module.data == windows_dirs("Data", *roots)


def test_windows_without_a_user_skips_the_per_user_directories(load_confdir):
    module = load_confdir("win32", PROGRAMFILES=r"C:\Program Files")

    assert module.variation == windows_dirs("Variation", r"C:\Program Files")
    assert module.data == windows_dirs("Data", r"C:\Program Files")


def test_windows_with_an_empty_environment_keeps_the_bundled_directories(
    load_confdir,
):
    module = load_confdir("win32")

    assert module.variation == windows_dirs("Variation")
    assert module.data == windows_dirs("Data")


def test_linux_searches_usr_local_share(load_confdir):
    module = load_confdir("linux", HOME="/var/lib/simulator")

    roots = (os.path.join("/var/lib/simulator", ".snmpsim"), SHARED_DIR)

    assert module.variation == posix_dirs("variation", *roots)
    assert module.data == posix_dirs("data", *roots)


def test_macos_directories_stay_as_they_were(load_confdir):
    module = load_confdir("darwin", HOME="/Users/simulator")

    roots = (os.path.join("/Users/simulator", ".snmpsim"), SHARED_DIR)

    assert module.variation == posix_dirs("variation", *roots)
    assert module.data == posix_dirs("data", *roots)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_posix_without_home_skips_the_per_user_directories(load_confdir, platform):
    module = load_confdir(platform)

    assert module.variation == posix_dirs("variation", SHARED_DIR)
    assert module.data == posix_dirs("data", SHARED_DIR)
