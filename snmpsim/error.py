#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#


class SnmpsimError(Exception):
    pass


class ModuleNotConfigured(SnmpsimError):
    """A variation module which cannot work without options got none.

    Every variation module found is initialized, whether or not a recording
    uses it, so this is how the sql and redis modules of an installation
    that has no database for them start. It is not a failure.
    """


class NoDataNotification(SnmpsimError):
    pass


class MoreDataNotification(SnmpsimError):
    def __init__(self, **kwargs):
        self.__kwargs = kwargs

    def __contains__(self, key):
        return key in self.__kwargs

    def __getitem__(self, key):
        return self.__kwargs[key]

    def get(self, key):
        return self.__kwargs.get(key)

    def keys(self):
        return self.__kwargs.keys()
