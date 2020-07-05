# This file is part of aiootp, an asynchronous one-time-pad based crypto
# and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["paths", "SecurePath", "DatabasePath"]


__doc__ = """
A small collection of ``pathlib.Path`` objects with references to
potentially helpful directories.
"""


import os
from pathlib import Path
from .commons import Namespace


def CurrentPath():
    """
    Returns a ``pathlib.Path`` object pointing to the current working
    directory.
    """
    return Path(os.getcwd()).absolute()


def RootPath():
    """
    Returns a ``pathlib.Path`` object pointing to this module's directory.
    """
    dir_path = os.path.dirname(os.path.realpath(__file__))
    return Path(dir_path).absolute()


def PackagePath():
    """
    Returns a ``pathlib.Path`` object pointing to this package's top
    level directory.
    """
    return RootPath().parent


def TorPath(dir_function=RootPath):
    """
    Returns a ``pathlib.Path`` object pointing to an optional tor
    directory.
    """
    return dir_function() / "tor"


def DatabasePath(dir_function=RootPath):
    """
    Returns a ``pathlib.Path`` object pointing to the default directory
    encrypted databases are saved to.
    """
    return dir_function() / "databases"


def SecurePath(dir_function=DatabasePath):
    from .ciphers import salt

    secured_directory = dir_function() / "secure"
    if not secured_directory.exists():
        secured_directory.mkdir()
        (secured_directory / salt()[:64]).mkdir()
    for path in secured_directory.iterdir():
        if len(path.stem) == 64:
            return path.absolute()
    path = secured_directory / salt()[:64]
    path.mkdir()
    return path.absolute()


__extras = {
    "Path": Path,
    "TorPath": TorPath,
    "RootPath": RootPath,
    "SecurePath": SecurePath,
    "PackagePath": PackagePath,
    "CurrentPath": CurrentPath,
    "DatabasePath": DatabasePath,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
}


paths = Namespace.make_module("paths", mapping=__extras)

