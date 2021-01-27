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
import aiofiles
from pathlib import Path
from .asynchs import aos
from .asynchs import switch
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


async def amake_hash_file(path):
    from .ciphers import asalt

    key = await asalt()
    filename = key[:64]
    secret = key[64:]
    filepath = path / filename
    async with aiofiles.open(filepath, "w") as new_file:
        await new_file.write(secret)
    await aos.chmod(filepath, 0o000)


def make_hash_file(path):
    from .ciphers import salt

    key = salt()
    filename = key[:64]
    secret = key[64:]
    filepath = path / filename
    with open(filepath, "w") as new_file:
        new_file.write(secret)
    os.chmod(filepath, 0o000)


async def afind_hash_file(path):
    for subpath in path.iterdir():
        if subpath.is_file() and len(subpath.stem) == 64:
            return subpath.absolute()
        await switch()


def find_hash_file(path):
    for subpath in path.iterdir():
        if subpath.is_file() and len(subpath.stem) == 64:
            return subpath.absolute()


async def aread_hash_file(filepath):
    try:
        await aos.chmod(filepath, 0o700)
        async with aiofiles.open(filepath, "r") as hash_file:
            return await hash_file.read()
    finally:
        await aos.chmod(filepath, 0o000)


def read_hash_file(filepath):
    try:
        os.chmod(filepath, 0o700)
        with open(filepath, "r") as hash_file:
            return hash_file.read()
    finally:
        os.chmod(filepath, 0o000)


def SecurePath(dir_function=DatabasePath):
    path = dir_function() / "secure"
    if not path.exists():
        path.mkdir()
    filepath = find_hash_file(path)
    if not filepath:
        make_hash_file(path)
        return find_hash_file(path)
    else:
        return filepath


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
    "_afind_hash_file": afind_hash_file,
    "_find_hash_file": find_hash_file,
    "_amake_hash_file": amake_hash_file,
    "_make_hash_file": make_hash_file,
    "_aread_hash_file": aread_hash_file,
    "_read_hash_file": read_hash_file,
}


paths = Namespace.make_module("paths", mapping=__extras)

