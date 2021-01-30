# This file is part of aiootp, an asynchronous one-time-pad based crypto
# and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["paths", "SecurePath", "AsyncSecurePath", "DatabasePath"]


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


async def adeniable_filename(key, *, size=8):
    from .generics import asha_256, axi_mix

    if size > 16:
        raise ValueError("Choose a ``size`` <= 16 bytes.")
    return (await asha_256(await axi_mix(key, size=size)))[:60]


def deniable_filename(key, *, size=8):
    from .generics import sha_256, xi_mix

    if size > 16:
        raise ValueError("Choose a ``size`` <= 16 bytes.")
    return sha_256(xi_mix(key, size=size))[:60]


async def amake_salt_file(path, *, key=None):
    from .randoms import acsprng

    salt = await acsprng()
    secret = salt[:64]
    filename = await adeniable_filename(key) if key else salt[64:]
    filepath = path / filename
    async with aiofiles.open(filepath, "wb") as f:
        await f.write(bytes.fromhex(secret))
    await aos.chmod(filepath, 0o000)


def make_salt_file(path, *, key=None):
    from .randoms import csprng

    salt = csprng()
    secret = salt[:64]
    filename = deniable_filename(key) if key else salt[64:]
    filepath = path / filename
    with open(filepath, "wb") as f:
        f.write(bytes.fromhex(secret))
    os.chmod(filepath, 0o000)


async def afind_salt_file(path, *, key=None):
    if key:
        return path / await adeniable_filename(key)
    for subpath in path.iterdir():
        if subpath.is_file() and len(subpath.stem) == 64:
            return subpath.absolute()
        await switch()


def find_salt_file(path, *, key=None):
    if key:
        return path / deniable_filename(key)
    for subpath in path.iterdir():
        if subpath.is_file() and len(subpath.stem) == 64:
            return subpath.absolute()


async def aread_salt_file(filepath):
    try:
        await aos.chmod(filepath, 0o700)
        async with aiofiles.open(filepath, "rb") as salt_file:
            salt = (await salt_file.read()).hex()
            if salt and len(salt) >= 64:
                return salt
            else:
                raise ValueError("The salt file is empty or corrupt!")
    finally:
        await aos.chmod(filepath, 0o000)


def read_salt_file(filepath):
    try:
        os.chmod(filepath, 0o700)
        with open(filepath, "rb") as salt_file:
            salt = salt_file.read().hex()
            if salt and len(salt) >= 64:
                return salt
            else:
                raise ValueError("The salt file is empty or corrupt!")
    finally:
        os.chmod(filepath, 0o000)


async def AsyncSecurePath(dir_function=DatabasePath, *, key=None):
    path = dir_function() / "secure"
    if not path.exists():
        path.mkdir()
    filepath = await afind_salt_file(path, key=key)
    if not filepath or not filepath.exists():
        await amake_salt_file(path, key=key)
        return await afind_salt_file(path, key=key)
    else:
        return filepath


def SecurePath(dir_function=DatabasePath, *, key=None):
    path = dir_function() / "secure"
    if not path.exists():
        path.mkdir()
    filepath = find_salt_file(path, key=key)
    if not filepath or not filepath.exists():
        make_salt_file(path, key=key)
        return find_salt_file(path, key=key)
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
    "AsyncSecurePath": AsyncSecurePath,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "_afind_salt_file": afind_salt_file,
    "_find_salt_file": find_salt_file,
    "_amake_salt_file": amake_salt_file,
    "_make_salt_file": make_salt_file,
    "_aread_salt_file": aread_salt_file,
    "_read_salt_file": read_salt_file,
    "_adeniable_filename": adeniable_filename,
    "_deniable_filename": deniable_filename,
}


paths = Namespace.make_module("paths", mapping=__extras)

