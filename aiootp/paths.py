# This file is part of aiootp:
# an application agnostic — async-compatible — anonymity & cryptography
# library, providing access to high-level Pythonic utilities to simplify
# the tasks of secure data processing, communication & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = []


__doc__ = (
    "A small collection of ``pathlib.Path`` objects with references to "
    "potentially helpful directories."
)


import os
import aiofiles
from pathlib import Path
from hashlib import sha3_256
from secrets import token_bytes
from .__constants import *
from ._exceptions import *
from ._typing import Typing
from .asynchs import aos
from .commons import make_module
from .generics import BytesIO


def CurrentPath() -> Path:
    """
    Returns a ``pathlib.Path`` object pointing to the current working
    directory.
    """
    return Path(os.getcwd()).absolute()


def RootPath() -> Path:
    """
    Returns a ``pathlib.Path`` object pointing to this module's directory.
    """
    dir_path = os.path.dirname(os.path.realpath(__file__))
    return Path(dir_path).absolute()


def PackagePath() -> Path:
    """
    Returns a ``pathlib.Path`` object pointing to this package's top
    level directory.
    """
    return RootPath().parent


def TorPath(*, path: Typing.OptionalPathStr = None) -> Path:
    """
    Returns a ``pathlib.Path`` object pointing to an optional tor
    directory.
    """
    return (Path(path).absolute() if path else RootPath()) / "tor"


def DatabasePath(*, path: Typing.OptionalPathStr = None) -> Path:
    """
    Returns a ``pathlib.Path`` object pointing to the default directory
    encrypted databases are saved to.
    """
    return (Path(path).absolute() if path else RootPath()) / "databases"


async def adeniable_filename(key: bytes, *, size: int = 8) -> str:
    """
    Xors subsequent bytes-type, ``size`` length segments of ``key`` with
    each other to create a condensed & variably forgeable hash. This
    hash is used as a filename which is deniably attributable to a
    particular ``key``.
    """
    from .generics import axi_mix

    if size > 16 or size <= 0:
        raise Issue.value_must_be_value("size", "<= 16 and > 0")
    filename = sha3_256(await axi_mix(key, size=size)).digest()
    return await BytesIO.abytes_to_filename(filename[FILENAME_HASH_SLICE])


def deniable_filename(key: bytes, *, size: int = 8) -> str:
    """
    Xors subsequent bytes-type, ``size`` length segments of ``key`` with
    each other to create a condensed & variably forgeable hash. This
    hash is used as a filename which is deniably attributable to a
    particular ``key``.
    """
    from .generics import xi_mix

    if size > 16 or size <= 0:
        raise Issue.value_must_be_value("size", "<= 16 and > 0")
    filename = sha3_256(xi_mix(key, size=size)).digest()
    return BytesIO.bytes_to_filename(filename[FILENAME_HASH_SLICE])


async def amake_salt_file(path: Path, *, key: bytes) -> None:
    """
    Creates & populates the ``path`` file with a sensitive cryptographic
    salt used to harden user databases. If ``key`` is specified then the
    filename is deterministically derived from the key so a database can
    find its own salt. These salt files have their permissions changed
    with `os.chmod` to `0o000` after they're created.
    """
    secret = token_bytes(32)
    filename = await adeniable_filename(key)
    filepath = path / filename
    async with aiofiles.open(filepath, "wb") as f:
        await f.write(secret)
    await aos.chmod(filepath, 0o000)


def make_salt_file(path: Path, *, key: bytes) -> None:
    """
    Creates & populates the ``path`` file with a sensitive cryptographic
    salt used to harden user databases. If ``key`` is specified then the
    filename is deterministically derived from the key so a database can
    find its own salt. These salt files have their permissions changed
    with `os.chmod` to `0o000` after they're created.
    """
    secret = token_bytes(32)
    filename = deniable_filename(key)
    filepath = path / filename
    with open(filepath, "wb") as f:
        f.write(secret)
    os.chmod(filepath, 0o000)


async def afind_salt_file(path: Path, *, key: bytes) -> Path:
    """
    This returns the path of a sensitive cryptographic salt used to
    harden user databases. If ``key`` is specified, the salt filename is
    deterministically derived from the key so a database can find its
    own salt.
    """
    return path / await adeniable_filename(key)


def find_salt_file(path: Path, *, key: bytes) -> Path:
    """
    This returns the path of a sensitive cryptographic salt used to
    harden user databases. If ``key`` is specified, the salt filename is
    deterministically derived from the key so a database can find its
    own salt.
    """
    return path / deniable_filename(key)


async def aread_salt_file(filepath: Typing.PathStr) -> bytes:
    """
    This returns the sensitive cryptographic salt contained within the
    file located at ``filepath``. The file has its permissions changed
    with `os.chmod` to `0o000` after its read.
    """
    try:
        await aos.chmod(filepath, 0o700)
        async with aiofiles.open(filepath, "rb") as salt_file:
            salt = await salt_file.read()
            if len(salt) >= 32:
                return salt
            else:
                raise ValueError("The salt file is empty or corrupt!")
    finally:
        await aos.chmod(filepath, 0o000)


def read_salt_file(filepath) -> bytes:
    """
    This returns the sensitive cryptographic salt contained within the
    file located at ``filepath``. The file has its permissions changed
    with `os.chmod` to `0o000` after its read.
    """
    try:
        os.chmod(filepath, 0o700)
        with open(filepath, "rb") as salt_file:
            salt = salt_file.read()
            if len(salt) >= 32:
                return salt
            else:
                raise ValueError("The salt file is empty or corrupt!")
    finally:
        os.chmod(filepath, 0o000)


async def adelete_salt_file(filepath) -> None:
    """
    This returns the sensitive cryptographic salt contained within the
    file located at ``filepath``. The file has its permissions changed
    with `os.chmod` to `0o000` after its read.
    """
    await aos.chmod(filepath, 0o700)
    await aos.remove(filepath)


def delete_salt_file(filepath) -> None:
    """
    This returns the sensitive cryptographic salt contained within the
    file located at ``filepath``. The file has its permissions changed
    with `os.chmod` to `0o000` after its read.
    """
    os.chmod(filepath, 0o700)
    os.remove(filepath)


async def AsyncSecurePath(
    path: Typing.OptionalPathStr = None,
    *,
    key: Typing.Optional[bytes] = None,
    _admin: bool = False,
) -> Path:
    """
    This constructor returns the path for files which contain sensitive
    cryptographic salts used to harden user databases. If ``key`` is
    specified then the salt filename is deterministically derived from
    the key so a database can find its own salt. These salt files have
    their permissions changed with `os.chmod` to `0o000` before & after
    they're read from or created.
    """
    path = (Path(path).absolute() if path else DatabasePath()) / "secure"
    admin_path = path / "_admin"
    if not path.exists():
        await aos.mkdir(path)
    if not admin_path.exists():
        await aos.mkdir(admin_path)
    if not key:
        return path
    elif _admin:
        filepath = await afind_salt_file(admin_path, key=key)
        if not filepath or not filepath.exists():
            await amake_salt_file(admin_path, key=key)
    else:
        filepath = await afind_salt_file(path, key=key)
        if not filepath or not filepath.exists():
            await amake_salt_file(path, key=key)
    return filepath


def SecurePath(
    path: Typing.OptionalPathStr = None,
    *,
    key: Typing.Optional[bytes] = None,
    _admin: bool = False,
) -> Path:
    """
    This constructor returns the path for files which contain sensitive
    cryptographic salts used to harden user databases. If ``key`` is
    specified then the salt filename is deterministically derived from
    the key so a database can find its own salt. These salt files have
    their permissions changed with `os.chmod` to `0o000` before & after
    they're read from or created.
    """
    path = (Path(path).absolute() if path else DatabasePath()) / "secure"
    admin_path = path / "_admin"
    if not path.exists():
        os.mkdir(path)
    if not admin_path.exists():
        os.mkdir(admin_path)
    if not key:
        return path
    if _admin:
        filepath = find_salt_file(admin_path, key=key)
        if not filepath or not filepath.exists():
            make_salt_file(admin_path, key=key)
    else:
        filepath = find_salt_file(path, key=key)
        if not filepath or not filepath.exists():
            make_salt_file(path, key=key)
    return filepath


extras = dict(
    AsyncSecurePath=AsyncSecurePath,
    CurrentPath=CurrentPath,
    DatabasePath=DatabasePath,
    PackagePath=PackagePath,
    Path=Path,
    RootPath=RootPath,
    SecurePath=SecurePath,
    TorPath=TorPath,
    __doc__=__doc__,
    __package__=__package__,
    _afind_salt_file=afind_salt_file,
    _adelete_salt_file=adelete_salt_file,
    _amake_salt_file=amake_salt_file,
    _aread_salt_file=aread_salt_file,
    _find_salt_file=find_salt_file,
    _delete_salt_file=delete_salt_file,
    _make_salt_file=make_salt_file,
    _read_salt_file=read_salt_file,
    adeniable_filename=adeniable_filename,
    deniable_filename=deniable_filename,
)


paths = make_module("paths", mapping=extras)

