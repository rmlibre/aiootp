# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2024 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


"""
A collection of `pathlib.Path`'s & file IO utilities.
"""

__all__ = []


import aiofiles
from pathlib import Path
from hashlib import sha3_256
from secrets import token_bytes

from ._typing import Typing as t
from ._constants import FILENAME_HASH_SLICE
from ._exceptions import Issue
from .asynchs import aos


def RootPath() -> Path:
    """
    Returns a `pathlib.Path` object pointing to this module's directory.
    """
    return Path(__file__).absolute().parent


def DatabasePath() -> Path:
    """
    Returns a `pathlib.Path` object pointing to the default directory
    where encrypted database files are saved.
    """
    return RootPath() / "db"


async def adeniable_filename(key: bytes, *, size: int = 8) -> str:
    """
    XORs `size` length bytes-type segments of a `key`, returning a
    variably forgeable, base-38 encoded hash from the condensed value.
    """
    from .generics.transform import axi_mix

    if not (16 >= size >= 1):
        raise Issue.value_must("size", "be <= 16 and > 0")
    elif not (len(key) >= 2 * size):
        raise Issue.value_must("size", "be at least 2x key length")

    filename = sha3_256(await axi_mix(key, size=size)).digest()
    return await t.ByteIO.abytes_to_filename(filename[FILENAME_HASH_SLICE])


def deniable_filename(key: bytes, *, size: int = 8) -> str:
    """
    XORs `size` length bytes-type segments of a `key`, returning a
    variably forgeable, base-38 encoded hash from the condensed value.
    """
    from .generics.transform import xi_mix

    if not (16 >= size >= 1):
        raise Issue.value_must("size", "be <= 16 and > 0")
    elif not (len(key) >= 2 * size):
        raise Issue.value_must("size", "be at least 2x key length")

    filename = sha3_256(xi_mix(key, size=size)).digest()
    return t.ByteIO.bytes_to_filename(filename[FILENAME_HASH_SLICE])


async def afind_salt_file(path: Path, *, key: bytes) -> Path:
    """
    Derives the filename to a cryptographic salt from a `key` & returns
    it joined to the provided `path` directory.
    """
    return path.absolute() / await adeniable_filename(key)


def find_salt_file(path: Path, *, key: bytes) -> Path:
    """
    Derives the filename to a cryptographic salt from a `key` & returns
    it joined to the provided `path` directory.
    """
    return path.absolute() / deniable_filename(key)


async def amake_salt_file(path: Path, *, salt: bytes = b"") -> None:
    """
    Saves a cryptographic `salt` contained within the file located at
    `path`. If no `salt` is provided, a new random 32-byte salt is used.
    """
    salt = salt if salt else token_bytes(32)
    if len(salt) < 32:
        raise Issue.value_must("salt", "be >= 32-bytes")

    async with aiofiles.open(path, "wb") as salt_file:
        await salt_file.write(salt)
    await aos.chmod(path, 0o000)


def make_salt_file(path: Path, *, salt: bytes = b"") -> None:
    """
    Saves a cryptographic `salt` contained within the file located at
    `path`. If no `salt` is provided, a new random 32-byte salt is used.
    """
    salt = salt if salt else token_bytes(32)
    if len(salt) < 32:
        raise Issue.value_must("salt", "be >= 32-bytes")

    path = Path(path)
    path.write_bytes(salt)
    path.chmod(0o000)


async def aread_salt_file(path: t.PathStr) -> bytes:
    """
    Returns the cryptographic salt contained within the file located at
    `path`.
    """
    try:
        await aos.chmod(path, 0o600)
        async with aiofiles.open(path, "rb") as salt_file:
            salt = await salt_file.read()
            if len(salt) >= 32:
                return salt
            else:
                raise Issue.value_must("salt", "be >= 32-bytes")
    finally:
        await aos.chmod(path, 0o000)


def read_salt_file(path: t.PathStr) -> bytes:
    """
    Returns the cryptographic salt contained within the file located at
    `path`.
    """
    try:
        path = Path(path)
        path.chmod(0o600)
        salt = path.read_bytes()

        if len(salt) >= 32:
            return salt
        else:
            raise Issue.value_must("salt", "be >= 32-bytes")
    finally:
        path.chmod(0o000)


async def aupdate_salt_file(path: t.PathStr, *, salt: bytes) -> None:
    """
    Replaces the cryptographic salt contained within the file located at
    `path` with the new `salt` value.
    """
    if len(salt) < 32:
        raise Issue.value_must("salt", "be >= 32-bytes")

    try:
        await aos.chmod(path, 0o600)
        async with aiofiles.open(path, "wb") as salt_file:
            await salt_file.write(salt)
    finally:
        await aos.chmod(path, 0o000)


def update_salt_file(path: t.PathStr, *, salt: bytes) -> None:
    """
    Replaces the cryptographic salt contained within the file located at
    `path` with the new `salt` value.
    """
    if len(salt) < 32:
        raise Issue.value_must("salt", "be >= 32-bytes")

    try:
        path = Path(path)
        path.chmod(0o600)
        path.write_bytes(salt)
    finally:
        path.chmod(0o000)


async def adelete_salt_file(path: t.PathStr) -> None:
    """
    Deletes cryptographic salt contained within the file located at
    `path`.
    """
    await aos.chmod(path, 0o600)
    await aos.remove(path)


def delete_salt_file(path: t.PathStr) -> None:
    """
    Deletes cryptographic salt contained within the file located at
    `path`.
    """
    path = Path(path)
    path.chmod(0o600)
    path.unlink(path)


async def AsyncSecureSaltPath(
    path: t.OptionalPathStr = None, *, key: bytes, _admin: bool = False
) -> Path:
    """
    Returns either a directory path where sensitive files are stored, or
    the file in that directory whose name is derived from `key`. The
    `_admin` flag is for internal package management of such files.
    """
    path = (Path(path).absolute() if path else DatabasePath()) / "secure"
    path.is_dir() or await aos.mkdir(path)

    if _admin:
        admin_path = path / "_admin"
        admin_path.is_dir() or await aos.mkdir(admin_path)
        salt_path = await afind_salt_file(admin_path, key=key)
    else:
        salt_path = await afind_salt_file(path, key=key)

    salt_path.is_file() or await amake_salt_file(salt_path)
    return salt_path


def SecureSaltPath(
    path: t.OptionalPathStr = None, *, key: bytes, _admin: bool = False
) -> Path:
    """
    Returns either a directory path where sensitive files are stored, or
    the file in that directory whose name is derived from `key`. The
    `_admin` flag is for internal package management of such files.
    """
    path = (Path(path).absolute() if path else DatabasePath()) / "secure"
    path.is_dir() or path.mkdir()

    if _admin:
        admin_path = path / "_admin"
        admin_path.is_dir() or admin_path.mkdir()
        salt_path = find_salt_file(admin_path, key=key)
    else:
        salt_path = find_salt_file(path, key=key)

    salt_path.is_file() or make_salt_file(salt_path)
    return salt_path


module_api = dict(
    AsyncSecureSaltPath=AsyncSecureSaltPath,
    DatabasePath=DatabasePath,
    Path=Path,
    RootPath=RootPath,
    SecureSaltPath=SecureSaltPath,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    _afind_salt_file=afind_salt_file,
    _adelete_salt_file=adelete_salt_file,
    _amake_salt_file=amake_salt_file,
    _aread_salt_file=aread_salt_file,
    _aupdate_salt_file=aupdate_salt_file,
    _find_salt_file=find_salt_file,
    _delete_salt_file=delete_salt_file,
    _make_salt_file=make_salt_file,
    _read_salt_file=read_salt_file,
    _update_salt_file=update_salt_file,
    adeniable_filename=adeniable_filename,
    deniable_filename=deniable_filename,
)
