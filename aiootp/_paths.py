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


__all__ = []


__doc__ = "A collection of `pathlib.Path`'s & file IO utilities."


import os
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
    dir_path = os.path.dirname(os.path.realpath(__file__))
    return Path(dir_path).absolute()


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
    global axi_mix

    from .generics.transform import axi_mix

    if 16 < size < 1:
        raise Issue.value_must("size", "be <= 16 and > 0")      # pragma: no cover
    filename = sha3_256(await axi_mix(key, size=size)).digest()
    return await t.ByteIO.abytes_to_filename(filename[FILENAME_HASH_SLICE])


def deniable_filename(key: bytes, *, size: int = 8) -> str:
    """
    XORs `size` length bytes-type segments of a `key`, returning a
    variably forgeable, base-38 encoded hash from the condensed value.
    """
    global xi_mix

    from .generics.transform import xi_mix

    if 16 < size < 1:
        raise Issue.value_must("size", "be <= 16 and > 0")      # pragma: no cover
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
    async with aiofiles.open(path, "wb") as salt_file:
        await salt_file.write(salt)
    await aos.chmod(path, 0o000)


def make_salt_file(path: Path, *, salt: bytes = b"") -> None:
    """
    Saves a cryptographic `salt` contained within the file located at
    `path`. If no `salt` is provided, a new random 32-byte salt is used.
    """
    salt = salt if salt else token_bytes(32)
    with open(path, "wb") as salt_file:
        salt_file.write(salt)
    os.chmod(path, 0o000)


async def aread_salt_file(path: t.PathStr) -> bytes:
    """
    Returns the cryptographic salt contained within the file located at
    `path`.
    """
    try:
        await aos.chmod(path, 0o700)
        async with aiofiles.open(path, "rb") as salt_file:
            salt = await salt_file.read()
            if len(salt) >= 32:
                return salt
            else:
                raise ValueError("len(salt) must be >= 32")     # pragma: no cover
    finally:
        await aos.chmod(path, 0o000)


def read_salt_file(path: t.PathStr) -> bytes:
    """
    Returns the cryptographic salt contained within the file located at
    `path`.
    """
    try:
        os.chmod(path, 0o700)
        with open(path, "rb") as salt_file:
            salt = salt_file.read()
            if len(salt) >= 32:
                return salt
            else:
                raise ValueError("len(salt) must be >= 32")     # pragma: no cover
    finally:
        os.chmod(path, 0o000)


async def aupdate_salt_file(path: t.PathStr, *, salt: bytes) -> None:
    """
    Replaces the cryptographic salt contained within the file located at
    `path` with the new `salt` value.
    """
    if len(salt) < 32:                                          # pragma: no cover
        raise ValueError("len(salt) must be >= 32")             # pragma: no cover
    try:                                                        # pragma: no cover
        await aos.chmod(path, 0o700)                            # pragma: no cover
        async with aiofiles.open(path, "wb") as salt_file:      # pragma: no cover
            await salt_file.write(salt)                         # pragma: no cover
    finally:                                                    # pragma: no cover
        await aos.chmod(path, 0o000)                            # pragma: no cover


def update_salt_file(path: t.PathStr, *, salt: bytes) -> None:
    """
    Replaces the cryptographic salt contained within the file located at
    `path` with the new `salt` value.
    """
    if len(salt) < 32:
        raise ValueError("len(salt) must be >= 32")             # pragma: no cover
    try:
        os.chmod(path, 0o700)
        with open(path, "wb") as salt_file:
            salt_file.write(salt)
    finally:
        os.chmod(path, 0o000)


async def adelete_salt_file(path: t.PathStr) -> None:
    """
    Deletes cryptographic salt contained within the file located at
    `path`.
    """
    await aos.chmod(path, 0o700)
    await aos.remove(path)


def delete_salt_file(path: t.PathStr) -> None:
    """
    Deletes cryptographic salt contained within the file located at
    `path`.
    """
    os.chmod(path, 0o700)
    os.remove(path)


async def AsyncSecurePath(
    path: t.OptionalPathStr = None,
    *,
    key: t.Optional[bytes] = None,
    _admin: bool = False,
) -> Path:
    """
    Returns either a directory path where sensitive files are stored, or
    the file in that directory whose name is derived from `key`. The
    `_admin` flag is for internal package management of such files.
    """
    path = (Path(path).absolute() if path else DatabasePath()) / "secure"
    admin_path = path / "_admin"
    0 if path.is_dir() else await aos.mkdir(path)
    0 if admin_path.is_dir() else await aos.mkdir(admin_path)
    if key:
        fp = await afind_salt_file(admin_path if _admin else path, key=key)
        0 if fp.is_file() else await amake_salt_file(fp)
        return fp
    else:
        return path                                             # pragma: no cover


def SecurePath(
    path: t.OptionalPathStr = None,
    *,
    key: t.Optional[bytes] = None,
    _admin: bool = False,
) -> Path:
    """
    Returns either a directory path where sensitive files are stored, or
    the file in that directory whose name is derived from `key`. The
    `_admin` flag is for internal package management of such files.
    """
    path = (Path(path).absolute() if path else DatabasePath()) / "secure"
    admin_path = path / "_admin"
    0 if path.is_dir() else os.mkdir(path)
    0 if admin_path.is_dir() else os.mkdir(admin_path)
    if key:
        fp = find_salt_file(admin_path if _admin else path, key=key)
        0 if fp.is_file() else make_salt_file(fp)
        return fp
    else:
        return path                                             # pragma: no cover


module_api = dict(
    AsyncSecurePath=AsyncSecurePath,
    DatabasePath=DatabasePath,
    Path=Path,
    RootPath=RootPath,
    SecurePath=SecurePath,
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

