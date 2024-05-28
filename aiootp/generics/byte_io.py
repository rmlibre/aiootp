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


__all__ = ["ByteIO"]


__doc__ = "File IO & bytes encoding utilities."


import aiofiles
from math import ceil
from base64 import urlsafe_b64encode, urlsafe_b64decode

from aiootp._typing import Typing as t
from aiootp._constants import Tables, BIG
from aiootp.commons import FrozenInstance
from aiootp.asynchs import asleep

from .transform import abase_as_int, base_as_int, aint_as_base, int_as_base
from .canon import fullblock_ljust


class ByteIO(FrozenInstance):
    """
    An interface for bytes encodinga & IO operations.
    """

    __slots__ = ()

    @staticmethod
    async def abytes_to_urlsafe(value: bytes) -> bytes:
        """
        Converts a raw bytes `value` to a url safe, base64 encoded
        byte string.
        """
        await asleep()
        return urlsafe_b64encode(value).replace(b"=", b"")

    @staticmethod
    def bytes_to_urlsafe(value: bytes) -> bytes:
        """
        Converts a raw bytes `value` to a url safe, base64 encoded
        byte string.
        """
        urlsafe_value = urlsafe_b64encode(value)
        return urlsafe_value.replace(b"=", b"")

    @staticmethod
    async def aurlsafe_to_bytes(value: t.AnyStr) -> bytes:
        """
        Turns a url safe base64 encoded `value` back into a raw
        decoded byte string.
        """
        await asleep()
        if value.__class__ is str:
            value = value.encode()
        return urlsafe_b64decode(fullblock_ljust(value, 4, pad=b"="))

    @staticmethod
    def urlsafe_to_bytes(value: t.AnyStr) -> bytes:
        """
        Turns a url safe base64 encoded `value` back into a raw
        decoded byte string.
        """
        if value.__class__ is str:
            value = value.encode()
        return urlsafe_b64decode(fullblock_ljust(value, 4, pad=b"="))

    @staticmethod
    async def abytes_to_filename(value: bytes) -> str:
        """
        Returns the received bytes-type `value` in base38 encoding,
        which can be used as a filename to maintain compatibility on a
        very wide array of platforms.
        """
        return await aint_as_base(
            int.from_bytes(value, BIG), base=38, table=Tables.BASE_38
        )

    @staticmethod
    def bytes_to_filename(value: bytes) -> str:
        """
        Returns the received bytes-type `value` in base38 encoding,
        which can be used as a filename to maintain compatibility on a
        very wide array of platforms.
        """
        return int_as_base(
            int.from_bytes(value, BIG), base=38, table=Tables.BASE_38
        )

    @staticmethod
    async def afilename_to_bytes(filename: str) -> bytes:
        """
        Returns the base38 encoded `filename` as raw decoded bytes.
        """
        result = await abase_as_int(filename, base=38, table=Tables.BASE_38)
        byte_count = ceil(result.bit_length() / 8)
        return result.to_bytes(byte_count, BIG)

    @staticmethod
    def filename_to_bytes(filename: str) -> bytes:
        """
        Returns the base38 encoded `filename` as raw decoded bytes.
        """
        result = base_as_int(filename, base=38, table=Tables.BASE_38)
        byte_count = ceil(result.bit_length() / 8)
        return result.to_bytes(byte_count, BIG)

    @staticmethod
    async def aread(path: t.PathStr) -> bytes:
        """
        Reads the bytes data from the file at `path`.
        """
        async with aiofiles.open(path, "rb") as f:
            return await f.read()

    @staticmethod
    def read(path: t.PathStr) -> bytes:
        """
        Reads the bytes data from the file at `path`.
        """
        with open(path, "rb") as f:
            return f.read()

    @staticmethod
    async def awrite(path: t.PathStr, data: bytes) -> None:
        """
        Writes bytes `data` to the file at `path`.
        """
        async with aiofiles.open(path, "wb+") as f:
            await f.write(data)

    @staticmethod
    def write(path: t.PathStr, data: bytes) -> None:
        """
        Writes bytes `data` to the file at `path`.
        """
        with open(path, "wb+") as f:
            f.write(data)

    @staticmethod
    async def aappend(path: t.PathStr, data: bytes) -> None:
        """
        Appends bytes `data` to the file at `path`.
        """
        async with aiofiles.open(path, "ab+") as f:
            await f.write(data)

    @staticmethod
    def append(path: t.PathStr, data: bytes) -> None:
        """
        Appends bytes `data` to the file at `path`.
        """
        with open(path, "ab+") as f:
            f.write(data)


module_api = dict(
    ByteIO=t.add_type(ByteIO),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

