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


__all__ = [
    "abase_as_int",
    "aint_as_base",
    "axi_mix",
    "base_as_int",
    "int_as_base",
    "xi_mix",
]


__doc__ = "Functions to transform the representation of data."


from aiootp._typing import Typing as t
from aiootp._constants import BIG, Tables
from aiootp._exceptions import Issue
from aiootp._gentools import abatch, batch
from aiootp.asynchs import asleep


async def abase_as_int(
    string: t.AnyStr,
    base: t.Optional[int] = None,
    *,
    table: t.AnyStr = Tables.ASCII_95,
) -> int:
    """
    Convert `string` in numerical `base` into decimal integer.
    """
    if base is None:
        base = len(table)
    power = 1
    result = 0
    base_table = table[:base]
    await asleep()
    for char in reversed(string):
        if char not in base_table:
            raise Issue.invalid_value("base with the given table")
        result += base_table.find(char) * power
        power = power * base
    await asleep()
    return result


def base_as_int(
    string: t.AnyStr,
    base: t.Optional[int] = None,
    *,
    table: t.AnyStr = Tables.ASCII_95,
) -> int:
    """
    Convert `string` in numerical `base` into decimal integer.
    """
    if base is None:
        base = len(table)
    power = 1
    result = 0
    base_table = table[:base]
    for char in reversed(string):
        if char not in base_table:
            raise Issue.invalid_value("base with the given table")
        result += base_table.find(char) * power
        power = power * base
    return result


async def aint_as_base(
    number: int,
    base: t.Optional[int] = None,
    *,
    table: t.AnyStr = Tables.ASCII_95,
) -> t.AnyStr:
    """
    Convert an `number` back into a string in numerical `base`.
    """
    if not number:
        return table[:1]
    elif base is None:
        base = len(table)
    digits = []
    base_table = table[:base]
    await asleep()
    while number:
        digits.append(base_table[number % base])
        number //= base
    digits.reverse()
    await asleep()
    if base_table.__class__ is bytes:
        return bytes(digits)
    else:
        return "".join(digits)


def int_as_base(
    number: int,
    base: t.Optional[int] = None,
    *,
    table: t.AnyStr = Tables.ASCII_95,
) -> t.AnyStr:
    """
    Convert an `number` back into a string in numerical `base`.
    """
    if not number:
        return table[:1]
    elif base is None:
        base = len(table)
    digits = []
    base_table = table[:base]
    while number:
        digits.append(base_table[number % base])
        number //= base
    digits.reverse()
    if base_table.__class__ is bytes:
        return bytes(digits)
    else:
        return "".join(digits)


async def axi_mix(bytes_hash: bytes, size: int = 8) -> bytes:
    """
    Xors subsequent `size` length segments of `bytes_hash` with each
    other to condense the hash down to `size` bytes.
    """
    result = 0
    async for chunk in abatch(bytes_hash, size=size):
        result ^= int.from_bytes(chunk, BIG)
    return result.to_bytes(size, BIG)


def xi_mix(bytes_hash: bytes, size: int = 8) -> bytes:
    """
    Xors subsequent `size` length segments of `bytes_hash` with each
    other to condense the hash down to `size` bytes.
    """
    result = 0
    for chunk in batch(bytes_hash, size=size):
        result ^= int.from_bytes(chunk, BIG)
    return result.to_bytes(size, BIG)


module_api = dict(
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    abase_as_int=abase_as_int,
    aint_as_base=aint_as_base,
    axi_mix=axi_mix,
    base_as_int=base_as_int,
    int_as_base=int_as_base,
    xi_mix=xi_mix,
)

