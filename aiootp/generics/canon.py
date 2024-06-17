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
    "abytes_are_equal",
    "acanonical_pack",
    "acanonical_unpack",
    "adecode_items",
    "aencode_items",
    "aencode_key",
    "afullblock_ljust",
    "bytes_are_equal",
    "canonical_pack",
    "canonical_unpack",
    "decode_items",
    "fullblock_ljust",
    "encode_items",
    "encode_key",
    "test_canonical_padding",
]


__doc__ = "Canonicalization utilities."


import io
from math import ceil
from collections import deque
from hmac import compare_digest as bytes_are_equal

from aiootp._typing import Typing as t
from aiootp._constants import LITTLE, BIG, INT_BYTES
from aiootp._exceptions import Issue, CanonicalIssue
from aiootp._gentools import abatch, batch, arange
from aiootp.asynchs import asleep


async def abytes_are_equal(value_0: bytes, value_1: bytes) -> bool:
    """
    Tests if two bytes values are equal with a simple & fast timing-safe
    comparison function from the `hmac` module.
    """
    await asleep()
    return bytes_are_equal(value_0, value_1)


async def afullblock_ljust(
    data: bytes, blocksize: int, *, pad: bytes = b"\x00"
) -> bytes:
    """
    Right pads a `bytes`-type `data` value to a multiple of the
    integer `blocksize` with `pad` characters.
    """
    await asleep()
    return data.ljust(blocksize * ceil(len(data) / blocksize), pad)


def fullblock_ljust(
    data: bytes, blocksize: int, *, pad: bytes = b"\x00"
) -> bytes:
    """
    Right pads a `bytes`-type `data` value to a multiple of the
    integer `blocksize` with `pad` characters.
    """
    return data.ljust(blocksize * ceil(len(data) / blocksize), pad)


async def aencode_key(
    key: bytes, blocksize: int, *, pad: bytes = b"\x00"
) -> bytes:
    """
    Returns a symmetric `key` canonically encoded so as to be
    prepended to other canonically encoded data for use in hash
    functions.
    """
    if not key:
        raise Issue.value_must("key", "be supplied for encoding")
    key_length = len(key).to_bytes(8, LITTLE)
    bsize = blocksize.to_bytes(8, LITTLE)
    return await afullblock_ljust(
        b"".join((key, key_length, bsize, pad)), blocksize, pad=pad
    )


def encode_key(
    key: bytes, blocksize: int, *, pad: bytes = b"\x00"
) -> bytes:
    """
    Returns a symmetric `key` canonically encoded so as to be
    prepended to other canonically encoded data for use in hash
    functions.
    """
    if not key:
        raise Issue.value_must("key", "be supplied for encoding")
    key_length = len(key).to_bytes(8, LITTLE)
    bsize = blocksize.to_bytes(8, LITTLE)
    return fullblock_ljust(
        b"".join((key, key_length, bsize, pad)), blocksize, pad=pad
    )


async def aencode_items(
    *items: bytes, int_bytes: int = INT_BYTES
) -> t.AsyncGenerator[bytes, None]:
    """
    Yields each item in `items` with encoded length metadata attached.
    """
    yield int_bytes.to_bytes(1, BIG)
    yield len(items).to_bytes(int_bytes, BIG)
    for item in items:
        await asleep()
        yield len(item).to_bytes(int_bytes, BIG) + item


def encode_items(
    *items: bytes, int_bytes: int = INT_BYTES
) -> t.Generator[bytes, None, None]:
    """
    Yields each item in `items` with encoded length metadata attached.
    """
    yield int_bytes.to_bytes(1, BIG)
    yield len(items).to_bytes(int_bytes, BIG)
    for item in items:
        yield len(item).to_bytes(int_bytes, BIG) + item


async def acanonical_pack(
    *items: bytes,
    blocksize: int = 1,
    pad: bytes = b"\x00",
    int_bytes: int = INT_BYTES,
) -> bytes:
    """
    Returns a joined iterable of bytes-type `items` with encoded length
    metadata of the iterable & each item attached. The result is right-
    padded with `pad` to a multiple of the `blocksize`. This can be used
    to prevent canonicalization & length extension attacks when hashing
    arbitrary collections of inputs.

    https://soatok.blog/2021/07/30/canonicalization-attacks-against-macs
    -and-signatures/

     _____________________________________
    |                                     |
    |           Format Diagram:           |
    |_____________________________________|

    I = `int_bytes`
    |----  len(result) % blocksize == 0, right padded with `pad`  -----|
     __________________________________________________________________
    |                   |               |                            | |
    |   len(Iterable)   |   len(Item)   |            Item            | |
    |                   |               |                            | |
    |     I-bytes       |    I-bytes    |           X-bytes          | |
    |     = W + 2       |    = X        |                            | |
    |___________________|_______________|____________________________| |
    |                   |                                            | |
    |   1 x at start    |           W x once for each item           | |
    |___________________|____________________________________________|_|
    """
    blocksize_blob = blocksize.to_bytes(int_bytes, BIG)
    items = [
        item
        async for item
        in aencode_items(blocksize_blob, pad, *items, int_bytes=int_bytes)
    ]
    return fullblock_ljust(b"".join(items), blocksize, pad=pad)


def canonical_pack(
    *items: bytes,
    blocksize: int = 1,
    pad: bytes = b"\x00",
    int_bytes: int = INT_BYTES,
) -> bytes:
    """
    Returns a joined iterable of bytes-type `items` with encoded length
    metadata of the iterable & each item attached. The result is right-
    padded with `pad` to a multiple of the `blocksize`. This can be used
    to prevent canonicalization & length extension attacks when hashing
    arbitrary collections of inputs.

    https://soatok.blog/2021/07/30/canonicalization-attacks-against-macs
    -and-signatures/

     _____________________________________
    |                                     |
    |           Format Diagram:           |
    |_____________________________________|

    I = `int_bytes`
    |----  len(result) % blocksize == 0, right padded with `pad`  -----|
     __________________________________________________________________
    |                   |               |                            | |
    |   len(Iterable)   |   len(Item)   |            Item            | |
    |                   |               |                            | |
    |     I-bytes       |    I-bytes    |           X-bytes          | |
    |     = W + 2       |    = X        |                            | |
    |___________________|_______________|____________________________| |
    |                   |                                            | |
    |   1 x at start    |           W x once for each item           | |
    |___________________|____________________________________________|_|
    """
    blocksize_blob = blocksize.to_bytes(int_bytes, BIG)
    items = encode_items(blocksize_blob, pad, *items, int_bytes=int_bytes)
    return fullblock_ljust(b"".join(items), blocksize, pad=pad)


async def adecode_items(
    read: t.Callable[[int], bytes], item_count: int, int_bytes: int
) -> t.AsyncGenerator[bytes, None]:
    """
    Extracts each size-item pair from the `read` callable, which
    outputs a number of canonically encoded bytes equal to the integer
    it receives as an argument. Yields all `item_count` number of
    items one at a time if each item's length matches its declared
    length, otherwise raises `CanonicalEncodingError`. `int_bytes` is
    the number of bytes that were used to encode item lengths.
    """
    async for _ in arange(item_count):
        item_size = int.from_bytes(read(int_bytes), BIG)
        item = read(item_size)
        if len(item) != item_size:
            raise CanonicalIssue.item_length_mismatch()
        yield item


def decode_items(
    read: t.Callable[[int], bytes], item_count: int, int_bytes: int
) -> t.Generator[bytes, None, None]:
    """
    Extracts each size-item pair from the `read` callable, which
    outputs a number of canonically encoded bytes equal to the integer
    it receives as an argument. Yields all `item_count` number of
    items one at a time if each item's length matches its declared
    length, otherwise raises `CanonicalEncodingError`. `int_bytes` is
    the number of bytes that were used to encode item lengths.
    """
    for _ in range(item_count):
        item_size = int.from_bytes(read(int_bytes), BIG)
        item = read(item_size)
        if len(item) != item_size:
            raise CanonicalIssue.item_length_mismatch()
        yield item


def test_canonical_padding(
    read: t.Callable[[int], bytes], items: t.Deque[bytes], total_size: int
) -> None:
    """
    Raises `CanonicalEncodingError` if an invalid type of padding is
    detected in the bytes-type data produced by the `read` callable.
    """
    try:
        blocksize = int.from_bytes(items.popleft(), BIG)
        pad = items.popleft()
    except IndexError as error:
        raise CanonicalIssue.missing_metadata_items() from error
    if total_size % blocksize:
        raise CanonicalIssue.data_length_blocksize_mismatch()
    elif len(pad) != 1 or not set(pad).issuperset(read()):
        raise CanonicalIssue.invalid_padding()


async def acanonical_unpack(items: bytes) -> t.Deque[bytes]:
    """
    Extracts the bytes-type values that have been canonically encoded
    into the `items` byte string. `int_bytes` is the number of bytes
    that were used to encode item lengths.
    """
    total_size = len(items)
    read = io.BytesIO(items).read
    int_bytes = int.from_bytes(read(1), BIG)
    item_count = int.from_bytes(read(int_bytes), BIG)
    if total_size < int_bytes * (item_count + 1) + 3:
        raise CanonicalIssue.inflated_size_declaration()
    items = deque(
        [item async for item in adecode_items(read, item_count, int_bytes)],
        maxlen=item_count,
    )
    test_canonical_padding(read, items, total_size)
    return items


def canonical_unpack(items: bytes) -> t.Deque[bytes]:
    """
    Extracts the bytes-type values that have been canonically encoded
    into the `items` byte string. `int_bytes` is the number of bytes
    that were used to encode item lengths.
    """
    total_size = len(items)
    read = io.BytesIO(items).read
    int_bytes = int.from_bytes(read(1), BIG)
    item_count = int.from_bytes(read(int_bytes), BIG)
    if total_size < int_bytes * (item_count + 1) + 3:
        raise CanonicalIssue.inflated_size_declaration()
    items = deque(
        decode_items(read, item_count, int_bytes), maxlen=item_count
    )
    test_canonical_padding(read, items, total_size)
    return items


module_api = dict(
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    abytes_are_equal=abytes_are_equal,
    acanonical_pack=acanonical_pack,
    acanonical_unpack=acanonical_unpack,
    adecode_items=adecode_items,
    aencode_items=aencode_items,
    aencode_key=aencode_key,
    afullblock_ljust=afullblock_ljust,
    bytes_are_equal=bytes_are_equal,
    canonical_pack=canonical_pack,
    canonical_unpack=canonical_unpack,
    decode_items=decode_items,
    fullblock_ljust=fullblock_ljust,
    encode_items=encode_items,
    encode_key=encode_key,
    test_canonical_padding=test_canonical_padding,
)

