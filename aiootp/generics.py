# This file is part of aiootp, an asynchronous crypto and anonymity
# library. Home of the Chunky2048 psuedo one-time pad stream cipher.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "Domains",
    "abytes_are_equal",
    "ahash_bytes",
    "bytes_are_equal",
    "hash_bytes",
]


__doc__ = (
    "A collection of basic utilities for simplifying & supporting the r"
    "est of the codebase."
)


import io
import hmac
import math
import json
import heapq
import base64
import aiofiles
import builtins
from pathlib import Path
from collections import deque
from inspect import getsource
from secrets import token_bytes
from hmac import compare_digest as bytes_are_equal
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from base64 import (
    standard_b64encode,
    standard_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)
from .__constants import *
from ._containers import *
from ._exceptions import *
from ._typing import Typing as t
from .commons import OpenNamespace, make_module
from .asynchs import Threads, Processes
from .asynchs import (
    sleep,
    asleep,
    gather,
    this_year,
    this_month,
    this_day,
    this_hour,
    this_minute,
    this_second,
    this_millisecond,
    this_microsecond,
    this_nanosecond,
)


class Clock:
    """
    A class whose objects are used for creating & measuring bytes-type
    timestamps, with configurable the units & epoch of measure.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp.generics import Clock

    # Create an object with specified units & epoch ->
    ns_clock = Clock("nanoseconds", epoch=0)

    # Create a bytes-type timestamp of the object's current time in
    # nanoseconds from its epoch ->
    timestamp = ns_clock.make_timestamp(size=8)

    # Retrieve the elapsed time from the object's current time & a given
    # timestamp ->
    while ns_clock.delta(timestamp) < 2_000_000_000: # wait two seconds
        await do_something_else()

    # Throw a `TimestampExpired` error if a given timestamp is older
    # than `ttl` units from the object's current time ->
    try:
        ns_clock.test_timestamp(timestamp, ttl=1_000_000_000)
    except ns_clock.TimestampExpired as e:
        print(f"Timestamp expired by {e.expired_by} # of {e.unit}.")
        'Timestamp expired by 287491003983 # of nanoseconds.'

    # These are the supported units ->
    year_clock = Clock("years")
    month_clock = Clock("months")
    day_clock = Clock("days")
    hour_clock = Clock("hours")
    minute_clock = Clock("minutes")
    second_clock = Clock("seconds")
    ms_clock = Clock("milliseconds")
    µs_clock = Clock("microseconds")
    ns_clock = Clock("nanoseconds")

    # The `epoch` is always measured in nanoseconds from the UNIX epoch of 0
    hour_clock = Clock("hours", epoch=9000)  # time starts 9000 nanoseconds
                                             # after the UNIX epoch
    # The default epoch for the package is 1672531200000000000,
    # Sun, 01 Jan 2023 00:00:00 UTC
    """

    __slots__ = ("_time", "_epoch", "_unit")

    _times: OpenNamespace = OpenNamespace(
        years=this_year,
        months=this_month,
        days=this_day,
        hours=this_hour,
        minutes=this_minute,
        seconds=this_second,
        milliseconds=this_millisecond,
        microseconds=this_microsecond,
        nanoseconds=this_nanosecond,
    )

    TimestampExpired = TimestampExpired

    def __init__(
        self, unit: str = SECONDS, *, epoch: int = EPOCH_NS
    ) -> None:
        """
        Create an object which can create & measure bytes-type
        timestamps, with configurable units & epoch of measure.
        """
        if unit not in self._times:
            raise Issue.invalid_value("time unit", unit)
        self._unit = unit
        self._time = self._times[unit]
        self._epoch = epoch

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__qualname__}("
            f"{repr(self._unit)}, epoch={self._epoch})"
        )

    async def atime(self) -> int:
        """
        Returns the instance's conception of the current time as an
        integer, which is the number of time units since the instance's
        epoch.
        """
        await asleep()
        return self._time(self._epoch)

    def time(self) -> int:
        """
        Returns the instance's conception of the current time as an
        integer, which is the number of time units since the instance's
        epoch.
        """
        return self._time(self._epoch)

    async def amake_timestamp(
        self,
        *,
        size: int = SAFE_TIMESTAMP_BYTES,
        byte_order: str = BIG,
    ) -> bytes:
        """
        Returns a ``size``-byte ``byte_order``-endian representation of
        the instance's conception of the current time.
        """
        return (await self.atime()).to_bytes(size, byte_order)

    def make_timestamp(
        self,
        *,
        size: int = SAFE_TIMESTAMP_BYTES,
        byte_order: str = BIG,
    ) -> bytes:
        """
        Returns a ``size``-byte ``byte_order``-endian representation of
        the instance's conception of the current time.
        """
        return self.time().to_bytes(size, byte_order)

    async def aread_timestamp(
        self, timestamp: bytes, *, byte_order: str = BIG
    ) -> int:
        """
        Returns the integer representation of the ``byte_order``-endian
        bytes-type ``timestamp``.
        """
        await asleep()
        return int.from_bytes(timestamp, byte_order)

    def read_timestamp(
        self, timestamp: bytes, *, byte_order: str = BIG
    ) -> int:
        """
        Returns the integer representation of the ``byte_order``-endian
        bytes-type ``timestamp``.
        """
        return int.from_bytes(timestamp, byte_order)

    async def adelta(
        self, timestamp: bytes, *, byte_order: str = BIG
    ) -> int:
        """
        Takes a ``timestamp`` & returns the integer difference between
        the instance's conception of the current time & the timestamp.
        """
        return await self.atime() - await self.aread_timestamp(timestamp)

    def delta(
        self, timestamp: bytes, *, byte_order: str = BIG
    ) -> int:
        """
        Takes a ``timestamp`` & returns the integer difference between
        the instance's conception of the current time & the timestamp.
        """
        return self.time() - self.read_timestamp(timestamp)

    async def atest_timestamp(
        self, timestamp: bytes, ttl: int, *, byte_order: str = BIG
    ) -> None:
        """
        Raises ``TimestampExpired`` if ``timestamp`` is more than
        ``ttl`` time units old from the instance's conception of the
        current time.
        """
        delta = await self.adelta(timestamp, byte_order=byte_order)
        timestamp_is_expired = delta > ttl
        expired_by = delta - ttl
        if not ttl:
            return
        elif timestamp_is_expired:
            raise TimestampIssue.timestamp_expired(self._unit, expired_by)

    def test_timestamp(
        self, timestamp: bytes, ttl: int, *, byte_order: str = BIG
    ) -> None:
        """
        Raises ``TimestampExpired`` if ``timestamp`` is more than
        ``ttl`` time units old from the instance's conception of the
        current time.
        """
        delta = self.delta(timestamp, byte_order=byte_order)
        timestamp_is_expired = delta > ttl
        expired_by = delta - ttl
        if not ttl:
            return
        elif timestamp_is_expired:
            raise TimestampIssue.timestamp_expired(self._unit, expired_by)


class MaskedClock(Clock):
    """
    Adds a constant integer as a simple mask to the time values produced
    by instances, the result becomes the instance's conception of the
    current time.
    """

    __slots__ = ("_mask")

    def __init__(self, *a, mask: int, **kw) -> None:
        """
        Stores the mask value & runs the base class' initializer.
        """
        self._mask = mask
        super().__init__(*a, **kw)

    async def atime(self) -> int:
        """
        Returns the instance's conception of the current time as an
        integer, which is the number of time units since the instance's
        epoch.
        """
        await asleep()
        return self._time(self._epoch) + self._mask

    def time(self) -> int:
        """
        Returns the instance's conception of the current time as an
        integer, which is the number of time units since the instance's
        epoch.
        """
        return self._time(self._epoch) + self._mask


clock = Clock(SECONDS)


def src(obj, *, display=True) -> t.Optional[str]:
    """
    Prints the source code of an object to the screen or, if ``display``
    is toggled to a falsey value, returns the source code instead.
    """
    if display:
        print(getsource(obj))
    else:
        return getsource(obj)


async def abytes_are_equal(value_0: bytes, value_1: bytes) -> bool:
    """
    Tests if two bytes values are equal with a simple & fast timing-safe
    comparison function from the `hmac` module.
    """
    await asleep()
    return bytes_are_equal(value_0, value_1)


async def abytes_as_int(
    data: bytes, *, byte_order: str = BIG
) -> int:
    """
    Returns the `bytes`-type ``data`` value as a ``byte_order``-endian
    `int`.
    """
    await asleep()
    return int.from_bytes(data, byte_order)


def bytes_as_int(data: bytes, *, byte_order: str = BIG) -> int:
    """
    Returns the `bytes`-type ``data`` value as a ``byte_order``-endian
    `int`.
    """
    return int.from_bytes(data, byte_order)


async def aint_as_bytes(
    data: int, *, size: int = 8, byte_order: str = BIG
) -> bytes:
    """
    Returns an integer ``data`` as a ``byte_order``-endian, ``size``
    -byte bytestring.
    """
    await asleep()
    return data.to_bytes(size, byte_order)


def int_as_bytes(
    data: int, *, size: int = 8, byte_order: str = BIG
) -> bytes:
    """
    Returns an integer ``data`` as a ``byte_order``-endian, ``size``
    -byte bytestring.
    """
    return data.to_bytes(size, byte_order)


async def alen_as_bytes(
    data: t.Sequence, size: int = 8, byte_order: str = BIG
) -> bytes:
    """
    Returns the `len` of ``data`` as a ``byte_order``-endian, ``size``-
    byte bytestring.
    """
    await asleep()
    return len(data).to_bytes(size, byte_order)


def len_as_bytes(
    data: t.Sequence, size: int = 8, byte_order: str = BIG
) -> bytes:
    """
    Returns the `len` of ``data`` as a ``byte_order``-endian, ``size``-
    byte bytestring.
    """
    return len(data).to_bytes(size, byte_order)


async def abase_as_int(
    string: t.AnyStr,
    base: int = 0,
    *,
    table: t.AnyStr = Tables.ASCII_95,
) -> int:
    """
    Convert ``string`` in numerical ``base`` into decimal integer.
    """
    if not base:
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
    base: int = 0,
    *,
    table: t.AnyStr = Tables.ASCII_95,
) -> int:
    """
    Convert ``string`` in numerical ``base`` into decimal integer.
    """
    if not base:
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
    base: int = 0,
    *,
    table: t.AnyStr = Tables.ASCII_95,
) -> t.AnyStr:
    """
    Convert an ``number`` back into a string in numerical ``base``.
    """
    if not number:
        return table[:1]
    elif not base:
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
    base: int = 0,
    *,
    table: t.AnyStr = Tables.ASCII_95,
) -> t.AnyStr:
    """
    Convert an ``number`` back into a string in numerical ``base``.
    """
    if not number:
        return table[:1]
    elif not base:
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
    Xors subsequent ``size`` length segments of ``bytes_hash`` with each
    other to condense the hash down to ``size`` bytes.
    """
    result = 0
    async for chunk in BytesIO.adata(bytes_hash, size=size):
        result ^= int.from_bytes(chunk, BIG)
    return result.to_bytes(size, BIG)


def xi_mix(bytes_hash: bytes, size: int = 8) -> bytes:
    """
    Xors subsequent ``size`` length segments of ``bytes_hash`` with each
    other to condense the hash down to ``size`` bytes.
    """
    result = 0
    for chunk in BytesIO.data(bytes_hash, size=size):
        result ^= int.from_bytes(chunk, BIG)
    return result.to_bytes(size, BIG)


async def afullblock_ljust(
    data: bytes, blocksize: int, *, pad: bytes = b"\x00"
) -> bytes:
    """
    Right pads a `bytes`-type ``data`` value to a multiple of the
    integer ``blocksize`` with ``pad`` characters.

    A ``blocksize`` value of `1`, or less, is a no-op.
    """
    await asleep()
    if blocksize <= 1:
        return data
    return data.ljust(blocksize * math.ceil(len(data) / blocksize), pad)


def fullblock_ljust(
    data: bytes, blocksize: int, *, pad: bytes = b"\x00"
) -> bytes:
    """
    Right pads a `bytes`-type ``data`` value to a multiple of the
    integer ``blocksize`` with ``pad`` characters.

    A ``blocksize`` value of `1`, or less, is a no-op.
    """
    if blocksize <= 1:
        return data
    return data.ljust(blocksize * math.ceil(len(data) / blocksize), pad)


async def aencode_key(
    key: bytes, blocksize: int, *, pad: bytes = b"\x00"
) -> bytes:
    """
    Returns a symmetric ``key`` canonically encoded so as to be
    prepended to other canonically encoded data for use in hash
    functions.
    """
    if not key:
        raise Issue.value_must("key", "be supplied for encoding")
    key_length = len_as_bytes(key, byte_order=LITTLE)
    bsize = int_as_bytes(blocksize, byte_order=LITTLE)
    return await afullblock_ljust(
        b"".join((key, key_length, bsize, pad)), blocksize, pad=pad
    )


def encode_key(
    key: bytes, blocksize: int, *, pad: bytes = b"\x00"
) -> bytes:
    """
    Returns a symmetric ``key`` canonically encoded so as to be
    prepended to other canonically encoded data for use in hash
    functions.
    """
    if not key:
        raise Issue.value_must("key", "be supplied for encoding")
    key_length = len_as_bytes(key, byte_order=LITTLE)
    bsize = int_as_bytes(blocksize, byte_order=LITTLE)
    return fullblock_ljust(
        b"".join((key, key_length, bsize, pad)), blocksize, pad=pad
    )


async def aencode_items(
    *items: t.Iterable[bytes], int_bytes: int = 8
) -> t.AsyncGenerator[None, bytes]:
    """
    Yields each item in ``items`` with encoded length metadata attached.
    """
    yield len(items).to_bytes(int_bytes, BIG)
    for item in items:
        await asleep()
        yield len(item).to_bytes(int_bytes, BIG) + item


def encode_items(
    *items: t.Iterable[bytes], int_bytes: int = 8
) -> t.Generator[None, bytes, None]:
    """
    Yields each item in ``items`` with encoded length metadata attached.
    --------
    WARNING: This only yields deterministic results in versions of
    -------- python which guarantee the input order of items in a
    dictionary is preserved.
    """
    yield len(items).to_bytes(int_bytes, BIG)
    for item in items:
        yield len(item).to_bytes(int_bytes, BIG) + item


async def acanonical_pack(
    *items: t.Iterable[bytes],
    blocksize: int = 1,
    pad: bytes = b"\x00",
    int_bytes: int = 8,
) -> bytes:
    """
    Returns a joined iterable of bytes-type ``items`` with encoded
    length metadata of the iterable & each item attached. The result is
    right-padded with ``pad`` to a multiple of the ``blocksize``.  This
    can be used to prevent canonicalization attacks when processing hash
    inputs.

    https://soatok.blog/2021/07/30/canonicalization-attacks-against-macs
    -and-signatures/

    https://soatok.blog/2020/10/06/dead-ends-in-cryptanalysis-1-length-
    extension-attacks/

     _____________________________________
    |                                     |
    |           Format Diagram:           |
    |_____________________________________|

    I = ``int_bytes``
    |---  len(result) % blocksize == 0, right padded with ``pad``  ----|
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
    blocksize_blob = int_as_bytes(blocksize, size=int_bytes)
    items = [
        item
        async for item
        in aencode_items(blocksize_blob, pad, *items, int_bytes=int_bytes)
    ]
    return fullblock_ljust(b"".join(items), blocksize, pad=pad)


def canonical_pack(
    *items: t.Iterable[bytes],
    blocksize: int = 1,
    pad: bytes = b"\x00",
    int_bytes: int = 8,
) -> bytes:
    """
    Returns a joined iterable of bytes-type ``items`` with encoded
    length metadata of the iterable & each item attached. The result is
    right-padded with ``pad`` to a multiple of the ``blocksize``.  This
    can be used to prevent canonicalization attacks when processing hash
    inputs.

    https://soatok.blog/2021/07/30/canonicalization-attacks-against-macs
    -and-signatures/

    https://soatok.blog/2020/10/06/dead-ends-in-cryptanalysis-1-length-
    extension-attacks/

     _____________________________________
    |                                     |
    |           Format Diagram:           |
    |_____________________________________|

    I = ``int_bytes``
    |---  len(result) % blocksize == 0, right padded with ``pad``  ----|
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
    blocksize_blob = int_as_bytes(blocksize, size=int_bytes)
    items = encode_items(blocksize_blob, pad, *items, int_bytes=int_bytes)
    return fullblock_ljust(b"".join(items), blocksize, pad=pad)


async def _arange(*a) -> t.AsyncGenerator[None, int]:
    """
    An async version of ``builtins.range``.
    """
    for result in range(*a):
        await asleep()
        yield result


async def adecode_items(
    read: t.Callable[[int], bytes], item_count: int, int_bytes: int
) -> t.AsyncGenerator[None, bytes]:
    """
    Extracts each size-item pair from the ``read`` callable, which
    outputs a number of canonically encoded bytes equal to the integer
    it receives as an argument. Yields all ``item_count`` number of
    items one at a time if each item's length matches its declared
    length, otherwise raises `CanonicalEncodingError`. ``int_bytes`` is
    the number of bytes that were used to encode item lengths.
    """
    async for _ in _arange(item_count):
        item_size = int.from_bytes(read(int_bytes), BIG)
        item = read(item_size)
        if len(item) != item_size:
            raise CanonicalIssue.item_length_mismatch()
        yield item


def decode_items(
    read: t.Callable[[int], bytes], item_count: int, int_bytes: int
) -> t.Generator[None, bytes, None]:
    """
    Extracts each size-item pair from the ``read`` callable, which
    outputs a number of canonically encoded bytes equal to the integer
    it receives as an argument. Yields all ``item_count`` number of
    items one at a time if each item's length matches its declared
    length, otherwise raises `CanonicalEncodingError`. ``int_bytes`` is
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
    detected in the bytes-type data produced by the ``read`` callable.
    """
    try:
        blocksize = bytes_as_int(items.popleft())
        pad = items.popleft()
    except IndexError as error:
        raise CanonicalIssue.missing_metadata_items() from error
    remainder = total_size % blocksize
    padding = read()
    if remainder:
        raise CanonicalIssue.data_length_blocksize_mismatch()
    elif len(pad) != len(set(padding).union(pad)) or len(pad) > 1:
        raise CanonicalIssue.invalid_padding()


async def acanonical_unpack(
    items: bytes, *, int_bytes: int = 8
) -> t.Deque[bytes]:
    """
    Extracts the bytes-type values that have been canonically encoded
    into the ``items`` byte string. ``int_bytes`` is the number of bytes
    that were used to encode item lengths.
    """
    total_size = len(items)
    read = io.BytesIO(items).read
    item_count = await abytes_as_int(read(int_bytes))
    if item_count > total_size - int_bytes * (item_count + 1):
        raise CanonicalIssue.inflated_size_declaration()
    items = deque(
        [item async for item in adecode_items(read, item_count, int_bytes)],
        maxlen=item_count,
    )
    test_canonical_padding(read, items, total_size)
    return items


def canonical_unpack(items: bytes, *, int_bytes: int = 8) -> t.Deque[bytes]:
    """
    Extracts the bytes-type values that have been canonically encoded
    into the ``items`` byte string. ``int_bytes`` is the number of bytes
    that were used to encode item lengths.
    """
    total_size = len(items)
    read = io.BytesIO(items).read
    item_count = bytes_as_int(read(int_bytes))
    if item_count > total_size - int_bytes * (item_count + 1):
        raise CanonicalIssue.inflated_size_declaration()
    items = deque(
        decode_items(read, item_count, int_bytes), maxlen=item_count
    )
    test_canonical_padding(read, items, total_size)
    return items


async def ahash_bytes(
    *collection: t.Iterable[bytes],
    hasher: t.Any = sha3_512,
    pad: bytes = b"\x00",
    size: t.Optional[int] = 0,
    key: bytes = b"",
) -> bytes:
    """
    Joins the ``collection`` of `bytes`-type objects with a canonical
    encoding & returns the ``hasher`` object's digest of the encoded
    result.

    ``size`` may be specified if the ``hasher`` object's `digest`
    method so requires.

    Returns a keyed-hash if ``key`` is specified.
    """
    obj = hasher()
    obj.update(
        (await aencode_key(key, obj.block_size, pad=pad) if key else b"")
        + await acanonical_pack(
            int_as_bytes(size if size else obj.digest_size),
            *collection,
            blocksize=obj.block_size,
            pad=pad,
        )
    )
    if size:
        return obj.digest(size)
    return obj.digest()


def hash_bytes(
    *collection: t.Iterable[bytes],
    hasher: t.Any = sha3_512,
    pad: bytes = b"\x00",
    size: t.Optional[int] = 0,
    key: bytes = b"",
) -> bytes:
    """
    Joins the ``collection`` of `bytes`-type objects with a canonical
    encoding & returns the ``hasher`` object's digest of the encoded
    result.

    ``size`` may be specified if the ``hasher`` object's `digest`
    method so requires.

    Returns a keyed-hash if ``key`` is specified.
    """
    obj = hasher()
    obj.update(
        (encode_key(key, obj.block_size, pad=pad) if key else b"")
        + canonical_pack(
            int_as_bytes(size if size else obj.digest_size),
            *collection,
            blocksize=obj.block_size,
            pad=pad,
        )
    )
    if size:
        return obj.digest(size)
    return obj.digest()


class DomainEncoder:
    """
    A base class which enables domain constants to be encoded & created
    for specific use cases.
    """

    __slots__ = ()

    _DOMAIN: bytes = b"domain_constant_encoder"

    @classmethod
    async def aencode_constant(
        cls,
        constant: t.AnyStr,
        size: int = 8,
        *,
        domain: bytes = b"",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Receives a `str` or `bytes`-type ``constant``, encodes & hashes
        it under a ``domain``, along with the metadata of the encoding,
        then returns the ``size``-byte digest from the `shake_128` XOF.

        These returned values are used by the package as inputs to other
        functions which in turn makes their outputs domain-specific.
        This has various security benefits, such as:

        https://eprint.iacr.org/2010/264.pdf & more recent published
        works show schemes which are not provably secure, may be
        transformable into provably secure schemes just with some
        assumptions that functions which they rely upon happen to be
        domain-specific.
        """
        if constant.__class__ is not bytes:
            constant = constant.encode()
        return await ahash_bytes(
            cls._DOMAIN, domain, aad, constant, hasher=shake_128, size=size
        )

    @classmethod
    def encode_constant(
        cls,
        constant: t.AnyStr,
        size: int = 8,
        *,
        domain: bytes = b"",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Receives a `str` or `bytes`-type ``constant``, encodes & hashes
        it under a ``domain``, along with the metadata of the encoding,
        then returns the ``size``-byte digest from the `shake_128` XOF.

        These returned values are used by the package as inputs to other
        functions which in turn makes their outputs domain-specific.
        This has various security benefits, such as:

        https://eprint.iacr.org/2010/264.pdf & more recent published
        works show schemes which are not provably secure, may be
        transformable into provably secure schemes just with some
        assumptions that functions which they rely upon happen to be
        domain-specific.
        """
        if constant.__class__ is not bytes:
            constant = constant.encode()
        return hash_bytes(
            cls._DOMAIN, domain, aad, constant, hasher=shake_128, size=size
        )


class Domains(DomainEncoder):
    """
    A collection of encoded constants which can augment function inputs
    to make their outputs domain-specific.
    """

    __slots__ = ()

    _encode = DomainEncoder.encode_constant

    IV: bytes = _encode(IV)
    DH2: bytes = _encode(DH2)
    DH3: bytes = _encode(DH3)
    KDF: bytes = _encode(KDF)
    HMAC: bytes = _encode(HMAC)
    PRNG: bytes = _encode(PRNG)
    SALT: bytes = _encode(SALT)
    SEED: bytes = _encode(SEED)
    USER: bytes = _encode(USER)
    ECDHE: bytes = _encode(ECDHE)
    SHMAC: bytes = _encode(SHMAC)
    STATE: bytes = _encode(STATE)
    AIOOTP: bytes = _encode(AIOOTP)
    CSPRNG: bytes = _encode(CSPRNG)
    KEY_ID: bytes = _encode(KEY_ID)
    CHANNEL: bytes = _encode(CHANNEL)
    ENTROPY: bytes = _encode(ENTROPY)
    METATAG: bytes = _encode(METATAG)
    PAYLOAD: bytes = _encode(PAYLOAD)
    SIGNALS: bytes = _encode(SIGNALS)
    BLOCK_ID: bytes = _encode(BLOCK_ID)
    DATABASE: bytes = _encode(DATABASE)
    EQUALITY: bytes = _encode(EQUALITY)
    FILENAME: bytes = _encode(FILENAME)
    FILE_KEY: bytes = _encode(FILE_KEY)
    MANIFEST: bytes = _encode(MANIFEST)
    MNEMONIC: bytes = _encode(MNEMONIC)
    USERNAME: bytes = _encode(USERNAME)
    CLIENT_ID: bytes = _encode(CLIENT_ID)
    GUID_SALT: bytes = _encode(GUID_SALT)
    KEYSTREAM: bytes = _encode(KEYSTREAM)
    PASSCRYPT: bytes = _encode(PASSCRYPT)
    MESSAGE_ID: bytes = _encode(MESSAGE_ID)
    PASSPHRASE: bytes = _encode(PASSPHRASE)
    PUBLIC_KEY: bytes = _encode(PUBLIC_KEY)
    SECRET_KEY: bytes = _encode(SECRET_KEY)
    CHUNKY_2048: bytes = _encode(CHUNKY_2048)
    MESSAGE_KEY: bytes = _encode(MESSAGE_KEY)
    METATAG_KEY: bytes = _encode(METATAG_KEY)
    SESSION_KEY: bytes = _encode(SESSION_KEY)
    CLIENT_INDEX: bytes = _encode(CLIENT_INDEX)
    REGISTRATION: bytes = _encode(REGISTRATION)
    EMAIL_ADDRESS: bytes = _encode(EMAIL_ADDRESS)
    SENDING_COUNT: bytes = _encode(SENDING_COUNT)
    AUTHENTICATION: bytes = _encode(AUTHENTICATION)
    DIFFIE_HELLMAN: bytes = _encode(DIFFIE_HELLMAN)
    PACKAGE_SIGNER: bytes = _encode(PACKAGE_SIGNER)
    SECURE_CHANNEL: bytes = _encode(SECURE_CHANNEL)
    SENDING_STREAM: bytes = _encode(SENDING_STREAM)
    GUID_CLOCK_MASK: bytes = _encode(GUID_CLOCK_MASK)
    RECEIVING_COUNT: bytes = _encode(RECEIVING_COUNT)
    RECEIVING_STREAM: bytes = _encode(RECEIVING_STREAM)
    CLIENT_MESSAGE_KEY: bytes = _encode(CLIENT_MESSAGE_KEY)
    SERVER_MESSAGE_KEY: bytes = _encode(SERVER_MESSAGE_KEY)
    EXTENDED_DH_EXCHANGE: bytes = _encode(EXTENDED_DH_EXCHANGE)


class Hasher:
    """
    A class that creates instances to mimic & add functionality to the
    hashing object passed in during initialization.
    """

    __slots__ = ("_obj",)

    xi_mix = xi_mix
    axi_mix = axi_mix

    def __init__(self, data: bytes = b"", *, obj: t.Any = sha3_512) -> None:
        """
        Copies over the object dictionary of the ``obj`` hashing object.
        """
        self._obj = obj(data)

    @property
    def name(self) -> str:
        return self._obj.name

    @property
    def block_size(self) -> int:
        return self._obj.block_size

    @property
    def digest_size(self) -> int:
        return self._obj.digest_size

    @property
    def update(self) -> callable:
        return self._obj.update

    @property
    def digest(self) -> callable:
        return self._obj.digest

    @property
    def hexdigest(self) -> callable:
        return self._obj.hexdigest

    def copy(self) -> "cls":
        """
        Allows the user to create a copy instance of the hashing object.
        """
        new_self = self.__class__(obj=HASHER_TYPES[self._obj.name])
        new_self._obj = self._obj.copy()
        return new_self

    async def ahash(self, *data: t.Iterable[bytes], size: int = 0) -> bytes:
        """
        Receives any number of arguments of bytes type ``data`` &
        updates the instance with them all sequentially & canonically
        encoded.
        """
        kw = dict(blocksize=self.block_size)
        if size:
            digest_size = size.to_bytes(8, BIG)
            self.update(await acanonical_pack(digest_size, *data, **kw))
            return self.digest(size)
        else:
            self.update(await acanonical_pack(*data, **kw))
            return self.digest()

    def hash(self, *data: t.Iterable[bytes], size: int = 0) -> bytes:
        """
        Receives any number of arguments of bytes type ``data`` &
        updates the instance with them all sequentially & canonically
        encoded.
        """
        kw = dict(blocksize=self.block_size)
        if size:
            digest_size = size.to_bytes(8, BIG)
            self.update(canonical_pack(digest_size, *data, **kw))
            return self.digest(size)
        else:
            self.update(canonical_pack(*data, **kw))
            return self.digest()


class Padding:
    """
    Manages the (de-)padding of plaintext with various values which
    improve the package's online AEAD cipher's salt reuse / misuse
    resistance, replay attack mitigations & deniability.

     _____________________________________
    |                                     |
    |  Format Diagram: Plaintext Padding  |
    |_____________________________________|
     __________________________________________________________________
    |                      |                      |                    |
    |      Inner-Header    |        Body          |       Footer       |
    |-----------|----------|----------------------|---------|----------|
    | timestamp | SIV-key  |      plaintext       | padding | sentinel |
    |  4-bytes  | 16-bytes |       X-bytes        | Y-bytes |  1-byte  |
    |___________|__________|______________________|_________|__________|

    ``Inner-Header``: Two values: a 4-byte timestamp which aids in salt
        reuse / misuse resistance & can mitigate replay attacks, & a 16-
        byte SIV-key which also aids in salt reuse / misuse resistance.
        The timestamp, which is a counter, & the SIV-key, which is a
        random value with a (1 / 2**64) collision chance, protect
        plaintext from salt reuse / misuse even if ~2**64 ciphertext
        messages are sent in a single second which use the same `key`,
        `salt`, `aad` & `iv`. However, the inner-header will leak
        information about the timestamp if more than one message is sent
        with the same `key`, `salt`, `aad` & `iv`.

    ``Footer``: A single-byte sentinel appended at the end of plaintext
        which encodes an integer of how many bytes of padding fill the
        footer, including the random padding that preceed it. After
        padding, the final block of plaintext will be 256 bytes. Y can
        be any value between [0, 255] inclusive, where `0` means 256-
        bytes of total padding, & `1` means only the sentinel is needed
        for padding.
    """

    __slots__ = ()

    _EPOCH: int = EPOCH_NS
    _BLOCKSIZE: int = BLOCKSIZE
    _SENTINEL_BYTES: int = PADDING_SENTINEL_BYTES
    _MIN_PADDING_BLOCKS: int = MIN_PADDING_BLOCKS
    _TIMESTAMP_BYTES: int = TIMESTAMP_BYTES
    _TIMESTAMP_SLICE: int = TIMESTAMP_SLICE
    _INNER_HEADER_BYTES: int = INNER_HEADER_BYTES
    _INNER_HEADER_SLICE: slice = INNER_HEADER_SLICE
    _SIV_KEY_BYTES: int = SIV_KEY_BYTES
    _SIV_KEY_SLICE: slice = SIV_KEY_SLICE

    @classmethod
    async def amake_timestamp(cls) -> bytes:
        """
        Returns a 4-byte timestamp measured in seconds from the epoch
        set by the package (1672531200: Sun, 01 Jan 2023 00:00:00 UTC).
        """
        return await clock.amake_timestamp(size=cls._TIMESTAMP_BYTES)

    @classmethod
    def make_timestamp(cls) -> bytes:
        """
        Returns a 4-byte timestamp measured in seconds from the epoch
        set by the package (1672531200: Sun, 01 Jan 2023 00:00:00 UTC).
        """
        return clock.make_timestamp(size=cls._TIMESTAMP_BYTES)

    @classmethod
    async def amake_siv_key(cls) -> bytes:
        """
        Returns a 16-byte random bytestring. This value is used by the
        `SyntheticIV` class to ensure every encryption is randomized &
        unique even if a `salt`, `aad` & `iv` are reused with the same
        `key`.
        """
        from .randoms import agenerate_siv_key

        return await agenerate_siv_key(cls._SIV_KEY_BYTES)

    @classmethod
    def make_siv_key(cls) -> bytes:
        """
        Returns a 16-byte random bytestring. This value is used by the
        `SyntheticIV` class to ensure every encryption is randomized &
        unique even if a `salt`, `aad` & `iv` are reused with the same
        `key`.
        """
        from .randoms import generate_siv_key

        return generate_siv_key(cls._SIV_KEY_BYTES)

    @classmethod
    async def astart_padding(cls) -> bytes:
        """
        Returns the 4-byte timestamp & 16-byte SIV-key. The timestamp
        allows a time-to-live feature to exist for all ciphertexts,
        aiding against replay attacks, & improves salt reuse / misuse
        resistance. The random SIV-key gives the `Chunky2048` cipher an
        additional 64 bits of salt reuse-misuse security. Together they
        ensure that each encryption is globally unique, & that ~2**64
        messages can be sent each second before needing to rely on
        having a unique permutation of `key`, `salt`, `aad` & `iv`
        to protect the message plaintext.
        """
        return await cls.amake_timestamp() + await cls.amake_siv_key()

    @classmethod
    def start_padding(cls) -> bytes:
        """
        Returns the 4-byte timestamp & 16-byte SIV-key. The timestamp
        allows a time-to-live feature to exist for all ciphertexts,
        aiding against replay attacks, & improves salt reuse / misuse
        resistance. The random SIV-key gives the `Chunky2048` cipher an
        additional 64 bits of salt reuse-misuse security. Together they
        ensure that each encryption is globally unique, & that ~2**64
        messages can be sent each second before needing to rely on
        having a unique permutation of `key`, `salt`, `aad` & `iv`
        to protect the message plaintext.
        """
        return cls.make_timestamp() + cls.make_siv_key()

    @classmethod
    async def _amake_extra_padding(cls) -> bytes:
        """
        Returns a number of random bytes equal to the length of a block.

        These bytes provide a kind of deniability, where an adversary
        with even unlimited computational capability can't distinguish
        between all possible legitimate plaintexts. This is because
        there are enough random padding degrees of freedom (between 0 &
        255 bytes) for such an adversary to create a super-exponentially
        large number of plaintexts which appear legitimate under any key
        (satisfy verification tags) & appear plausible (they can be made
        to be almost any message + random padding).
        """
        await asleep()
        return token_bytes(cls._BLOCKSIZE * (1 + cls._MIN_PADDING_BLOCKS))

    @classmethod
    def _make_extra_padding(cls) -> bytes:
        """
        Returns a number of random bytes equal to the length of a block.

        These bytes provide a kind of deniability, where an adversary
        with even unlimited computational capability can't distinguish
        between all possible legitimate plaintexts. This is because
        there are enough random padding degrees of freedom (between 0 &
        255 bytes) for such an adversary to create a super-exponentially
        large number of plaintexts which appear legitimate under any key
        (satisfy verification tags) & appear plausible (they can be made
        to be almost any message + random padding).
        """
        return token_bytes(cls._BLOCKSIZE * (1 + cls._MIN_PADDING_BLOCKS))

    @classmethod
    async def _adata_measurements(cls, size: int) -> PlaintextMeasurements:
        """
        Does padding measurements based on the ``size`` of some
        unpadded data & stores the findings in an object for convenient
        usage.
        """
        await asleep()
        blocksize = cls._BLOCKSIZE * (1 + cls._MIN_PADDING_BLOCKS)
        remainder = (cls._INNER_HEADER_BYTES + size) % blocksize
        padding_size = blocksize - remainder
        sentinel = padding_size % blocksize
        return PlaintextMeasurements(
            padding_size=padding_size,
            pad_sentinel=sentinel.to_bytes(
                cls._SENTINEL_BYTES, BIG
            ),
        )

    @classmethod
    def _data_measurements(cls, size: int) -> PlaintextMeasurements:
        """
        Does padding measurements based on the ``size`` of some
        unpadded data & stores the findings in an object for convenient
        usage.
        """
        blocksize = cls._BLOCKSIZE * (1 + MIN_PADDING_BLOCKS)
        remainder = (cls._INNER_HEADER_BYTES + size) % blocksize
        padding_size = blocksize - remainder
        sentinel = padding_size % blocksize
        return PlaintextMeasurements(
            padding_size=padding_size,
            pad_sentinel=sentinel.to_bytes(
                cls._SENTINEL_BYTES, BIG
            ),
        )

    @classmethod
    async def _amake_end_padding(
        cls, report: PlaintextMeasurements
    ) -> bytes:
        """
        Returns 256 bytes of random padding & a single byte which
        encodes the padding size.
        """
        extra_padding = await cls._amake_extra_padding()
        return extra_padding + report.pad_sentinel

    @classmethod
    def _make_end_padding(cls, report: PlaintextMeasurements) -> bytes:
        """
        Returns 256 bytes of random padding & a single byte which
        encodes the padding size.
        """
        extra_padding = cls._make_extra_padding()
        return extra_padding + report.pad_sentinel

    @classmethod
    async def aend_padding(cls, size: int) -> bytes:
        """
        Returns the `bytes`-type padding to be appended to the end of
        some unpadded data, given its ``size``.
        """
        report = await cls._adata_measurements(size)
        padding = await cls._amake_end_padding(report)
        return padding[-report.padding_size :]

    @classmethod
    def end_padding(cls, size: int) -> bytes:
        """
        Returns the `bytes`-type padding to be appended to the end of
        some unpadded data, given its ``size``.
        """
        report = cls._data_measurements(size)
        padding = cls._make_end_padding(report)
        return padding[-report.padding_size :]

    @classmethod
    async def apad_plaintext(cls, data: bytes) -> bytes:
        """
        Pads & returns a plaintext ``data`` with various values that
        improve the package's online AEAD cipher, Chunky2048 salt reuse
        misuse resistance, replay attack mitigations & deniability.

        Prepends a 4-byte timestamp & 16-byte SIV-key. The timestamp
        allows a time-to-live feature to exist for all ciphertexts,
        aiding against replay attacks, & improves salt reuse / misuse
        resistance. The random SIV-key gives the `Chunky2048` cipher an
        additional 64 bits of salt reuse-misuse security. Together they
        ensure that each encryption is globally unique, & that ~2**64
        messages can be sent each second before needing to rely on
        having a unique permutation of `key`, `salt`, `aad` & `iv`
        to protect the message plaintext.

        The end padding consists a single final sentinel byte. It
        denotes how many random bytes of padding preceed the sentinel
        which make the final block of plaintext a multiple of 256 bytes.
        The randomness of the end padding, its minimal corroborability
        with user secrets, or session values, & the cipher's large &
        variable effective key-space aids the cipher's deniability.
        """
        start_padding = await cls.astart_padding()
        end_padding = await cls.aend_padding(len(data))
        return b"".join((start_padding, data, end_padding))

    @classmethod
    def pad_plaintext(cls, data: bytes) -> bytes:
        """
        Pads & returns a plaintext ``data`` with various values that
        improve the package's online AEAD cipher, Chunky2048 salt reuse
        misuse resistance, replay attack mitigations & deniability.

        Prepends a 4-byte timestamp & 16-byte SIV-key. The timestamp
        allows a time-to-live feature to exist for all ciphertexts,
        aiding against replay attacks, & improves salt reuse / misuse
        resistance. The random SIV-key gives the `Chunky2048` cipher an
        additional 64 bits of salt reuse-misuse security. Together they
        ensure that each encryption is globally unique, & that ~2**64
        messages can be sent each second before needing to rely on
        having a unique permutation of `key`, `salt`, `aad` & `iv`
        to protect the message plaintext.

        The end padding consists a single final sentinel byte. It
        denotes how many random bytes of padding preceed the sentinel
        which make the final block of plaintext a multiple of 256 bytes.
        The randomness of the end padding, its minimal corroborability
        with user secrets, or session values, & the cipher's large &
        variable effective key-space aids the cipher's deniability.
        """
        start_padding = cls.start_padding()
        end_padding = cls.end_padding(len(data))
        return b"".join((start_padding, data, end_padding))

    @classmethod
    async def adepadding_start_index(cls) -> int:
        """
        Returns a start index which is used to slice off the prepended
        4-byte timestamp & 16-byte SIV-key from a plaintext.
        """
        return INNER_HEADER_BYTES

    @classmethod
    def depadding_start_index(cls) -> int:
        """
        Returns a start index which is used to slice off the prepended
        4-byte timestamp & 16-byte SIV-key from a plaintext.
        """
        return INNER_HEADER_BYTES

    @classmethod
    async def adepadding_end_index(cls, data: bytes) -> int:
        """
        Returns an end index which is used to slice off the appended
        values from some plaintext ``data``:
        - The appended variable-[0, 255]-byte random padding.
        - The appended 1-byte padding sentinel.
        """
        sentinel = int.from_bytes(
            data[-cls._SENTINEL_BYTES :], BIG
        )
        blocksize = cls._BLOCKSIZE * (1 + cls._MIN_PADDING_BLOCKS)
        return -(sentinel if sentinel else blocksize)

    @classmethod
    def depadding_end_index(cls, data: bytes) -> int:
        """
        Returns an end index which is used to slice off the appended
        values from some plaintext ``data``:
        - The appended variable-[0, 255]-byte random padding.
        - The appended 1-byte padding sentinel.
        """
        sentinel = int.from_bytes(
            data[-cls._SENTINEL_BYTES :], BIG
        )
        blocksize = cls._BLOCKSIZE * (1 + cls._MIN_PADDING_BLOCKS)
        return -(sentinel if sentinel else blocksize)

    @classmethod
    async def adepad_plaintext(cls, data: bytes, *, ttl: int = 0) -> bytes:
        """
        Returns ``data`` after these values are removed:
        - The prepended 4-byte timestamp.
        - The prepended 16-byte SIV-key.
        - The appended variable-[0, 255]-byte random padding.
        - The appended 1-byte padding sentinel.
        """
        clock.test_timestamp(data[cls._TIMESTAMP_SLICE], ttl=ttl)
        start_index = await cls.adepadding_start_index()
        end_index = await cls.adepadding_end_index(data)
        return data[start_index:end_index]

    @classmethod
    def depad_plaintext(cls, data: bytes, *, ttl: int = 0) -> bytes:
        """
        Returns ``data`` after these values are removed:
        - The prepended 4-byte timestamp.
        - The prepended 16-byte SIV-key.
        - The appended variable-[0, 255]-byte random padding.
        - The appended 1-byte padding sentinel.
        """
        clock.test_timestamp(data[cls._TIMESTAMP_SLICE], ttl=ttl)
        start_index = cls.depadding_start_index()
        end_index = cls.depadding_end_index(data)
        return data[start_index:end_index]


class BytesIO:
    """
    A utility class for converting bytes ciphertext to & from different
    formats & provides an interface for reading/writing bytes ciphertext
    to & from files.
    """

    __slots__ = ()

    _CIPHERTEXT: str = CIPHERTEXT
    _SHMAC: str = SHMAC
    _SALT: str = SALT
    _IV: str = IV
    _BLOCKSIZE: int = BLOCKSIZE
    _HEADER_BYTES: int = HEADER_BYTES

    @staticmethod
    async def adata(
        sequence: bytes, size: int = BLOCKSIZE
    ) -> t.AsyncGenerator[None, bytes]:
        """
        Runs through a sequence & yields ``size`` sized chunks of the bytes
        sequence one chunk at a time. By default this async generator yields
        all elements in the sequence.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        sequence = 4 * b" Data testing..."

        async for piece in adata(sequence,size=32):
            print(piece)
        >>> b' Data testing... Data testing...'
            b' Data testing... Data testing...'

        async for piece in adata(sequence, size=64):
            print(piece)
        >>> b' Data testing... Data testing... Data testing... Data testing...'
        """
        try:
            read = io.BytesIO(sequence).read
            while True:
                await asleep()
                yield read(size) or raise_exception(StopIteration)
        except StopIteration:
            pass

    @staticmethod
    def data(
        sequence: bytes, size: int = BLOCKSIZE
    ) -> t.Generator[None, bytes, None]:
        """
        Runs through a sequence & yields ``size`` sized chunks of the bytes
        sequence one chunk at a time. By default this generator yields all
        elements in the sequence.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        sequence = 4 * b" Data testing..."

        for piece in data(sequence, size=32):
            print(piece)
        >>> b' Data testing... Data testing...'
            b' Data testing... Data testing...'

        for piece in data(sequence, size=64):
            print(piece)
        >>> b' Data testing... Data testing... Data testing... Data testing...'
        """
        try:
            read = io.BytesIO(sequence).read
            while True:
                yield read(size) or raise_exception(StopIteration)
        except StopIteration:
            pass

    @staticmethod
    async def abytes_to_urlsafe(value: bytes) -> bytes:
        """
        Converts a raw bytes ``value`` to a url safe, base64 encoded
        byte string.
        """
        await asleep()
        return urlsafe_b64encode(value).replace(b"=", b"")

    @staticmethod
    def bytes_to_urlsafe(value: bytes) -> bytes:
        """
        Converts a raw bytes ``value`` to a url safe, base64 encoded
        byte string.
        """
        urlsafe_value = urlsafe_b64encode(value)
        return urlsafe_value.replace(b"=", b"")

    @staticmethod
    async def aurlsafe_to_bytes(value: t.AnyStr) -> bytes:
        """
        Turns a url safe base64 encoded ``value`` back into a raw
        decoded byte string.
        """
        await asleep()
        if value.__class__ is str:
            value = value.encode()
        return urlsafe_b64decode(fullblock_ljust(value, 4, pad=b"="))

    @staticmethod
    def urlsafe_to_bytes(value: t.AnyStr) -> bytes:
        """
        Turns a url safe base64 encoded ``value`` back into a raw
        decoded byte string.
        """
        if value.__class__ is str:
            value = value.encode()
        return urlsafe_b64decode(fullblock_ljust(value, 4, pad=b"="))

    @staticmethod
    async def abytes_to_base64(value: bytes) -> bytes:
        """
        Returns a raw byte string ``value`` after being standard base64
        encoded.
        """
        await asleep()
        return standard_b64encode(value)

    @staticmethod
    def bytes_to_base64(value: bytes) -> bytes:
        """
        Returns a raw byte string ``value`` after being standard base64
        encoded.
        """
        return standard_b64encode(value)

    @staticmethod
    async def abase64_to_bytes(value: t.AnyStr) -> bytes:
        """
        Converts a standard base64 encoded ``value`` back into a raw
        decoded byte string.
        """
        await asleep()
        if value.__class__ is str:
            value = value.encode()
        return standard_b64decode(value)

    @staticmethod
    def base64_to_bytes(value: t.AnyStr) -> bytes:
        """
        Converts a standard base64 encoded ``value`` back into a raw
        decoded byte string.
        """
        if value.__class__ is str:
            value = value.encode()
        return standard_b64decode(value)

    @staticmethod
    async def abytes_to_filename(value: bytes) -> str:
        """
        Returns the received bytes-type ``value`` in base38 encoding,
        which can be used as a filename to maintain compatibility on a
        very wide array of platforms.
        """
        return await aint_as_base(
            int.from_bytes(value, BIG), base=38, table=Tables.BASE_38
        )

    @staticmethod
    def bytes_to_filename(value: bytes) -> str:
        """
        Returns the received bytes-type ``value`` in base38 encoding,
        which can be used as a filename to maintain compatibility on a
        very wide array of platforms.
        """
        return int_as_base(
            int.from_bytes(value, BIG), base=38, table=Tables.BASE_38
        )

    @staticmethod
    async def afilename_to_bytes(filename: str) -> bytes:
        """
        Returns the base38 encoded ``filename`` as raw decoded bytes.
        """
        result = await abase_as_int(filename, base=38, table=Tables.BASE_38)
        byte_count = math.ceil(result.bit_length() / 8)
        return result.to_bytes(byte_count, BIG)

    @staticmethod
    def filename_to_bytes(filename: str) -> bytes:
        """
        Returns the base38 encoded ``filename`` as raw decoded bytes.
        """
        result = base_as_int(filename, base=38, table=Tables.BASE_38)
        byte_count = math.ceil(result.bit_length() / 8)
        return result.to_bytes(byte_count, BIG)

    @classmethod
    async def aread(cls, path: t.PathStr) -> bytes:
        """
        Reads the bytes data from the file at ``path``.
        """
        async with aiofiles.open(path, "rb") as f:
            return await f.read()

    @classmethod
    def read(cls, path: t.PathStr) -> bytes:
        """
        Reads the bytes data from the file at ``path``.
        """
        with open(path, "rb") as f:
            return f.read()

    @classmethod
    async def awrite(cls, path: t.PathStr, data: bytes) -> None:
        """
        Writes bytes ``data`` to a bytes file at ``path``.
        """
        async with aiofiles.open(path, "wb+") as f:
            await f.write(data)

    @classmethod
    def write(cls, path: t.PathStr, data: bytes) -> None:
        """
        Writes bytes ``data`` to a bytes file at ``path``.
        """
        with open(path, "wb+") as f:
            f.write(data)

    @classmethod
    def _validate_ciphertext_size(cls, ciphertext: bytes) -> None:
        """
        Measures the ``size`` of a blob of bytes ciphertext that has its
        header attached. If it doesn't conform to the standard then
        raises ValueError. If the ``ciphertext`` that's passed isn't of
        bytes type then ``TypeErrpr`` is raised.
        """
        size = len(ciphertext) - cls._HEADER_BYTES
        if ciphertext.__class__ is not bytes:
            raise Issue.value_must_be_type("ciphertext", bytes)
        elif size <= 0 or size % cls._BLOCKSIZE:
            raise CiphertextIssue.invalid_ciphertext_size(len(ciphertext))

    @classmethod
    async def _aprocess_json_to_ciphertext(
        cls, data: t.JSONCiphertext
    ) -> t.AsyncGenerator[None, bytes]:
        """
        Converts JSON formatted `Chunky2048` ciphertext into bytes
        values which are yielded one logical piece at a time: first the
        header parts, then each block of ciphertext.
        """
        data = JSONCiphertext(data)
        BLOCKSIZE = cls._BLOCKSIZE
        abase64_to_bytes = cls.abase64_to_bytes
        yield bytes.fromhex(data.shmac)
        yield bytes.fromhex(data.salt)
        yield bytes.fromhex(data.iv)
        for chunk in data.ciphertext:
            await asleep()
            yield await abase64_to_bytes(chunk)

    @classmethod
    def _process_json_to_ciphertext(
        cls, data: t.JSONCiphertext
    ) -> t.Generator[None, bytes, None]:
        """
        Converts JSON formatted `Chunky2048` ciphertext into bytes
        values which are yielded one logical piece at a time: first the
        header parts, then each block of ciphertext.
        """
        data = JSONCiphertext(data)
        BLOCKSIZE = cls._BLOCKSIZE
        base64_to_bytes = cls.base64_to_bytes
        yield bytes.fromhex(data.shmac)
        yield bytes.fromhex(data.salt)
        yield bytes.fromhex(data.iv)
        for chunk in data.ciphertext:
            yield base64_to_bytes(chunk)

    @classmethod
    async def ajson_to_ciphertext(cls, data: t.JSONCiphertext) -> bytes:
        """
        Converts JSON ``data`` of dict ciphertext into a bytes object.
        """
        data = b"".join(
            [part async for part in cls._aprocess_json_to_ciphertext(data)]
        )
        cls._validate_ciphertext_size(data)
        return data

    @classmethod
    def json_to_ciphertext(cls, data: t.JSONCiphertext) -> bytes:
        """
        Converts JSON ``data`` of dict ciphertext into a bytes object.
        """
        data = b"".join(cls._process_json_to_ciphertext(data))
        cls._validate_ciphertext_size(data)
        return data

    @classmethod
    async def _aprocess_ciphertext_to_json(
        cls, data: bytes
    ) -> t.AsyncGenerator[None, str]:
        """
        Takes in bytes ``data`` for initial processing. Yields the
        header parts in hex first, then the ciphertext blocks base64
        encoded.
        """
        to_int = int.from_bytes
        abytes_to_base64 = cls.abytes_to_base64
        cls._validate_ciphertext_size(data)
        yield data[SHMAC_SLICE].hex()
        yield data[SALT_SLICE].hex()
        yield data[IV_SLICE].hex()
        async for block in cls.adata(
            data[CIPHERTEXT_SLICE], size=BLOCKSIZE
        ):
            yield (await abytes_to_base64(block)).decode()

    @classmethod
    def _process_ciphertext_to_json(
        cls, data: bytes
    ) -> t.Generator[None, str, None]:
        """
        Takes in bytes ``data`` for initial processing. Yields the
        header parts in hex first, then the ciphertext blocks base64
        encoded.
        """
        to_int = int.from_bytes
        bytes_to_base64 = cls.bytes_to_base64
        cls._validate_ciphertext_size(data)
        yield data[SHMAC_SLICE].hex()
        yield data[SALT_SLICE].hex()
        yield data[IV_SLICE].hex()
        for block in cls.data(data[CIPHERTEXT_SLICE], size=BLOCKSIZE):
            yield bytes_to_base64(block).decode()

    @classmethod
    async def aciphertext_to_json(cls, data: bytes) -> t.Dict[str, str]:
        """
        Converts bytes ``data`` ciphertext into a JSON ready dictionary.
        """
        data = cls._aprocess_ciphertext_to_json(data)
        return {
            cls._SHMAC: await data.asend(None),
            cls._SALT: await data.asend(None),
            cls._IV: await data.asend(None),
            cls._CIPHERTEXT: [block async for block in data],
        }

    @classmethod
    def ciphertext_to_json(cls, data: bytes) -> t.Dict[str, str]:
        """
        Converts bytes ``data`` ciphertext into a JSON ready dictionary.
        """
        data = cls._process_ciphertext_to_json(data)
        return {
            cls._SHMAC: data.send(None),
            cls._SALT: data.send(None),
            cls._IV: data.send(None),
            cls._CIPHERTEXT: [*data],
        }


extras = dict(
    BytesIO=BytesIO,
    Domains=Domains,
    Hasher=Hasher,
    Clock=Clock,
    MaskedClock=MaskedClock,
    _Padding=Padding,
    __doc__=__doc__,
    __package__=__package__,
    _src=src,
    abase_as_int=abase_as_int,
    abytes_are_equal=abytes_are_equal,
    acanonical_pack=acanonical_pack,
    acanonical_unpack=acanonical_unpack,
    aencode_key=aencode_key,
    ahash_bytes=ahash_bytes,
    aint_as_base=aint_as_base,
    axi_mix=axi_mix,
    base_as_int=base_as_int,
    bytes_are_equal=bytes_are_equal,
    canonical_pack=canonical_pack,
    canonical_unpack=canonical_unpack,
    encode_key=encode_key,
    hash_bytes=hash_bytes,
    int_as_base=int_as_base,
    xi_mix=xi_mix,
)


generics = make_module("generics", mapping=extras)

