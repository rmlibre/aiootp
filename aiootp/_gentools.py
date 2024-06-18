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


__doc__ = "A collection of (async) generator utilities."


import io
import asyncio
from types import GeneratorType
from types import AsyncGeneratorType
from collections.abc import Iterable, Iterator
from collections.abc import AsyncIterable, AsyncIterator
from inspect import isasyncgenfunction as is_async_gen_function
from inspect import isgeneratorfunction as is_generator_function

from ._typing import Typing as t
from ._constants import BIG
from ._exceptions import Issue, raise_exception


def is_async_iterable(obj: t.Any, /) -> bool:
    """
    Returns a bool of whether `obj` supports async iteration.
    """
    return isinstance(obj, AsyncIterable)


def is_iterable(obj: t.Any, /) -> bool:
    """
    Returns a bool of whether `obj` supports iteration.
    """
    return isinstance(obj, Iterable)


def is_async_iterator(obj: t.Any, /) -> bool:
    """
    Returns a bool of whether `obj` is an async iterator.
    """
    return isinstance(obj, AsyncIterator)


def is_iterator(obj: t.Any, /) -> bool:
    """
    Returns a bool of whether `obj` is an iterator.
    """
    return isinstance(obj, Iterator)


def is_async_generator(obj: t.Any, /) -> bool:
    """
    Returns a bool of whether `obj` is an async generator.
    """
    return isinstance(obj, AsyncGeneratorType)


def is_generator(obj: t.Any, /) -> bool:
    """
    Returns a bool of whether `obj` is an generator.
    """
    return isinstance(obj, GeneratorType)


async def abatch(
    sequence: bytes, /, *, size: int, buffer_type: type = io.BytesIO
) -> t.AsyncGenerator[bytes, None]:
    """
    Runs through a sequence & yields `size` sized chunks of the bytes
    sequence one chunk at a time. By default this async generator yields
    all elements in the sequence.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    sequence = 4 * b" Testing data..."

    async for piece in abatch(sequence, size=32):
        print(piece)
    >>> b' Testing data... Testing data...'
        b' Testing data... Testing data...'

    async for piece in abatch(sequence, size=64):
        print(piece)
    >>> b' Testing data... Testing data... Testing data... Testing data...'
    """
    try:
        read = buffer_type(sequence).read
        while True:
            await asyncio.sleep(0)
            yield read(size) or raise_exception(StopIteration)
    except StopIteration:
        pass


def batch(
    sequence: bytes, /, *, size: int, buffer_type: type = io.BytesIO
) -> t.Generator[bytes, None, None]:
    """
    Runs through a sequence & yields `size` sized chunks of the bytes
    sequence one chunk at a time. By default this generator yields all
    elements in the sequence.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    sequence = 4 * b" Testing data..."

    for piece in batch(sequence, size=32):
        print(piece)
    >>> b' Testing data... Testing data...'
        b' Testing data... Testing data...'

    for piece in batch(sequence, size=64):
        print(piece)
    >>> b' Testing data... Testing data... Testing data... Testing data...'
    """
    try:
        read = buffer_type(sequence).read
        while True:
            yield read(size) or raise_exception(StopIteration)
    except StopIteration:
        pass


async def aresize(
    sequence: t.Sequence[t.Any], /, size: int, *, blocks: int = 0
) -> t.AsyncGenerator[t.Sequence[t.Any], None]:
    """
    Runs through a `sequence` & yields `size` sized chunks of the
    sequence one chunk at a time. `blocks` is the total number of
    chunks allowed to be yielded from the generator. By default this
    generator yields all elements in the sequence.
    """
    length = len(sequence)
    if not blocks or (blocks * size >= length):
        blocks = length + size
    else:
        blocks = (blocks * size) + 1
    async for previous_end, end in azip(
        range(0, blocks, size), range(size, blocks, size)
    ):
        yield sequence[previous_end:end]


def resize(
    sequence: t.Sequence[t.Any], /, size: int, *, blocks: int = 0
) -> t.Generator[t.Sequence[t.Any], None, None]:
    """
    Runs through a `sequence` & yields `size` sized chunks of the
    sequence one chunk at a time. `blocks` is the total number of
    chunks allowed to be yielded from the generator. By default this
    generator yields all elements in the sequence.
    """
    length = len(sequence)
    if not blocks or (blocks * size >= length):
        blocks = length + size
    else:
        blocks = (blocks * size) + 1
    for previous_end, end in zip(
        range(0, blocks, size), range(size, blocks, size)
    ):
        yield sequence[previous_end:end]


async def aunpack(
    iterable: t.AsyncOrSyncIterable[t.Any], /
) -> t.AsyncGenerator[t.Any, None]:
    """
    Runs through an iterable &/or async iterable & yields elements one
    at a time.
    """
    if is_async_iterable(iterable):
        async for item in iterable:
            yield item
    else:
        for item in iterable:
            await asyncio.sleep(0)
            yield item


def unpack(
    iterable: t.Iterable[t.Any], /
) -> t.Generator[t.Any, None, None]:
    """
    Runs through an iterable & yields elements one at a time.
    """
    yield from iterable


async def azip(
    *iterables: t.AsyncOrSyncIterable[t.Any]
) -> t.AsyncGenerator[t.List[t.Any], None]:
    """
    Creates an asynchronous version of the `builtins.zip` function
    which is wrapped by the `Comprende` class.
    """
    coroutines = [aunpack(iterable).__anext__ for iterable in iterables]
    try:
        while True:
            yield [await coroutine() for coroutine in coroutines]
    except (StopAsyncIteration, StopIteration):
        pass


async def acycle(
    iterable: t.AsyncOrSyncIterable[t.Any], /
) -> t.AsyncGenerator[t.Any, None]:
    """
    Unendingly cycles in order over the elements of an async iterable.
    """
    results = []
    if is_async_iterable(iterable):
        async for result in iterable:
            yield result
            results.append(result)
    else:
        for result in iterable:
            await asyncio.sleep(0)
            yield result
            results.append(result)
    while results:
        for result in results:
            await asyncio.sleep(0)
            yield result


def cycle(iterable: t.Iterable[t.Any], /) -> t.Generator[t.Any, None, None]:
    """
    Unendingly cycles in order over the elements of a sync iterable.
    """
    results = []
    for result in iterable:
        yield result
        results.append(result)
    while results:
        for result in results:
            yield result


async def abytes_count(
    *, start: int = 0, size: int = 8, byte_order: str = BIG
) -> t.AsyncGenerator[bytes, None]:
    """
    Unendingly yields incrementing numbers starting from `start`.
    """
    index = start
    while True:
        await asyncio.sleep(0)
        yield index.to_bytes(size, byte_order)
        index += 1


def bytes_count(
    *, start: int = 0, size: int = 8, byte_order: str = BIG
) -> t.Generator[bytes, None, None]:
    """
    Unendingly yields incrementing numbers starting from `start`.
    """
    index = start
    while True:
        yield index.to_bytes(size, byte_order)
        index += 1


async def acount(*, start: int = 0) -> t.AsyncGenerator[int, None]:
    """
    Unendingly yields incrementing numbers starting from `start`.
    """
    if start.__class__ is not int:
        raise Issue.value_must_be_type("start", int)
    index = start
    while True:
        await asyncio.sleep(0)
        yield index
        index += 1


def count(*, start: int = 0) -> t.Generator[int, None, None]:
    """
    Unendingly yields incrementing numbers starting from `start`.
    """
    if start.__class__ is not int:
        raise Issue.value_must_be_type("start", int)
    index = start
    while True:
        yield index
        index += 1


async def abytes_range(
    *a, size: int = 8, byte_order: str = BIG
) -> t.AsyncGenerator[int, None]:
    """
    An async version of `builtins.range` wrapped by the `Comprende`
    class, & returns its values as bytes instead.
    """
    for result in range(*a):
        await asyncio.sleep(0)
        yield result.to_bytes(size, byte_order)


def bytes_range(
    *a, size: int = 8, byte_order: str = BIG
) -> t.Generator[int, None, None]:
    """
    A synchronous version of `builtins.range` which is wrapped by the
    `Comprende` class, & returns its values as bytes instead.
    """
    for result in range(*a):
        yield result.to_bytes(size, byte_order)


async def arange(*a: t.Optional[int]) -> t.AsyncGenerator[int, None]:
    """
    An async version of `builtins.range`.
    """
    for result in range(*a):
        await asyncio.sleep(0)
        yield result


async def acollate(
    *iterables: t.AsyncOrSyncIterable[t.Any]
) -> t.AsyncGenerator[t.Any, None]:
    """
    Takes a collection of iterables &/or async iterables & exhausts them
    one at a time from left to right.
    """
    for iterable in iterables:
        if is_async_iterable(iterable):
            async for result in iterable:
                yield result
        else:
            for result in iterable:
                await asyncio.sleep(0)
                yield result


def collate(
    *iterables: t.Iterable[t.Any]
) -> t.Generator[t.Any, None, None]:
    """
    Takes a collection of iterables & exhausts them one at a time from
    left to right.
    """
    for iterable in iterables:
        for result in iterable:
            yield result


async def apopleft(
    queue: t.SupportsPopleft, /
) -> t.AsyncGenerator[t.Any, None]:
    """
    An async generator which calls the `popleft()` method on `queue`
    for every iteration, & exits on `IndexError`.
    """
    while True:
        try:
            yield queue.popleft()
        except IndexError:
            break


def popleft(
    queue: t.SupportsPopleft, /
) -> t.Generator[t.Any, None, None]:
    """
    A generator which calls the `popleft()` method on `queue` for
    every iteration, & exits on `IndexError`.
    """
    while True:
        try:
            yield queue.popleft()
        except IndexError:
            break


module_api = dict(
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    abatch=abatch,
    abytes_count=abytes_count,
    abytes_range=abytes_range,
    acollate=acollate,
    acount=acount,
    acycle=acycle,
    apopleft=apopleft,
    arange=arange,
    aresize=aresize,
    aunpack=aunpack,
    azip=azip,
    batch=batch,
    bytes_count=bytes_count,
    bytes_range=bytes_range,
    collate=collate,
    count=count,
    cycle=cycle,
    is_async_iterable=is_async_iterable,
    is_async_iterator=is_async_iterator,
    is_async_generator=is_async_generator,
    is_async_gen_function=is_async_gen_function,
    is_generator=is_generator,
    is_generator_function=is_generator_function,
    is_iterable=is_iterable,
    is_iterator=is_iterator,
    popleft=popleft,
    resize=resize,
    unpack=unpack,
)

