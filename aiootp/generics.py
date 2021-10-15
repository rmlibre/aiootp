# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "generics",
    "gentools",
    "BytesIO",
    "Comprende",
    "Domains",
    "Hasher",
    "Padding",
    "abytes_are_equal",
    "asha3__256",
    "asha3__256_hmac",
    "asha3__512",
    "asha3__512_hmac",
    "bytes_are_equal",
    "sha3__256",
    "sha3__256_hmac",
    "sha3__512",
    "sha3__512_hmac",
]


__doc__ = (
    "A collection of basic utilities for simplifying & supporting the r"
    "est of the codebase."
)


import hmac
import math
import json
import heapq
import base64
import secrets
import aiofiles
import builtins
from pathlib import Path
from os import linesep
from sys import getsizeof
from functools import wraps
from functools import lru_cache
from types import GeneratorType
from types import AsyncGeneratorType
from contextlib import contextmanager
from hashlib import blake2s
from hashlib import sha3_256, sha3_512, shake_256
from hmac import compare_digest as bytes_are_equal
from collections import deque
from collections.abc import Iterable, Iterator
from collections.abc import AsyncIterable, AsyncIterator
from inspect import getsource
from inspect import isfunction as is_function
from inspect import isawaitable as is_awaitable
from inspect import iscoroutinefunction as is_async_function
from inspect import isasyncgenfunction as is_async_gen_function
from inspect import isgeneratorfunction as is_generator_function
from .__async_lru import alru_cache
from .__aiocontext import async_contextmanager
from ._exceptions import *
from ._typing import Typing
from .debuggers import DebugControl
from .commons import PrimeGroups
from .commons import *
from commons import *  # import the module's constants
from ._containers import *
from _containers import *
from .asynchs import *
from .asynchs import asleep, gather, this_second, time


def src(obj, *, display=True):
    """
    Prints the source code of an object to the screen or, if ``display``
    is toggled to a falsey value, returns the source code instead.
    """
    if display:
        print(getsource(obj))
    else:
        return getsource(obj)


def size_of(obj, *, display=False):
    """
    Returns the memory size of an object ``obj`` in bytes.
    """
    if not display:
        return getsizeof(obj)
    else:
        print(getsizeof(obj))


def is_exception(obj):
    """
    Returns a bool of whether ``obj`` is an exception object.
    """
    return hasattr(obj, "__cause__")


def is_async_iterable(obj):
    """
    Returns a bool of whether ``obj`` supports async iteration.
    """
    return isinstance(obj, AsyncIterable)


def is_iterable(obj):
    """
    Returns a bool of whether ``obj`` supports iteration.
    """
    return isinstance(obj, Iterable)


def is_async_iterator(obj):
    """
    Returns a bool of whether ``obj`` is an async iterator.
    """
    return isinstance(obj, AsyncIterator)


def is_iterator(obj):
    """
    Returns a bool of whether ``obj`` is an iterator.
    """
    return isinstance(obj, Iterator)


def is_async_generator(obj):
    """
    Returns a bool of whether ``obj`` is an async generator.
    """
    return isinstance(obj, AsyncGeneratorType)


def is_generator(obj):
    """
    Returns a bool of whether ``obj`` is an generator.
    """
    return isinstance(obj, GeneratorType)


async def abytes_are_equal(value_0: bytes, value_1: bytes):
    """
    Tests if two bytes values are equal with a simple & fast timing-safe
    comparison function from the `hmac` module.
    """
    await asleep()
    return bytes_are_equal(value_0, value_1)


async def arightmost_bit(number: int):
    """
    Returns the value of the right-most bit of a given positive integer.
    """
    await asleep()
    return number ^ (number & (number - 1))


def rightmost_bit(number: int):
    """
    Returns the value of the right-most bit of a given positive integer.
    """
    return number ^ (number & (number - 1))


async def ato_base64(binary: Typing.AnyStr, encoding: str = "utf-8"):
    """
    A version of ``base64.standard_b64encode``.
    """
    if binary.__class__ is not bytes:
        binary = binary.encode(encoding)
    await asleep()
    return base64.standard_b64encode(binary)


def to_base64(binary: Typing.AnyStr, encoding: str = "utf-8"):
    """
    A version of ``base64.standard_b64encode``.
    """
    if binary.__class__ is not bytes:
        binary = binary.encode(encoding)
    return base64.standard_b64encode(binary)


async def afrom_base64(base_64: Typing.AnyStr, encoding: str = "utf-8"):
    """
    A version of ``base64.standard_b64decode``.
    """
    if base_64.__class__ is not bytes:
        base_64 = base_64.encode(encoding)
    await asleep()
    return base64.standard_b64decode(base_64)


def from_base64(base_64: Typing.AnyStr, encoding: str = "utf-8"):
    """
    A version of ``base64.standard_b64decode``.
    """
    if base_64.__class__ is not bytes:
        base_64 = base_64.encode(encoding)
    return base64.standard_b64decode(base_64)


async def abase_to_int(
    string: str,
    base: int,
    *,
    table: Typing.Sequence[Typing.AnyStr] = Tables.ASCII_95,
):
    """
    Convert ``string`` in numerical ``base`` into decimal integer.
    """
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


def base_to_int(
    string: str,
    base: int,
    *,
    table: Typing.Sequence[Typing.AnyStr] = Tables.ASCII_95,
):
    """
    Convert ``string`` in numerical ``base`` into decimal integer.
    """
    power = 1
    result = 0
    base_table = table[:base]
    for char in reversed(string):
        if char not in base_table:
            raise Issue.invalid_value("base with the given table")
        result += base_table.find(char) * power
        power = power * base
    return result


async def aint_to_base(
    number: int,
    base: int,
    *,
    table: Typing.Sequence[Typing.AnyStr] = Tables.ASCII_95,
):
    """
    Convert an ``number`` back into a string in numerical ``base``.
    """
    digits = []
    base_table = table[:base]
    await asleep()
    while number:
        digits.append(base_table[number % base])
        number //= base
    await asleep()
    if digits:
        digits.reverse()
        return digits[0][:0].join(digits)
    else:
        return table[:1]


def int_to_base(
    number: int,
    base: int,
    *,
    table: Typing.Sequence[Typing.AnyStr] = Tables.ASCII_95,
):
    """
    Convert an ``number`` back into a string in numerical ``base``.
    """
    digits = []
    base_table = table[:base]
    while number:
        digits.append(base_table[number % base])
        number //= base
    if digits:
        digits.reverse()
        return digits[0][:0].join(digits)
    else:
        return table[:1]


async def asha3__256(*data: Typing.Iterable, hex: bool = True):
    """
    A string-based version of ``hashlib.sha3_256``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    await asleep()
    if hex:
        return sha3_256(str(data).encode()).hexdigest()
    else:
        return sha3_256(str(data).encode()).digest()


def sha3__256(*data: Typing.Iterable, hex: bool = True):
    """
    A string-based version of ``hashlib.sha3_256``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    if hex:
        return sha3_256(str(data).encode()).hexdigest()
    else:
        return sha3_256(str(data).encode()).digest()


async def asha3__256_hmac(
    data: Typing.Union[bytes, Typing.Any],
    *,
    key: Typing.Union[bytes, Typing.Any],
    hex: bool = True,
):
    """
    An HMAC-esque version of the ``hashlib.sha3_512`` function.
    """
    await asleep()
    bytes_key = key if key.__class__ is bytes else repr(key).encode()
    bytes_data = data if data.__class__ is bytes else repr(data).encode()
    await asleep()
    if hex:
        return hmac.new(bytes_key, bytes_data, sha3_256).hexdigest()
    else:
        return hmac.new(bytes_key, bytes_data, sha3_256).digest()


def sha3__256_hmac(
    data: Typing.Union[bytes, Typing.Any],
    *,
    key: Typing.Union[bytes, Typing.Any],
    hex: bool = True,
):
    """
    An HMAC-esque version of the ``hashlib.sha3_512`` function.
    """
    bytes_key = key if key.__class__ is bytes else repr(key).encode()
    bytes_data = data if data.__class__ is bytes else repr(data).encode()
    if hex:
        return hmac.new(bytes_key, bytes_data, sha3_256).hexdigest()
    else:
        return hmac.new(bytes_key, bytes_data, sha3_256).digest()


async def asha3__512(*data: Typing.Iterable, hex: bool = True):
    """
    A string-based version of ``hashlib.sha3_512``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    await asleep()
    if hex:
        return sha3_512(str(data).encode()).hexdigest()
    else:
        return sha3_512(str(data).encode()).digest()


def sha3__512(*data: Typing.Iterable, hex: bool = True):
    """
    A string-based version of ``hashlib.sha3_512``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    if hex:
        return sha3_512(str(data).encode()).hexdigest()
    else:
        return sha3_512(str(data).encode()).digest()


async def asha3__512_hmac(
    data: Typing.Union[bytes, Typing.Any],
    *,
    key: Typing.Union[bytes, Typing.Any],
    hex: bool = True,
):
    """
    An HMAC-esque version of the ``hashlib.sha3_512`` function.
    """
    await asleep()
    bytes_key = key if key.__class__ is bytes else repr(key).encode()
    bytes_data = data if data.__class__ is bytes else repr(data).encode()
    await asleep()
    if hex:
        return hmac.new(bytes_key, bytes_data, sha3_512).hexdigest()
    else:
        return hmac.new(bytes_key, bytes_data, sha3_512).digest()


def sha3__512_hmac(
    data: Typing.Union[bytes, Typing.Any],
    *,
    key: Typing.Union[bytes, Typing.Any],
    hex: bool = True,
):
    """
    An HMAC-esque version of the ``hashlib.sha3_512`` function.
    """
    bytes_key = key if key.__class__ is bytes else repr(key).encode()
    bytes_data = data if data.__class__ is bytes else repr(data).encode()
    if hex:
        return hmac.new(bytes_key, bytes_data, sha3_512).hexdigest()
    else:
        return hmac.new(bytes_key, bytes_data, sha3_512).digest()


async def axi_mix(bytes_hash: bytes, size: int = 8):
    """
    Xors subsequent ``size`` length segments of ``bytes_hash`` with each
    other to condense the bytes hash down to ``size`` bytes.
    """
    result = 0
    async for chunk in adata.root(bytes_hash, size=size):
        result ^= int.from_bytes(chunk, "big")
    return result.to_bytes(size, "big")


def xi_mix(bytes_hash: bytes, size: int = 8):
    """
    Xors subsequent ``size`` length segments of ``bytes_hash`` with each
    other to condense the bytes hash down to ``size`` bytes.
    """
    result = 0
    for chunk in data.root(bytes_hash, size=size):
        result ^= int.from_bytes(chunk, "big")
    return result.to_bytes(size, "big")


async def ahash_bytes(
    *collection: Typing.Iterable[bytes],
    hasher: Typing.Any = sha3_512,
    on: bytes = b"",
):
    """
    Joins all bytes objects in ``collection`` ``on`` a value & returns
    the digest after passing all the joined bytes into the ``hasher``.
    """
    await asleep()
    return hasher(on.join(collection)).digest()


def hash_bytes(
    *collection: Typing.Iterable[bytes],
    hasher: Typing.Any = sha3_512,
    on: bytes = b"",
):
    """
    Joins all bytes objects in ``collection`` ``on`` a value & returns
    the digest after passing all the joined bytes into the ``hasher``.
    """
    return hasher(on.join(collection)).digest()


class Hasher:
    """
    A class that creates instances to mimmic & add functionality to the
    hashing object passed in during initialization.
    """

    __slots__ = (
        "_obj",
        "block_size",
        "copy",
        "digest",
        "digest_size",
        "hexdigest",
        "name",
        "update",
    )

    _MOD: int = PrimeGroups.MOD_512
    _BASE: int = UniformPrimes.PRIME_256
    _MASK: int = UniformPrimes.PRIME_512

    xi_mix = xi_mix
    axi_mix = axi_mix

    @classmethod
    async def amask_byte_order(
        cls, sequence: bytes, *, base: int = _BASE, mod: int = _MOD
    ):
        """
        Uses each byte in a ``sequence`` as multiples along with ``base``
        & takes that result ``mod`` a number to mask the order of the
        bytes in the sequence. This final result is returned back to the
        user as a new bytes sequence. Both ``mod`` & ``base`` should be
        distinct prime numbers.
        """
        if base == mod:
            raise Issue.value_must("base", "!= mod")
        product = 3
        await asleep()
        for byte in bytes(sequence):
            product *= byte + 1    # <- Ensure non-zero
        await asleep()
        masked_value = (base * product * cls._MASK) % mod
        return masked_value.to_bytes(math.ceil(mod.bit_length() / 8), "big")

    @classmethod
    def mask_byte_order(
        cls, sequence: bytes, *, base: int = _BASE, mod: int = _MOD
    ):
        """
        Uses each byte in a ``sequence`` as multiples along with ``base``
        & takes that result ``mod`` a number to mask the order of the
        bytes in the sequence. This final result is returned back to the
        user as a new bytes sequence. Both ``mod`` & ``base`` should be
        distinct prime numbers.
        """
        if base == mod:
            raise Issue.value_must("base", "!= mod")
        product = 3
        for byte in bytes(sequence):
            product *= byte + 1    # <- Ensure non-zero
        masked_value = (base * product * cls._MASK) % mod
        return masked_value.to_bytes(math.ceil(mod.bit_length() / 8), "big")

    @classmethod
    async def ashrink(
        cls,
        *data: Typing.Iterable[bytes],
        size: int = 8,
        on: bytes = b"",
        obj: Typing.Any = sha3_512,
    ):
        """
        Hashes an iterable of ``data`` elements joined ``on`` a value
        & returns ``size`` byte `xi_mix` reduction of the result.
        """
        await asleep()
        hashed_data = obj(on.join(data)).digest()
        await asleep()
        return await cls.axi_mix(hashed_data, size=size)

    @classmethod
    def shrink(
        cls,
        *data: Typing.Iterable[bytes],
        size: int = 8,
        on: bytes = b"",
        obj: Typing.Any = sha3_512,
    ):
        """
        Hashes an iterable of ``data`` elements joined ``on`` a value
        & returns ``size`` byte `xi_mix` reduction of the result.
        """
        hashed_data = obj(on.join(data)).digest()
        return cls.xi_mix(hashed_data, size=size)

    def __init__(self, data: bytes = b"", *, obj: Typing.Any = sha3_512):
        """
        Copies over the object dictionary of the ``obj`` hashing object.
        """
        self._obj = obj(data)
        for attr in dir(self._obj):
            if attr[:1] != "_":
                setattr(self, attr, getattr(self._obj, attr))

    async def ahash(
        self,
        *data: Typing.Iterable[bytes],
        on: bytes = b"",
        size: int = None,
    ):
        """
        Receives any number of arguments of bytes type ``data`` &
        updates the instance with them all sequentially.
        """
        await asleep()
        self.update(on.join(data))
        await asleep()
        if size:
            return self.digest(size)
        return self.digest()

    def hash(
        self,
        *data: Typing.Iterable[bytes],
        on: bytes = b"",
        size: int = None,
    ):
        """
        Receives any number of arguments of bytes type ``data`` &
        updates the instance with them all sequentially.
        """
        self.update(on.join(data))
        if size:
            return self.digest(size)
        return self.digest()


def display_exception_info(error):
    """
    Prints out debug information of exceptions.
    """
    print("Error Type:", error)
    print("Error Args:", error.args)
    print("Error Cause:", error.__cause__)
    print("Error Value:", getattr(error, "value", None))


class ExampleException(Exception):
    """
    Empty, unused placeholder exception.
    """

    __slots__ = ()


class AsyncRelayExceptions:
    """
    Creates objects which can run user-specified code in the event of
    an exception or at the end of a context.
    """

    __slots__ = ("aexcept_code", "afinally_code")

    read_me = f"""
    Overwrite {__slots__} methods with custom async functions.
    They will proc in ``aiootp.generics.aignore`` async context manager
    when:

    1.  {__slots__[0]} - the ignored exceptions are raised within the
    context.

    But always,
    2.  {__slots__[1]} - at the end of the context.
    """

    def __init__(self, if_except=None, finally_run=None):
        async def placeholder(*a, **kw):
            return self.read_me

        self.aexcept_code = if_except if if_except else placeholder
        self.afinally_code = finally_run if finally_run else placeholder


class RelayExceptions:
    """
    Creates objects which can run user-specified code in the event of
    an exception or at the end of a context.
    """

    __slots__ = ("except_code", "finally_code")

    read_me = f"""
    Overwrite {__slots__} methods with custom functions.
    They will proc in ``aiootp.generics.ignore`` context manager when:

    1.  {__slots__[0]} - the ignored exceptions are raised within the
    context.

    But always,
    2.  {__slots__[1]} - at the end of the context.
    """

    def __init__(self, if_except=None, finally_run=None):
        def placeholder(*a, **kw):
            return self.read_me

        self.except_code = if_except if if_except else placeholder
        self.finally_code = finally_run if finally_run else placeholder


@async_contextmanager
async def aignore(
    *exceptions, display=False, if_except=None, finally_run=None
):
    """
    Usage example:

    async with aignore(TypeError):
        c = a + b
        # exception is surpressed if adding a and b raises a TypeError

    Or, dynamically choose which exceptions to catch, and call custom
    cleanup code. ->

    async def cleanup(error=None):
        await database.asave()

    async with ignore(DynamicException, IOError) as error_relay:
        error_relay.aexcept_code = cleanup
        # This will close ``database`` if either DynamicException or
        # IOError are raised within the block.

        error_relay.afinally_code = cleanup
        # This will ensure close is called on ``database`` in a finally
        # block.

    async with aignore(IOError, if_except=cleanup) as relay:
        # Or more cleanly, pass the function to be run during an
        # exception into ``if_except``.

    async with aignore(IOError, finally_run=cleanup) as relay:
        # Similarly, to declare a function to run in the finally block.
    """
    try:
        exceptions = exceptions if exceptions else ExampleException
        relay = AsyncRelayExceptions(if_except, finally_run)
        await asleep()
        yield relay
    except exceptions as error:
        if display:
            display_exception_info(error)
        await relay.aexcept_code(error)
    except Exception as error:
        if display:
            display_exception_info(error)
        raise error
    finally:
        await relay.afinally_code()


@contextmanager
def ignore(*exceptions, display=False, if_except=None, finally_run=None):
    """
    Usage example:

    with ignore(TypeError):
        c = a + b
        # exception is surpressed if adding a and b raises a TypeError

    Or, dynamically choose which exceptions to catch, and call custom
    cleanup code. ->

    def cleanup(error=None):
        database.save()

    with ignore(DynamicException, IOError) as error_relay:
        error_relay.except_code = cleanup
        # This will close ``database`` if either DynamicException or
        # IOError are raised within the block.

        error_relay.finally_code = cleanup
        # This will ensure close is called on ``database`` in a finally
        # block.

    with ignore(DynamicException, IOError, if_except=cleanup) as relay:
        # Or more cleanly, pass the function to be run during an
        # exception into ``if_except``.

    with ignore(DynamicException, IOError, finally_run=cleanup) as relay:
        # Similarly, to declare a function to run in the finally block.
    """
    try:
        exceptions = exceptions if exceptions else ExampleException
        relay = RelayExceptions(if_except, finally_run)
        yield relay
    except exceptions as error:
        if display:
            display_exception_info(error)
        relay.except_code(error)
    except Exception as error:
        if display:
            display_exception_info(error)
        raise error
    finally:
        relay.finally_code()


def comprehension(*, catcher=None, **kwargs):
    """
    A decorator which wraps async & sync generator functions with the
    ``Comprende`` class, or the wrapper passed into ``catcher``. Can
    also optionally surgically replace arguments and keywords to the
    functions. This is helpful for being able to dynamically wrap
    functions in different contexts to alter behavior.
    """

    def func_catch(func):
        func.root = func

        @wraps(func)
        def gen_wrapper(*a, **kw):
            cls = Comprende if not catcher else catcher
            return cls(func, *a, **{**kw, **kwargs})

        return gen_wrapper

    return func_catch


async def anext(coroutine_iterator: Typing.Iterator):
    """
    Creates an asynchronous version of the ``builtins.next`` function.
    """
    return await coroutine_iterator.__anext__()


class Enumerate:
    """
    An ``enumerate`` variant that supports sync & async generators.
    """

    __slots__ = ("gen", "start")

    def __init__(self, gen, start=0):
        self.gen = gen
        self.start = start

    async def __aiter__(self):
        """
        Adds an incrementing number to each yielded result of either an
        async or sync generator.
        """
        if is_async_iterable(self.gen):
            counter = self.start
            async for result in self.gen:
                yield counter, result
                counter += 1
        else:
            for result in self.__iter__():
                await asleep()
                yield result

    def __iter__(self):
        """
        Adds an incrementing number to each yielded result of either a
        synchronous generator.
        """
        counter = self.start
        for result in self.gen:
            yield counter, result
            counter += 1


@comprehension()
async def azip(*iterables: Typing.AsyncOrSyncIterable[Typing.Any]):
    """
    Creates an asynchronous version of the ``builtins.zip`` function
    which is wrapped by the ``Comprende`` class.
    """
    aiter = aunpack.root
    coroutines = [aiter(iterable).__anext__ for iterable in iterables]
    try:
        while True:
            yield [await coroutine() for coroutine in coroutines]
    except StopAsyncIteration:
        pass


@comprehension()
def _zip(*iterables: Typing.Iterable[Typing.Any]):
    """
    Creates a synchronous version of the zip builtin function which is
    wrapped by the ``Comprende`` class.
    """
    for results in zip(*iterables):
        yield results


@comprehension()
async def aunpack(iterable: Typing.AsyncOrSyncIterable[Typing.Any]):
    """
    Runs through an iterable &/or async iterable & yields elements one
    at a time.
    """
    if is_async_iterable(iterable):
        async for item in iterable:
            yield item
    else:
        for item in iterable:
            await asleep()
            yield item


@comprehension()
def unpack(iterable: Typing.Iterable[Typing.Any]):
    """
    Runs through an iterable & yields elements one at a time.
    """
    yield from iterable


@comprehension()
async def aecho(initial_value: Typing.Any = None):
    """
    A coroutine which yields the values the are sent into it. It's most
    useful as a debugger or in Comprende data processing chains.

    Usage Example:

    str_to_int = await aecho("").aencode().abytes_to_int().aprime()
    assert 2271432183284425044093 == await str_to_int('{"t0": 0}')
    assert 2271432184383936672125 == await str_to_int('{"t1": 1}')
    assert 2271432185483448300157 == await str_to_int('{"t2": 2}')

    int_to_str = await aecho(0).aint_to_bytes(size=1).adecode().aprime()
    assert '!' == await int_to_str(33)
    assert '@' == await int_to_str(64)
    assert 'A' == await int_to_str(65)
    """
    got = yield initial_value
    while True:
        await asleep()
        got = yield got


@comprehension()
def echo(initial_value: Typing.Any = None):
    """
    A coroutine which yields the values the are sent into it. It's most
    useful as a debugger or in Comprende data processing chains.

    Usage Example:

    str_to_int = echo("").encode().bytes_to_int().prime()
    assert 2271432183284425044093 == str_to_int('{"t0": 0}')
    assert 2271432184383936672125 == str_to_int('{"t1": 1}')
    assert 2271432185483448300157 == str_to_int('{"t2": 2}')

    int_to_str = echo(0).int_to_bytes(size=1).decode().prime()
    assert '!' == int_to_str(33)
    assert '@' == int_to_str(64)
    assert 'A' == int_to_str(65)
    """
    got = yield initial_value
    while True:
        got = yield got


@comprehension()
async def acycle(iterable: Typing.AsyncOrSyncIterable[Typing.Any]):
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
            await asleep()
            yield result
            results.append(result)
    if results:
        while True:
            for result in results:
                await asleep()
                yield result


@comprehension()
def cycle(iterable: Typing.Iterable[Typing.Any]):
    """
    Unendingly cycles in order over the elements of a sync iterable.
    """
    results = []
    for result in iterable:
        yield result
        results.append(result)
    if results:
        while True:
            for result in results:
                yield result


@comprehension()
async def abytes_count(
    start: int = 0, *, size: int = 8, byte_order: str = "big"
):
    """
    Unendingly yields incrementing numbers starting from ``start``.
    """
    index = start
    while True:
        await asleep()
        yield index.to_bytes(size, byte_order)
        index += 1


@comprehension()
def bytes_count(start: int = 0, *, size: int = 8, byte_order: str = "big"):
    """
    Unendingly yields incrementing numbers starting from ``start``.
    """
    index = start
    while True:
        yield index.to_bytes(size, byte_order)
        index += 1


@comprehension()
async def acount(start: int = 0):
    """
    Unendingly yields incrementing numbers starting from ``start``.
    """
    index = start
    while True:
        await asleep()
        yield index
        index += 1


@comprehension()
def count(start: int = 0):
    """
    Unendingly yields incrementing numbers starting from ``start``.
    """
    index = start
    while True:
        yield index
        index += 1


@comprehension()
async def abirth(base: Typing.Any, *, stop: bool = True):
    """
    Yields ``base`` in its entirety once by default. If ``stop`` is set
    falsey then it's yielded unendingly. Useful for spawning a value
    into chainable ``Comprende`` generators.
    """
    if stop:
        yield base
    else:
        while True:
            await asleep()
            yield base


@comprehension()
def birth(base: Typing.Any, *, stop: bool = True):
    """
    Yields ``base`` in its entirety once by default. If ``stop`` is set
    falsey then it's yielded unendingly. Useful for spawning a value
    into chainable ``Comprende`` generators.
    """
    if stop:
        yield base
    else:
        while True:
            yield base


@comprehension()
async def adata(
    sequence: Typing.Sequence[Typing.Any],
    size: int = BLOCKSIZE,
    *,
    blocks: int = 0,
):
    """
    Runs through a sequence & yields ``size`` sized chunks of the
    sequence one chunk at a time. ``blocks`` is the total number of
    chunks allowed to be yielded from the generator. By default this
    generator yields all elements in the sequence.

    Usage Example:

    sequence = 4 * " Data testing..."

    async for piece in adata(sequence, size=32):
        print(piece)
    >>> ' Data testing... Data testing...'
        ' Data testing... Data testing...'

    async for piece in adata(sequence, size=64):
        print(piece)
    >>> ' Data testing... Data testing... Data testing... Data testing...'
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


@comprehension()
def data(
    sequence: Typing.Sequence[Typing.Any],
    size: int = BLOCKSIZE,
    *,
    blocks: int = 0,
):
    """
    Runs through a sequence & yields ``size`` sized chunks of the
    sequence one chunk at a time. ``blocks`` is the total number of
    chunks allowed to be yielded from the generator. By default this
    generator yields all elements in the sequence.

    Usage Example:

    sequence = 4 * " Data testing..."

    for piece in data(sequence, size=32):
        print(piece)
    >>> ' Data testing... Data testing...'
        ' Data testing... Data testing...'

    for piece in data(sequence, size=64):
        print(piece)
    >>> ' Data testing... Data testing... Data testing... Data testing...'
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


@comprehension()
async def _araw_reader(data: bytes):
    """
    An async generator which provides an api for reading an amount of
    elements from a sequence ``data`` which users can determine on each
    iteration by sending integers into the async generator as a
    coroutine.
    """
    position = 0
    size = yield
    while True:
        await asleep()
        new_size = yield data[position:position + size]
        position += size
        size = new_size


@comprehension()
def _raw_reader(data: bytes):
    """
    A generator which provides an api for reading an amount of elements
    from a sequence ``data`` which users can determine on each iteration
    by sending integers into the generator as a coroutine.
    """
    position = 0
    size = yield
    while True:
        new_size = yield data[position:position + size]
        position += size
        size = new_size


async def areader(
    data: Typing.Sequence[Typing.Any], *, comprehension: bool = False
):
    """
    Provides an api for reading an amount of elements from a sequence
    ``data`` which users can determine on each iteration by sending
    integers into the returned async generator as a coroutine.
    """
    if comprehension:
        reader = _araw_reader(data)
    else:
        reader = _araw_reader.root(data)
    await reader.asend(None)
    return reader


def reader(
    data: Typing.Sequence[Typing.Any], *, comprehension: bool = False
):
    """
    Provides an api for reading an amount of elements from a sequence
    ``data`` which users can determine on each iteration by sending
    integers into the returned generator as a coroutine.
    """
    if comprehension:
        reader = _raw_reader(data)
    else:
        reader = _raw_reader.root(data)
    reader.send(None)
    return reader


@comprehension()
async def aorder(
    *iterables: Typing.Iterable[Typing.AsyncOrSyncIterable[Typing.Any]]
):
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
                await asleep()
                yield result


@comprehension()
def order(*iterables: Typing.Iterable[Typing.Iterable[Typing.Any]]):
    """
    Takes a collection of iterables & exhausts them one at a time from
    left to right.
    """
    for iterable in iterables:
        for result in iterable:
            yield result


@comprehension()
async def askip(
    iterable: Typing.AsyncOrSyncIterable[Typing.Any], steps: int = 1
):
    """
    An async generator that produces the values yielded from ``iterable``
    once every ``steps`` number of iterations, otherwise produces
    ``None`` until ``iterable`` is exhausted.
    """
    if is_async_iterable(iterable):
        async for result in iterable:
            for _ in range(steps):
                yield
            await asleep()
            yield result
    else:
        for result in iterable:
            await asleep()
            for _ in range(steps):
                yield
            await asleep()
            yield result


@comprehension()
def skip(iterable: Typing.Iterable[Typing.Any], steps: int = 1):
    """
    A sync generator that produces the values yielded from ``iterable``
    once every ``steps`` number of iterations, otherwise produces
    ``None`` until ``iterable`` is exhausted.
    """
    for result in iterable:
        for _ in range(steps):
            yield
        yield result


@comprehension()
async def acompact(
    iterable: Typing.AsyncOrSyncIterable[Typing.Any], batch_size: int = 1
):
    """
    An async generator that yields ``batch_size`` number of elements
    from an async or sync ``iterable`` at a time.
    """
    stack = {}
    indexes = cycle.root(range(batch_size - 1, -1, -1))
    async for toggle, item in azip(indexes, iterable):
        stack[toggle] = item
        if not toggle:
            yield [*stack.values()]
            stack.clear()
    if stack:
        yield [*stack.values()]


@comprehension()
def compact(iterable: Typing.Iterable[Typing.Any], batch_size: int = 1):
    """
    A generator that yields ``batch_size`` number of elements from an
    ``iterable`` at a time.
    """
    stack = {}
    indexes = cycle.root(range(batch_size - 1, -1, -1))
    for toggle, item in zip(indexes, iterable):
        stack[toggle] = item
        if not toggle:
            yield [*stack.values()]
            stack.clear()
    if stack:
        yield [*stack.values()]


@comprehension()
async def apopleft(queue: Typing.SupportsPopleft):
    """
    An async generator which calls the ``popleft()`` method on ``queue``
    for every iteration, & exits on ``IndexError``.
    """
    while True:
        try:
            yield queue.popleft()
        except IndexError:
            break


@comprehension()
def popleft(queue: Typing.SupportsPopleft):
    """
    A generator which calls the ``popleft()`` method on ``queue`` for
    every iteration, & exits on ``IndexError``.
    """
    while True:
        try:
            yield queue.popleft()
        except IndexError:
            break


@comprehension()
async def apop(queue: Typing.SupportsPop):
    """
    An async generator which calls the ``pop()`` method on ``queue``
    for every iteration, & exits on ``IndexError``.
    """
    while True:
        try:
            yield queue.pop()
        except IndexError:
            break


@comprehension()
def pop(queue: Typing.SupportsPop):
    """
    A generator which calls the ``pop()`` method on ``queue`` for
    every iteration, & exits on ``IndexError``.
    """
    while True:
        try:
            yield queue.pop()
        except IndexError:
            break


@comprehension()
async def apick(
    names: Typing.AsyncOrSyncIterable[Typing.Hashable],
    mapping: Typing.Union[
        Typing.Sequence, Typing.Mapping[Typing.Hashable, Typing.Any]
    ],
):
    """
    Does a bracketed lookup on ``mapping`` for each name in ``names``.
    """
    names = names if is_async_iterable(names) else aunpack(names)
    async for name in names:
        try:
            yield mapping[name]
        except KeyError:
            break


@comprehension()
def pick(
    names: Typing.Iterable[Typing.Hashable],
    mapping: Typing.Union[
        Typing.Sequence, Typing.Mapping[Typing.Hashable, Typing.Any]
    ],
):
    """
    Does a bracketed lookup on ``mapping`` for each name in ``names``.
    """
    for name in names:
        try:
            yield mapping[name]
        except KeyError:
            break


@comprehension()
async def await_on(
    queue: Typing.Container[Typing.Any],
    *,
    probe_frequency: Typing.PositiveRealNumber = 0.0001,
    timeout: Typing.PositiveRealNumber = 1,
):
    """
    An async generator that waits ``timeout`` number of seconds each
    iteration & checks every ``probe_frequency`` number of seconds for
    entries to populate a ``queue`` & yields the queue when an entry
    exists in the queue.
    """
    while True:
        start = time()
        while not queue and (time() - start < timeout):
            await asleep(probe_frequency)
        if time() - start > timeout:
            break
        yield queue


@comprehension()
def wait_on(
    queue: Typing.Container[Typing.Any],
    *,
    probe_frequency: Typing.PositiveRealNumber = 0.0001,
    timeout: Typing.PositiveRealNumber = 1,
):
    """
    An generator that waits ``timeout`` number of seconds each iteration
    & checks every ``probe_frequency`` number of seconds for entries to
    populate a ``queue`` & yields the queue when an entry exists in the
    queue.
    """
    while True:
        start = time()
        while not queue and (time() - start < timeout):
            asynchs.sleep(probe_frequency)
        if time() - start > timeout:
            break
        yield queue


@comprehension()
async def arange(*a, **kw):
    """
    An async version of ``builtins.range``.
    """
    for result in range(*a, **kw):
        await asleep()
        yield result


@comprehension()
def _range(*a, **kw):
    """
    Creates a synchronous version of ``builtins.range`` which is
    wrapped by the ``Comprende`` class.
    """
    for result in range(*a, **kw):
        yield result


@comprehension()
async def abytes_range(*a, size: int = 8, byte_order: str = "big", **kw):
    """
    An async version of ``builtins.range`` wrapped by the ``Comprende``
    class, & returns its values as bytes instead.
    """
    for result in range(*a, **kw):
        await asleep()
        yield result.to_bytes(size, byte_order)


@comprehension()
def bytes_range(*a, size: int = 8, byte_order: str = "big", **kw):
    """
    A synchronous version of ``builtins.range`` which is wrapped by the
    ``Comprende`` class, & returns its values as bytes instead.
    """
    for result in range(*a, **kw):
        yield result.to_bytes(size, byte_order)


class BaseComprende:
    """
    This class is a generator wrapper that exposes an api for making
    sync & async generators more useful by making their many
    features easier to use. BaseComprende allows the retrieving of sync
    & async generator "return" values, & opens channels of communication
    to, from & in between sync & async coroutines.
    """

    __slots__ = (
        "__call__",
        "_areturn_cache",
        "_args",
        "_cache_index",
        "_func",
        "_gen",
        "_is_async",
        "_kwargs",
        "_messages",
        "_return",
        "_return_cache",
        "_thrown",
        "send",
        "asend",
    )

    _ASYNC_GEN_DONE = "async generator raised StopAsyncIteration"

    _cached = {}
    _generators = {"__aiter__", "__iter__"}
    _methods = {
        "athrow",
        "throw",
        "aclose",
        "close",
        "areset",
        "reset",
        "aprime",
        "prime",
        "aresult",
        "result",
        "acatch",
        "catch",
        "arelay",
        "relay",
        "aclass_relay",
        "class_relay",
        "aclear",
        "clear",
        "aclear_class",
        "clear_class",
        "_aauto_cache",
        "_auto_cache",
    }
    _properties = {"_precomputed", "messages"}

    decorator = comprehension
    eager_methods = {
        "alist",
        "list",
        "adeque",
        "deque",
        "aset",
        "set",
        "adict",
        "dict",
        "ajoin",
        "join",
        "aexhaust",
        "exhaust",
    }
    lazy_methods = {"asend", "send"}

    def __init__(self, func, *a, chained: bool = False, **kw):
        """
        Establishes async / sync properties of new objects & copies
        over wrapped functions' signatures.
        """
        self._initialize_generic_attributes(func, a, kw)
        self._initialize_object_message_chain(chained)
        if is_async_gen_function(func):
            self.__set_async()
        else:
            self.__set_sync()

    def _initialize_generic_attributes(self, func, a, kw):
        """
        Populate the instance's basic attributes.
        """
        self._args = a
        self._kwargs = kw
        self._func = func
        self._thrown = deque()
        self._return = deque()
        self._cache_index = b""

    @property
    def messages(self):
        """
        Contains a namespace object that can be used within instance
        methods to pass messages in & out of `Comprende` objects.
        """
        return self._messages

    def _initialize_object_message_chain(self, chained: bool = False):
        """
        Objects in a chain can communicate with each other through this
        `messages` Namespace object. It is also used internally by the
        class to help instance's keep track with each other's state.
        """
        if chained:
            self._messages = self._args[0].messages
            self._messages._chained_instances.append(self)
        else:
            self._messages = Namespace(_chained_instances=[self])

    async def __aexamine_sent_exceptions(self, gen: Typing.Generator):
        """
        Catches ``UserWarning``s which signals that the generator, or a
        subgenerator in the stack, has raised a return value.
        """
        while True:
            got = yield
            if got.__class__ is UserWarning:
                if any(got.args):
                    self._thrown.append(got.args[0])
                await gen.athrow(got)

    async def _acomprehension(self):
        """
        Wraps the user's generator & monitors the values being sent into
        coroutine for the `UserWarning()` signal to halt iteration &
        return the exception's value.
        """
        gen = self._func(*self._args, **self._kwargs)
        catch_UserWarning = self.__aexamine_sent_exceptions(gen).asend
        await catch_UserWarning(None)
        asend = gen.asend
        async with self.acatch():
            got = None
            while True:
                got = yield await asend(got)
                await catch_UserWarning(got)

    def __set_async(self):
        """
        Does the wrapping of user async generators to allow catching
        return values.
        """
        self._is_async = True
        self._gen = self._acomprehension()
        self.send = None
        asend = self.asend = self._gen.asend
        self.__call__ = lambda got=None: asend(got)

    def __examine_sent_exceptions(self, gen: Typing.Generator):
        """
        Catches ``UserWarning``s which signals that the generator, or a
        subgenerator in the stack, has raised a return value.
        """
        while True:
            got = yield
            if got.__class__ is UserWarning:
                if any(got.args):
                    self._thrown.append(got.args[0])
                gen.throw(got)

    def _comprehension(self):
        """
        Wraps the user's generator & monitors the values being sent into
        coroutine for the `UserWarning()` signal to halt iteration &
        return the exception's value.
        """
        gen = self._func(*self._args, **self._kwargs)
        catch_UserWarning = self.__examine_sent_exceptions(gen).send
        catch_UserWarning(None)
        send = gen.send
        with self.catch():
            got = None
            while True:
                got = yield send(got)
                catch_UserWarning(got)

    def __set_sync(self):
        """
        Does the wrapping of user generators to allow catching return
        values.
        """
        self._is_async = False
        self._gen = self._comprehension()
        self.asend = None
        send = self.send = self._gen.send
        self.__call__ = lambda got=None: send(got)

    def __next__(self):
        """
        Allows calling ``builtins.next`` on async / sync generators &
        coroutines.
        """
        if self._is_async:
            return self.asend(None)
        else:
            return self.send(None)

    async def __aiter__(self, *, got=None):
        """
        Iterates over the wrapped async generator / coroutine & produces
        its values directly, or from alru_cache if an eager calculation
        has already computed the gererators values.
        """
        if self._precomputed:
            async with self._aauto_cache() as results:
                for result in results:
                    await asleep()
                    yield result
        else:
            while True:
                try:
                    got = yield await self(got)
                except StopAsyncIteration:
                    break

    def __iter__(self, *, got=None):
        """
        Iterates over the wrapped generator / coroutine and produces its
        values directly, or from lru_cache if an eager calculation has
        already computed the gererators values.
        """
        if self._precomputed:
            with self._auto_cache() as results:
                yield from results
        else:
            while True:
                try:
                    got = yield self(got)
                except StopIteration:
                    break

    async def __aenter__(self):
        """
        Opens a context & yields ``self``.
        """
        return self

    def __enter__(self):
        """
        Opens a context & yields ``self``.
        """
        return self

    async def __aexit__(
        self, exc_type=None, exc_value=None, traceback=None
    ):
        """
        Surpresses StopAsyncIteration exceptions within a context.
        Clears the cached results upon exit.
        """
        try:
            if exc_type is StopAsyncIteration:
                return True
        finally:
            await self.aclear()

    def __exit__(self, exc_type=None, exc_value=None, traceback=None):
        """
        Surpresses StopIteration exceptions within a context. Clears the
        cached results upon exit.
        """
        try:
            if exc_type is StopIteration:
                return True
        finally:
            self.clear()

    def __repr__(self, *, mask: bool = True):
        """
        Displays the string which, if ``exec``'d, would yield a new
        equivalent object.
        """
        a = self._args
        kw = self._kwargs
        func = self._func.__qualname__
        cls = self.__class__.__qualname__
        tab = f"{linesep + 4 * ' '}"
        _repr = f"{cls}({tab}func={func},{tab}"
        if not mask or DebugControl.is_debugging():
            return _repr + f"*{a},{tab}**{kw},{linesep})"
        else:
            _repr += f"args={len(a)},{tab}kwargs={len(kw)},{linesep})"
            return _repr

    def __del__(self):
        """
        Attempts to cleanup instance caches when deleted or garbage
        collected to reduce memory overhead.
        """
        self.clear()
        if hasattr(self, "gen"):
            del self._gen

    async def aprime(self):
        """
        Resets the instance's async wrapper generator & ``asend``s in a
        ``None`` value to prime the generator, i.e. bringing it to the
        first yield statement.
        """
        await self.areset()
        await self(None)
        return self

    def prime(self):
        """
        Resets the instance's sync wrapper generator & ``send``s in a
        ``None`` value to prime the generator, i.e. bringing it to the
        first yield statement.
        """
        self.reset()
        self(None)
        return self

    async def areset(self, *, _top_of_the_chain=True):
        """
        Replaces the generator wrapper with a new async wrapper.
        """
        await asleep()
        if _top_of_the_chain:
            for instance in self.messages._chained_instances:
                await instance.areset(_top_of_the_chain=False)
        else:
            self.__set_async()
        return self

    def reset(self, *, _top_of_the_chain=True):
        """
        Replaces the generator wrapper with a new sync wrapper.
        """
        if _top_of_the_chain:
            for instance in self.messages._chained_instances:
                instance.reset(_top_of_the_chain=False)
        else:
            self.__set_sync()
        return self

    @async_contextmanager
    async def acatch(self):
        """
        Handles catching the return values passed through exceptions
        from async generators & makes sure other errors are propagated
        correctly up to user code. Asynchronous generators don't already
        have a mechanism for returning values. So this async context
        manager handles catching return values from UserWarning
        exceptions & appends those results to ``self._return``. Items
        in the result queue are accessible from ``self.aresult()``.
        """
        try:
            await asleep()
            yield self
        except UserWarning as done:
            if done.args:
                self._return.append(done.args[0])
        except RuntimeError as done:
            if self._ASYNC_GEN_DONE not in done.args:
                raise done
        except StopAsyncIteration:
            pass

    @contextmanager
    def catch(self):
        """
        Handles catching the return values passed through exceptions
        from sync generators & makes sure other errors are propagated
        correctly up to user code. Synchronous generators already have
        a mechanism for returning values. This context manager handles
        catching StopIteration values, & for the sake of parity with
        async generators, it also catches return values from UserWarning
        exceptions & appends those results to ``self._return``. Items
        in the result queue are accessible from ``self.result()``.
        """
        try:
            yield self
        except UserWarning as done:
            if done.args:
                self._return.append(done.args[0])
        except StopIteration as done:
            if getattr(done, "value", None) != None:
                self._return.append(done.value)

    @classmethod
    @async_contextmanager
    async def aclass_relay(cls, result=None, *, source=None):
        """
        This is a lower level context manager for users who've created
        async generators that need to propagate results up to calling
        code. Code in this context manager's block will return ``result``
        or the return value of a ``source`` Comprende async generator
        up to its caller in a UserWarning exception.
        """
        try:
            await asleep()
            yield source
        except UserWarning:
            if result != None:
                raise UserWarning(result)
            raise UserWarning(await source.aresult(exit=True))

    @classmethod
    @contextmanager
    def class_relay(cls, result=None, *, source=None):
        """
        This is a lower level context manager for users who've created
        sync generators that need to propagate results up to calling
        code. Code in this context manager's block will relay a ``result``
        or the return value of a ``source`` Comprende sync generator
        up to its caller in a UserWarning exception.
        """
        try:
            yield source
        except (StopIteration, UserWarning):
            if result != None:
                raise UserWarning(result)
            raise UserWarning(source.result(exit=True))

    @async_contextmanager
    async def arelay(self, result=None, *, source=None):
        """
        This is a lower level context manager for users who've created
        async generators that need to propagate results up to calling
        code. Code in this context manager's block will return ``result``
        or the return value of a ``source`` Comprende async generator
        up to its caller in a UserWarning exception.
        """
        try:
            source = source if source else self
            yield source
        except UserWarning:
            if result != None:
                raise UserWarning(result)
            raise UserWarning(await source.aresult(exit=True))

    @contextmanager
    def relay(self, result=None, *, source=None):
        """
        This is a lower level context manager for users who've created
        sync generators that need to propagate results up to calling
        code. Code in this context manager's block will relay a ``result``
        or the return value of a ``source`` Comprende sync generator
        up to its caller in a UserWarning exception.
        """
        try:
            source = source if source else self
            yield source
        except (StopIteration, UserWarning):
            if result != None:
                raise UserWarning(result)
            raise UserWarning(source.result(exit=True))

    async def aresult(self, *, pop=False, exit=False, silent=True):
        """
        Controls access to instance results. This method can cause an
        async generator to close when ``exit`` is truthy & returns its
        results if it has any. If ``pop`` is truthy, the results are
        popped off the result queue, & by default surpresses ``IndexError``
        if no results are in the queue. If ``silent`` is truthy, then
        exceptions are not ignored & the first raised exception is
        printed to stdout.
        """
        if exit and silent:
            async with aignore(
                TypeError, StopAsyncIteration, display=not silent
            ):
                await self(UserWarning())
        elif exit:
            await self(UserWarning())
        async with aignore(IndexError, display=not silent):
            if pop:
                return self._return.popleft()
            else:
                return self._return[0]

    def result(self, *, pop=False, exit=False, silent=True):
        """
        Controls access to instance results. This method can cause an
        sync generator to close when ``exit`` is truthy & returns its
        results if it has any. If ``pop`` is truthy, the results are
        popped off the result queue, & by default surpresses ``IndexError``
        if no results are in the queue. If ``silent`` is truthy, then
        exceptions are not ignored & the first raised exception is
        printed to stdout.
        """
        if exit and silent:
            with ignore(TypeError, StopIteration, display=not silent):
                self(UserWarning())
        elif exit:
            self(UserWarning())
        with ignore(IndexError, display=not silent):
            if pop:
                return self._return.popleft()
            else:
                return self._return[0]

    @staticmethod
    async def _amake_cache_index(size: int = 16):
        """
        Calculates a ``size``-byte pseudo-random index which is used to
        find an instance with cached results from the class.
        """
        await asleep()
        return secrets.token_bytes(size)

    @staticmethod
    def _make_cache_index(size: int = 16):
        """
        Calculates a ``size``-byte pseudo-random index which is used to
        find an instance with cached results from the class.
        """
        return secrets.token_bytes(size)

    @property
    def _precomputed(self):
        """
        Checks the class' dictionary of cached flags for the generator's
        ``self._cache_index`` id. Returns the instance if found, False
        if not.
        """
        return self.__class__._cached.get(self._cache_index)

    async def _aset_cache(self):
        """
        Creates a per-instance function that returns precomputed results
        with lru cache turned on to save on speed for instances that have
        called async methods or generators which do eager computation of
        an async generator's entire result set.
        """

        @alru_cache(maxsize=1)
        async def _areturn_cache(cache_index=None):
            return [result async for result in self]

        await asleep()
        self._areturn_cache = _areturn_cache
        self._cache_index = await self._amake_cache_index()

    def _set_cache(self):
        """
        Creates a per-instance function that returns precomputed results
        with lru cache turned on to save on speed for instances that have
        called sync methods or generators which do eager computation of
        a generator's entire result set.
        """

        @lru_cache(maxsize=1)
        def _return_cache(cache_index=None):
            return [*self]

        self._return_cache = _return_cache
        self._cache_index = self._make_cache_index()

    @async_contextmanager
    async def _aauto_cache(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``list``, then ``alru_cache``'s the result
        & yields it as a context manager. Finally, adds the instance
        into the class' ``_cached`` dictionary to more easily find &
        manage the memory overhead of caching values.
        """
        try:
            if not self._cache_index:
                await self._aset_cache()
            yield await self._areturn_cache(self._cache_index)
        finally:
            self.__class__._cached[self._cache_index] = self

    @contextmanager
    def _auto_cache(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``list``, then ``lru_cache``'s the result
        & yields it as a context manager. Finally, adds the instance
        into the class' ``_cached`` dictionary to more easily find &
        manage the memory overhead of caching values.
        """
        try:
            if not self._cache_index:
                self._set_cache()
            yield self._return_cache(self._cache_index)
        finally:
            self.__class__._cached[self._cache_index] = self

    async def _astored_caches(self):
        """
        Returns the lru cached methods of an instance in an iterable.
        """
        if hasattr(self, "_return_cache"):
            await asleep()
            yield self._return_cache
        if hasattr(self, "_areturn_cache"):
            await asleep()
            yield self._areturn_cache

    def _stored_caches(self):
        """
        Returns the lru cached methods of an instance in an iterable.
        """
        if hasattr(self, "_return_cache"):
            yield self._return_cache
        if hasattr(self, "_areturn_cache"):
            yield self._areturn_cache

    async def alist(self, *, mutable=False, cache=False):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``list``, then ``alru_cache``'s the result
        & returns it.

        The `results` list here is a direct mutable representation of
        the generator's internal state. Meaning, upon further loops over
        the generator, it will read & yield values directly from this
        list. For this reason, the list is copied before being returned.
        If a user wants to utilize this behaviour, then that will have
        to be specified manually by setting the ``mutable`` boolean
        keyword argument be set to `True`.
        """
        if not cache:
            return [item async for item in self]
        async with self._aauto_cache() as results:
            return results if mutable else list(results)

    def list(self, *, mutable=False, cache=False):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a ``list``, then ``lru_cache``'s the result
        & returns it.

        The `results` list here is a direct mutable representation of
        the generator's internal state. Meaning, upon further loops over
        the generator, it will read & yield values directly from this
        list. For this reason, the list is copied before being returned.
        If a user wants to utilize this behaviour, then that will have
        to be specified manually by setting the ``mutable`` boolean
        keyword argument be set to `True`.
        """
        if not cache:
            return list(self)
        with self._auto_cache() as results:
            return results if mutable else list(results)

    async def adeque(self, *, maxlen=None, cache=False):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``collections.deque``, then ``alru_cache``'s
        the result & returns it.
        """
        if not cache:
            return deque([item async for item in self], maxlen=maxlen)
        async with self._aauto_cache() as results:
            return deque(results, maxlen=maxlen)

    def deque(self, *, maxlen=None, cache=False):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a ``collections.deque``, then ``lru_cache``'s
        the result & returns it.
        """
        if not cache:
            return deque(self, maxlen=maxlen)
        with self._auto_cache() as results:
            return deque(results, maxlen=maxlen)

    async def aset(self, *, cache=False):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``set``, then ``alru_cache``'s the result
        & returns it.
        """
        if not cache:
            return {item async for item in self}
        async with self._aauto_cache() as results:
            return set(results)

    def set(self, *, cache=False):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a ``set``, then ``lru_cache``'s the result
        & returns it.
        """
        if not cache:
            return set(self)
        with self._auto_cache() as results:
            return set(results)

    async def adict(self, *, cache=False):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``dict``, then ``alru_cache``'s the result
        & returns it.
        """
        if not cache:
            return {key: value async for key, value in self}
        async with self._aauto_cache() as results:
            return dict(results)

    def dict(self, *, cache=False):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a ``dict``, then ``lru_cache``'s the result
        & returns it.
        """
        if not cache:
            return dict(self)
        with self._auto_cache() as results:
            return dict(results)

    async def ajoin(self, on="", *, cache=False):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together ``on`` the string that's passed, then
        ``alru_cache``'s the result & returns it.
        """
        if not cache:
            return on.join([item async for item in self])
        async with self._aauto_cache() as results:
            return on.join(results)

    def join(self, on="", *, cache=False):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together ``on`` the string that's passed, then
        ``lru_cache``'s the result & returns it.
        """
        if not cache:
            return on.join(self)
        with self._auto_cache() as results:
            return on.join(results)

    async def aexhaust(self):
        """
        Iterates over the entirety of the underlying Comprende async
        generator without yielding the results. Instead, it only returns
        the final yielded result.
        """
        async for result in self:
            pass
        if "result" in vars():
            return result

    def exhaust(self):
        """
        Iterates over the entirety of the underlying Comprende sync
        generator without yielding the results. Instead, it only returns
        the final yielded result.
        """
        for result in self:
            pass
        if "result" in vars():
            return result

    @classmethod
    async def aclear_class(cls):
        """
        Allows users to manually clear the cache of all the class'
        instances.
        """
        for cache_index, instance in dict(cls._cached).items():
            del cls._cached[cache_index]
            async for cache in instance._astored_caches():
                cache.cache_clear()
            instance._cache_index = b""

    @classmethod
    def clear_class(cls):
        """
        Allows users to manually clear the cache of all the class'
        instances.
        """
        for cache_index, instance in dict(cls._cached).items():
            del cls._cached[cache_index]
            for cache in instance._stored_caches():
                cache.cache_clear()
            instance._cache_index = b""

    async def aclear(self, *, cls=False):
        """
        Allows users to manually clear the cache of an instance, or if
        ``cls`` is ``True`` clears the cache of every instance.
        """
        if cls == True:
            await self.aclear_class()
        elif self._precomputed:
            try:
                del self.__class__._cached[self._cache_index]
                async for cache in self._astored_caches():
                    cache.cache_clear()
            finally:
                self._cache_index = b""

    def clear(self, *, cls=False):
        """
        Allows users to manually clear the cache of an instance, or if
        ``cls`` is ``True`` clears the cache of every instance.
        """
        if cls == True:
            self.clear_class()
        elif self._precomputed:
            try:
                del self.__class__._cached[self._cache_index]
                for cache in self._stored_caches():
                    cache.cache_clear()
            finally:
                self._cache_index = b""

    @property
    def ag_await(self):
        """
        Copies the interface for async generators.
        """
        return self._gen.ag_await

    @property
    def gi_yieldfrom(self):
        """
        Copies the interface for generators.
        """
        return self._gen.gi_yieldfrom

    @property
    def ag_code(self):
        """
        Copies the interface for async generators.
        """
        return self._gen.ag_code

    @property
    def gi_code(self):
        """
        Copies the interface for generators.
        """
        return self._gen.gi_code

    @property
    def ag_frame(self):
        """
        Copies the interface for async generators.
        """
        return self._gen.ag_frame

    @property
    def gi_frame(self):
        """
        Copies the interface for generators.
        """
        return self._gen.gi_frame

    @property
    def ag_running(self):
        """
        Copies the interface for async generators.
        """
        return self._gen.ag_running

    @property
    def gi_running(self):
        """
        Copies the interface for generators.
        """
        return self._gen.gi_running

    async def aclose(self, *a, **kw):
        """
        This is quivalent to a wrapped async generator's ``aclose``
        method.
        """
        return await self._gen.aclose(*a, **kw)

    def close(self, *a, **kw):
        """
        This is quivalent to a wrapped sync generator's ``close`` method.
        """
        return self._gen.close(*a, **kw)

    async def athrow(self, exc_type, exc_value=None, traceback=None):
        """
        This is quivalent to a wrapped async generator's ``athrow``
        method.
        """
        await self._gen.athrow(exc_type, exc_value, traceback)

    def throw(self, exc_type, exc_value=None, traceback=None):
        """
        This is quivalent to a wrapped sync generator's ``throw`` method.
        """
        self._gen.throw(exc_type, exc_value, traceback)


class Comprende(BaseComprende):
    """
    Comprende is a generator wrapper class that exposes an expansive api
    for making sync & async generators more useful by making their many
    features easier to use. Comprende allows for easily retrieving
    sync & async generator "return" values, has built-in methods that
    support dotted chaining for inline data processing, & it opens
    channels of communication to, from & in between sync & async
    coroutines.
    """

    __slots__ = ()

    _cached = {}
    _methods = BaseComprende._methods.union({"__getitem__"})

    eager_generators = {
        "aheappop",
        "heappop",
        "areversed",
        "reversed",
        "asort",
        "sort",
    }
    lazy_generators = {
        "_agetitem",
        "_getitem",
        "atimeout",
        "timeout",
        "ajson_loads",
        "json_loads",
        "ajson_dumps",
        "json_dumps",
        "aencode",
        "encode",
        "adecode",
        "decode",
        "astr",
        "str",
        "aint",
        "int",
        "ahex",
        "hex",
        "abin",
        "bin",
        "aoct",
        "oct",
        "abytes",
        "bytes",
        "abytes_to_int",
        "bytes_to_int",
        "aint_to_bytes",
        "int_to_bytes",
        "ahex_to_bytes",
        "hex_to_bytes",
        "abytes_to_hex",
        "bytes_to_hex",
        "ato_base",
        "to_base",
        "afrom_base",
        "from_base",
        "azfill",
        "zfill",
        "aslice",
        "slice",
        "aindex",
        "index",
        "areplace",
        "replace",
        "asplit",
        "split",
        "atag",
        "tag",
        "ahalt",
        "halt",
        "afeed",
        "feed",
        "afeed_self",
        "feed_self",
        "aresize",
        "resize",
        "adelimit",
        "delimit",
        "adelimited_resize",
        "delimited_resize",
        "ato_base64",
        "to_base64",
        "afrom_base64",
        "from_base64",
        "aint_to_ascii",
        "int_to_ascii",
        "aascii_to_int",
        "ascii_to_int",
        "asha3__512",
        "sha3__512",
        "asha3__512_hmac",
        "sha3__512_hmac",
        "asha3__256",
        "sha3__256",
        "asha3__256_hmac",
        "sha3__256_hmac",
    }

    @staticmethod
    def _unpack_slice(index: Typing.Index, _max: int = 1 << 128):
        """
        Returns the `start`, `stop` & `step` values from a slice object.
        """
        if index.__class__ is int:
            return index, index + 1, 1
        return (
            index.start if index.start.__class__ is int else 0,
            index.stop if index.stop.__class__ is int else _max,
            index.step if index.step.__class__ is int else 1,
        )

    def _set_index(self, index: Typing.Index):
        """
        Interprets the slice or int passed into __getitem__ into an
        iterable of a range object.
        """
        index = self._unpack_slice(index)
        for value in index:
            if value.__class__ is int and value < 0:
                raise Issue.value_must_be_value("index", "positive int")
        return iter(range(*index)).__next__

    async def _agetitem(self, index: Typing.Index):
        """
        Allows indexing of async generators to yield the values
        associated with the slice or integer passed into the brackets.
        Does not support negative indices.
        """
        got = None
        next_target = self._set_index(index)
        with ignore(StopIteration, StopAsyncIteration):
            target = next_target()
            async for match in acount.root():
                if target == match:
                    got = yield await self(got)
                    target = next_target()
                else:
                    await self(got)
                    got = None

    def _getitem(self, index: Typing.Index):
        """
        Allows indexing of generators to yield the values associated
        with the slice or integer passed into the brackets. Does not
        support negative indices.
        """
        got = None
        next_target = self._set_index(index)
        with ignore(StopIteration):
            target = next_target()
            for match in count.root():
                if target == match:
                    got = yield self(got)
                    target = next_target()
                else:
                    self(got)
                    got = None

    def __getitem__(self, index: Typing.Index):
        """
        Allows indexing of generators & async generators to yield the
        values associated with the slice or integer passed into the
        brackets. Does not support negative indices.
        """
        if self._is_async:
            return self._agetitem(index)
        else:
            return self._getitem(index)

    async def areversed(self, span: Typing.OptionalIndex = None):
        """
        Exhausts the underlying Comprende async generator upto ``span``
        number of iterations, then yields the results in reversed order.
        """
        target = self[:span] if span else self
        async with target as accumulator:
            results = await accumulator.alist()
        for result in reversed(results):
            yield result

    def reversed(self, span: Typing.OptionalIndex = None):
        """
        Exhausts the underlying Comprende sync generator upto ``span``
        number of iterations, then yields the results in reversed order.
        """
        target = self[:span] if span else self
        with target as accumulator:
            results = accumulator.list()
        yield from reversed(results)

    def __reversed__(self):
        """
        Allows reversing async/sync generators, but must compute all
        values first to do so.
        """
        if self._is_async:
            return self.areversed()
        else:
            return self.reversed()

    async def asort(
        self,
        *,
        key: Typing.Optional[Typing.Callable] = None,
        span: Typing.OptionalIndex = None,
    ):
        """
        Exhausts the underlying Comprende async generator upto ``span``
        number of iterations, then yields the results in sorted order.
        """
        target = self[:span] if span else self
        async with target as accumulator:
            results = await accumulator.alist()
        for result in sorted(results, key=key):
            yield result

    def sort(
        self,
        *,
        key: Typing.Optional[Typing.Callable] = None,
        span: Typing.OptionalIndex = None,
    ):
        """
        Exhausts the underlying Comprende sync generator upto ``span``
        number of iterations, then yields the results in sorted order.
        """
        target = self[:span] if span else self
        yield from sorted(target, key=key)

    async def aheappop(self, span: Typing.OptionalIndex = None):
        """
        Exhausts the underlying Comprende async generator upto ``span``
        number of iterations, then yields the results in sorted order
        based on the ``heapq.heappop`` function.
        """
        target = self[:span] if span else self
        async with target as accumulator:
            results = await accumulator.alist()
        heapq.heapify(results)
        while True:
            try:
                yield heapq.heappop(results)
            except IndexError:
                break

    def heappop(self, span: Typing.OptionalIndex = None):
        """
        Exhausts the underlying Comprende sync generator upto ``span``
        number of iterations, then yields the results in sorted order
        based on the ``heapq.heappop`` function.
        """
        target = self[:span] if span else self
        with target as accumulator:
            results = accumulator.list()
        heapq.heapify(results)
        while True:
            try:
                yield heapq.heappop(results)
            except IndexError:
                break

    async def atimeout(
        self,
        seconds: int = 5,
        *,
        probe_frequency: Typing.PositiveRealNumber = 0,
    ):
        """
        Stops the instance's wrapped async generator's current iteration
        after a ``seconds`` number of seconds. Otherwise, the countdown
        is restarted after every on-time iteration & the result is
        yielded. Runs the wrapped generator as a async task to acheive
        this.
        """
        got = None
        while True:
            time_start = time()
            iteration = asynchs.new_task(self.asend(got))
            while not iteration.done():
                await asleep(probe_frequency)
                if time() - time_start >= seconds:
                    break
            if iteration.done():
                got = yield await iteration
            else:
                iteration.cancel()
                break

    def timeout(
        self,
        seconds: int = 5,
        *,
        probe_frequency: Typing.PositiveRealNumber = 0,
    ):
        """
        Stops the instance's wrapped sync generator's current iteration
        after a ``seconds`` number of seconds. Otherwise, the countdown
        is restarted after every on-time iteration & the result is
        yielded. Runs the wrapped generator in a thread pool to acheive
        this.
        """
        got = None
        try:
            while True:
                time_start = time()
                iteration = asynchs.Threads.submit(self.send, got)
                while not iteration.done():
                    asynchs.sleep(probe_frequency)
                    if time() - time_start >= seconds:
                        break
                if iteration.done():
                    got = yield iteration.result()
                else:
                    iteration.cancel()
                    break
        except StopIteration:
            pass

    async def ahalt(
        self,
        sentinel: Typing.Any = "",
        *,
        sentinels: Typing.SupportsContains = (),
    ):
        """
        Takes a ``sentinel`` or iterable of ``sentinels`` & halts the
        underlying Comprende async generator if it yields any of those
        sentinels.
        """
        try:
            got = None
            sentinels = set(sentinels) if sentinels else {sentinel}
            while True:
                result = await self(got)
                if result in sentinels:
                    break
                got = yield result
        except StopAsyncIteration:
            pass

    def halt(
        self,
        sentinel: Typing.Any = "",
        *,
        sentinels: Typing.SupportsContains = (),
    ):
        """
        Takes a ``sentinel`` or iterable of ``sentinels`` & halts the
        underlying Comprende sync generator if it yields any of those
        sentinels.
        """
        try:
            got = None
            sentinels = set(sentinels) if sentinels else {sentinel}
            while True:
                result = self(got)
                if result in sentinels:
                    break
                got = yield result
        except StopIteration:
            pass

    async def afeed(self, iterable: Typing.Iterable[Typing.Any]):
        """
        Takes in an sync or async iterable & sends those values into an
        async coroutine which automates the process of driving an async
        generator which is expecting results from a caller.
        """
        yield await self(None)
        async for food in aunpack.root(iterable):
            yield await self(food)

    def feed(self, iterable: Typing.Iterable[Typing.Any]):
        """
        Takes in an iterable & sends those values into a sync coroutine
        which automates the process of driving a generator which is
        expecting results from a caller.
        """
        try:
            yield self(None)
            for food in iterable:
                yield self(food)
        except StopIteration:
            pass

    async def afeed_self(self):
        """
        Recursively feeds the results of an async generator back into
        itself as coroutine values for the ``asend`` function.
        """
        food = await self(None)
        yield food
        while True:
            food = await self(food)
            yield food

    def feed_self(self):
        """
        Recursively feeds the results of an generator back into itself
        as coroutine values for the ``send`` function.
        """
        try:
            food = self(None)
            yield food
            while True:
                food = self(food)
                yield food
        except StopIteration:
            pass

    async def atag(self, tags: Typing.Iterable[Typing.Any] = None):
        """
        By default behaves like ``enumerate`` for each value yielded
        from the underlying Comprende async generator. Optionally,
        ``tags`` can be passed a sync or async iterable & prepends those
        values to the generator's results.
        """
        got = None
        if tags:
            async for name in aunpack.root(tags):
                got = yield name, await self(got)
        else:
            async for index in acount.root():
                got = yield index, await self(got)

    def tag(self, tags: Typing.Iterable[Typing.Any] = None):
        """
        By default behaves like ``enumerate`` for each value yielded
        from the underlying Comprende sync generator. Optionally,
        ``tags`` can be passed an iterable & prepends those values to
        the generator's results.
        """
        got = None
        try:
            if tags:
                for name in tags:
                    got = yield name, self(got)
            else:
                for index in count.root():
                    got = yield index, self(got)
        except StopIteration:
            pass

    async def aresize(self, size: int = BLOCKSIZE):
        """
        Buffers the output from the underlying Comprende async generator
        to yield the results in chunks of length ``size``.
        """
        result = await self(None)
        while True:
            while len(result) >= size:
                yield result[:size]
                result = result[size:]
            try:
                result += await self(None)
            except StopAsyncIteration:
                break
        if result:
            yield result

    def resize(self, size: int = BLOCKSIZE):
        """
        Buffers the output from the underlying Comprende sync generator
        to yield the results in chunks of length ``size``.
        """
        result = self(None)
        while True:
            while len(result) >= size:
                yield result[:size]
                result = result[size:]
            try:
                result += self(None)
            except StopIteration:
                break
        if result:
            yield result

    async def adelimit(self, delimiter: Typing.AnyStr = " "):
        """
        Adds a user-defined ``delimiter`` to the end of end result
        yielded from the underlying ``Comprende`` async generator.
        """
        got = None
        while True:
            got = yield await self(got) + delimiter

    def delimit(self, delimiter: Typing.AnyStr = " "):
        """
        Adds a user-defined ``delimiter`` to the end of end result
        yielded from the underlying ``Comprende`` generator.
        """
        got = None
        try:
            while True:
                got = yield self(got) + delimiter
        except StopIteration:
            pass

    async def adelimited_resize(self, delimiter: Typing.AnyStr = " "):
        """
        Yields the results of the underlying ``Comprende`` async
        generator in chunks delimited by ``delimiter``. The ``base``
        keyword argument is an empty sequence of the same type
        (``str`` or ``bytes``) that the yielded results are in.
        """
        cache = delimiter[:0]
        async for result in self:
            result = (cache + result).lstrip(delimiter)
            while delimiter in result:
                index = result.find(delimiter)
                yield result[:index]
                result = result[index:].lstrip(delimiter)
            cache = result
        if cache:
            yield cache

    def delimited_resize(self, delimiter: Typing.AnyStr = " "):
        """
        Yields the results of the underlying ``Comprende`` generator in
        chunks delimited by ``delimiter``.
        """
        cache = delimiter[:0]
        for result in self:
            result = (cache + result).lstrip(delimiter)
            while delimiter in result:
                index = result.find(delimiter)
                yield result[:index]
                result = result[index:].lstrip(delimiter)
            cache = result
        if cache:
            yield cache

    async def ato_base64(self):
        """
        Applies ``base64.standard_b64encode`` conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        while True:
            got = yield to_base64(await self(got))

    def to_base64(self):
        """
        Applies ``base64.standard_b64encode`` conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        try:
            while True:
                got = yield to_base64(self(got))
        except StopIteration:
            pass

    async def afrom_base64(self):
        """
        Applies ``base64.standard_b64decode`` conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        while True:
            got = yield from_base64(await self(got))

    def from_base64(self):
        """
        Applies ``base64.standard_b64decode`` conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        try:
            while True:
                got = yield from_base64(self(got))
        except StopIteration:
            pass

    async def aint_to_ascii(self):
        """
        Applies a ``binascii`` int-to-ascii conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        while True:
            got = yield (await self(got)).to_bytes(
                math.ceil(result.bit_length() / 8), "big"
            ).decode()

    def int_to_ascii(self):
        """
        Applies a ``binascii`` int-to-ascii conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        try:
            while True:
                got = yield self(got).to_bytes(
                    math.ceil(result.bit_length() / 8), "big"
                ).decode()
        except StopIteration:
            pass

    async def aascii_to_int(self):
        """
        Applies a ``binascii`` ascii-to-int conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        while True:
            got = yield int.from_bytes(
                (await self(got)).encode(), "big"
            )

    def ascii_to_int(self):
        """
        Applies a ``binascii`` ascii-to-int conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        try:
            while True:
                got = yield int.from_bytes(self(got).encode(), "big")
        except StopIteration:
            pass

    async def asha3__512(self, *, salt: Typing.Any = None):
        """
        Applies ``hashlib.sha3_512()`` to each value that's yielded
        from the underlying Comprende async generator before yielding
        the result.
        """
        got = None
        if salt:
            while True:
                got = yield await asha3__512(salt, await self(got))
        else:
            while True:
                got = yield await asha3__512(await self(got))

    def sha3__512(self, *, salt: Typing.Any = None):
        """
        Applies ``hashlib.sha3_512()`` to each value that's yielded
        from the underlying Comprende sync generator before yielding
        the result.
        """
        got = None
        try:
            if salt:
                while True:
                    got = yield sha3__512(salt, self(got))
            else:
                while True:
                    got = yield sha3__512(self(got))
        except StopIteration:
            pass

    async def asha3__512_hmac(
        self, *, key: Typing.Any, salt: Typing.Any = None
    ):
        """
        Applies a ``hashlib.sha3_512()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        if salt:
            while True:
                got = yield await asha3__512_hmac(
                    (salt, await self(got)), key=key
                )
        else:
            while True:
                got = yield await asha3__512_hmac(await self(got), key=key)

    def sha3__512_hmac(self, *, key: Typing.Any, salt: Typing.Any = None):
        """
        Applies a ``hashlib.sha3_512()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        try:
            if salt:
                while True:
                    got = yield sha3__512_hmac((salt, self(got)), key=key)
            else:
                while True:
                    got = yield sha3__512_hmac(self(got), key=key)
        except StopIteration:
            pass

    async def asha3__256(self, *, salt: Typing.Any = None):
        """
        Applies ``hashlib.sha3_256()`` to each value that's yielded
        from the underlying Comprende async generator before yielding
        the result.
        """
        got = None
        if salt:
            while True:
                got = yield await asha3__256(salt, await self(got))
        else:
            while True:
                got = yield await asha3__256(await self(got))

    def sha3__256(self, *, salt: Typing.Any = None):
        """
        Applies ``hashlib.sha3_256()`` to each value that's yielded
        from the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            if salt:
                while True:
                    got = yield sha3__256(salt, self(got))
            else:
                while True:
                    got = yield sha3__256(self(got))
        except StopIteration:
            pass

    async def asha3__256_hmac(
        self, *, key: Typing.Any, salt: Typing.Any = None
    ):
        """
        Applies a ``hashlib.sha3_256()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        if salt:
            while True:
                got = yield await asha3__256_hmac(
                    (salt, await self(got)), key=key
                )
        else:
            while True:
                got = yield await asha3__256_hmac(await self(got), key=key)

    def sha3__256_hmac(self, *, key: Typing.Any, salt: Typing.Any = None):
        """
        Applies a ``hashlib.sha3_256()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        try:
            if salt:
                while True:
                    got = yield sha3__256_hmac((salt, self(got)), key=key)
            else:
                while True:
                    got = yield sha3__256_hmac(self(got), key=key)
        except StopIteration:
            pass

    async def aint(self, *a, **kw):
        """
        Applies ``builtins.int(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        while True:
            got = yield int(await self(got), *a, **kw)

    def int(self, *a, **kw):
        """
        Applies ``builtins.int(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield builtins.int(self(got), *a, **kw)
        except StopIteration:
            pass

    async def abytes_to_int(self, byte_order: str = "big"):
        """
        Applies ``int.from_bytes(result, byte_order)`` to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        while True:
            got = yield int.from_bytes(await self(got), byte_order)

    def bytes_to_int(self, byte_order: str = "big"):
        """
        Applies ``int.from_bytes(result, byte_order)`` to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        try:
            while True:
                got = yield int.from_bytes(self(got), byte_order)
        except StopIteration:
            pass

    async def aint_to_bytes(
        self, size: int = BLOCKSIZE, byte_order: str = "big"
    ):
        """
        Applies ``int.to_bytes(result, size, byte_order)`` to each
        value that's yielded from the underlying Comprende async
        generator before yielding the result.
        """
        got = None
        while True:
            got = yield (await self(got)).to_bytes(size, byte_order)

    def int_to_bytes(self, size: int = BLOCKSIZE, byte_order: str = "big"):
        """
        Applies ``int.to_bytes(result, size, byte_order)`` to each
        value that's yielded from the underlying Comprende sync
        generator before yielding the result.
        """
        got = None
        try:
            while True:
                got = yield self(got).to_bytes(size, byte_order)
        except StopIteration:
            pass

    async def ahex_to_bytes(self):
        """
        Applies ``bytes.fromhex(result)`` to each value that's yielded
        from the underlying Comprende async generator before yielding
        the result.
        """
        got = None
        while True:
            got = yield bytes.fromhex(await self(got))

    def hex_to_bytes(self):
        """
        Applies ``bytes.fromhex(result)`` to each value that's yielded
        from the underlying Comprende sync generator before yielding
        the result.
        """
        got = None
        try:
            while True:
                got = yield bytes.fromhex(self(got))
        except StopIteration:
            pass

    async def abytes_to_hex(self):
        """
        Applies ``bytes.hex(result)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        while True:
            got = yield (await self(got)).hex()

    def bytes_to_hex(self):
        """
        Applies ``bytes.hex(result)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield self(got).hex()
        except StopIteration:
            pass

    async def ato_base(self, base: int = 95, table: str = Tables.ASCII_95):
        """
        Converts each integer value that's yielded from the underlying
        Comprende async generator to a string in ``base`` before yielding
        the result.
        """
        got = None
        while True:
            got = yield await aint_to_base(await self(got), base, table)

    def to_base(self, base: int = 95, table: str = Tables.ASCII_95):
        """
        Converts each integer value that's yielded from the underlying
        Comprende sync generator to a string in ``base`` before yielding
        the result.
        """
        got = None
        try:
            while True:
                got = yield int_to_base(self(got), base, table)
        except StopIteration:
            pass

    async def afrom_base(
        self, base: int = 95, table: str = Tables.ASCII_95
    ):
        """
        Convert string results of generator results in numerical ``base``
        into decimal.
        """
        got = None
        while True:
            got = yield await abase_to_int(await self(got), base, table)

    def from_base(self, base: int = 95, table: str = Tables.ASCII_95):
        """
        Convert ``string`` in numerical ``base`` into decimal.
        """
        got = None
        try:
            while True:
                got = yield base_to_int(self(got), base, table)
        except StopIteration:
            pass

    async def azfill(self, *a, **kw):
        """
        Applies ``builtins.zfill(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        while True:
            got = yield (await self(got)).zfill(*a, **kw)

    def zfill(self, *a, **kw):
        """
        Applies ``builtins.zfill(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield self(got).zfill(*a, **kw)
        except StopIteration:
            pass

    async def aslice(self, *a):
        """
        Applies ``builtins.slice(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        selected = slice(*a)
        while True:
            got = yield (await self(got))[selected]

    def slice(self, *a):
        """
        Applies ``builtins.slice(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        selected = slice(*a)
        try:
            while True:
                got = yield self(got)[selected]
        except StopIteration:
            pass

    async def aindex(self, selected: Typing.Union[int, slice]):
        """
        Yields the ``selected`` index of each result produced by the
        underlying Comprende async generator.
        """
        got = None
        while True:
            got = yield (await self(got))[selected]

    def index(self, selected: Typing.Union[int, slice]):
        """
        Yields the ``selected`` index of each result produced by the
        underlying Comprende sync generator.
        """
        got = None
        try:
            while True:
                got = yield self(got)[selected]
        except StopIteration:
            pass

    async def astr(self, *a, **kw):
        """
        Applies ``builtins.str(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        while True:
            got = yield str(await self(got), *a, **kw)

    def str(self, *a, **kw):
        """
        Applies ``builtins.str()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        _str = builtins.str
        try:
            while True:
                got = yield _str(self(got), *a, **kw)
        except StopIteration:
            pass

    async def asplit(self, *a, **kw):
        """
        Applies ``value.split()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        while True:
            got = yield (await self(got)).split(*a, **kw)

    def split(self, *a, **kw):
        """
        Applies ``value.split()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                yield self(got).split(*a, **kw)
        except StopIteration:
            pass

    async def areplace(self, *a, **kw):
        """
        Applies ``value.replace()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        while True:
            got = yield (await self(got)).replace(*a, **kw)

    def replace(self, *a, **kw):
        """
        Applies ``value.replace()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield self(got).replace(*a, **kw)
        except StopIteration:
            pass

    async def aencode(self, *a, **kw):
        """
        Applies ``value.encode()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        while True:
            got = yield (await self(got)).encode(*a, **kw)

    def encode(self, *a, **kw):
        """
        Applies ``value.encode()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield self(got).encode(*a, **kw)
        except StopIteration:
            pass

    async def adecode(self, *a, **kw):
        """
        Applies ``value.decode()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        while True:
            got = yield (await self(got)).decode(*a, **kw)

    def decode(self, *a, **kw):
        """
        Applies ``value.decode()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield self(got).decode(*a, **kw)
        except StopIteration:
            pass

    async def ajson_loads(self, *a, **kw):
        """
        Applies ``json.loads()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        while True:
            got = yield json.loads(await self(got), *a, **kw)

    def json_loads(self, *a, **kw):
        """
        Applies ``json.loads()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield json.loads(self(got), *a, **kw)
        except StopIteration:
            pass

    async def ajson_dumps(self, *a, **kw):
        """
        Applies ``json.dumps()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        while True:
            got = yield json.dumps(await self(got), *a, **kw)

    def json_dumps(self, *a, **kw):
        """
        Applies ``json.dumps()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield json.dumps(self(got), *a, **kw)
        except StopIteration:
            pass

    async def abin(self, *a, **kw):
        """
        Applies ``builtins.bin()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        while True:
            got = yield bin(await self(got), *a, **kw)[2:]

    def bin(self, *a, **kw):
        """
        Applies ``builtins.bin()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        _bin = builtins.bin
        try:
            while True:
                got = yield _bin(self(got), *a, **kw)[2:]
        except StopIteration:
            pass

    async def aoct(self, *a, **kw):
        """
        Applies ``builtins.bin()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        while True:
            got = yield oct(await self(got), *a, **kw)[2:]

    def oct(self, *a, **kw):
        """
        Applies ``builtins.bin()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        _oct = builtins.oct
        try:
            while True:
                got = yield _oct(self(got), *a, **kw)[2:]
        except StopIteration:
            pass

    async def ahex(self, prefix: bool = False):
        """
        Applies ``builtins.hex()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        start = 0 if prefix else 2
        while True:
            got = yield hex(await self(got))[start:]

    def hex(self, prefix: bool = False):
        """
        Applies ``builtins.hex()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        _hex = builtins.hex
        start = 0 if prefix else 2
        try:
            while True:
                got = yield _hex(self(got))[start:]
        except StopIteration:
            pass

    async def abytes(self, *a, **kw):
        """
        Applies ``builtins.bytes()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        while True:
            got = yield bytes(await self(got), *a, **kw)

    def bytes(self, *a, **kw):
        """
        Applies ``builtins.bytes()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        _bytes = builtins.bytes
        try:
            while True:
                got = yield _bytes(self(got), *a, **kw)
        except StopIteration:
            pass

    for method in lazy_generators.union(eager_generators):
        vars()[method] = comprehension(chained=True)(vars()[method])
    del method


class Domains:
    """
    A collection of encoded constants which can augment function inputs
    to make their outputs domain specific.
    """

    __slots__ = ()

    @staticmethod
    async def aencode_constant(constant: Typing.AnyStr):
        """
        Receives a bytes-type ``constant``, hashes it under a domain which
        is specific to this function, & returns a compressed 8-byte value.
        These returned values are used by the package as inputs to other
        functions which in turn makes their outputs domain-specific. This
        has various security benefits such as:

        https://eprint.iacr.org/2010/264.pdf
        & more recent published works show schemes which are not provably
        secure, may be transformable into provably secure schemes just with
        some assumptions that certain functions which they rely happen to be
        domain-specific.
        """
        await asleep()
        if constant.__class__ is not bytes:
            constant = constant.encode()
        hashed_constant = await ahash_bytes(b"encoded_constant:", constant)
        return await axi_mix(hashed_constant, size=8)

    @staticmethod
    def encode_constant(constant: Typing.AnyStr):
        """
        Receives a bytes-type ``constant``, hashes it under a domain which
        is specific to this function, & returns a compressed 8-byte value.
        These returned values are used by the package as inputs to other
        functions which in turn makes their outputs domain-specific. This
        has various security benefits such as:

        https://eprint.iacr.org/2010/264.pdf
        & more recent published works show schemes which are not provably
        secure, may be transformable into provably secure schemes just with
        some assumptions that certain functions which they rely happen to be
        domain-specific.
        """
        if constant.__class__ is not bytes:
            constant = constant.encode()
        hashed_constant = hash_bytes(b"encoded_constant:", constant)
        return xi_mix(hashed_constant, size=8)

    _encode = encode_constant.__func__

    DH2: bytes = _encode(DH2)
    DH3: bytes = _encode(DH3)
    KDF: bytes = _encode(KDF)
    SIV: bytes = _encode(SIV)
    HMAC: bytes = _encode(HMAC)
    SEED: bytes = _encode(SEED)
    SALT: bytes = _encode(SALT)
    UUID: bytes = _encode(UUID)
    SHMAC: bytes = _encode(SHMAC)
    TOKEN: bytes = _encode(TOKEN)
    KEY_ID: bytes = _encode(KEY_ID)
    DIGEST: bytes = _encode(DIGEST)
    PAYLOAD: bytes = _encode(PAYLOAD)
    METATAG: bytes = _encode(METATAG)
    SIV_KEY: bytes = _encode(SIV_KEY)
    ENTROPY: bytes = _encode(ENTROPY)
    EQUALITY: bytes = _encode(EQUALITY)
    MANIFEST: bytes = _encode(MANIFEST)
    BLOCK_ID: bytes = _encode(BLOCK_ID)
    FILENAME: bytes = _encode(FILENAME)
    FILE_KEY: bytes = _encode(FILE_KEY)
    PASSCRYPT: bytes = _encode(PASSCRYPT)
    KEYSTREAM: bytes = _encode(KEYSTREAM)
    CLIENT_ID: bytes = _encode(CLIENT_ID)
    MESSAGE_ID: bytes = _encode(MESSAGE_ID)
    CHUNKY_2048: bytes = _encode(CHUNKY_2048)
    METATAG_KEY: bytes = _encode(METATAG_KEY)
    MESSAGE_KEY: bytes = _encode(MESSAGE_KEY)
    PADDING_KEY: bytes = _encode(PADDING_KEY)
    SESSION_KEY: bytes = _encode(SESSION_KEY)
    CLIENT_INDEX: bytes = _encode(CLIENT_INDEX)
    REGISTRATION: bytes = _encode(REGISTRATION)
    SENDING_COUNT: bytes = _encode(SENDING_COUNT)
    DIFFIE_HELLMAN: bytes = _encode(DIFFIE_HELLMAN)
    AUTHENTICATION: bytes = _encode(AUTHENTICATION)
    SECURE_CHANNEL: bytes = _encode(SECURE_CHANNEL)
    SENDING_STREAM: bytes = _encode(SENDING_STREAM)
    RECEIVING_COUNT: bytes = _encode(RECEIVING_COUNT)
    RECEIVING_STREAM: bytes = _encode(RECEIVING_STREAM)
    CLIENT_MESSAGE_KEY: bytes = _encode(CLIENT_MESSAGE_KEY)
    SERVER_MESSAGE_KEY: bytes = _encode(SERVER_MESSAGE_KEY)
    EXTENDED_DH_EXCHANGE: bytes = _encode(EXTENDED_DH_EXCHANGE)


async def amake_timestamp(
    *, width: int = TIMESTAMP_BYTES, byteorder: str = "big"
):
    """
    Returns a ``width`` length byte sequence representation of the
    current time in seconds.
    """
    await asleep()
    return this_second().to_bytes(width, byteorder)


def make_timestamp(*, width: int = TIMESTAMP_BYTES, byteorder: str = "big"):
    """
    Returns a ``width`` length byte sequence representation of the
    current time in seconds.
    """
    return this_second().to_bytes(width, byteorder)


async def atimestamp_ttl_delta(timestamp: bytes, ttl: int):
    """
    Takes a ``timestamp`` & returns the difference between now & the
    timestamp & the ``ttl`` time-to-live limit. If the result is
    positive, then the elapsed time from the timestamp has exceeded the
    ttl limit.
    """
    delta = this_second() - int.from_bytes(timestamp, "big")
    return delta - ttl


def timestamp_ttl_delta(timestamp: bytes, ttl: int):
    """
    Takes a ``timestamp`` & returns the difference between now & the
    timestamp & the ``ttl`` time-to-live limit. If the result is
    positive, then the elapsed time from the timestamp has exceeded the
    ttl limit.
    """
    delta = this_second() - int.from_bytes(timestamp, "big")
    return delta - ttl


async def atest_timestamp(timestamp: bytes, ttl: int):
    """
    Raises ``ValueError`` if ``timestamp`` is more than ``ttl`` seconds
    from the current time.
    """
    is_invalid_timestamp_length = len(timestamp) != TIMESTAMP_BYTES
    seconds = timespan = await atimestamp_ttl_delta(timestamp, ttl)
    timestamp_is_expired = timespan > 0
    await asleep()
    if is_invalid_timestamp_length:
        raise PlaintextIssue.invalid_timestamp_format()
    elif not ttl:
        return
    elif timestamp_is_expired:
        error = PlaintextIssue.timestamp_expired(seconds)
        error.seconds_expired = seconds
        raise error


def test_timestamp(timestamp: bytes, ttl: int):
    """
    Raises ``ValueError`` if ``timestamp`` is more than ``ttl`` seconds
    from the current time.
    """
    is_invalid_timestamp_length = len(timestamp) != TIMESTAMP_BYTES
    seconds = timespan = timestamp_ttl_delta(timestamp, ttl)
    timestamp_is_expired = timespan > 0
    if is_invalid_timestamp_length:
        raise PlaintextIssue.invalid_timestamp_format()
    elif not ttl:
        return
    elif timestamp_is_expired:
        error = PlaintextIssue.timestamp_expired(seconds)
        error.seconds_expired = seconds
        raise error


class Padding:
    """
    Manages the padding of plaintext with various values that improve
    the package's online / offline AEAD cipher security & converts it
    into an MRAE scheme.

    Padding Diagram:
     _________________________________________________________________
    |          Inner-Header           |     Body    |      Footer     |
    | timestamp |       SIV-key       |  plaintext  |     padding     |
    |  8-bytes  |      16-bytes       |   X-bytes   |     Y-bytes     |

    ``timestamp``: An 8-byte timestamp which aids in salt reuse / misuse
        resistance & can mitigate replay attacks.

    ``SIV-key``: A 16-byte ephemeral & random key which aids in salt
        reuse / misuse resistance.

    ``Footer``: 32 pseudo-random bytes derived from a cipher rounds'
        particular `key`, `salt` & `aad` as well as OS randomness. Y has
        four categories of potential sizes:
        When Y == 0-bytes:
            Y can be 0-bytes if the inner-header + body is exactly a
            multiple of the 256-byte blocksize.
        When Y == 256-bytes:
            Y can be 256-bytes when the plaintext X contains no data.
        When 32 <= Y < 256:
            Y can be 32-bytes or more, but less than 256, if the inner-
            header + body is at least 32 bytes less than a multiple of
            the 256-byte blocksize.
        When Y == 256 + ε and 0 < ε < 32:
            Y can be greater than 256 but less than 256 + 32-bytes if
            the inner-header + body leaves less than 32 bytes before
            reaching a multiple of the 256-byte blocksize.
        These rules ensure the padding can reliably be removed after
        decryption since it either doesn't exist or has at least 32 key-
        dependant, unique, pseudo-random, searchable bytes.
    """

    __slots__ = ()

    _BLOCKSIZE: int = BLOCKSIZE
    _TWO_BLOCKS: int = 2 * BLOCKSIZE
    _EXTRA_PADDING_BYTES: int = BLOCKSIZE
    _PADDING_KEY_BYTES: int = PADDING_KEY_BYTES
    _SIV_KEY_BYTES: int = SIV_KEY_BYTES
    _TIMESTAMP_BYTES: int = TIMESTAMP_BYTES
    _INNER_HEADER_BYTES: int = INNER_HEADER_BYTES
    _INNER_HEADER_SLICE: int = INNER_HEADER_SLICE

    amake_timestamp = staticmethod(amake_timestamp)
    atest_timestamp = staticmethod(atest_timestamp)
    make_timestamp = staticmethod(make_timestamp)
    test_timestamp = staticmethod(test_timestamp)

    @classmethod
    async def amake_siv_key(cls):
        """
        Returns a 16-byte SIV-key to be prepended to some data bytes.
        """
        await asleep()
        return secrets.token_bytes(cls._SIV_KEY_BYTES)

    @classmethod
    def make_siv_key(cls):
        """
        Returns a 16-byte SIV-key to be prepended to some data bytes.
        """
        return secrets.token_bytes(cls._SIV_KEY_BYTES)

    @classmethod
    async def astart_padding(cls):
        """
        Returns a 24-byte value which when prepended to plaintext will
        improve the `Chunky2048` AEAD cipher's security & converts it
        into an MRAE scheme.

        Returns the 8-byte timestamp & a 16-byte random & ephemeral SIV-
        key. The timestamp allows a time-to-live feature to exist for
        all ciphertexts, aiding replay attack resistance. It also,
        along with the SIV-key, ensures that the synthetic IV, which is
        derived from the keyed-hash of the first plaintext block, is
        globally unique. The SIV therefore makes the keystream &
        resulting ciphertext globally unique & salt reuse / misuse
        resistant.
        """
        return await cls.amake_timestamp() + await cls.amake_siv_key()

    @classmethod
    def start_padding(cls):
        """
        Returns a 24-byte value which when prepended to plaintext will
        improve the `Chunky2048` AEAD cipher's security & converts it
        into an MRAE scheme.

        Returns the 8-byte timestamp & a 16-byte random & ephemeral SIV-
        key. The timestamp allows a time-to-live feature to exist for
        all ciphertexts, aiding replay attack resistance. It also,
        along with the SIV-key, ensures that the synthetic IV, which is
        derived from the keyed-hash of the first plaintext block, is
        globally unique. The SIV therefore makes the keystream &
        resulting ciphertext globally unique & salt reuse / misuse
        resistant.
        """
        return cls.make_timestamp() + cls.make_siv_key()

    @classmethod
    async def _adata_measurements(cls, length: int):
        """
        Does padding measurements based on the ``length`` of some
        unpadded data & stores the findings in an object for convenient
        usage.
        """
        await asleep()
        remainder = (length + cls._INNER_HEADER_BYTES) % cls._BLOCKSIZE
        padding_size = cls._BLOCKSIZE - remainder
        return PlaintextMeasurements(
            length=length,
            remainder=remainder,
            padding_size=padding_size,
            no_padding_required=data and not remainder,
            padding_sentinel_fits=padding_size >= 32,
        )

    @classmethod
    def _data_measurements(cls, length: int):
        """
        Does padding measurements based on the ``length`` of some
        unpadded data & stores the findings in an object for convenient
        usage.
        """
        remainder = (length + cls._INNER_HEADER_BYTES) % cls._BLOCKSIZE
        padding_size = cls._BLOCKSIZE - remainder
        return PlaintextMeasurements(
            length=length,
            remainder=remainder,
            padding_size=padding_size,
            no_padding_required=data and not remainder,
            padding_sentinel_fits=padding_size >= 32,
        )

    @classmethod
    async def _amake_extra_padding(cls):
        """
        Returns a number of random bytes equal to the length of a block.

        These bytes provide a kind of deniability, where an adversary
        with even unlimited computational capability can't distinguish
        between all possible legitimate plaintexts. This is because
        there are enough random padding degrees of freedom (between 0 &
        255 bytes) for such an adversary to create an exponentially
        large number of plaintexts which appear legitimate under any key
        (satisfy verification tags) & appear plausible (they can be made
        to be almost any message + random padding).

        This deniability doesn't apply when the plaintext is already
        known by an adversary.
        """
        await asleep()
        return secrets.token_bytes(cls._EXTRA_PADDING_BYTES)

    @classmethod
    def _make_extra_padding(cls):
        """
        Returns a number of random bytes equal to the length of a block.

        These bytes provide a kind of deniability, where an adversary
        with even unlimited computational capability can't distinguish
        between all possible legitimate plaintexts. This is because
        there are enough random padding degrees of freedom (between 0 &
        255 bytes) for such an adversary to create an exponentially
        large number of plaintexts which appear legitimate under any key
        (satisfy verification tags) & appear plausible (they can be made
        to be almost any message + random padding).

        This deniability doesn't apply when the plaintext is already
        known by an adversary.
        """
        return secrets.token_bytes(cls._EXTRA_PADDING_BYTES)

    @classmethod
    async def _amake_end_padding(cls, key_bundle):
        """
        Returns 32 bytes of keyed padding, & 256 bytes of random padding.
        """
        key_bundle._mode.validate()
        keyed_padding = key_bundle._padding_key
        extra_padding = await cls._amake_extra_padding()
        return keyed_padding + extra_padding

    @classmethod
    def _make_end_padding(cls, key_bundle):
        """
        Returns 32 bytes of keyed padding, & 256 bytes of random padding.
        """
        key_bundle._mode.validate()
        keyed_padding = key_bundle._padding_key
        extra_padding = cls._make_extra_padding()
        return keyed_padding + extra_padding

    @classmethod
    async def aend_padding(cls, data: bytes, key_bundle):
        """
        Returns the padding bytes that are to be appended to the end of
        some unpadded ``data``.

        The returned bytes incluce a padding key which aids against
        padding oracle attacks. The padding key is derived from the
        user's `key`, `salt` & `aad` values. The final random padding
        will make the ``data``, when prepended with the 24-byte start
        padding, a multiple of 256 bytes.
        """
        report = await cls._adata_measurements(len(data))
        padding = await cls._amake_end_padding(key_bundle)
        if report.no_padding_required:
            padding_slice = slice(0)
        elif report.padding_sentinel_fits:
            padding_slice = slice(report.padding_size)
        else:
            padding_slice = slice(report.padding_size + cls._BLOCKSIZE)
        return padding[padding_slice]

    @classmethod
    def end_padding(cls, data: bytes, key_bundle):
        """
        Returns the padding bytes that are to be appended to the end of
        some unpadded ``data``.

        The returned bytes incluce a padding key which aids against
        padding oracle attacks. The padding key is derived from the
        user's `key`, `salt` & `aad` values. The final random padding
        will make the ``data``, when prepended with the 24-byte start
        padding, a multiple of 256 bytes.
        """
        report = cls._data_measurements(len(data))
        padding = cls._make_end_padding(key_bundle)
        if report.no_padding_required:
            padding_slice = slice(0)
        elif report.padding_sentinel_fits:
            padding_slice = slice(report.padding_size)
        else:
            padding_slice = slice(report.padding_size + cls._BLOCKSIZE)
        return padding[padding_slice]

    @classmethod
    async def adepadding_start_index(cls, data: bytes, *, ttl: int = 0):
        """
        Returns a start index which is used to slice off the following
        values from some plaintext ``data``:
        - The prepended 8-byte timestamp.
        - The prepended 16 byte SIV-key.
        """
        await atest_timestamp(data[TIMESTAMP_SLICE], ttl)
        return cls._INNER_HEADER_BYTES

    @classmethod
    def depadding_start_index(cls, data: bytes, *, ttl: int = 0):
        """
        Returns a start index which is used to slice off the following
        values from some plaintext ``data``:
        - The prepended 8-byte timestamp.
        - The prepended 16 byte SIV-key.
        """
        test_timestamp(data[TIMESTAMP_SLICE], ttl)
        return cls._INNER_HEADER_BYTES

    @classmethod
    async def adepadding_end_index(cls, data: bytes, key_bundle):
        """
        Returns an end index which is used to slice off the following
        values from some plaintext ``data``:
        - The appended 32-byte padding key.
        - The random padding bytes appended after the padding key.
        """
        key_bundle._mode.validate()
        key = key_bundle._padding_key
        index = data[:-cls._TWO_BLOCKS:-1].find(key[::-1])
        if index == -1:
            return None
        else:
            return -index - len(key)

    @classmethod
    def depadding_end_index(cls, data: bytes, key_bundle):
        """
        Returns an end index which is used to slice off the following
        values from some plaintext ``data``:
        - The appended 32-byte padding key.
        - The random padding bytes appended after the padding key.
        """
        key_bundle._mode.validate()
        key = key_bundle._padding_key
        index = data[:-cls._TWO_BLOCKS:-1].find(key[::-1])
        if index == -1:
            return None
        else:
            return -index - len(key)

    @classmethod
    async def apad_plaintext(cls, data: bytes, key_bundle):
        """
        Pads & returns a plaintext ``data`` with various values that
        improve the package's AEAD cipher security & converts it into an
        MRAE scheme.

        Prepends an 8-byte timestamp & a 16-byte random & ephemeral SIV-
        key to ``data``. The timestamp allows a time-to-live feature to
        exist for all ciphertexts, aiding replay attack resistance. It
        also, along with the SIV-key, ensures that the synthetic IV,
        which is derived from the keyed-hash of the first plaintext
        block, is globally unique. The SIV therefore makes the keystream
        & resulting ciphertext globally unique & salt reuse / misuse
        resistant.

        Also, appends 32-byte padding key. The padding key is derived
        from a hash of the `key`, `salt` & `aad` values. An amount of
        additional random padding will be appended to make the plaintext
        a multiple of 256 bytes.
        """
        start_padding = await cls.astart_padding()
        end_padding = await cls.aend_padding(data, key_bundle)
        return b"".join((start_padding, data, end_padding))

    @classmethod
    def pad_plaintext(cls, data: bytes, key_bundle):
        """
        Pads & returns a plaintext ``data`` with various values that
        improve the package's AEAD cipher security & converts it into an
        MRAE scheme.

        Prepends an 8-byte timestamp & a 16-byte random & ephemeral SIV-
        key to ``data``. The timestamp allows a time-to-live feature to
        exist for all ciphertexts, aiding replay attack resistance. It
        also, along with the SIV-key, ensures that the synthetic IV,
        which is derived from the keyed-hash of the first plaintext
        block, is globally unique. The SIV therefore makes the keystream
        & resulting ciphertext globally unique & salt reuse / misuse
        resistant.

        Also, appends 32-byte padding key. The padding key is derived
        from a hash of the `key`, `salt` & `aad` values. An amount of
        additional random padding will be appended to make the plaintext
        a multiple of 256 bytes.
        """
        start_padding = cls.start_padding()
        end_padding = cls.end_padding(data, key_bundle)
        return b"".join((start_padding, data, end_padding))

    @classmethod
    async def adepad_plaintext(
        cls, data: bytes, key_bundle, *, ttl: int = 0
    ):
        """
        Returns ``data`` after these values are removed:
        - The prepended 8-byte timestamp.
        - The prepended 16-byte SIV-key.
        - The appended 32-byte padding key.
        - The appended 0-255-byte random padding.
        """
        start_index = await cls.adepadding_start_index(data, ttl=ttl)
        end_index = await cls.adepadding_end_index(data, key_bundle)
        return data[start_index:end_index]

    @classmethod
    def depad_plaintext(cls, data: bytes, key_bundle, *, ttl: int = 0):
        """
        Returns ``data`` after these values are removed:
        - The prepended 8-byte timestamp.
        - The prepended 16-byte SIV-key.
        - The appended 32-byte padding key.
        - The appended 0-255-byte random padding.
        """
        start_index = cls.depadding_start_index(data, ttl=ttl)
        end_index = cls.depadding_end_index(data, key_bundle)
        return data[start_index:end_index]


class BytesIO:
    """
    A utility class for converting bytes ciphertext to & from different
    formats & provides an interface for reading/writing bytes ciphertext
    to & from files.
    """

    __slots__ = ()

    _CIPHERTEXT: str = CIPHERTEXT
    _HMAC: str = HMAC
    _SALT: str = SALT
    _SIV: str = SIV
    _EQUAL_SIGN: bytes = b"%3D"
    _BLOCKSIZE: int = BLOCKSIZE
    _HEADER_BYTES: int = HEADER_BYTES

    @classmethod
    def _validate_ciphertext_length(cls, ciphertext: bytes):
        """
        Measures the length of a blob of bytes ciphertext that has its
        salt & hmac attached. If it doesn't conform to the standard then
        raises ValueError. If the ``ciphertext`` that's passed isn't of
        bytes type then ``TypeErrpr`` is raised.
        """
        size = len(ciphertext) - cls._HEADER_BYTES
        if ciphertext.__class__ is not bytes:
            raise Issue.value_must_be_type("ciphertext", bytes)
        elif size <= 0 or size % cls._BLOCKSIZE:
            raise CiphertextIssue.invalid_ciphertext_length(len(ciphertext))

    @classmethod
    async def _aprocess_json_to_bytes(cls, data: Typing.JSONCiphertext):
        """
        Converts JSON formatted `Chunky2048` ciphertext into bytes
        values that are yielded one logical piece at a time.
        """
        data = JSONCiphertext(data)
        BLOCKSIZE = cls._BLOCKSIZE
        yield bytes.fromhex(data.hmac)
        yield bytes.fromhex(data.salt)
        yield bytes.fromhex(data.synthetic_iv)
        for chunk in data.ciphertext:
            await asleep()
            yield chunk.to_bytes(BLOCKSIZE, "big")

    @classmethod
    def _process_json_to_bytes(cls, data: Typing.JSONCiphertext):
        """
        Converts JSON formatted `Chunky2048` ciphertext into bytes
        values that are yielded one logical piece at a time.
        """
        data = JSONCiphertext(data)
        BLOCKSIZE = cls._BLOCKSIZE
        yield bytes.fromhex(data.hmac)
        yield bytes.fromhex(data.salt)
        yield bytes.fromhex(data.synthetic_iv)
        for chunk in data.ciphertext:
            yield chunk.to_bytes(BLOCKSIZE, "big")

    @classmethod
    async def ajson_to_bytes(cls, data: Typing.JSONCiphertext):
        """
        Converts JSON ``data`` of dict ciphertext into a bytes object.
        """
        data = b"".join(
            [block async for block in cls._aprocess_json_to_bytes(data)]
        )
        cls._validate_ciphertext_length(data)
        return data

    @classmethod
    def json_to_bytes(cls, data: Typing.JSONCiphertext):
        """
        Converts JSON ``data`` of dict ciphertext into a bytes object.
        """
        data = b"".join(cls._process_json_to_bytes(data))
        cls._validate_ciphertext_length(data)
        return data

    @classmethod
    async def _aprocess_bytes_to_json(cls, data: bytes):
        """
        Takes in bytes ``data`` for initial processing. Returns a
        namespace populated with the discovered ciphertext values.
        """
        to_int = int.from_bytes
        cls._validate_ciphertext_length(data)
        yield data[HMAC_SLICE].hex()
        yield data[SALT_SLICE].hex()
        yield data[SIV_SLICE].hex()
        async for block in adata.root(data[CIPHERTEXT_SLICE]):
            yield to_int(block, "big")

    @classmethod
    def _process_bytes_to_json(cls, data: bytes):
        """
        Takes in bytes ``data`` for initial processing. Returns a
        namespace populated with the discovered ciphertext values.
        """
        to_int = int.from_bytes
        cls._validate_ciphertext_length(data)
        yield data[HMAC_SLICE].hex()
        yield data[SALT_SLICE].hex()
        yield data[SIV_SLICE].hex()
        for block in gentools.data.root(data[CIPHERTEXT_SLICE]):
            yield to_int(block, "big")

    @classmethod
    async def abytes_to_json(cls, data: bytes):
        """
        Converts bytes ``data`` ciphertext into a JSON ready dictionary.
        """
        data = cls._aprocess_bytes_to_json(data)
        return {
            cls._HMAC: await data.asend(None),
            cls._SALT: await data.asend(None),
            cls._SIV: await data.asend(None),
            cls._CIPHERTEXT: [block async for block in data],
        }

    @classmethod
    def bytes_to_json(cls, data: bytes):
        """
        Converts bytes ``data`` ciphertext into a JSON ready dictionary.
        """
        data = cls._process_bytes_to_json(data)
        return {
            cls._HMAC: data.send(None),
            cls._SALT: data.send(None),
            cls._SIV: data.send(None),
            cls._CIPHERTEXT: [*data],
        }

    @classmethod
    async def abytes_to_urlsafe(cls, byte_string: bytes):
        """
        Turns a ``byte_string`` into a url safe string derived from the
        given ``table``.
        """
        await asleep()
        urlsafe_token = base64.urlsafe_b64encode(byte_string)
        await asleep()
        return urlsafe_token.replace(b"=", cls._EQUAL_SIGN)

    @classmethod
    def bytes_to_urlsafe(cls, byte_string: bytes):
        """
        Turns a ``byte_string`` into a url safe string derived from the
        given ``table``.
        """
        urlsafe_token = base64.urlsafe_b64encode(byte_string)
        return urlsafe_token.replace(b"=", cls._EQUAL_SIGN)

    @classmethod
    async def aurlsafe_to_bytes(cls, token: bytes):
        """
        Turns a url safe ``token`` into a bytes type string.
        """
        await asleep()
        EQUAL_SIGN = cls._EQUAL_SIGN
        return base64.urlsafe_b64decode(token.replace(EQUAL_SIGN, b"="))

    @classmethod
    def urlsafe_to_bytes(cls, token: bytes):
        """
        Turns a url safe ``token`` into a bytes type string.
        """
        EQUAL_SIGN = cls._EQUAL_SIGN
        return base64.urlsafe_b64decode(token.replace(EQUAL_SIGN, b"="))

    @classmethod
    async def aread(cls, path: Typing.PathStr):
        """
        Reads the bytes ciphertext file at ``path``.
        """
        async with aiofiles.open(path, "rb") as f:
            return await f.read()

    @classmethod
    def read(cls, path: Typing.PathStr):
        """
        Reads the bytes ciphertext file at ``path``.
        """
        with open(path, "rb") as f:
            return f.read()

    @classmethod
    async def awrite(cls, path: Typing.PathStr, ciphertext: bytes):
        """
        Writes bytes ``ciphertext`` to a bytes file at ``path``.
        """
        async with aiofiles.open(path, "wb+") as f:
            await f.write(ciphertext)

    @classmethod
    def write(cls, path: Typing.PathStr, ciphertext: bytes):
        """
        Writes bytes ``ciphertext`` to a bytes file at ``path``.
        """
        with open(path, "wb+") as f:
            f.write(ciphertext)


gentools = OpenNamespace(
    BaseComprende=BaseComprende,
    Comprende=Comprende,
    Enumerate=Enumerate,
    abirth=abirth,
    abytes_count=abytes_count,
    abytes_range=abytes_range,
    acompact=acompact,
    acount=acount,
    acycle=acycle,
    adata=adata,
    aecho=aecho,
    aorder=aorder,
    apick=apick,
    apop=apop,
    apopleft=apopleft,
    arange=arange,
    areader=areader,
    askip=askip,
    aunpack=aunpack,
    await_on=await_on,
    azip=azip,
    birth=birth,
    bytes_count=bytes_count,
    bytes_range=bytes_range,
    compact=compact,
    comprehension=comprehension,
    count=count,
    cycle=cycle,
    data=data,
    echo=echo,
    order=order,
    pick=pick,
    pop=pop,
    popleft=popleft,
    range=_range,
    reader=reader,
    skip=skip,
    unpack=unpack,
    wait_on=wait_on,
    zip=_zip,
)


extras = dict(
    BytesIO=BytesIO,
    Domains=Domains,
    Hasher=Hasher,
    Padding=Padding,
    __doc__=__doc__,
    __main_exports__=__all__,
    __package__=__package__,
    abase_to_int=abase_to_int,
    abytes_are_equal=abytes_are_equal,
    afrom_base64=afrom_base64,
    ahash_bytes=ahash_bytes,
    aignore=aignore,
    aint_to_base=aint_to_base,
    alru_cache=alru_cache,
    amake_timestamp=amake_timestamp,
    anext=anext,
    arightmost_bit=arightmost_bit,
    asha3__256=asha3__256,
    asha3__256_hmac=asha3__256_hmac,
    asha3__512=asha3__512,
    asha3__512_hmac=asha3__512_hmac,
    async_contextmanager=async_contextmanager,
    ato_base64=ato_base64,
    axi_mix=axi_mix,
    base64=base64,
    base_to_int=base_to_int,
    bytes_are_equal=bytes_are_equal,
    from_base64=from_base64,
    hash_bytes=hash_bytes,
    ignore=ignore,
    int_to_base=int_to_base,
    is_async_function=is_async_function,
    is_async_gen_function=is_async_gen_function,
    is_async_generator=is_async_generator,
    is_async_iterable=is_async_iterable,
    is_async_iterator=is_async_iterator,
    is_awaitable=is_awaitable,
    is_exception=is_exception,
    is_generator=is_generator,
    is_generator_function=is_generator_function,
    is_iterable=is_iterable,
    is_iterator=is_iterator,
    json=json,
    lru_cache=lru_cache,
    make_timestamp=make_timestamp,
    rightmost_bit=rightmost_bit,
    sha3__256=sha3__256,
    sha3__256_hmac=sha3__256_hmac,
    sha3__512=sha3__512,
    sha3__512_hmac=sha3__512_hmac,
    size_of=size_of,
    src=src,
    to_base64=to_base64,
    xi_mix=xi_mix,
)


generics = commons.make_module("generics", mapping=extras)

