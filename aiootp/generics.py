# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "generics",
    "json",
    "BytesIO",
    "Comprende",
    "Hasher",
    "comprehension",
    "azip",
    "anext",
    "arange",
    "aunpack",
    "unpack",
    "abirth",
    "birth",
    "adata",
    "data",
    "aorder",
    "order",
    "apick",
    "pick",
    "acycle",
    "cycle",
    "acount",
    "count",
    "apop",
    "pop",
    "apopleft",
    "popleft",
    "await_on",
    "wait_on",
    "apad_bytes",
    "pad_bytes",
    "adepad_bytes",
    "depad_bytes",
    "asha_256",
    "sha_256",
    "asha_256_hmac",
    "sha_256_hmac",
    "asha_512",
    "sha_512",
    "asha_512_hmac",
    "sha_512_hmac",
]


__doc__ = """
A collection of basic utilities for simplifying & supporting the rest of
the codebase.
"""


import math
import json
import heapq
import base64
import random
import secrets
import aiofiles
import builtins
from os import linesep
from sys import getsizeof
from functools import wraps
from functools import lru_cache
from async_lru import alru_cache
from types import GeneratorType
from types import AsyncGeneratorType
from random import uniform
from contextlib import contextmanager
from hashlib import sha3_256
from hashlib import sha3_512
from hashlib import shake_256
from collections import deque
from collections.abc import Iterable
from collections.abc import Iterator
from collections.abc import AsyncIterable
from collections.abc import AsyncIterator
from inspect import getsource
from inspect import isawaitable as is_awaitable
from inspect import iscoroutinefunction as is_async_function
from inspect import isasyncgenfunction as is_async_gen_function
from inspect import isgeneratorfunction as is_generator_function
from .__aiocontext import async_contextmanager
from .commons import *
from .commons import BasePrimeGroups
from .asynchs import *
from .asynchs import time
from .asynchs import this_second
from . import DebugControl


def src(obj, display=True):
    """
    Prints the source code of an object to the screen or, if ``display``
    is toggled to a falsey value, returns the source code instead.
    """
    if display:
        print(getsource(obj))
    else:
        return getsource(obj)


def size_of(obj, display=False):
    """
    Returns the memory size of an object `data` in bytes.
    """
    if not display:
        return getsizeof(obj)
    else:
        print(getsizeof(obj))


class AsyncInit(type):
    """
    A metaclass that allows classes to use asynchronous ``__init__``
    methods. Inspired by David Beazley.
    """

    async def __call__(cls, *args, **kwargs):
        self = cls.__new__(cls, *args, **kwargs)
        await self.__init__(*args, **kwargs)
        return self


class Enumerate:
    """
    An ``enumerate`` variant that supports sync & async generators.
    """

    __slots__ = ["gen", "start"]

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
                await asleep(0)
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


def convert_static_method_to_member(
    self, static_method_name, static_method, *args, **kwargs
):
    """
    Overwrites a static method, or sets a free function, as an object's
    member function with the option to insert custom parameters to the
    function.
    """

    @wraps(static_method)
    def wrapped_static_method(*a, **kw):
        """
        Replaces the parameters to the static method or free function
        being turned into a member function of an object.
        """
        new_args = list(args)
        new_args[: len(a)] = a[:]
        new_kwargs = {**kwargs, **kw}
        return static_method(*new_args, **new_kwargs)

    setattr(self, static_method_name, wrapped_static_method)


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


class AsyncRelayExceptions:
    __slots__ = ["aexcept_code", "afinally_code"]

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
    __slots__ = ["except_code", "finally_code"]

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
        await asleep(0)
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


async def acheck_timestamp(timestamp, ttl):
    """
    Raises ``ValueError`` if ``timestamp`` is more than ``ttl`` seconds
    from the current time.
    """
    is_invalid_timestamp_length = len(timestamp) != 8
    timespan = this_second() - int.from_bytes(timestamp, "big") - ttl
    timestamp_is_expired = timespan > 0
    await asleep(0)
    if is_invalid_timestamp_length:
        raise ValueError("Invalid timestamp format, must be 8 bytes long.")
    elif not ttl:
        return
    elif timestamp_is_expired:
        error = TimeoutError(f"Timestamp expired by <{timespan}> seconds.")
        error.value = timespan
        raise error


def check_timestamp(timestamp, ttl):
    """
    Raises ``ValueError`` if ``timestamp`` is more than ``ttl`` seconds
    from the current time.
    """
    is_invalid_timestamp_length = len(timestamp) != 8
    timespan = this_second() - int.from_bytes(timestamp, "big") - ttl
    timestamp_is_expired = timespan > 0
    if is_invalid_timestamp_length:
        raise ValueError("Invalid timestamp format, must be 8 bytes long.")
    elif not ttl:
        return
    elif timestamp_is_expired:
        error = TimeoutError(f"Timestamp expired by <{timespan}> seconds.")
        error.value = timespan
        raise error


async def amake_timestamp(width=8, byteorder="big"):
    """
    Returns a ``width`` length byte sequence representation of the
    current time in seconds.
    """
    await asleep(0)
    return this_second().to_bytes(width, byteorder)


def make_timestamp(width=8, byteorder="big"):
    """
    Returns a ``width`` length byte sequence representation of the
    current time in seconds.
    """
    return this_second().to_bytes(width, byteorder)


async def apad_bytes(data, *, salted_key, buffer=256):
    """
    Prepends an eight byte timestamp to ``data`` to allow a time-to-live
    feature to exist for all ciphertexts, aiding against replay attacks
    & reuse of stale authorization tokens. Appends padding bytes to
    ``data`` that are the ``shake_256`` output of an object fed a
    ``salted_key`` to aid in CCA security.
    """
    await asleep(0)
    timestamp_length = 8
    remainder = (len(data) + timestamp_length) % buffer
    padding_size = buffer - remainder
    padding = shake_256(salted_key).digest(2 * buffer)
    timestamp = await amake_timestamp()
    if data and not remainder:
        return timestamp + data
    elif padding_size >= 32:
        return timestamp + data + padding[:padding_size]
    else:
        return timestamp + data + padding[: padding_size + buffer]


def pad_bytes(data, *, salted_key, buffer=256):
    """
    Prepends an eight byte timestamp to ``data`` to allow a time-to-live
    feature to exist for all ciphertexts, aiding against replay attacks
    & reuse of stale authorization tokens. Appends padding bytes to
    ``data`` that are the ``shake_256`` output of an object fed a
    ``salted_key`` to aid in CCA security.
    """
    timestamp_length = 8
    remainder = (len(data) + timestamp_length) % buffer
    padding_size = buffer - remainder
    padding = shake_256(salted_key).digest(2 * buffer)
    timestamp = make_timestamp()
    if data and not remainder:
        return timestamp + data
    elif padding_size >= 32:
        return timestamp + data + padding[:padding_size]
    else:
        return timestamp + data + padding[: padding_size + buffer]


async def adepad_bytes(data, *, salted_key, ttl=0):
    """
    Removes from ``data`` the prepended eight byte timestamp & appended
    padding bytes that are built from the ``shake_256`` output of an
    object fed a ``salted_key``.
    """
    await acheck_timestamp(data[:8], ttl)
    padding = shake_256(salted_key).digest(32)
    padding_index = data.find(padding)
    await asleep(0)
    if padding_index == -1:
        return data[8:]
    else:
        return data[8:padding_index]


def depad_bytes(data, *, salted_key, ttl=0):
    """
    Removes from ``data`` the prepended eight byte timestamp & appended
    padding bytes that are built from the ``shake_256`` output of an
    object fed a ``salted_key``.
    """
    check_timestamp(data[:8], ttl)
    padding = shake_256(salted_key).digest(32)
    padding_index = data.find(padding)
    if padding_index == -1:
        return data[8:]
    else:
        return data[8:padding_index]


class BytesIO:
    """
    A utility class for converting json/dict ciphertext to & from bytes
    objects. Also, provides an interface for transparently writing
    ciphertext as bytes files & reading bytes ciphertext files as json
    dictionaries. This class also has access to the plaintext padding
    algorithm used by the package.
    """

    EQUAL_SIGN = b"%3D"
    HMAC = commons.HMAC
    SALT = commons.SALT
    PLAINTEXT = commons.PLAINTEXT
    CIPHERTEXT = commons.CIPHERTEXT
    HMAC_BYTES = commons.HMAC_BYTES
    SALT_BYTES = commons.SALT_BYTES
    MAP_ENCODING = commons.MAP_ENCODING
    LIST_ENCODING = commons.LIST_ENCODING
    BASE_36_TABLE = commons.BASE_36_TABLE
    URL_SAFE_TABLE = commons.URL_SAFE_TABLE
    ASCII_TABLE_128 = commons.ASCII_TABLE_128
    pad_bytes = staticmethod(pad_bytes)
    apad_bytes = staticmethod(apad_bytes)
    depad_bytes = staticmethod(depad_bytes)
    adepad_bytes = staticmethod(adepad_bytes)
    check_timestamp = staticmethod(check_timestamp)
    acheck_timestamp = staticmethod(acheck_timestamp)
    amake_timestamp = staticmethod(amake_timestamp)
    make_timestamp = staticmethod(make_timestamp)

    def __init__(self):
        pass

    @classmethod
    def _pop(cls, name, obj):
        """
        An exception-free pop from a dictionary.
        """
        if obj.get(name):
            return obj.pop(name)

    @classmethod
    def _load_json(cls, obj):
        """
        Loads a string as json or copies makes a copy of an existing
        dictionary depending on the type of ``obj``.
        """
        if not issubclass(obj.__class__, dict):
            return json.loads(obj)
        return dict(obj)

    @classmethod
    def _make_stack(cls):
        """
        Creates an empty template namespace to hold processed values to
        & from bytes ciphertext.
        """
        return Namespace(
            copy=None, result=None, hmac=None, salt=None, ciphertext=None
        )

    @classmethod
    def _process_json(cls, data):
        """
        Takes in json ``data`` for initial processing. Returns a
        namespace populated with the discovered values.
        """
        obj = cls._make_stack()
        obj.result = b""
        obj.copy = cls._load_json(data)
        obj.hmac = cls._pop(cls.HMAC, obj.copy)
        obj.salt = cls._pop(cls.SALT, obj.copy)
        obj.ciphertext = cls._pop(cls.CIPHERTEXT, obj.copy)
        return obj

    @classmethod
    def _validate_ciphertext_length(cls, ciphertext):
        """
        Measures the length of a blob of bytes ciphertext that has its
        salt & hmac attached. If it doesn't conform to the standard then
        raises ValueError. If the ``ciphertext`` that's passed isn't of
        bytes type then ``TypeErrpr`` is raised.
        """
        if not issubclass(ciphertext.__class__, bytes):
            raise TypeError(commons.CIPHERTEXT_IS_NOT_BYTES)
        elif (len(ciphertext) - cls.HMAC_BYTES - cls.SALT_BYTES) % 256:
            raise ValueError(commons.INVALID_CIPHERTEXT_LENGTH)

    @classmethod
    async def ajson_to_bytes(cls, data):
        """
        Converts json ``data`` of listed ciphertext into a bytes object.
        """
        data = cls._process_json(data)
        data.result = bytes.fromhex(data.hmac + data.salt)
        for chunk in data.ciphertext:
            await asleep(0)
            data.result += chunk.to_bytes(256, "big")
        cls._validate_ciphertext_length(data.result)
        return data.result

    @classmethod
    def json_to_bytes(cls, data):
        """
        Converts json ``data`` of listed ciphertext into a bytes object.
        """
        data = cls._process_json(data)
        data.result = bytes.fromhex(data.hmac + data.salt)
        data.result += b"".join(
            chunk.to_bytes(256, "big") for chunk in data.ciphertext
        )
        cls._validate_ciphertext_length(data.result)
        return data.result

    @classmethod
    def _process_bytes(cls, data, *, encoding=LIST_ENCODING):
        """
        Takes in bytes ``data`` for initial processing. Returns a
        namespace populated with the discovered ciphertext values.
        ``LIST_ENCODING`` is the default encoding for all ciphertext.
        Databases used to use the ``MAP_ENCODING``, but they now also
        output listed ciphertext.
        """
        cls._validate_ciphertext_length(data)
        obj = cls._make_stack()
        obj.result = {}
        obj.copy = data
        obj.hmac = data[:32]
        obj.salt = data[32:64]
        obj.ciphertext = data[64:]
        return obj

    @classmethod
    async def abytes_to_json(cls, data, *, encoding=LIST_ENCODING):
        """
        Converts bytes ``data`` of listed ciphertext back into a json
        dictionary. ``LIST_ENCODING`` is the default encoding for all
        ciphertext. Databases used to use the ``MAP_ENCODING``, but they
        now also output listed ciphertext.
        """
        streamer = adata.root
        obj = cls._process_bytes(data, encoding=encoding)
        obj.result["ciphertext"] = [
            int.from_bytes(chunk, "big")
            async for chunk in streamer(obj.ciphertext)
        ]
        obj.result["hmac"] = obj.hmac.hex()
        obj.result["salt"] = obj.salt.hex()
        return obj.result

    @classmethod
    def bytes_to_json(cls, data, *, encoding=LIST_ENCODING):
        """
        Converts bytes ``data`` of listed ciphertext back into a json
        dictionary. ``LIST_ENCODING`` is the default encoding for all
        ciphertext. Databases used to use the ``MAP_ENCODING``, but they
        now also output listed ciphertext.
        """
        streamer = generics.data.root
        obj = cls._process_bytes(data, encoding=encoding)
        obj.result["ciphertext"] = [
            int.from_bytes(chunk, "big")
            for chunk in streamer(obj.ciphertext)
        ]
        obj.result["hmac"] = obj.hmac.hex()
        obj.result["salt"] = obj.salt.hex()
        return obj.result

    @classmethod
    async def abytes_to_urlsafe(cls, byte_string):
        """
        Turns a ``bytes_string`` into a url safe string derived from the
        given ``table``.
        """
        urlsafe_token = base64.urlsafe_b64encode(byte_string)
        await asleep(0)
        return urlsafe_token.replace(b"=", cls.EQUAL_SIGN)

    @classmethod
    def bytes_to_urlsafe(cls, byte_string):
        """
        Turns a ``bytes_string`` into a url safe string derived from the
        given ``table``.
        """
        urlsafe_token = base64.urlsafe_b64encode(byte_string)
        return urlsafe_token.replace(b"=", cls.EQUAL_SIGN)

    @classmethod
    async def aurlsafe_to_bytes(cls, token):
        """
        Turns a url safe token into a bytes type string.
        """
        decoded_token = token.replace(cls.EQUAL_SIGN, b"=")
        await asleep(0)
        return base64.urlsafe_b64decode(decoded_token)

    @classmethod
    def urlsafe_to_bytes(cls, token):
        """
        Turns a url safe token into a bytes type string.
        """
        decoded_token = token.replace(cls.EQUAL_SIGN, b"=")
        return base64.urlsafe_b64decode(decoded_token)

    @classmethod
    async def ajson_to_ascii(cls, data, *, table=URL_SAFE_TABLE):
        """
        Converts json ciphertext into ascii consisting of characters
        found inside the ``table`` keyword argument.
        """
        int_data = int.from_bytes(await cls.ajson_to_bytes(data), "big")
        return await ainverse_int(int_data, len(table), table)

    @classmethod
    def json_to_ascii(cls, data, *, table=URL_SAFE_TABLE):
        """
        Converts json ciphertext into ascii consisting of characters
        found inside the ``table`` keyword argument.
        """
        int_data = int.from_bytes(cls.json_to_bytes(data), "big")
        return inverse_int(int_data, len(table), table)

    @classmethod
    async def aascii_to_json(cls, data, *, table=URL_SAFE_TABLE):
        """
        Converts ascii formated ciphertext, consisting of characters
        from the ``table`` keyword argument, back into json.
        """
        int_data = await abase_to_decimal(data, len(table), table=table)
        length = math.ceil(int_data.bit_length() / 8)
        return await cls.abytes_to_json(int_data.to_bytes(length, "big"))

    @classmethod
    def ascii_to_json(cls, data, *, table=URL_SAFE_TABLE):
        """
        Converts ascii formated ciphertext, consisting of characters
        from the ``table`` keyword argument, back into json.
        """
        int_data = base_to_decimal(data, base=len(table), table=table)
        length = math.ceil(int_data.bit_length() / 8)
        return cls.bytes_to_json(int_data.to_bytes(length, "big"))

    @classmethod
    async def aread(cls, path, *, encoding=LIST_ENCODING):
        """
        Reads the bytes file at ``path`` under a certain ``encoding``.
        ``LIST_ENCODING`` is the default encoding for all ciphertext.
        Databases used to use the ``MAP_ENCODING``, but they now also
        output listed ciphertext.
        """
        async with aiofiles.open(path, "rb") as f:
            return await cls.abytes_to_json(
                await f.read(), encoding=encoding
            )

    @classmethod
    def read(cls, path, *, encoding=LIST_ENCODING):
        """
        Reads the bytes file at ``path`` under a certain ``encoding``.
        ``LIST_ENCODING`` is the default encoding for all ciphertext.
        Databases used to use the ``MAP_ENCODING``, but they now also
        output listed ciphertext.
        """
        with open(path, "rb") as f:
            return cls.bytes_to_json(f.read(), encoding=encoding)

    @classmethod
    async def awrite(cls, path, ciphertext):
        """
        Writes json ``ciphertext`` to a bytes file at ``path``.
        """
        async with aiofiles.open(path, "wb+") as f:
            await f.write(await cls.ajson_to_bytes(ciphertext))

    @classmethod
    def write(cls, path, ciphertext):
        """
        Writes json ``ciphertext`` to a bytes file at ``path``.
        """
        with open(path, "wb+") as f:
            f.write(cls.json_to_bytes(ciphertext))


async def acustomize_parameters(
    a=(), kw=(), indexes=(), args=(), kwargs=()
):
    """
    Replaces ``a`` and ``kw`` arguments & keyword arguments with ``args``
    if ``indexes`` is specified, and ``kwargs``.
    """
    if args and indexes:
        a = list(a)
        for index in indexes:
            a[index] = args[index]
        await asleep(0)
    for kwarg in kwargs:
        kw[kwarg] = kwargs[kwarg]
    await asleep(0)
    return a, kw


def customize_parameters(a=(), kw=(), indexes=(), args=(), kwargs=()):
    """
    Replaces ``a`` and ``kw`` arguments & keyword arguments with ``args``
    if ``indexes`` is specified, and ``kwargs``.
    """
    if args and indexes:
        a = list(a)
        for index in indexes:
            a[index] = args[index]
    for kwarg in kwargs:
        kw[kwarg] = kwargs[kwarg]
    return a, kw


def comprehension(*args, indexes=(), catcher=None, **kwargs):
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
            nonlocal catcher

            a, kw = customize_parameters(a, kw, indexes, args, kwargs)
            catcher = Comprende if catcher == None else catcher
            return catcher(func, *a, **kw)

        return gen_wrapper

    return func_catch


class Comprende:
    """
    Comprende is a generator wrapper class that exposes an innovative,
    clean api for making sync & async generators more useful by making
    their many features easier to use. Comprende allows for easily
    retrieving generator "return" values, has built-in methods that
    support dotted chaining for inline data processing of generator
    outputs, & it opens channels of communication to and from sync &
    async coroutines designed to be driven by a caller.

    Comprende is what generator comprehensions should be.

    Usage Example:

    def gen(x=None, y=None):
        # The final result is returned normally in a sync generator ->
        z = yield x + y
        return x * y * z

    # Easily drive the generator forward.
    with Comprende(gen, x=1, y=2) as example:
        z = 3

        # Calling the object will send ``None`` into the coroutine ->
        sum_of_x_y = example()
        assert sum_of_x_y == 3

        # Passing ``z`` will send it into the coroutine, cause it to
        # reach the return statement & exit the context manager ->
        example(z)

    # The result returned from the generator is now available ->
    product_of_x_y_z = example.result()
    assert product_of_x_y_z == 6

    # The ``example`` variable is actually the Comprende object, which
    # redirects values to the wrapped generator's ``send()`` method
    # using the instance's ``__call__()`` method.  It's still available
    # after the context closes ->
    assert example.__class__.__name__ == "Comprende"

    # Here's another example ->
    @aiootp.comprehension()
    def one_byte_numbers():
        for number in range(256):
            yield number

    # Chained ``Comprende`` generators are excellent inline data
    # processors ->
    base64_data = [
        b64_byte
        for b64_byte
        in one_byte_numbers().int_to_bytes(1).to_base64()
    ]
    # This converted each number to bytes then base64 encoded them.

    # We can wrap other iterables to add functionality to them ->
    @aiootp.comprehension()
    def unpack(iterable):
        for item in iterable:
            yield item

    # This example just hashes each output then yields them
    for hex_hash in unpack(base64_data).sha_256():
        print(hex_hash)


    Async Usage Example:

    async def gen(x=None, y=None):
        # Because having a return statement in an async generator is a
        # SyntaxError, the return value is expected to be passed into
        # UserWarning, and then raised to propagate upstream. It's then
        # available from the instance's ``aresult`` method ->

        z = yield x + y
        result = x * y * z
        raise UserWarning(result)

    # Easily drive the generator forward.
    async with Comprende(gen, x=1, y=2) as example:
        z = 3

        # Awaiting the object's call will send ``None`` into the
        # coroutine ->
        sum_of_x_y = await example()
        assert sum_of_x_y == 3

        # Passing ``z`` will send it into the coroutine, cause it to
        # the raise statement & exit the context manager ->
        await example(az)

    # The result returned from the generator is now available ->
    product_of_x_y_z = await example.aresult()
    assert product_of_x_y_z == 6

    # Let's see some other ways async generators mirror synchronous
    # ones ->
    @aiootp.comprehension()
    async def one_byte_numbers():
        for number in range(256):
            yield number

    # This is asynchronous data processing ->
    base64_data = [
        b64_byte
        async for b64_byte
        in one_byte_numbers().aint_to_bytes(1).ato_base64()
    ]

    # We can wrap other iterables to add asynchronous functionality to
    # them ->
    @aiootp.comprehension()
    async def unpack(iterable):
        for item in iterable:
            yield item

    # Want only the first twenty results? ->
    async for hex_hash in unpack(base64_data).asha_256()[:20]:
        # Then you can slice the generator.
        print(hex_hash)

    # Users can slice generators to receive more complex output rules,
    # like: Getting every second result starting from the third result
    # to the 50th ->
    async for result in unpack(base64_data)[3:50:2]:
        print(result)

    # Although, negative slice numbers are not supported.

    # ``Comprende`` generators have loads of tooling for users to explore.
    # Play around with it and take a look at the other chainable generator
    # methods in ``aiootp.Comprende.lazy_generators``.

    Comprende has many more useful features to play around with! Have
    fun with it!
    """

    decorator = comprehension

    _cached = {}

    __slots__ = [
        "gen",
        "func",
        "args",
        "kwargs",
        "iterator",
        "_async",
        "_runsum",
        "_return",
        "_thrown",
        "__call__",
        "_acache_yield",
        "_cache_yield",
    ]

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
        "adelimit_resize",
        "delimit_resize",
        "ato_base64",
        "to_base64",
        "afrom_base64",
        "from_base64",
        "aint_to_ascii",
        "int_to_ascii",
        "aascii_to_int",
        "ascii_to_int",
        "asha_512",
        "sha_512",
        "asha_512_hmac",
        "sha_512_hmac",
        "asum_sha_512",
        "sum_sha_512",
        "asha_256",
        "sha_256",
        "asha_256_hmac",
        "sha_256_hmac",
        "asum_sha_256",
        "sum_sha_256",
    }

    eager_generators = {
        "aheappop",
        "heappop",
        "areversed",
        "reversed",
        "asort",
        "sort",
    }

    _generators = {"__aiter__", "__iter__"}

    lazy_methods = {"anext", "next", "asend", "send"}

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

    _methods = {
        "athrows",
        "throws",
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
        "aclear",
        "clear",
        "acatch",
        "catch",
        "arelay",
        "relay",
        "aauto_cache",
        "auto_cache",
        "aclear_class",
        "clear_class",
        "runsum",
        "precomputed",
    }

    ASYNC_GEN_DONE = "async generator raised StopAsyncIteration"

    def __init__(self, func=None, *a, **kw):
        """
        Establishes async / sync properties of new objects & copies
        over wrapped functions' signatures.
        """
        self.args = a
        self.kwargs = kw
        self._runsum = b""
        self._thrown = deque()
        self._return = deque()
        if is_async_gen_function(func):
            self.func = func
            self.gen = self.__set_async()
            self.iterator = _aiter.root(self.gen)
        else:
            self.func = func if func != None else unpack
            self.gen = self.__set_sync()
            self.iterator = iter(self.gen)

    async def areset(self):
        """
        Replaces the generator wrapper with a new async wrapper.
        """
        self.gen = self.__set_async()
        return self

    def reset(self):
        """
        Replaces the generator wrapper with a new sync wrapper.
        """
        self.gen = self.__set_sync()
        return self

    async def __aexamine_sent_exceptions(self, gen=None, got=None):
        """
        Catches ``UserWarning``s which signals that the generator, or a
        subgenerator in the stack, has raised a return value.
        """
        while True:
            got = yield got
            if issubclass(got.__class__, UserWarning):
                if any(got.args):
                    self._thrown.append(got.args[0])
                await gen.athrow(got)

    def __set_async(self):
        """
        Does the wrapping of user async generators to allow catching
        return values.
        """

        @wraps(self.func)
        async def _acomprehension(gen=None):
            catch_UserWarning = self.__aexamine_sent_exceptions(gen)
            await catch_UserWarning.asend(None)
            async with self.acatch():
                got = None
                while True:
                    got = yield await gen.asend(got)
                    await catch_UserWarning.asend(got)

        self._async = True
        self.__call__ = self._acall
        return _acomprehension(self.func(*self.args, **self.kwargs))

    def __examine_sent_exceptions(self, gen=None, got=None):
        """
        Catches ``UserWarning``s which signals that the generator, or a
        subgenerator in the stack, has raised a return value.
        """
        while True:
            got = yield got
            if issubclass(got.__class__, UserWarning):
                if any(got.args):
                    self._thrown.append(got.args[0])
                gen.throw(got)

    def __set_sync(self):
        """
        Does the wrapping of user generators to allow catching return
        values.
        """

        @wraps(self.func)
        def _comprehension(gen=None):
            catch_UserWarning = self.__examine_sent_exceptions(gen)
            catch_UserWarning.send(None)
            with self.catch():
                got = None
                while True:
                    got = yield gen.send(got)
                    catch_UserWarning.send(got)

        self._async = False
        self.__call__ = self._call
        return _comprehension(self.func(*self.args, **self.kwargs))

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
            await asleep(0)
            yield self
        except UserWarning as done:
            if done.args:
                self._return.append(done.args[0])
        except RuntimeError as done:
            if self.ASYNC_GEN_DONE not in done.args:
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
    async def aclass_relay(cls, result=None, source=None):
        """
        This is a lower level context manager for users who've created
        async generators that need to propagate results up to calling
        code. Code in this context manager's block will return ``result``
        or the return value of a ``source`` Comprende async generator
        up to its caller in a UserWarning exception.
        """
        try:
            await asleep(0)
            yield source
        except UserWarning:
            if result != None:
                raise UserWarning(result)
            raise UserWarning(await source.aresult(exit=True))

    @async_contextmanager
    async def arelay(self, result=None, source=None):
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

    @classmethod
    @contextmanager
    def class_relay(cls, result=None, source=None):
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

    @contextmanager
    def relay(self, result=None, source=None):
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

    async def aprime(self):
        """
        Resets the instance's async wrapper generator & ``asend``s in a
        ``None`` value to prime the generator, i.e. bringing it to the
        first yield statement.
        """
        await self.areset()
        await self.gen.asend(None)
        return self

    def prime(self):
        """
        Resets the instance's sync wrapper generator & ``send``s in a
        ``None`` value to prime the generator, i.e. bringing it to the
        first yield statement.
        """
        self.reset()
        self.gen.send(None)
        return self

    async def asend(self, got=None):
        """
        Copies the wrapped async generator's ``asend`` method behavior.
        This is equivalent to an async Comprende generator's ``__call__``
        method.
        """
        return await self.gen.asend(got)

    def send(self, got=None):
        """
        Copies the wrapped sync generator's ``send`` method behavior.
        This is equivalent to a sync Comprende generator's ``__call__``
        method.
        """
        return self.gen.send(got)

    async def athrow(self, exc_type, exc_value=None, traceback=None):
        """
        This is quivalent to a wrapped async generator's ``athrow``
        method.
        """
        await self.gen.athrow(exc_type, exc_value, traceback)

    def throw(self, exc_type, exc_value=None, traceback=None):
        """
        This is quivalent to a wrapped sync generator's ``throw`` method.
        """
        self.gen.throw(exc_type, exc_value, traceback)

    @property
    def ag_await(self):
        """
        Copies the interface for async generators.
        """
        return self.gen.ag_await

    @property
    def gi_yieldfrom(self):
        """
        Copies the interface for generators.
        """
        return self.gen.gi_yieldfrom

    @property
    def ag_code(self):
        """
        Copies the interface for async generators.
        """
        return self.gen.ag_code

    @property
    def gi_code(self):
        """
        Copies the interface for generators.
        """
        return self.gen.gi_code

    @property
    def ag_frame(self):
        """
        Copies the interface for async generators.
        """
        return self.gen.ag_frame

    @property
    def gi_frame(self):
        """
        Copies the interface for generators.
        """
        return self.gen.gi_frame

    @property
    def ag_running(self):
        """
        Copies the interface for async generators.
        """
        return self.gen.ag_running

    @property
    def gi_running(self):
        """
        Copies the interface for generators.
        """
        return self.gen.gi_running

    async def aclose(self, *a, **kw):
        """
        This is quivalent to a wrapped async generator's ``aclose``
        method.
        """
        return await self.gen.aclose(*a, **kw)

    def close(self, *a, **kw):
        """
        This is quivalent to a wrapped sync generator's ``close`` method.
        """
        return self.gen.close(*a, **kw)

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
                await self.gen.asend(UserWarning())
        elif exit:
            await self.gen.asend(UserWarning())
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
                self.gen.send(UserWarning())
        elif exit:
            self.gen.send(UserWarning())
        with ignore(IndexError, display=not silent):
            if pop:
                return self._return.popleft()
            else:
                return self._return[0]

    async def athrows(self):
        """
        When causing an async generator to exit using ``self.aresult()``,
        the exception is appended to the instance ``self._thrown`` queue.
        Normally this doesn't have significance, but users can adapt this
        queue & override ``self.aresult`` to send in relevant values
        instead.
        """
        await asleep(0)
        return self._thrown

    def throws(self):
        """
        When causing a sync generator to exit using ``self.result()``,
        the exception is appended to the instance ``self._thrown`` queue.
        Normally this doesn't have significance, but users can adapt this
        queue & override ``self.result`` to send in relevant values
        instead.
        """
        return self._thrown

    async def anext(self, *a):
        """
        Advances the wrapped async generator to the next yield.
        """
        return await self.iterator.asend(None)

    def next(self, *a):
        """
        Advances the wrapped sync generator to the next yield.
        """
        return builtins.next(self.iterator)

    def __del__(self):
        """
        Attempts to cleanup instance caches when deleted or garbage
        collected to reduce memory overhead.
        """
        self.clear()
        if hasattr(self, "gen"):
            del self.gen

    @classmethod
    async def aclear_class(cls):
        """
        Allows users to manually clear the cache of all the class'
        instances.
        """
        for runsum, instance in dict(cls._cached).items():
            del cls._cached[runsum]
            async for cache in instance._acache_has():
                cache.cache_clear()
            instance._runsum = b""

    @classmethod
    def clear_class(cls):
        """
        Allows users to manually clear the cache of all the class'
        instances.
        """
        for runsum, instance in dict(cls._cached).items():
            del cls._cached[runsum]
            for cache in instance._cache_has():
                cache.cache_clear()
            instance._runsum = b""

    async def aclear(self, *, cls=False):
        """
        Allows users to manually clear the cache of an instance, or if
        ``cls`` is ``True`` clears the cache of every instance.
        """
        if cls == True:
            await self.aclear_class()
        elif self.precomputed:
            try:
                del self.__class__._cached[self.runsum]
                async for cache in self._acache_has():
                    cache.cache_clear()
            finally:
                self._runsum = b""

    def clear(self, *, cls=False):
        """
        Allows users to manually clear the cache of an instance, or if
        ``cls`` is ``True`` clears the cache of every instance.
        """
        if cls == True:
            self.clear_class()
        elif self.precomputed:
            try:
                del self.__class__._cached[self.runsum]
                for cache in self._cache_has():
                    cache.cache_clear()
            finally:
                self._runsum = b""

    async def _acache_has(self):
        """
        Returns the lru cached methods of an instance in an iterable.
        """
        if hasattr(self, "_cache_yield"):
            await asleep(0)
            yield self._cache_yield
        if hasattr(self, "_acache_yield"):
            await asleep(0)
            yield self._acache_yield

    def _cache_has(self):
        """
        Returns the lru cached methods of an instance in an iterable.
        """
        if hasattr(self, "_cache_yield"):
            yield self._cache_yield
        if hasattr(self, "_acache_yield"):
            yield self._acache_yield

    async def _aset_cache(self):
        """
        Creates a per-instance function that returns precomputed results
        with lru cache turned on to save on speed for instances that have
        called async methods or generators which do eager computation of
        an async generator's entire result set.
        """

        @alru_cache(maxsize=2)
        async def _acache_yield(runsum=None):
            return [result async for result in self]

        await asleep(0)
        self._acache_yield = _acache_yield
        self._runsum = await self._amake_runsum()

    def _set_cache(self):
        """
        Creates a per-instance function that returns precomputed results
        with lru cache turned on to save on speed for instances that have
        called sync methods or generators which do eager computation of
        a generator's entire result set.
        """

        @lru_cache(maxsize=2)
        def _cache_yield(runsum=None):
            return [result for result in self]

        self._cache_yield = _cache_yield
        self._runsum = self._make_runsum()

    @staticmethod
    async def _amake_runsum(*args):
        """
        Calculates a 32-byte pseudo-random id for instances to mark
        themselves as having cached results.
        """
        return bytes.fromhex(
            await asha_256(secrets.token_bytes(32), args)
        )

    @staticmethod
    def _make_runsum(*args):
        """
        Calculates a 32-byte pseudo-random id for instances to mark
        themselves as having cached results.
        """
        return bytes.fromhex(sha_256(secrets.token_bytes(32), args))

    @property
    def runsum(self):
        """
        Returns an empty bytes string if the instance generator has not
        cached any results, or returns the generator's 16-byte id if it
        has.
        """
        return self._runsum[:16]

    @property
    def precomputed(self):
        """
        Checks the class' dictionary of cached flags for the generator's
        ``self.runsum`` id. Returns the instance if found, False if not.
        """
        if self._runsum and self.runsum in self.__class__._cached:
            return self.__class__._cached[self.runsum]
        else:
            return False

    @async_contextmanager
    async def aauto_cache(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``list``, then ``alru_cache``'s the result
        & yields it as a context manager. Finally, adds the instance
        into the class' ``_cached`` dictionary to more easily find &
        manage the memory overhead of caching values.
        """
        try:
            if not self._runsum:
                await self._aset_cache()
            yield await self._acache_yield(self.runsum)
        finally:
            self.__class__._cached[self.runsum] = self

    @contextmanager
    def auto_cache(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``list``, then ``lru_cache``'s the result
        & yields it as a context manager. Finally, adds the instance
        into the class' ``_cached`` dictionary to more easily find &
        manage the memory overhead of caching values.
        """
        try:
            if not self._runsum:
                self._set_cache()
            yield self._cache_yield(self.runsum)
        finally:
            self.__class__._cached[self.runsum] = self

    async def alist(self, *, mutable=False):
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
        async with self.aauto_cache() as results:
            return results if mutable else list(results)

    def list(self, *, mutable=False):
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
        with self.auto_cache() as results:
            return results if mutable else list(results)

    async def adeque(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``collections.deque``, then ``alru_cache``'s
        the result & returns it.
        """
        async with self.aauto_cache() as results:
            return deque(results)

    def deque(self):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a ``collections.deque``, then ``lru_cache``'s
        the result & returns it.
        """
        with self.auto_cache() as results:
            return deque(results)

    async def aset(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``set``, then ``alru_cache``'s the result
        & returns it.
        """
        async with self.aauto_cache() as results:
            return set(results)

    def set(self):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a ``set``, then ``lru_cache``'s the result
        & returns it.
        """
        with self.auto_cache() as results:
            return set(results)

    async def adict(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``dict``, then ``alru_cache``'s the result
        & returns it.
        """
        async with self.aauto_cache() as results:
            return dict(results)

    def dict(self):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a ``dict``, then ``lru_cache``'s the result
        & returns it.
        """
        with self.auto_cache() as results:
            return dict(results)

    async def ajoin(self, on=""):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together ``on`` the string that's passed, then
        ``alru_cache``'s the result & returns it.
        """
        async with self.aauto_cache() as results:
            return on.join(results)

    def join(self, on=""):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together ``on`` the string that's passed, then
        ``lru_cache``'s the result & returns it.
        """
        with self.auto_cache() as results:
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

    async def atimeout(self, seconds=5, *, probe_frequency=0):
        """
        Stops the instance's wrapped async generator's current iteration
        after a ``seconds`` number of seconds. Otherwise, the countdown
        is restarted after every on-time iteration & the result is
        yielded. Runs the wrapped generator as a async task to acheive
        this.
        """
        iterator = self.__aiter__().__anext__
        while True:
            time_start = time()
            iteration = asynchs.new_task(iterator())
            while not iteration.done():
                await asleep(probe_frequency)
                if time() - time_start >= seconds:
                    break
            if iteration.done():
                yield await iteration
            else:
                iteration.cancel()
                break

    def timeout(self, seconds=5, *, probe_frequency=0):
        """
        Stops the instance's wrapped sync generator's current iteration
        after a ``seconds`` number of seconds. Otherwise, the countdown
        is restarted after every on-time iteration & the result is
        yielded. Runs the wrapped generator in a thread pool to acheive
        this.
        """
        iterator = self.__iter__().__next__
        while True:
            time_start = time()
            iteration = asynchs.Threads.submit(iterator)
            while not iteration.done():
                asynchs.sleep(probe_frequency)
                if time() - time_start >= seconds:
                    break
            if iteration.done():
                yield iteration.result()
            else:
                iteration.cancel()
                break

    async def ahalt(self, sentinel="", *, sentinels=()):
        """
        Takes a ``sentinel`` or iterable of ``sentinels`` & halts the
        underlying Comprende async generator if it yields any of those
        sentinels.
        """
        sentinels = set(sentinels) if sentinels else {sentinel}
        async for result in self:
            if result in sentinels:
                break
            yield result

    def halt(self, sentinel="", *, sentinels=()):
        """
        Takes a ``sentinel`` or iterable of ``sentinels`` & halts the
        underlying Comprende sync generator if it yields any of those
        sentinels.
        """
        sentinels = set(sentinels) if sentinels else {sentinel}
        for result in self:
            if result in sentinels:
                break
            yield result

    async def afeed(self, iterable=None):
        """
        Takes in an sync or async iterable & sends those values into an
        async coroutine which automates the process of driving an async
        generator which is expecting results from a caller.
        """
        asend = self.gen.asend
        yield await asend(None)
        async for food in aunpack.root(iterable):
            yield await asend(food)

    def feed(self, iterable=None):
        """
        Takes in an iterable & sends those values into a sync coroutine
        which automates the process of driving a generator which is
        expecting results from a caller.
        """
        send = self.gen.send
        yield send(None)
        for food in iterable:
            yield send(food)

    async def afeed_self(self):
        """
        Recursively feeds the results of an async generator back into
        itself as coroutine values for the ``asend`` function.
        """
        asend = self.gen.asend
        food = await asend(None)
        yield food
        while True:
            food = await asend(food)
            yield food

    def feed_self(self):
        """
        Recursively feeds the results of an generator back into itself
        as coroutine values for the ``send`` function.
        """
        send = self.gen.send
        food = send(None)
        yield food
        while True:
            food = send(food)
            yield food

    async def atag(self, tags=None):
        """
        By default behaves like ``enumerate`` for each value yielded
        from the underlying Comprende async generator. Optionally,
        ``tags`` can be passed a sync or async iterable & prepends those
        values to the generator's results.
        """
        if tags:
            async for name, item in azip(tags, self):
                yield name, item
        else:
            async for name, item in Enumerate(self):
                yield name, item

    def tag(self, tags=None):
        """
        By default behaves like ``enumerate`` for each value yielded
        from the underlying Comprende sync generator. Optionally,
        ``tags`` can be passed an iterable & prepends those values to
        the generator's results.
        """
        if tags:
            for name, item in zip(tags, self):
                yield name, item
        else:
            for name, item in enumerate(self):
                yield name, item

    async def aheappop(self, span=None):
        """
        Exhausts the underlying Comprende async generator upto ``span``
        number of iterations, then yields the results in sorted order
        based on the ``heapq.heappop`` function.
        """
        target = self[:span] if span else self
        async with target as accumulator:
            results = await accumulator.alist(mutable=True)
        heapq.heapify(results)
        while True:
            try:
                yield heapq.heappop(results)
            except IndexError:
                break

    def heappop(self, span=None):
        """
        Exhausts the underlying Comprende sync generator upto ``span``
        number of iterations, then yields the results in sorted order
        based on the ``heapq.heappop`` function.
        """
        target = self[:span] if span else self
        with target as accumulator:
            results = accumulator.list(mutable=True)
        heapq.heapify(results)
        while True:
            try:
                yield heapq.heappop(results)
            except IndexError:
                break

    async def areversed(self, span=None):
        """
        Exhausts the underlying Comprende async generator upto ``span``
        number of iterations, then yields the results in reversed order.
        """
        target = self[:span] if span else self
        async with target as accumulator:
            results = await accumulator.alist(mutable=True)
        for result in reversed(results):
            await asleep(0)
            yield result

    def reversed(self, span=None):
        """
        Exhausts the underlying Comprende sync generator upto ``span``
        number of iterations, then yields the results in reversed order.
        """
        target = self[:span] if span else self
        with target as accumulator:
            results = accumulator.list(mutable=True)
        for result in reversed(results):
            yield result

    async def asort(self, *, key=None, span=None):
        """
        Exhausts the underlying Comprende async generator upto ``span``
        number of iterations, then yields the results in sorted order.
        """
        target = self[:span] if span else self
        async with target as accumulator:
            results = await accumulator.alist(mutable=True)
        results.sort(key=key)
        for result in results:
            await asleep(0)
            yield result

    def sort(self, *, key=None, span=None):
        """
        Exhausts the underlying Comprende sync generator upto ``span``
        number of iterations, then yields the results in sorted order.
        """
        target = self[:span] if span else self
        with target as accumulator:
            results = accumulator.list(mutable=True)
        results.sort(key=key)
        for result in results:
            yield result

    async def aresize(self, size=256):
        """
        Buffers the output from the underlying Comprende async generator
        to yield the results in chunks of length ``size``.
        """
        next_self = self.anext
        result = await next_self()
        while True:
            while len(result) >= size:
                yield result[:size]
                result = result[size:]
            try:
                result += await next_self()
            except StopAsyncIteration:
                break
        if result:
            yield result

    def resize(self, size=256):
        """
        Buffers the output from the underlying Comprende sync generator
        to yield the results in chunks of length ``size``.
        """
        next_self = self.next
        result = next_self()
        while True:
            while len(result) >= size:
                yield result[:size]
                result = result[size:]
            try:
                result += next_self()
            except StopIteration:
                break
        if result:
            yield result

    async def adelimit(self, delimiter=" "):
        """
        Adds a user-defined ``delimiter`` to the end of end result
        yielded from the underlying ``Comprende`` async generator.
        """
        async for result in self:
            yield result + delimiter

    def delimit(self, delimiter=" "):
        """
        Adds a user-defined ``delimiter`` to the end of end result
        yielded from the underlying ``Comprende`` generator.
        """
        for result in self:
            yield result + delimiter

    async def adelimit_resize(self, delimiter=" ", base=""):
        """
        Yields the results of the underlying ``Comprende`` async
        generator in chunks delimited by ``delimiter``. The ``base``
        keyword argument is an empty sequence of the same type
        (``str`` or ``bytes``) that the yielded results are in.
        """
        cache = base
        async for result in self:
            result = (cache + result).lstrip(delimiter)
            while delimiter in result:
                index = result.find(delimiter)
                yield result[:index]
                result = result[index:].lstrip(delimiter)
            cache = result
        if cache:
            yield cache

    def delimit_resize(self, delimiter=" ", base=""):
        """
        Yields the results of the underlying ``Comprende`` generator in
        chunks delimited by ``delimiter``. The ``base`` keyword argument
        is an empty sequence of the same type (``str`` or ``bytes``)
        that the yielded results are in.
        """
        cache = base
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
        async for result in self:
            yield to_b64(result)

    def to_base64(self):
        """
        Applies ``base64.standard_b64encode`` conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        for result in self:
            yield to_b64(result)

    async def afrom_base64(self):
        """
        Applies ``base64.standard_b64decode`` conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        async for result in self:
            yield from_b64(result)

    def from_base64(self):
        """
        Applies ``base64.standard_b64decode`` conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        for result in self:
            yield from_b64(result)

    async def aint_to_ascii(self):
        """
        Applies a ``binascii`` int-to-ascii conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        async for result in self:
            yield result.to_bytes(
                math.ceil(result.bit_length() / 8), "big"
            ).decode()

    def int_to_ascii(self):
        """
        Applies a ``binascii`` int-to-ascii conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        for result in self:
            yield result.to_bytes(
                math.ceil(result.bit_length() / 8), "big"
            ).decode()

    async def aascii_to_int(self):
        """
        Applies a ``binascii`` ascii-to-int conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        async for result in self:
            yield int.from_bytes(result.encode(), "big")

    def ascii_to_int(self):
        """
        Applies a ``binascii`` ascii-to-int conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        for result in self:
            yield int.from_bytes(result.encode(), "big")

    async def asha_512(self, *, salt=None):
        """
        Applies ``hashlib.sha3_512()`` to each value that's yielded
        from the underlying Comprende async generator before yielding
        the result.
        """
        if salt:
            async for result in self:
                yield await asha_512(salt, result)
        else:
            async for result in self:
                yield await asha_512(result)

    def sha_512(self, *, salt=None):
        """
        Applies ``hashlib.sha3_512()`` to each value that's yielded
        from the underlying Comprende sync generator before yielding
        the result.
        """
        if salt:
            for result in self:
                yield sha_512(salt, result)
        else:
            for result in self:
                yield sha_512(result)

    async def asha_512_hmac(self, *, key, salt=None):
        """
        Applies a ``hashlib.sha3_512()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        if salt:
            async for result in self:
                yield await asha_512_hmac((salt, result), key=key)
        else:
            async for result in self:
                yield await asha_512_hmac(result, key=key)

    def sha_512_hmac(self, *, key, salt=None):
        """
        Applies a ``hashlib.sha3_512()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        if salt:
            for result in self:
                yield sha_512_hmac((salt, result), key=key)
        else:
            for result in self:
                yield sha_512_hmac(result, key=key)

    async def asum_sha_512(self, *, salt=None):
        """
        Cumulatively applies a ``hashlib.sha3_512()`` to each value
        that's yielded from the underlying Comprende async generator
        with the results of prior hashing before yielding the result.
        """
        summary = await asha_512(salt)
        async for result in self:
            summary = await asha_512(salt, summary, result)
            yield summary

    def sum_sha_512(self, *, salt=None):
        """
        Cumulatively applies a ``hashlib.sha3_512()`` to each value
        that's yielded from the underlying Comprende sync generator with
        the results of prior hashing before yielding the result.
        """
        summary = sha_512(salt)
        for result in self:
            summary = sha_512(salt, summary, result)
            yield summary

    async def asha_256(self, *, salt=None):
        """
        Applies ``hashlib.sha3_256()`` to each value that's yielded
        from the underlying Comprende async generator before yielding
        the result.
        """
        if salt:
            async for result in self:
                yield await asha_256(salt, result)
        else:
            async for result in self:
                yield await asha_256(result)

    def sha_256(self, *, salt=None):
        """
        Applies ``hashlib.sha3_256()`` to each value that's yielded
        from the underlying Comprende sync generator before yielding the
        result.
        """
        if salt:
            for result in self:
                yield sha_256(salt, result)
        else:
            for result in self:
                yield sha_256(result)

    async def asha_256_hmac(self, *, key, salt=None):
        """
        Applies a ``hashlib.sha3_256()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        if salt:
            async for result in self:
                yield await asha_256_hmac((salt, result), key=key)
        else:
            async for result in self:
                yield await asha_256_hmac(result, key=key)

    def sha_256_hmac(self, *, key, salt=None):
        """
        Applies a ``hashlib.sha3_256()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        if salt:
            for result in self:
                yield sha_256_hmac((salt, result), key=key)
        else:
            for result in self:
                yield sha_256_hmac(result, key=key)

    async def asum_sha_256(self, *, salt=None):
        """
        Cumulatively applies a ``hashlib.sha3_256()`` to each value
        that's yielded from the underlying Comprende async generator
        with the results of prior hashing before yielding the result.
        """
        summary = await asha_256(salt)
        async for result in self:
            summary = await asha_256(salt, summary, result)
            yield summary

    def sum_sha_256(self, *, salt=None):
        """
        Cumulatively applies a ``hashlib.sha3_256()`` to each value
        that's yielded from the underlying Comprende sync generator with
        the results of prior hashing before yielding the result.
        """
        summary = sha_256(salt)
        for result in self:
            summary = sha_256(salt, summary, result)
            yield summary

    async def aint(self, *a, **kw):
        """
        Applies ``builtins.int(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        async for result in self:
            yield int(result, *a, **kw)

    def int(self, *a, **kw):
        """
        Applies ``builtins.int(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        for result in self:
            yield builtins.int(result, *a, **kw)

    async def abytes_to_int(self, byte_order="big"):
        """
        Applies ``int.from_bytes(result, byte_order)`` to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        async for result in self:
            yield int.from_bytes(result, byte_order)

    def bytes_to_int(self, byte_order="big"):
        """
        Applies ``int.from_bytes(result, byte_order)`` to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        for result in self:
            yield int.from_bytes(result, byte_order)

    async def aint_to_bytes(self, size=256, byte_order="big"):
        """
        Applies ``int.to_bytes(result, size, byte_order)`` to each
        value that's yielded from the underlying Comprende async
        generator before yielding the result.
        """
        async for result in self:
            yield result.to_bytes(size, byte_order)

    def int_to_bytes(self, size=256, byte_order="big"):
        """
        Applies ``int.to_bytes(result, size, byte_order)`` to each
        value that's yielded from the underlying Comprende sync
        generator before yielding the result.
        """
        for result in self:
            yield result.to_bytes(size, byte_order)

    async def ahex_to_bytes(self):
        """
        Applies ``bytes.fromhex(result)`` to each value that's yielded
        from the underlying Comprende async generator before yielding
        the result.
        """
        async for result in self:
            yield bytes.fromhex(result)

    def hex_to_bytes(self):
        """
        Applies ``bytes.fromhex(result)`` to each value that's yielded
        from the underlying Comprende sync generator before yielding
        the result.
        """
        for result in self:
            yield bytes.fromhex(result)

    async def abytes_to_hex(self):
        """
        Applies ``bytes.hex(result)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        async for result in self:
            yield result.hex()

    def bytes_to_hex(self):
        """
        Applies ``bytes.hex(result)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        for result in self:
            yield result.hex()

    async def ato_base(self, base=95, table=ASCII_TABLE):
        """
        Converts each integer value that's yielded from the underlying
        Comprende async generator to a string in ``base`` before yielding
        the result.
        """
        async for result in self:
            yield await ainverse_int(result, base, table)

    def to_base(self, base=95, table=ASCII_TABLE):
        """
        Converts each integer value that's yielded from the underlying
        Comprende sync generator to a string in ``base`` before yielding
        the result.
        """
        for result in self:
            yield inverse_int(result, base, table)

    async def afrom_base(self, base=95, table=ASCII_TABLE):
        """
        Convert string results of generator results in numerical ``base``
        into decimal.
        """
        async for result in self:
            yield await abase_to_decimal(result, base, table)

    def from_base(self, base=95, table=ASCII_TABLE):
        """
        Convert ``string`` in numerical ``base`` into decimal.
        """
        for result in self:
            yield base_to_decimal(result, base, table)

    async def azfill(self, *a, **kw):
        """
        Applies ``builtins.zfill(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        async for result in self:
            yield result.zfill(*a, **kw)

    def zfill(self, *a, **kw):
        """
        Applies ``builtins.zfill(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        for result in self:
            yield result.zfill(*a, **kw)

    async def aslice(self, *a):
        """
        Applies ``builtins.slice(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        selected = slice(*a)
        async for result in self:
            yield result[selected]

    def slice(self, *a):
        """
        Applies ``builtins.slice(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        selected = slice(*a)
        for result in self:
            yield result[selected]

    async def aindex(self, selected=None):
        """
        Yields the ``selected`` index of each result produced by the
        underlying Comprende async generator.
        """
        async for result in self:
            yield result[selected]

    def index(self, selected=None):
        """
        Yields the ``selected`` index of each result produced by the
        underlying Comprende sync generator.
        """
        for result in self:
            yield result[selected]

    async def astr(self, *a, **kw):
        """
        Applies ``builtins.str(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        async for result in self:
            yield str(result, *a, **kw)

    def str(self, *a, **kw):
        """
        Applies ``builtins.str()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        _str = builtins.str
        for result in self:
            yield _str(result, *a, **kw)

    async def asplit(self, *a, **kw):
        """
        Applies ``value.split()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        async for result in self:
            yield result.split(*a, **kw)

    def split(self, *a, **kw):
        """
        Applies ``value.split()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        for result in self:
            yield result.split(*a, **kw)

    async def areplace(self, *a, **kw):
        """
        Applies ``value.replace()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        async for result in self:
            yield result.replace(*a, **kw)

    def replace(self, *a, **kw):
        """
        Applies ``value.replace()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        for result in self:
            yield result.replace(*a, **kw)

    async def aencode(self, *a, **kw):
        """
        Applies ``value.encode()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        async for result in self:
            yield result.encode(*a, **kw)

    def encode(self, *a, **kw):
        """
        Applies ``value.encode()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        for result in self:
            yield result.encode(*a, **kw)

    async def adecode(self, *a, **kw):
        """
        Applies ``value.decode()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        async for result in self:
            yield result.decode(*a, **kw)

    def decode(self, *a, **kw):
        """
        Applies ``value.decode()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        for result in self:
            yield result.decode(*a, **kw)

    async def ajson_loads(self, *a, **kw):
        """
        Applies ``json.loads()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        async for result in self:
            yield json.loads(result, *a, **kw)

    def json_loads(self, *a, **kw):
        """
        Applies ``json.loads()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        for result in self:
            yield json.loads(result, *a, **kw)

    async def ajson_dumps(self, *a, **kw):
        """
        Applies ``json.dumps()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        async for result in self:
            yield json.dumps(result, *a, **kw)

    def json_dumps(self, *a, **kw):
        """
        Applies ``json.dumps()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        for result in self:
            yield json.dumps(result, *a, **kw)

    async def ahex(self, prefix=False):
        """
        Applies ``builtins.hex()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        start = 0 if prefix else 2
        async for result in self:
            yield hex(result)[start:]

    def hex(self, prefix=False):
        """
        Applies ``builtins.hex()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        _hex = builtins.hex
        start = 0 if prefix else 2
        for result in self:
            yield _hex(result)[start:]

    async def abytes(self, *a, **kw):
        """
        Applies ``builtins.bytes()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        async for result in self:
            yield bytes(result, *a, **kw)

    def bytes(self, *a, **kw):
        """
        Applies ``builtins.bytes()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        _bytes = builtins.bytes
        for result in self:
            yield _bytes(result, *a, **kw)

    async def abin(self, *a, **kw):
        """
        Applies ``builtins.bin()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        async for result in self:
            yield bin(result, *a, **kw)

    def bin(self, *a, **kw):
        """
        Applies ``builtins.bin()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        _bin = builtins.bin
        for result in self:
            yield _bin(result, *a, **kw)

    async def __aenter__(self):
        """
        Opens a context & yields ``self``.
        """
        await self.areset()
        return self

    def __enter__(self):
        """
        Opens a context & yields ``self``.
        """
        self.reset()
        return self

    async def __aexit__(
        self, exc_type=None, exc_value=None, traceback=None
    ):
        """
        Surpresses StopAsyncIteration exceptions within a context.
        Clears the cached results upon exit.
        """
        try:
            if exc_type == StopAsyncIteration:
                return True
        finally:
            await self.aclear()

    def __exit__(self, exc_type=None, exc_value=None, traceback=None):
        """
        Surpresses StopIteration exceptions within a context. Clears the
        cached results upon exit.
        """
        try:
            if exc_type == StopIteration:
                return True
        finally:
            self.clear()

    async def __aiter__(self, *, got=None):
        """
        Iterates over the wrapped async generator / coroutine & produces
        its values directly, or from alru_cache if an eager calculation
        has already computed the gererators values.
        """
        await self.areset()
        if self.precomputed:
            async with self.aauto_cache() as results:
                for result in results:
                    await asleep(0)
                    yield result
        else:
            asend = self.gen.asend
            while True:
                try:
                    got = yield await asend(got)
                except StopAsyncIteration:
                    break

    def __iter__(self, *, got=None):
        """
        Iterates over the wrapped generator / coroutine and produces its
        values directly, or from lru_cache if an eager calculation has
        already computed the gererators values.
        """
        self.reset()
        if self.precomputed:
            with self.auto_cache() as results:
                for result in results:
                    yield result
        else:
            send = self.gen.send
            while True:
                try:
                    got = yield send(got)
                except StopIteration:
                    break

    def __next__(self):
        """
        Allows calling ``builtins.next`` on async / sync generators &
        coroutines.
        """
        if self._async:
            return self.anext()
        else:
            return self.next()

    async def _acall(self, got=None):
        """
        Allows the wrapped async generator / coroutine to receive
        ``asend`` values by using the class' __call__ method.
        """
        return await self.gen.asend(got)

    def _call(self, got=None):
        """
        Allows the wrapped generator / coroutine to receive ``send``
        values by using the class' __call__ method.
        """
        return self.gen.send(got)

    def __reversed__(self):
        """
        Allows reversing async/sync generators, but must compute all
        values first to do so.
        """
        if self._async:
            return self.areversed()
        else:
            return self.reversed()

    def __repr__(self, *, debugging=None):
        """
        Displays the string which, if ``exec``'d, would yield a new
        equivalent object.
        """
        a = self.args
        kw = self.kwargs
        func = self.func.__qualname__
        cls = self.__class__.__qualname__
        tab = f"{linesep + 4 * ' '}"
        _repr = f"{cls}({tab}func={func},{tab}"
        if debugging == None:
            debugging = DebugControl.is_debugging()
        if not debugging:
            _repr += f"args={len(a)},{tab}kwargs={len(kw)},{linesep})"
            return _repr
        else:
            _repr += f"*{a},{tab}**{kw},{linesep})"
            return _repr

    def _set_index(self, index, spanner=builtins.range, _max=bits[256]):
        """
        Interprets the slice or int passed into __getitem__ into a
        range object.
        """
        if isinstance(index, int):
            step = 1
            start = index
            stop = index + 1
        else:
            step = index.step if isinstance(index.step, int) else 1
            start = index.start if isinstance(index.start, int) else 0
            stop = index.stop if isinstance(index.stop, int) else _max
        return start, stop, step, spanner(start, stop, step)

    async def _agetitem(self, index):
        """
        Allows indexing of async generators to yield the values
        associated with the slice or integer passed into the brackets.
        """
        start, stop, step, span = self._set_index(index)
        next_target = iter(span).__next__
        with ignore(StopIteration):
            target = next_target()
            async for match, result in Enumerate(self):
                if target == match:
                    yield result
                    target = next_target()

    def _getitem(self, index):
        """
        Allows indexing of generators to yield the values associated
        with the slice or integer passed into the brackets.
        """
        start, stop, step, span = self._set_index(index)
        next_target = iter(span).__next__
        with ignore(StopIteration):
            target = next_target()
            for match, result in enumerate(self):
                if target == match:
                    yield result
                    target = next_target()

    def __getitem__(self, index):
        """
        Allows indexing of generators & async generators to yield the
        values associated with the slice or integer passed into the
        brackets.
        """
        if self._async:
            return self._agetitem(index)
        else:
            return self._getitem(index)

    for method in lazy_generators.union(eager_generators):
        vars()[method] = comprehension()(vars()[method])


async def anext(coro_iterator):
    """
    Creates an asynchronous version of the ``builtins.next`` function.
    """
    return await coro_iterator.__anext__()


@comprehension()
async def azip(*coros):
    """
    Creates an asynchronous version of the ``builtins.zip`` function
    which is wrapped by the ``Comprende`` class.
    """
    coros = [_aiter.root(coro).__anext__ for coro in coros]
    try:
        while True:
            yield [await coro() for coro in coros]
    except StopAsyncIteration:
        pass


@comprehension()
def _zip(*iterables):
    """
    Creates a synchronous version of the zip builtin function which is
    wrapped by the ``Comprende`` class.
    """
    for results in zip(*iterables):
        yield results


@comprehension()
async def _aiter(iterable):
    """
    Creates an async version of ``builtins.iter`` which is wrapped by
    the ``Comprende`` class.
    """
    if is_async_iterable(iterable):
        async for result in iterable:
            yield result
    else:
        for result in iterable:
            await asleep(0)
            yield result


@comprehension()
def _iter(iterable, *a, **kw):
    """
    Creates an synchronous version of ``builtins.iter`` that is wrapped
    by the ``Comprende`` class.
    """
    for result in iter(iterable, *a, **kw):
        yield result


@comprehension()
async def acycle(iterable):
    """
    Unendingly cycles in order over the elements of an async iterable.
    """
    results = []
    async for result in iterable:
        yield result
        results.append(result)
    if results:
        while True:
            for result in results:
                await asleep(0)
                yield result


@comprehension()
def cycle(iterable):
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
async def acount(start=0):
    """
    Unendingly yields incrementing numbers starting from ``start``.
    """
    index = start
    while True:
        await asleep(0)
        yield index
        index += 1


@comprehension()
def count(start=0):
    """
    Unendingly yields incrementing numbers starting from ``start``.
    """
    index = start
    while True:
        yield index
        index += 1


@comprehension()
async def abytes_count(start=0, *, length=8, byte_order="big"):
    """
    Unendingly yields incrementing numbers starting from ``start``.
    """
    index = start
    while True:
        await asleep(0)
        yield index.to_bytes(length, byte_order)
        index += 1


@comprehension()
def bytes_count(start=0, *, length=8, byte_order="big"):
    """
    Unendingly yields incrementing numbers starting from ``start``.
    """
    index = start
    while True:
        yield index.to_bytes(length, byte_order)
        index += 1


@comprehension()
async def aunpack(iterable=None):
    """
    Runs through an iterable &/or async iterable & yields elements one
    at a time.
    """
    if iterable == None:
        iterable = acount.root()
    if is_async_iterable(iterable):
        async for item in iterable:
            yield item
    else:
        for item in iterable:
            await asleep(0)
            yield item


@comprehension()
def unpack(iterable=None):
    """
    Runs through an iterable & yields elements one at a time.
    """
    if iterable == None:
        iterable = count.root()
    for result in iterable:
        yield result


@comprehension()
async def abirth(base="", *, stop=True):
    """
    Yields ``base`` in its entirety once by default. If ``stop`` is set
    `Falsey` then it's yielded unendingly. Useful for spawning a value
    into chainable ``Comprende`` generators.
    """
    if stop:
        yield base
    else:
        while True:
            await asleep(0)
            yield base


@comprehension()
def birth(base="", *, stop=True):
    """
    Yields ``base`` in its entirety once by default. If ``stop`` is set
    `Falsey` then it's yielded unendingly. Useful for spawning a value
    into chainable ``Comprende`` generators.
    """
    if stop:
        yield base
    else:
        while True:
            yield base


@comprehension()
async def adata(sequence="", size=256, *, stop="__length_end__"):
    """
    Runs through a sequence & yields ``size`` sized chunks of the
    sequence one chunk at a time. ``stop`` is the total number of
    elements in ``sequence`` allowed to be yielded from the generator.
    By default it yields all elements in the sequence. Custom use of
    ``stop`` can be very bug-prone: if the last segment of ``sequence``
    would push the total amount yielded over ``stop`` elements, then the
    entire last segment is dropped.
    """
    length = len(sequence)
    if stop == "__length_end__" or stop > length + size:
        stop = length + size
    else:
        stop += 1   # <- Make stop inclusive (how many elements allowed)
    async for last, end in azip(
        range(0, stop, size), range(size, stop, size)
    ):
        yield sequence[last:end]


@comprehension()
def data(sequence="", size=256, *, stop="__length_end__"):
    """
    Runs through a sequence & yields ``size`` sized chunks of the
    sequence one chunk at a time. ``stop`` is the total number of
    elements in ``sequence`` allowed to be yielded from the generator.
    By default it yields all elements in the sequence. Custom use of
    ``stop`` can be very bug-prone: if the last segment of ``sequence``
    would push the total amount yielded over ``stop`` elements, then the
    entire last segment is dropped.
    """
    length = len(sequence)
    if stop == "__length_end__" or stop > length + size:
        stop = length + size
    else:
        stop += 1   # <- Make stop inclusive (how many elements allowed)
    for last, end in zip(range(0, stop, size), range(size, stop, size)):
        yield sequence[last:end]


@comprehension()
async def aorder(*iterables):
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
                await asleep(0)
                yield result


@comprehension()
def order(*iterables):
    """
    Takes a collection of iterables & exhausts them one at a time from
    left to right.
    """
    for iterable in iterables:
        for result in iterable:
            yield result


@comprehension()
async def askip(iterable, steps=1):
    """
    An async generator that produces the values yielded from ``iterable``
    once every ``steps`` number of iterations, otherwise produces
    ``None`` until ``iterable`` is exhausted.
    """
    async for result in iterable:
        for _ in range(steps):
            yield
        await asleep(0)
        yield result


@comprehension()
def skip(iterable, steps=1):
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
async def acompact(iterable, batch_size=1):
    """
    An async generator that yields ``batch_size`` number of elements
    from an async or sync ``iterable`` at a time.
    """
    stack = {}
    indexes = list(reversed(range(batch_size)))
    async for toggle, item in azip(cycle(indexes), iterable):
        stack[toggle] = item
        if not toggle:
            yield list(stack.values())
            stack.clear()
    if stack:
        yield list(stack.values())


@comprehension()
def compact(iterable, batch_size=1):
    """
    A generator that yields ``batch_size`` number of elements from an
    ``iterable`` at a time.
    """
    stack = {}
    indexes = list(reversed(range(batch_size)))
    for toggle, item in zip(cycle(indexes), iterable):
        stack[toggle] = item
        if not toggle:
            yield list(stack.values())
            stack.clear()
    if stack:
        yield list(stack.values())


@comprehension()
async def apopleft(queue):
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
def popleft(queue):
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
async def apop(queue):
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
def pop(queue):
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
async def apick(names=None, mapping=None):
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
def pick(names=None, mapping=None):
    """
    Does a bracketed lookup on ``mapping`` for each name in ``names``.
    """
    for name in names:
        try:
            yield mapping[name]
        except KeyError:
            break


@comprehension()
async def await_on(queue, *, probe_frequency=0.0001, timeout=1):
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
def wait_on(queue, *, probe_frequency=0.0001, timeout=1):
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
        await asleep(0)
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
async def aseedrange(iterations, *, seed):
    """
    This async generator transforms ``builtins.range`` into a producer
    of ``iterations`` number of multiples of ``seed``.
    """
    for salt in seedrange.root(iterations, seed=seed):
        await asleep(0)
        yield salt


@comprehension()
def seedrange(iterations, *, seed):
    """
    This generator transforms ``builtins.range`` into a producer of
    ``iterations`` number of multiples of ``seed``.
    """
    for salt in range(seed, seed + (seed * iterations), seed):
        yield salt


async def ato_b64(binary=None, encoding="utf-8"):
    """
    A version of ``base64.standard_b64encode``.
    """
    if type(binary) != bytes:
        binary = bytes(binary, encoding)
    await asleep(0)
    return base64.standard_b64encode(binary)


def to_b64(binary=None, encoding="utf-8"):
    """
    A version of ``base64.standard_b64encode``.
    """
    if type(binary) != bytes:
        binary = bytes(binary, encoding)
    return base64.standard_b64encode(binary)


async def afrom_b64(base_64=None, encoding="utf-8"):
    """
    A version of ``base64.standard_b64decode``.
    """
    if type(base_64) != bytes:
        base_64 = base_64.encode(encoding)
    await asleep(0)
    return base64.standard_b64decode(base_64)


def from_b64(base_64=None, encoding="utf-8"):
    """
    A version of ``base64.standard_b64decode``.
    """
    if type(base_64) != bytes:
        base_64 = base_64.encode(encoding)
    return base64.standard_b64decode(base_64)


async def axi_mix(bytes_hash, size=8):
    """
    Xors subsequent ``size`` length segments of ``bytes_hash`` with each
    other to condense the bytes hash down to a ``size`` bytes.
    """
    result = 0
    async for chunk in adata.root(bytes_hash, size=size):
        result ^= int.from_bytes(chunk, "big")
    return result.to_bytes(size, "big")


def xi_mix(bytes_hash, size=8):
    """
    Xors subsequent ``size`` length segments of ``bytes_hash`` with each
    other to condense the bytes hash down to ``size`` bytes.
    """
    result = 0
    for chunk in data.root(bytes_hash, size=size):
        result ^= int.from_bytes(chunk, "big")
    return result.to_bytes(size, "big")


async def ahash_bytes(*collection, hasher=sha3_512, on=b""):
    """
    Joins all bytes objects in ``collection`` ``on`` a value & returns
    the digest after passing all the joined bytes into the ``hasher``.
    """
    await asleep(0)
    return hasher(on.join(collection)).digest()


def hash_bytes(*collection, hasher=sha3_512, on=b""):
    """
    Joins all bytes objects in ``collection`` ``on`` a value & returns
    the digest after passing all the joined bytes into the ``hasher``.
    """
    return hasher(on.join(collection)).digest()


async def asha_256(*args, sha256=sha3_256):
    """
    A string-based version of ``hashlib.sha3_256``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    await asleep(0)
    return sha256(str(args).encode()).hexdigest()


def sha_256(*args, sha256=sha3_256):
    """
    A string-based version of ``hashlib.sha3_256``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    return sha256(str(args).encode()).hexdigest()


async def asha_256_hmac(data, *, key):
    """
    An HMAC-esque version of the ``hashlib.sha3_512`` function.
    """
    return await asha_256(key, await asha_256(key, data))


def sha_256_hmac(data, *, key):
    """
    An HMAC-esque version of the ``hashlib.sha3_512`` function.
    """
    return sha_256(key, sha_256(key, data))


async def asha_512(*data, sha512=sha3_512):
    """
    A string-based version of ``hashlib.sha3_512``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    await asleep(0)
    return sha512(str(data).encode()).hexdigest()


def sha_512(*args, sha512=sha3_512):
    """
    A string-based version of ``hashlib.sha3_512``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    return sha512(str(args).encode()).hexdigest()


async def asha_512_hmac(data, *, key):
    """
    An HMAC-esque version of the ``hashlib.sha3_512`` function.
    """
    return await asha_512(key, await asha_512(key, data))


def sha_512_hmac(data, *, key):
    """
    An HMAC-esque version of the ``hashlib.sha3_512`` function.
    """
    return sha_512(key, sha_512(key, data))


class Hasher:
    """
    A class that creates instances to mimmic & add functionality to the
    hashing object passed in during initialization.
    """

    xi_mix = xi_mix
    axi_mix = axi_mix
    _MASK = commons.UNIFORM_PRIME_512

    def __init__(self, data=b"", *, obj=sha3_512):
        """
        Copies over the object dictionary of the ``obj`` hashing object.
        """
        self._obj = obj(data)
        for method in dir(obj):
            if not method.startswith("_"):
                setattr(self, method, getattr(self._obj, method))

    async def ahash(self, *data, on=b""):
        """
        Receives any number of arguments of bytes type ``data`` &
        updates the instance with them all sequentially.
        """
        await asleep(0)
        self.update(on.join(data))
        await asleep(0)
        return self.digest()

    def hash(self, *data, on=b""):
        """
        Receives any number of arguments of bytes type ``data`` &
        updates the instance with them all sequentially.
        """
        self.update(on.join(data))
        return self.digest()

    @classmethod
    async def amask_byte_order(
        cls, sequence, *, base=primes[256][-1], mod=BasePrimeGroups.MOD_512
    ):
        """
        Uses each byte in a ``sequence`` as multiples along with ``base``
        & takes that result ``mod`` a number to mask the order of the
        bytes in the sequence. This final result is returned back to the
        user as a new bytes sequence. Both ``mod`` & ``base`` should be
        prime numbers.
        """
        if base == mod:
            raise ValueError("``base`` & ``mod`` must be different!")
        product = 1
        await asleep(0)
        for byte in bytes(sequence):
            product *= byte + 1    # <- Ensure non-zero
        await asleep(0)
        masked_value = (base * product * cls._MASK) % mod
        return masked_value.to_bytes(math.ceil(mod.bit_length() / 8), "big")

    @classmethod
    def mask_byte_order(
        cls, sequence, *, base=primes[256][-1], mod=BasePrimeGroups.MOD_512
    ):
        """
        Uses each byte in a ``sequence`` as multiples along with ``base``
        & takes that result ``mod`` a number to mask the order of the
        bytes in the sequence. This final result is returned back to the
        user as a new bytes sequence. Both ``mod`` & ``base`` should be
        prime numbers.
        """
        if base == mod:
            raise ValueError("``base`` & ``mod`` must be different!")
        product = 1
        for byte in bytes(sequence):
            product *= byte + 1    # <- Ensure non-zero
        masked_value = (base * product * cls._MASK) % mod
        return masked_value.to_bytes(math.ceil(mod.bit_length() / 8), "big")


async def abase_to_decimal(string, base, table=ASCII_ALPHANUMERIC):
    """
    Convert ``string`` in numerical ``base`` into decimal integer.
    """
    power = 1
    result = 0
    base_table = table[:base]
    await asleep(0)
    for char in reversed(string):
        if base_table.find(char) == -1:
            raise ValueError("Invalid base with given string or table.")
        result += base_table.find(char) * power
        power = power * base
    await asleep(0)
    return result


def base_to_decimal(string, base, table=ASCII_ALPHANUMERIC):
    """
    Convert ``string`` in numerical ``base`` into decimal integer.
    """
    power = 1
    result = 0
    base_table = table[:base]
    for char in reversed(string):
        if base_table.find(char) == -1:
            raise ValueError("Invalid base with given string or table.")
        result += base_table.find(char) * power
        power = power * base
    return result


async def ainverse_int(number, base, table=ASCII_ALPHANUMERIC):
    """
    Convert an ``number`` back into a string in numerical ``base``.
    """
    digits = []
    base_table = table[:base]
    await asleep(0)
    while number:
        digits.append(base_table[number % base])
        number //= base
    await asleep(0)
    if digits:
        digits.reverse()
        return digits[0].__class__().join(digits)
    else:
        return table[0]


def inverse_int(number, base, table=ASCII_ALPHANUMERIC):
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
        return digits[0].__class__().join(digits)
    else:
        return table[0]


async def abuild_tree(depth=4, width=2, leaf=None):
    """
    Recursively builds a tree ``depth`` branches deep with ``width``
    branches per level, & places the placeholder value ``leaf`` at each
    endpoint of the tree.
    """
    if depth < 0:
        raise ValueError("The ``depth`` argument cannot be < 0")
    elif width <= 0:
        raise ValueError("The ``width`` argument cannot be <= 0")
    elif depth > 0:
        await asleep(0)
        next_depth = depth - 1
        return {
            branch: await abuild_tree(next_depth, width, leaf)
            for branch in range(width)
        }
    else:
        return leaf


def build_tree(depth=4, width=2, leaf=None):
    """
    Recursively builds a tree ``depth`` branches deep with ``width``
    branches per level, & places the placeholder value ``leaf`` at each
    endpoint of the tree.
    """
    if depth < 0:
        raise ValueError("The ``depth`` argument cannot be < 0")
    elif width <= 0:
        raise ValueError("The ``width`` argument cannot be <= 0")
    elif depth > 0:
        next_depth = depth - 1
        return {
            branch: build_tree(next_depth, width, leaf)
            for branch in range(width)
        }
    else:
        return leaf


__extras = {
    "AsyncInit": AsyncInit,
    "BytesIO": BytesIO,
    "Comprende": Comprende,
    "Enumerate": Enumerate,
    "Hasher": Hasher,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "abase_to_decimal": abase_to_decimal,
    "abuild_tree": abuild_tree,
    "abirth": abirth,
    "abytes_count": abytes_count,
    "acompact": acompact,
    "acount": acount,
    "acustomize_parameters": acustomize_parameters,
    "acycle": acycle,
    "adata": adata,
    "adepad_bytes": adepad_bytes,
    "afrom_b64": afrom_b64,
    "ahash_bytes": ahash_bytes,
    "aignore": aignore,
    "ainverse_int": ainverse_int,
    "aiter": _aiter,
    "amake_timestamp": amake_timestamp,
    "anext": anext,
    "aorder": aorder,
    "apad_bytes": apad_bytes,
    "apick": apick,
    "apop": apop,
    "apopleft": apopleft,
    "arange": arange,
    "aseedrange": aseedrange,
    "asha_256": asha_256,
    "asha_256_hmac": asha_256_hmac,
    "asha_512": asha_512,
    "asha_512_hmac": asha_512_hmac,
    "askip": askip,
    "ato_b64": ato_b64,
    "aunpack": aunpack,
    "await_on": await_on,
    "axi_mix": axi_mix,
    "azip": azip,
    "base_to_decimal": base_to_decimal,
    "build_tree": build_tree,
    "birth": birth,
    "bytes_count": bytes_count,
    "compact": compact,
    "comprehension": comprehension,
    "convert_static_method_to_member": convert_static_method_to_member,
    "count": count,
    "customize_parameters": customize_parameters,
    "cycle": cycle,
    "data": data,
    "depad_bytes": depad_bytes,
    "display_exception_info": display_exception_info,
    "from_b64": from_b64,
    "hash_bytes": hash_bytes,
    "ignore": ignore,
    "inverse_int": inverse_int,
    "is_async_function": is_async_function,
    "is_async_gen_function": is_async_gen_function,
    "is_async_generator": is_async_generator,
    "is_async_iterable": is_async_iterable,
    "is_async_iterator": is_async_iterator,
    "is_awaitable": is_awaitable,
    "is_exception": is_exception,
    "is_generator": is_generator,
    "is_generator_function": is_generator_function,
    "is_iterable": is_iterable,
    "is_iterator": is_iterator,
    "iter": _iter,
    "make_timestamp": make_timestamp,
    "order": order,
    "pad_bytes": pad_bytes,
    "pick": pick,
    "pop": pop,
    "popleft": popleft,
    "range": _range,
    "seedrange": seedrange,
    "sha3_256": sha3_256,
    "sha3_512": sha3_512,
    "sha_256": sha_256,
    "sha_256_hmac": sha_256_hmac,
    "sha_512": sha_512,
    "sha_512_hmac": sha_512_hmac,
    "size_of": size_of,
    "skip": skip,
    "src": src,
    "to_b64": to_b64,
    "unpack": unpack,
    "wait_on": wait_on,
    "xi_mix": xi_mix,
    "zip": _zip,
}


generics = Namespace.make_module("generics", mapping=__extras)

