# This file is part of aiootp, an asynchronous one-time-pad based crypto
# and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "generics",
    "Comprende",
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
    "apopleft",
    "popleft",
    "ajson_decode",
    "json_decode",
    "ajson_encode",
    "json_encode",
    "asha_256",
    "sha_256",
    "asha_256_hmac",
    "sha_256_hmac",
    "asha_512",
    "sha_512",
    "asha_512_hmac",
    "sha_512_hmac",
    "anc_256",
    "nc_256",
    "anc_256_hmac",
    "nc_256_hmac",
    "anc_512",
    "nc_512",
    "anc_512_hmac",
    "nc_512_hmac",
]


__doc__ = """
A collection of basic utilities for simplifying & supporting the rest of
the codebase.
"""


import re
import json
import heapq
import random
import binascii
import pybase64
import builtins
import itertools
import aioitertools
from sys import getsizeof
from functools import wraps
from functools import lru_cache
from async_lru import alru_cache
from types import GeneratorType
from types import AsyncGeneratorType
from random import uniform
from sympy import isprime as is_prime
from contextlib import contextmanager
from hashlib import sha3_256
from hashlib import sha3_512
from collections import deque
from collections.abc import Iterable
from collections.abc import Iterator
from collections.abc import AsyncIterable
from collections.abc import AsyncIterator
from aiocontext import async_contextmanager
from inspect import getsource
from inspect import isawaitable as is_awaitable
from inspect import iscoroutinefunction as is_async_function
from inspect import isasyncgenfunction as is_async_gen_function
from inspect import isgeneratorfunction as is_generator_function
from .commons import *
from .asynchs import *
from .asynchs import time
from . import DEBUG_MODE


count = itertools.count
aiter = aioitertools.iter
acount = aioitertools.count


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
                await switch()
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


class MemberFromStaticMethod:
    @staticmethod
    def convert(self, static_method_name, static_method, *args, **kwargs):
        @wraps(static_method)
        def wrapped_static_method(*a, **kw):
            try:
                new_args = list(args)
                for index, new_arg in enumerate(a):
                    new_args[index] = new_arg
                new_kwargs = dict(kwargs)
                new_kwargs.update(kw)
            except IndexError as error:
                raise NotImplementedError(
                    "Sending args into a method after they were replaced."
                ) from error
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
    They will proc in ``aiootp.generics.aignore`` async context manager if:

    1.  {__slots__[0]} - when the ignored exceptions are raised
    within the context.

    But always,
    2.  {__slots__[1]} - at the end of the context.
    """

    def __init__(self):
        async def placeholder():
            return self.read_me

        self.aexcept_code = placeholder
        self.afinally_code = placeholder


class RelayExceptions:
    __slots__ = ["except_code", "finally_code"]

    read_me = f"""
    Overwrite {__slots__} methods with custom functions.
    They will proc in ``aiootp.generics.ignore`` context manager if:

    1.  {__slots__[0]} - when the ignored exceptions are raised
    within the context.

    But always,
    2.  {__slots__[1]} - at the end of the context.
    """

    def __init__(self):
        def placeholder():
            return self.read_me

        self.except_code = placeholder
        self.finally_code = placeholder


@async_contextmanager
async def aignore(*exceptions, display=False):
    """
    Usage example:

    async with aignore(TypeError):
        c = a + b
        # exception is surpressed if adding a and b raises a TypeError

    Or, dynamically choose which exceptions to catch, and call custom
    cleanup code. ->

    async def cleanup():
        await database.asave()

    async with ignore() as error_relay:
        error_relay.aexcept_code = cleanup
        # This will close ``database`` if either DynamicException or
        # IOError are raised within the block.

        error_relay.afinally_code = cleanup
        # This will ensure close is called on ``database`` in a finally
        # block.
    """
    try:
        exceptions = exceptions if exceptions else ExampleException
        relay = AsyncRelayExceptions()
        yield relay
    except exceptions as error:
        if display:
            display_exception_info(error)
        await relay.aexcept_code()
    except Exception as error:
        if display:
            display_exception_info(error)
        raise error
    finally:
        await relay.afinally_code()


@contextmanager
def ignore(*exceptions, display=False):
    """
    Usage example:

    with ignore(TypeError):
        c = a + b
        # exception is surpressed if adding a and b raises a TypeError

    Or, dynamically choose which exceptions to catch, and call custom
    cleanup code. ->

    def cleanup():
        database.save()

    with ignore(DynamicException, IOError) as error_relay:
        error_relay.except_code = cleanup
        # This will close ``database`` if either DynamicException or
        # IOError are raised within the block.

        error_relay.finally_code = cleanup
        # This will ensure close is called on ``database`` in a finally
        # block.
    """
    try:
        exceptions = exceptions if exceptions else ExampleException
        relay = RelayExceptions()
        yield relay
    except exceptions as error:
        relay.except_code()
        if display:
            display_exception_info(error)
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
        # This will send in ``None``
        sum_of_x_y = example()
        assert sum_of_x_y == 3

        # This will cause the generator to reach the return and exit ->
        example(z)

    # The result returned from the generator is now available ->
    product_of_x_y_z = example.result()
    assert product_of_x_y_z == 6

    # The ``example`` variable is actually the Comprende object, which
    # redirects values to the wrapped generator's ``send()`` method
    # using the instance's ``__call__()`` method.  It's still available
    # after the context closes ->
    assert example.__class__.__name__ == "Comprende"

    for result in Comprende(gen, 1, 2).sha_256():
        # This will hash each output of a generator and yield the hash.

    ciphertext = []
    key = aiootp.csprng()
    for result in Comprende(gen, 1, 2).str().encrypt(key):
        # This will stringify each output of a generator, then encrypt
        # each result, and yield the ciphertext.
        ciphertext.append(result)

    for result in aiootp.unpack(ciphertext).decrypt(key):
        # This will yield the original results in plaintext
        print(result)

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
        # This will send in ``None``
        sum_of_x_y = await example()
        assert sum_of_x_y == 3

        # This will cause the generator to reach the return & exit the
        # context manager ->
        await example(z)

    # The result returned from the generator is now available ->
    product_of_x_y_z = await example.aresult()
    assert product_of_x_y_z == 6

    # The ``example`` variable is actually the Comprende object, which
    # redirects values to the wrapped generator's ``asend()`` method
    # using the instance's ``__call__()`` method. It's still available
    # after the context closes ->
    assert example.__class__.__name__ == "Comprende"

    async for result in Comprende(gen, 1, 2).asha_256():
        # This will hash each output of a generator and yield the hash.

    ciphertext = []
    key = await aiootp.acsprng()
    async for result in Comprende(gen, 1, 2).astr().aencrypt(key):
        # This will stringify each output of a generator, then encrypt
        # each result, and yield the ciphertext.
        ciphertext.append(result)

    async for result in aiootp.aunpack(ciphertext).adecrypt(key):
        # This will yield the original results in plaintext


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
        "aencrypt",
        "encrypt",
        "adecrypt",
        "decrypt",
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
        "ato_base",
        "to_base",
        "afrom_base",
        "from_base",
        "azfill",
        "zfill",
        "aslice",
        "slice",
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
        "asha_256",
        "sha_256",
        "asha_256_hmac",
        "sha_256_hmac",
    }

    eager_generators = {"aheappop", "heappop", "areversed", "reversed"}

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
        "acache_check",
        "cache_check",
        "aclass_clear",
        "class_clear",
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
        self._runsum = ""
        self._thrown = deque()
        self._return = deque()
        if is_async_gen_function(func):
            self.func = func
            self.gen = self.__set_async()
            self.iterator = aiter(self.gen)
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
            yield self
        except GeneratorExit as done:
            raise done
        except RuntimeError as done:
            if self.ASYNC_GEN_DONE not in done.args:
                raise done
        except StopAsyncIteration:
            pass
        except UserWarning as done:
            if done.args:
                self._return.append(done.args[0])

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
        except StopIteration as done:
            if getattr(done, "value", None) != None:
                self._return.append(done.value)
        except UserWarning as done:
            if done.args:
                self._return.append(done.args[0])

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
            yield self
        except UserWarning:
            if result != None:
                raise UserWarning(result)
            raise UserWarning(await source.aresult(exit=True))

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
            yield self
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
        await self(None)
        return self

    def prime(self):
        """
        Resets the instance's async wrapper generator & ``asend``s in a
        ``None`` value to prime the generator, i.e. bringing it to the
        first yield statement.
        """
        self.reset()
        self(None)
        return self

    async def asend(self, got=None):
        """
        Copies the wrapped async generator's ``asend`` method behavior.
        This is equivalent to an async Comprende generator's ``__call__``
        method.
        """
        return await self(got)

    def send(self, got=None):
        """
        Copies the wrapped sync generator's ``send`` method behavior.
        This is equivalent to a sync Comprende generator's ``__call__``
        method.
        """
        return self(got)

    async def athrow(self, *a, **kw):
        """
        This is quivalent to a wrapped async generator's ``athrow``
        method.
        """
        await self.gen.athrow(*a, **kw)
        return await self.aresult()

    def throw(self, *a, **kw):
        """
        This is quivalent to a wrapped sync generator's ``throw`` method.
        """
        self.gen.throw(*a, **kw)
        return self.result()

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
            with ignore(TypeError, display=not silent):
                await gather(self(UserWarning()), return_exceptions=True)
        elif exit:
            await self(UserWarning())
        with ignore(IndexError, display=not silent):
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

    async def athrows(self):
        """
        When causing an async generator to exit using ``self.aresult()``,
        the exception is appended to the instance ``self._thrown`` queue.
        Normally this doesn't have significance, but users can adapt this
        queue & override ``self.aresult`` to send in relevant values
        instead.
        """
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

    async def anext(self):
        """
        Advances the wrapped async generator to the next yield.
        """
        return await self.iterator.asend(None)

    def next(self):
        """
        Advances the wrapped sync generator to the next yield.
        """
        return builtins.next(self.iterator)

    @classmethod
    async def aclear_class(cls):
        """
        Allows users to manually clear the cache of all the class'
        instances.
        """
        await cls().aclear(cls=True)

    @classmethod
    def clear_class(cls):
        """
        Allows users to manually clear the cache of all the class'
        instances.
        """
        cls().clear(cls=True)

    def __del__(self):
        """
        Attempts to cleanup instance caches when deleted or garbage
        collected to reduce memory overhead.
        """
        self.clear()
        if hasattr(self, "gen"):
            del self.gen

    async def aclear(self, *, cls=False):
        """
        Allows users to manually clear the cache of an instance, or if
        ``cls`` is ``True`` clears the cache of every instance.
        """
        try:
            if cls == True:
                for instance in dict(self.__class__._cached).values():
                    await instance.aclear()
            elif self.precomputed != False:
                del self.__class__._cached[self.runsum]
                async for cache in self._acache_has():
                    cache.cache_clear()
        finally:
            self._runsum = ""

    def clear(self, *, cls=False):
        """
        Allows users to manually clear the cache of an instance, or if
        ``cls`` is ``True`` clears the cache of every instance.
        """
        try:
            if cls == True:
                for instance in dict(self.__class__._cached).values():
                    instance.clear()
            elif self.precomputed != False:
                del self.__class__._cached[self.runsum]
                for cache in self._cache_has():
                    cache.cache_clear()
        finally:
            self._runsum = ""

    async def _acache_has(self):
        """
        Returns the lru cached methods of an instance in an iterable.
        """
        if hasattr(self, "_cache_yield"):
            await switch()
            yield self._cache_yield
        if hasattr(self, "_acache_yield"):
            await switch()
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
            results = []
            async for result in self:
                results.append(result)
            return results

        self._runsum = await self._amake_runsum()
        self._acache_yield = _acache_yield

    def _set_cache(self):
        """
        Creates a per-instance function that returns precomputed results
        with lru cache turned on to save on speed for instances that have
        called sync methods or generators which do eager computation of
        a generator's entire result set.
        """
        @lru_cache(maxsize=2)
        def _cache_yield(runsum=None):
            results = []
            for result in self:
                results.append(result)
            return results

        self._runsum = self._make_runsum()
        self._cache_yield = _cache_yield

    @classmethod
    async def _amake_runsum(*args, low=bits[512], high=bits[513]):
        """
        Calculates a 512-bit pseudo-random hex string id to instances
        to mark themselves as having cached results.
        """
        return await asha_512(
            int(uniform(low, high)) % random.choice(primes[256]), *args
        )

    @classmethod
    def _make_runsum(*args, low=bits[512], high=bits[513]):
        """
        Calculates a 512-bit pseudo-random hex string id to instances
        to mark themselves as having cached results.
        """
        return sha_512(
            int(uniform(low, high)) % random.choice(primes[256]), *args
        )

    @property
    def runsum(self):
        """
        Returns an empty string if the instance generator has not cached
        any results. Returns the generator's 32-byte hex string id if it
        has.
        """
        return self._runsum[:32]

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
    async def acache_check(self):
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
    def cache_check(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``list``, then ``alru_cache``'s the result
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

    async def alist(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``list``, then ``alru_cache``'s the result
        & returns it.
        """
        async with self.acache_check() as results:
            return list(results)

    def list(self):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a ``list``, then ``alru_cache``'s the result
        & returns it.
        """
        with self.cache_check() as results:
            return list(results)

    async def adeque(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``collections.deque``, then ``alru_cache``'s
        the result & returns it.
        """
        async with self.acache_check() as results:
            return deque(results)

    def deque(self):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a ``collections.deque``, then ``alru_cache``'s
        the result & returns it.
        """
        with self.cache_check() as results:
            return deque(results)

    async def aset(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``set``, then ``alru_cache``'s the result
        & returns it.
        """
        async with self.acache_check() as results:
            return set(results)

    def set(self):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a ``set``, then ``alru_cache``'s the result
        & returns it.
        """
        with self.cache_check() as results:
            return set(results)

    async def adict(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``dict``, then ``alru_cache``'s the result
        & returns it.
        """
        async with self.acache_check() as results:
            return dict(results)

    def dict(self):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a ``dict``, then ``lru_cache``'s the result
        & returns it.
        """
        with self.cache_check() as results:
            return dict(results)

    async def ajoin(self, on=""):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together ``on`` the string that's passed, then
        ``alru_cache``'s the result & returns it.
        """
        async with self.acache_check() as results:
            return on.join(results)

    def join(self, on=""):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together ``on`` the string that's passed, then
        ``lru_cache``'s the result & returns it.
        """
        with self.cache_check() as results:
            return on.join(results)

    async def aexhaust(self):
        """
        Iterates over the entirety of the underlying Comprende async
        generator without yielding the results. Instead, it only returns
        the final yielded result.
        """
        async for result in self:
            pass
        if result:
            return result

    def exhaust(self):
        """
        Iterates over the entirety of the underlying Comprende sync
        generator without yielding the results. Instead, it only returns
        the final yielded result.
        """
        for result in self:
            pass
        if result:
            return result

    async def atimeout(self, delay=5):
        """
        Stops the instance's wrapped async generator after a ``delay``
        number of seconds. Can only cancel during times when ``self``
        async iteration has yielded control back to the caller.
        """
        current_time = time()
        async for result in self:
            if time() - current_time < delay:
                yield result
            else:
                break

    def timeout(self, delay=5):
        """
        Stops the instance's wrapped sync generator after a ``delay``
        number of seconds. Can only cancel during times when ``self``
        iteration has yielded control back to the caller.
        """
        current_time = time()
        for result in self:
            if time() - current_time < delay:
                yield result
            else:
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
        yield await self(None)
        async for food in aunpack(iterable):
            yield await self(food)

    def feed(self, iterable=None):
        """
        Takes in an iterable & sends those values into a sync coroutine
        which automates the process of driving a generator which is
        expecting results from a caller.
        """
        yield self(None)
        for food in iterable:
            yield self(food)

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
        food = self(None)
        yield food
        while True:
            food = self(food)
            yield food

    async def atag(self, of=None):
        """
        By default behaves like ``enumerate`` for each value yielded
        from the underlying Comprende async generator. Optionally,
        ``of`` can be passed a sync or async iterable & prepends those
        values to the generator's results.
        """
        names = of if of != None else acount()
        async for name, item in azip(names, self):
            yield name, item

    def tag(self, of=None):
        """
        By default behaves like ``enumerate`` for each value yielded
        from the underlying Comprende sync generator. Optionally, ``of``
        can be passed an iterable & prepends those values to the
        generator's results.
        """
        names = of if of != None else count()
        for name, item in zip(names, self):
            yield name, item

    async def aheappop(self, span=None, *, of=None):
        """
        Exhausts the underlying Comprende async generator upto ``span``
        number of iterations, then yields the results in sorted order
        based on the ``heapq.heappop`` function.
        """
        if of != None:
            async with aunpack(of)[:span] as accumulator:
                results = await accumulator.alist()
            heapq.heapify(results)
            async for result in self:
                try:
                    yield result, heapq.heappop(results)
                except IndexError:
                    break
        else:
            async with aunpack(self)[:span] as accumulator:
                results = await accumulator.alist()
            heapq.heapify(results)
            while True:
                try:
                    yield heapq.heappop(results)
                except IndexError:
                    break

    def heappop(self, span=None, *, of=None):
        """
        Exhausts the underlying Comprende sync generator upto ``span``
        number of iterations, then yields the results in sorted order
        based on the ``heapq.heappop`` function.
        """
        if of != None:
            with unpack(of)[:span] as accumulator:
                results = accumulator.list()
            heapq.heapify(results)
            for result in self:
                try:
                    yield result, heapq.heappop(results)
                except IndexError:
                    break
        else:
            with unpack(self)[:span] as accumulator:
                results = accumulator.list()
            heapq.heapify(results)
            while True:
                try:
                    yield heapq.heappop(results)
                except IndexError:
                    break

    async def areversed(self, span=None, *, of=None):
        """
        Exhausts the underlying Comprende async generator upto ``span``
        number of iterations, then yields the results in reversed order.
        """
        if of != None:
            async with unpack(of)[:span] as accumulator:
                results = await accumulator.adeque()
            async for prev, result in azip(self, reversed(results)):
                yield prev, result
        else:
            async with unpack(self)[:span] as accumulator:
                results = await accumulator.adeque()
            for result in reversed(results):
                await switch()
                yield result

    def reversed(self, span=None, *, of=None):
        """
        Exhausts the underlying Comprende sync generator upto ``span``
        number of iterations, then yields the results in reversed order.
        """
        if of != None:
            with unpack(of)[:span] as accumulator:
                results = accumulator.deque()
            for prev, result in zip(self, reversed(results)):
                yield prev, result
        else:
            with unpack(self)[:span] as accumulator:
                results = accumulator.deque()
            for result in reversed(results):
                yield result

    async def aresize(self, size=128, *, of=None):
        """
        Buffers the output from the underlying Comprende async generator
        to yield the results in chunks of length ``size``.
        """
        iterable_self = aiter(self)
        if of:
            new_source = aiter(of)
            result = await anext(new_source)
            while True:
                while len(result) >= size:
                    cache = result[size:]
                    yield await anext(iterable_self), result[:size]
                    result = cache
                try:
                    result += await anext(new_source)
                except StopAsyncIteration:
                    break
            if result:
                yield await anext(iterable_self), result
        else:
            result = await anext(iterable_self)
            while True:
                while len(result) >= size:
                    cache = result[size:]
                    yield result[:size]
                    result = cache
                try:
                    result += await anext(iterable_self)
                except StopAsyncIteration:
                    break
            if result:
                yield result

    def resize(self, size=128, *, of=None):
        """
        Buffers the output from the underlying Comprende sync generator
        to yield the results in chunks of length ``size``.
        """
        iterable_self = iter(self)
        if of:
            new_source = iter(of)
            result = next(new_source)
            while True:
                while len(result) >= size:
                    cache = result[size:]
                    yield next(iterable_self), result[:size]
                    result = cache
                try:
                    result += next(new_source)
                except StopIteration:
                    break
            if result:
                yield next(iterable_self), result
        else:
            result = next(iterable_self)
            while True:
                while len(result) >= size:
                    cache = result[size:]
                    yield result[:size]
                    result = cache
                try:
                    result += next(iterable_self)
                except StopIteration:
                    break
            if result:
                yield result

    async def ato_base64(self, *, of=None):
        """
        Applies ``pybase64.standard_b64encode`` conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, to_b64(result)
        else:
            async for result in self:
                yield to_b64(result)

    def to_base64(self, *, of=None):
        """
        Applies ``pybase64.standard_b64encode`` conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, to_b64(result)
        else:
            for result in self:
                yield to_b64(result)

    async def afrom_base64(self, *, of=None):
        """
        Applies ``pybase64.standard_b64decode`` conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, from_b64(result)
        else:
            async for result in self:
                yield from_b64(result)

    def from_base64(self, *, of=None):
        """
        Applies ``pybase64.standard_b64decode`` conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, from_b64(result)
        else:
            for result in self:
                yield from_b64(result)

    async def aint_to_ascii(self, *, of=None):
        """
        Applies a ``binascii`` int-to-ascii conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, result.to_bytes(
                    (result.bit_length() + 7) // 8, "big"
                ).decode()
        else:
            async for result in self:
                yield result.to_bytes(
                    (result.bit_length() + 7) // 8, "big"
                ).decode()

    def int_to_ascii(self, *, of=None):
        """
        Applies a ``binascii`` int-to-ascii conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        if of != None:
            for prev, result in azip(self, of):
                yield prev, result.to_bytes(
                    (result.bit_length() + 7) // 8, "big"
                ).decode()
        else:
            for result in self:
                yield result.to_bytes(
                    (result.bit_length() + 7) // 8, "big"
                ).decode()

    async def aascii_to_int(self, *, of=None):
        """
        Applies a ``binascii`` ascii-to-int conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, int.from_bytes(result.encode(), "big")
        else:
            async for result in self:
                yield int.from_bytes(result.encode(), "big")

    def ascii_to_int(self, *, of=None):
        """
        Applies a ``binascii`` ascii-to-int conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, int.from_bytes(result.encode(), "big")
        else:
            for result in self:
                yield int.from_bytes(result.encode(), "big")

    async def asha_512(self, salt=None, *, of=None):
        """
        Applies ``hashlib.sha3_512()`` to each value that's yielded
        from the underlying Comprende async generator before yielding
        the result.
        """
        if salt:
            if of != None:
                async for prev, result in azip(self, of):
                    yield prev, await asha_512(result, salt)
            else:
                async for result in self:
                    yield await asha_512(result, salt)
        else:
            if of != None:
                async for prev, result in azip(self, of):
                    yield prev, await asha_512(result)
            else:
                async for result in self:
                    yield await asha_512(result)

    def sha_512(self, salt=None, *, of=None):
        """
        Applies ``hashlib.sha3_512()`` to each value that's yielded
        from the underlying Comprende sync generator before yielding
        the result.
        """
        if salt:
            if of != None:
                for prev, result in zip(self, of):
                    yield prev, sha_512(result, salt)
            else:
                for result in self:
                    yield sha_512(result, salt)
        else:
            if of != None:
                for prev, result in zip(self, of):
                    yield prev, sha_512(result)
            else:
                for result in self:
                    yield sha_512(result)

    async def asha_512_hmac(self, key=None, salt=None, *, of=None):
        """
        Applies a ``hashlib.sha3_512()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        if salt:
            if of != None:
                async for prev, result in azip(self, of):
                    yield prev, await asha_512_hmac((result, salt), key=key)
            else:
                async for result in self:
                    yield await asha_512_hmac((result, salt), key=key)
        else:
            if of != None:
                async for prev, result in azip(self, of):
                    yield prev, await asha_512_hmac(result, key=key)
            else:
                async for result in self:
                    yield await asha_512_hmac(result, key=key)

    def sha_512_hmac(self, key=None, salt=None, *, of=None):
        """
        Applies a ``hashlib.sha3_512()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        if salt:
            if of != None:
                for prev, result in zip(self, of):
                    yield prev, sha_512_hmac((result, salt), key=key)
            else:
                for result in self:
                    yield sha_512_hmac((result, salt), key=key)
        else:
            if of != None:
                for prev, result in zip(self, of):
                    yield prev, sha_512_hmac(result, key=key)
            else:
                for result in self:
                    yield sha_512_hmac(result, key=key)

    async def asha_256(self, salt=None, *, of=None):
        """
        Applies ``hashlib.sha3_256()`` to each value that's yielded
        from the underlying Comprende async generator before yielding
        the result.
        """
        if salt:
            if of != None:
                async for prev, result in azip(self, of):
                    yield prev, await asha_256(result, salt)
            else:
                async for result in self:
                    yield await asha_256(result, salt)
        else:
            if of != None:
                async for prev, result in azip(self, of):
                    yield prev, await asha_256(result)
            else:
                async for result in self:
                    yield await asha_256(result)

    def sha_256(self, salt=None, *, of=None):
        """
        Applies ``hashlib.sha3_256()`` to each value that's yielded
        from the underlying Comprende sync generator before yielding the
        result.
        """
        if salt:
            if of != None:
                for prev, result in zip(self, of):
                    yield prev, sha_256(result, salt)
            else:
                for result in self:
                    yield sha_256(result, salt)
        else:
            if of != None:
                for prev, result in zip(self, of):
                    yield prev, sha_256(result)
            else:
                for result in self:
                    yield sha_256(result)

    async def asha_256_hmac(self, key=None, salt=None, *, of=None):
        """
        Applies a ``hashlib.sha3_256()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        if salt:
            if of != None:
                async for prev, result in azip(self, of):
                    yield prev, await asha_256_hmac((result, salt), key=key)
            else:
                async for result in self:
                    yield await asha_256_hmac((result, salt), key=key)
        else:
            if of != None:
                async for prev, result in azip(self, of):
                    yield prev, await asha_256_hmac(result, key=key)
            else:
                async for result in self:
                    yield await asha_256_hmac(result, key=key)

    def sha_256_hmac(self, key=None, salt=None, *, of=None):
        """
        Applies a ``hashlib.sha3_256()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        if salt:
            if of != None:
                for prev, result in zip(self, of):
                    yield prev, sha_256_hmac((result, salt), key=key)
            else:
                for result in self:
                    yield sha_256_hmac((result, salt), key=key)
        else:
            if of != None:
                for prev, result in zip(self, of):
                    yield prev, sha_256_hmac(result, key=key)
            else:
                for result in self:
                    yield sha_256_hmac(result, key=key)

    async def aint(self, *a, of=None, **kw):
        """
        Applies ``builtins.int(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, int(result, *a, **kw)
        else:
            async for result in self:
                yield int(result, *a, **kw)

    def int(self, *a, of=None, **kw):
        """
        Applies ``builtins.int(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, builtins.int(result, *a, **kw)
        else:
            for result in self:
                yield builtins.int(result, *a, **kw)

    async def ato_base(self, base=16, table=ASCII_ALPHANUMERIC, *, of=None):
        """
        Converts each integer value that's yielded from the underlying
        Comprende async generator to a string in ``base`` before yielding
        the result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, await ainverse_int(result, base, table)
        else:
            async for result in self:
                yield await ainverse_int(result, base, table)

    def to_base(self, base=16, table=ASCII_ALPHANUMERIC, *, of=None):
        """
        Converts each integer value that's yielded from the underlying
        Comprende sync generator to a string in ``base`` before yielding
        the result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, inverse_int(result, base, table)
        else:
            for result in self:
                yield inverse_int(result, base, table)

    async def afrom_base(self, base, table=ASCII_ALPHANUMERIC, *, of=None):
        """
        Convert string results of generator results in numerical ``base``
        into decimal.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, await abase_to_decimal(result, base, table)
        else:
            async for result in self:
                yield await abase_to_decimal(result, base, table)

    def from_base(self, base, table=ASCII_ALPHANUMERIC, *, of=None):
        """
        Convert ``string`` in numerical ``base`` into decimal.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, base_to_decimal(result, base, table)
        else:
            for result in self:
                yield base_to_decimal(result, base, table)

    async def azfill(self, *a, of=None, **kw):
        """
        Applies ``builtins.zfill(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, result.zfill(*a, **kw)
        else:
            async for result in self:
                yield result.zfill(*a, **kw)

    def zfill(self, *a, of=None, **kw):
        """
        Applies ``builtins.zfill(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, result.zfill(*a, **kw)
        else:
            for result in self:
                yield result.zfill(*a, **kw)

    async def aslice(self, *a, of=None):
        """
        Applies ``builtins.slice(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, result[slice(*a)]
        else:
            async for result in self:
                yield result[slice(*a)]

    def slice(self, *a, of=None):
        """
        Applies ``builtins.slice(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, result[slice(*a)]
        else:
            for result in self:
                yield result[slice(*a)]

    async def astr(self, *a, of=None, **kw):
        """
        Applies ``builtins.str(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, str(result, *a, **kw)
        else:
            async for result in self:
                yield str(result, *a, **kw)

    def str(self, *a, of=None, **kw):
        """
        Applies ``builtins.str()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, builtins.str(result, *a, **kw)
        else:
            for result in self:
                yield builtins.str(result, *a, **kw)

    async def aencode(self, *a, of=None, **kw):
        """
        Applies ``builtins.str(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, result.encode(*a, **kw)
        else:
            async for result in self:
                yield result.encode(*a, **kw)

    def encode(self, *a, of=None, **kw):
        """
        Applies ``builtins.str()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, result.encode(*a, **kw)
        else:
            for result in self:
                yield result.encode(*a, **kw)

    async def adecode(self, *a, of=None, **kw):
        """
        Applies ``builtins.str(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, result.decode(*a, **kw)
        else:
            async for result in self:
                yield result.decode(*a, **kw)

    def decode(self, *a, of=None, **kw):
        """
        Applies ``builtins.str()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, result.decode(*a, **kw)
        else:
            for result in self:
                yield result.decode(*a, **kw)

    async def ajson_loads(self, *a, of=None, **kw):
        """
        Applies ``json.loads()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, json.loads(result, *a, **kw)
        else:
            async for result in self:
                yield json.loads(result, *a, **kw)

    def json_loads(self, *a, of=None, **kw):
        """
        Applies ``json.loads()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, json.loads(result, *a, **kw)
        else:
            for result in self:
                yield json.loads(result, *a, **kw)

    async def ajson_dumps(self, *a, of=None, **kw):
        """
        Applies ``json.dumps()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, json.dumps(result, *a, **kw)
        else:
            async for result in self:
                yield json.dumps(result, *a, **kw)

    def json_dumps(self, *a, of=None, **kw):
        """
        Applies ``json.dumps()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, json.dumps(result, *a, **kw)
        else:
            for result in self:
                yield json.dumps(result, *a, **kw)

    async def ahex(self, *a, of=None, **kw):
        """
        Applies ``builtins.hex()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, hex(result, *a, **kw)
        else:
            async for result in self:
                yield hex(result, *a, **kw)

    def hex(self, *a, of=None, **kw):
        """
        Applies ``builtins.hex()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, builtins.hex(result, *a, **kw)
        else:
            for result in self:
                yield builtins.hex(result, *a, **kw)

    async def abytes(self, *a, of=None, **kw):
        """
        Applies ``builtins.bytes()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, bytes(result, *a, **kw)
        else:
            async for result in self:
                yield bytes(result, *a, **kw)

    def bytes(self, *a, of=None, **kw):
        """
        Applies ``builtins.bytes()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, builtins.bytes(result, *a, **kw)
        else:
            for result in self:
                yield builtins.bytes(result, *a, **kw)

    async def abin(self, *a, of=None, **kw):
        """
        Applies ``builtins.bin()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        if of != None:
            async for prev, result in azip(self, of):
                yield prev, bin(result, *a, **kw)
        else:
            async for result in self:
                yield bin(result, *a, **kw)

    def bin(self, *a, of=None, **kw):
        """
        Applies ``builtins.bin()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        if of != None:
            for prev, result in zip(self, of):
                yield prev, builtins.bin(result, *a, **kw)
        else:
            for result in self:
                yield builtins.bin(result, *a, **kw)

    async def __aenter__(self):
        """
        Opens a context & gives the ``self`` object & its ``aresult``
        method in a tuple. Async generators / coroutines can be designed
        to return values by raising UserWarning(return_value).
        """
        await self.areset()
        return self

    def __enter__(self):
        """
        Opens a context & gives the ``self`` object & its ``result``
        method in a tuple. Results can be designed to return values
        by using ``return`` within the generator, or raising
        UserWarning(return_value).
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
        Iterates over the wrapped async &/or sync generator / coroutine
        & produces its values directly, or from lru_cache if an eager
        calculation has already computed the gererators values.
        """
        await self.areset()
        if self.precomputed != False:
            async with self.acache_check() as results:
                for result in results:
                    await switch()
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
        self.reset()
        if self.precomputed != False:
            with self.cache_check() as results:
                for result in results:
                    yield result
        else:
            while True:
                try:
                    got = yield self(got)
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

    def __repr__(self, debugging=DEBUG_MODE):
        """
        Displays the string which, if ``exec``'d, would yield a new
        equivalent object.
        """
        a = self.args
        kw = self.kwargs
        func = self.func.__qualname__
        cls = self.__class__.__qualname__
        tab = f"\n{4 * ' '}"
        _repr = f"{cls}({tab}func={func},{tab}*{a},{tab}**{kw},\n)"
        if not debugging:
            key_finder = re.compile(r"[0-9a-fA-F]{64,}")
            for key in key_finder.finditer(_repr):
                _repr = _repr.replace(key.group(0), "<omitted-key>")
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
        start, stop, step, span = self._set_index(index, arange)
        with ignore(StopAsyncIteration):
            target = await span.anext()
            async for match, result in self.atag():
                if match >= stop:
                    break
                elif target == match:
                    yield result
                    target = await span.anext()

    def _getitem(self, index):
        """
        Allows indexing of generators to yield the values associated
        with the slice or integer passed into the brackets.
        """
        start, stop, step, span = self._set_index(index)
        limit = iter(span)
        with ignore(StopIteration):
            target = next(limit)
            for match, result in enumerate(self):
                if match >= stop:
                    break
                if target == match:
                    yield result
                    target = next(limit)

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


def anext(coro_iterator):
    """
    Creates an asynchronous version of the ``builtins.next`` function.
    """
    try:
        return coro_iterator.__anext__()
    except AttributeError:
        return aiter(coro_iterator).__anext__()


@comprehension()
async def azip(*coros):
    """
    Creates an asynchronous version of the ``builtins.zip`` function.
    """
    tasks = deque()
    coros = [aiter(coro).__anext__ for coro in coros]
    try:
        while True:
            for coro in coros:
                await aappend(tasks, new_task(coro()))
            yield await gather(*tasks)
            tasks.clear()
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
async def _acount(*args, **kwargs):
    """
    Creates an asynchronous version of ``aioitertools.count`` which is
    wrapped by the ``Comprende`` class.
    """
    async for result in acount(*args, **kwargs):
        yield result


@comprehension()
def _count(*args, **kwargs):
    """
    Creates a synchronous version of ``itertools.count`` that is wrapped
    by the ``Comprende`` class.
    """
    for result in count(*args, **kwargs):
        yield result


@comprehension()
async def _aiter(*a, **kw):
    """
    Creates an asynchronous version of ``aioitertools.iter`` which is
    wrapped by the ``Comprende`` class.
    """
    async for result in aiter(*a, **kw):
        yield result


@comprehension()
def _iter(*a, **kw):
    """
    Creates an asynchronous version of ``builtins.iter`` that is wrapped
    by the ``Comprende`` class.
    """
    for result in iter(*a, **kw):
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
    while True:
        for result in results:
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
    while True:
        for result in results:
            yield result


@comprehension()
async def aunpack(iterable=None):
    """
    Runs through an iterable &/or async iterable & yields elements one
    at a time.
    """
    if iterable == None:
        iterable = acount()
    if is_async_iterable(iterable):
        async for item in iterable:
            yield item
    else:
        for item in iterable:
            await switch()
            yield item


@comprehension()
def unpack(iterable=None):
    """
    Runs through an iterable & yields elements one at a time.
    """
    if iterable == None:
        iterable = count()
    for result in iterable:
        yield result


@comprehension()
async def abirth(base="", *, stop=True):
    """
    Yields ``base`` ``times`` number of times. Useful for feeding other
    ``Comprende`` generators the totality of the value ``base``, which
    doesn't have to be either iterable or async iterable.
    """
    if stop:
        yield base
    else:
        while True:
            yield base


@comprehension()
def birth(base="", *, stop=True):
    """
    Yields ``base`` ``times`` number of times. Useful for feeding other
    ``Comprende`` generators the totality of the value ``base``, which
    doesn't have to be iterable.
    """
    if stop:
        yield base
    else:
        while True:
            yield base


@comprehension()
async def adata(sequence="", size=246, *, stop="__length_end__"):
    """
    Runs through a sequence & yields ``size`` sized chunks of the
    sequence one chunk at a time.
    """
    if stop == "__length_end__":
        stop = len(sequence) + size
    async for last, end in azip(
        arange(0, stop, size), arange(size, stop, size)
    ):
        yield sequence[last:end]


@comprehension()
def data(sequence="", size=246, *, stop="__length_end__"):
    """
    Runs through a sequence & yields ``size`` sized chunks of the
    sequence one chunk at a time.
    """
    if stop == "__length_end__":
        stop = len(sequence) + size
    for last, end in zip(range(0, stop, size), range(size, stop, size)):
        yield sequence[last:end]


@comprehension()
async def ajson_encode(raw_data=None, size=246):
    """
    Turns the ``json.dumps`` function into an async generator yielding
    ``size`` length chunks of string data per iteration.
    """
    async for result in adata(json.dumps(raw_data), size=size):
        yield result


@comprehension()
def json_encode(raw_data=None, size=246):
    """
    Turns the ``json.dumps`` function into a generator yielding ``size``
    length chunks of string data per iteration.
    """
    for result in data(json.dumps(raw_data), size=size):
        yield result


@comprehension()
async def ajson_decode(json_data=None):
    """
    Turns the ``json.loads`` function into an async generator yielding
    the data back in one iteration.
    """
    yield json.loads(json_data)


@comprehension()
def json_decode(json_data=None):
    """
    Turns the ``json.loads`` function into a generator yielding the data
    back in one iteration.
    """
    yield json.loads(json_data)


@comprehension()
async def aorder(*iterables):
    """
    Takes a collection of iterables &/or async iterables & exhausts them
    one at a time from left to right.
    """
    for iterable in iterables:
        async for result in aunpack(iterable):
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
    stack = commons.Namespace()
    indexes = list(reversed(range(batch_size)))
    async for toggle, item in azip(cycle(indexes), iterable):
        stack[toggle] = item
        if not toggle:
            yield list(stack.namespace.values())
            stack.namespace.clear()
    if len(stack.namespace) < batch_size:
        yield list(stack.namespace.values())


@comprehension()
def compact(iterable, batch_size=1):
    """
    A generator that yields ``batch_size`` number of elements from an
    ``iterable`` at a time.
    """
    stack = commons.Namespace()
    indexes = list(reversed(range(batch_size)))
    for toggle, item in zip(cycle(indexes), iterable):
        stack[toggle] = item
        if not toggle:
            yield list(stack.namespace.values())
            stack.namespace.clear()
    if len(stack.namespace) < batch_size:
        yield list(stack.namespace.values())


@comprehension()
async def apopleft(queue):
    """
    An async generator which calls the ``popleft()`` method on ``queue``
    for every iterations, & exits on ``IndexError``.
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
    every iterations, & exits on ``IndexError``.
    """
    while True:
        try:
            yield queue.popleft()
        except IndexError:
            break


@comprehension()
async def apick(names=None, mapping=None):
    """
    Does a bracketed lookup on ``mapping`` for each name in ``names``.
    """
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
async def atimeout(iterable, delay=None):
    """
    Iterates over an async or sync ``iterable`` & halts iteration after
    ``delay`` time, even if results haven't been exhausted. Can only
    cancel during times when ``iterable`` has yielded control back to
    the caller.
    """
    async for result in aunpack(iterable).atimeout(delay):
        yield result


@comprehension()
def timeout(iterable, delay=None):
    """
    Iterates over a sync ``iterable`` & halts iteration after ``delay``
    time, even if results haven't been exhausted. Can only cancel during
    times when ``iterable`` has yielded control back to the caller.
    """
    for result in unpack(iterable).timeout(delay):
        yield result


@comprehension()
async def arange(*a, **kw):
    """
    An async version of ``builtins.range``.
    """
    for result in range(*a, **kw):
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
async def aseedrange(iterations, seed):
    """
    This async generator transforms ``builtins.range`` into a producer
    of ``iterations`` number of multiples of ``seed``.
    """
    for salt in seedrange(iterations, seed):
        yield salt
        await switch()


@comprehension()
def seedrange(iterations, seed):
    """
    This generator transforms ``builtins.range`` into a producer of
    ``iterations`` number of multiples of ``seed``.
    """
    for salt in range(seed, seed + (seed * iterations), seed):
        yield salt


async def astr(data="", *a):
    """
    An async wrapper of ``builtins.str``.
    """
    return str(data, *a)


@alru_cache()
async def aint(data=0, *a):
    """
    An async wrapper of ``builtins.int``.
    """
    return int(data, *a)


@alru_cache()
async def aabs(number=None):
    """Creates an asynchronous version of the builtin abs function."""
    return abs(number)


async def aappend(container=None, item=None):
    """Creates an asynchronous version of the container.append method."""
    container.append(item)


async def ato_b64(binary=None, encoding="utf-8"):
    """
    A version of ``pybase64.standard_b64encode``.
    """
    if type(binary) != bytes:
        binary = bytes(binary, encoding)
        await switch()
    return pybase64.standard_b64encode(binary)


def to_b64(binary=None, encoding="utf-8"):
    """
    A version of ``pybase64.standard_b64encode``.
    """
    if type(binary) != bytes:
        binary = bytes(binary, encoding)
    return pybase64.standard_b64encode(binary)


async def afrom_b64(base_64=None, encoding="utf-8"):
    """
    A version of ``pybase64.standard_b64decode``.
    """
    if type(base_64) != bytes:
        base_64 = base_64.encode(encoding)
        await switch()
    return pybase64.standard_b64decode(base_64)


def from_b64(base_64=None, encoding="utf-8"):
    """
    A version of ``pybase64.standard_b64decode``.
    """
    if type(base_64) != bytes:
        base_64 = base_64.encode(encoding)
    return pybase64.standard_b64decode(base_64)


async def asha_256(*args, sha256=sha3_256):
    """
    A string-based version of ``hashlib.sha3_256``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    return sha256((await astr(args)).encode("utf-8")).hexdigest()


def sha_256(*args, sha256=sha3_256):
    """
    A string-based version of ``hashlib.sha3_256``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    return sha256(str(args).encode("utf-8")).hexdigest()


async def asha_256_hmac(data, key=None):
    """
    An HMAC version of the ``hashlib.sha3_512`` function.
    """
    return await asha_256(await asha_256(data, key), key)


def sha_256_hmac(data, key=None):
    """
    An HMAC version of the ``hashlib.sha3_512`` function.
    """
    return sha_256(sha_256(data, key), key)


async def asha_512(*data, sha512=sha3_512):
    """
    A string-based version of ``hashlib.sha3_512``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    return sha512((await astr(data)).encode("utf-8")).hexdigest()


def sha_512(*args, sha512=sha3_512):
    """
    A string-based version of ``hashlib.sha3_512``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    return sha512(str(args).encode("utf-8")).hexdigest()


async def asha_512_hmac(data, key=None):
    """
    An HMAC version of the ``hashlib.sha3_512`` function.
    """
    return await asha_512(await asha_512(data, key), key)


def sha_512_hmac(data, key=None):
    """
    An HMAC version of the ``hashlib.sha3_512`` function.
    """
    return sha_512(sha_512(data, key), key)


async def anc_256(*data):
    """
    A "no collision" 512-bit hash which concatenates the output of two
    ``hashlib.sha3_256`` functions with one receiving the input ``data``,
    & the other receiving the input ``data`` twice. This means a
    collision would have to match the output of two separate hashes &
    the hash size is doubled. This theoretically increases the strength
    of collision resistance from 128-bits for a 256-bit hash, to
    256-bits for the newly created 512-bit joint hash.
    """
    return await asha_256(*data, *data) + await asha_256(*data)


def nc_256(*data):
    """
    A "no collision" 512-bit hash which concatenates the output of two
    ``hashlib.sha3_256`` functions with one receiving the input ``data``,
    & the other receiving the input ``data`` twice. This means a
    collision would have to match the output of two separate hashes &
    the hash size is doubled. This theoretically increases the strength
    of collision resistance from 128-bits for a 256-bit hash, to
    256-bits for the newly created 512-bit joint hash.
    """
    return sha_256(*data, *data) + sha_256(*data)


async def anc_256_hmac(*data, key=None):
    """
    An HMAC version of the no collision 256-bit hash.
    """
    return await anc_256(await anc_256(*data, key), key)


def nc_256_hmac(data, key=None):
    """
    An HMAC version of the no collision 256-bit hash.
    """
    return nc_256(nc_256(data, key), key)


async def anc_512(*data):
    """
    A "no collision" 1024-bit hash which concatenates the output of two
    ``hashlib.sha3_512`` functions with one receiving the input ``data``,
    & the other receiving the input ``data`` twice. This means a
    collision would have to match the output of two separate hashes &
    the hash size is doubled. This theoretically increases the strength
    of collision resistance from 256-bits for a 512-bit hash, to
    512-bits for the newly created 1024-bit joint hash.
    """
    return await asha_512(*data, *data) + await asha_512(*data)


def nc_512(*data):
    """
    A "no collision" 1024-bit hash which concatenates the output of two
    ``hashlib.sha3_512`` functions with one receiving the input ``data``,
    & the other receiving the input ``data`` twice. This means a
    collision would have to match the output of two separate hashes &
    the hash size is doubled. This theoretically increases the strength
    of collision resistance from 256-bits for a 512-bit hash, to
    512-bits for the newly created 1024-bit joint hash.
    """
    return sha_512(*data, *data) + sha_512(*data)


async def anc_512_hmac(*data, key=None):
    """
    An HMAC version of the no collision 512-bit hash.
    """
    return await anc_512(await anc_512(*data, key), key)


def nc_512_hmac(data, key=None):
    """
    An HMAC version of the no collision 512-bit hash.
    """
    return nc_512(nc_512(data, key), key)


async def aint_to_ascii(input_integer):
    """
    Uses ``binascii`` to convert integers into strings.
    """
    return input_integer.to_bytes(
        (input_integer.bit_length() + 7) // 8, "big"
    ).decode()


def int_to_ascii(input_integer):
    """
    Uses ``binascii`` to convert integers into strings.
    """
    return input_integer.to_bytes(
        (input_integer.bit_length() + 7) // 8, "big"
    ).decode()


async def aascii_to_int(data):
    """
    Uses ``binascii`` to convert strings into integers.
    """
    return int.from_bytes(data.encode(), "big")


def ascii_to_int(input_ascii):
    """
    Uses ``binascii`` to convert strings into integers.
    """
    return int.from_bytes(input_ascii.encode(), "big")


async def abase_to_decimal(string, base, table=ASCII_ALPHANUMERIC):
    """
    Convert ``string`` in numerical ``base`` into decimal.
    """
    power = 1
    result = 0
    base_table = table[:base]
    for char in reversed(string):
        if base_table.find(char) == -1:
            raise ValueError("Invalid base with given string or table.")
        await switch()
        result += base_table.find(char) * power
        power = power * base
    return result


def base_to_decimal(string, base, table=ASCII_ALPHANUMERIC):
    """
    Convert ``string`` in numerical ``base`` into decimal.
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
    num = await aabs(number)
    base_table = table[:base]
    while num:
        await aappend(digits, base_table[num % base])
        num //= base
    digits.append("-") if number < 0 else 0
    digits.reverse()
    return "".join(digits)


def inverse_int(number, base, table=ASCII_ALPHANUMERIC):
    """
    Convert an ``number`` back into a string in numerical ``base``.
    """
    digits = []
    num = abs(number)
    base_table = table[:base]
    while num:
        digits.append(base_table[num % base])
        num //= base
    digits.append("-") if number < 0 else 0
    digits.reverse()
    return "".join(digits)


async def abytes_to_int(bytes_object, result=""):
    """
    Concatenates the numerical byte values from a bytes object into an
    integer.
    """
    if type(bytes_object) != bytes:
        raise TypeError
    for number in bytes_object:
        result += await astr(number)
    return await aint(result)


def bytes_to_int(bytes_object, result=""):
    """
    Concatenates the numerical byte values from a bytes object into an
    integer.
    """
    if type(bytes_object) != bytes:
        raise TypeError
    return int("".join([str(byte) for byte in bytes_object]))


async def abinary_tree(depth=4, current=0, leaf={}):
    """
    Recursively builds a binary tree ``depth`` branches deep & places
    the placeholder value ``leaf`` at each endpoint of the tree.  The
    kwarg ``current`` is only to be used internally by the function to
    keep track of which recursion is being run.
    """
    if 0 < current < depth:
        upcoming = current + 1
        return {
            current: await abinary_tree(depth, upcoming, leaf=leaf),
            upcoming: await abinary_tree(depth, upcoming, leaf=leaf),
        }
    elif current == 0:
        return {0: await abinary_tree(depth, 1, leaf=leaf)}
    else:
        return leaf


def binary_tree(depth=4, current=0, leaf={}):
    """
    Recursively builds a binary tree ``depth`` branches deep & places
    the placeholder value ``leaf`` at each endpoint of the tree.  The
    kwarg ``current`` is only to be used internally by the function to
    keep track of which recursion is being run.
    """
    if 0 < current < depth:
        upcoming = current + 1
        return {
            current: binary_tree(depth, upcoming, leaf=leaf),
            upcoming: binary_tree(depth, upcoming, leaf=leaf),
        }
    elif current == 0:
        return {0: binary_tree(depth, 1, leaf=leaf)}
    else:
        return leaf


__extras = {
    "AsyncInit": AsyncInit,
    "Comprende": Comprende,
    "Enumerate": Enumerate,
    "MemberFromStaticMethod": MemberFromStaticMethod,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "aabs": aabs,
    "aappend": aappend,
    "aascii_to_int": aascii_to_int,
    "abase_to_decimal": abase_to_decimal,
    "abinary_tree": abinary_tree,
    "abirth": abirth,
    "abytes_to_int": abytes_to_int,
    "acompact": acompact,
    "acount": _acount,
    "acycle": acycle,
    "adata": adata,
    "afrom_b64": afrom_b64,
    "apick": apick,
    "aignore": aignore,
    "aint": aint,
    "aint_to_ascii": aint_to_ascii,
    "ainverse_int": ainverse_int,
    "aiter": _aiter,
    "ajson_decode": ajson_decode,
    "ajson_encode": ajson_encode,
    "anc_256": anc_256,
    "anc_256_hmac": anc_256_hmac,
    "anc_512": anc_512,
    "anc_512_hmac": anc_512_hmac,
    "anext": anext,
    "aorder": aorder,
    "apopleft": apopleft,
    "arange": arange,
    "ascii_to_int": ascii_to_int,
    "aseedrange": aseedrange,
    "asha_256": asha_256,
    "asha_256_hmac": asha_256_hmac,
    "asha_512": asha_512,
    "asha_512_hmac": asha_512_hmac,
    "askip": askip,
    "astr": astr,
    "ato_b64": ato_b64,
    "aunpack": aunpack,
    "azip": azip,
    "base_to_decimal": base_to_decimal,
    "binary_tree": binary_tree,
    "birth": birth,
    "bytes_to_int": bytes_to_int,
    "compact": compact,
    "comprehension": comprehension,
    "count": _count,
    "customize_parameters": customize_parameters,
    "cycle": cycle,
    "data": data,
    "display_exception_info": display_exception_info,
    "from_b64": from_b64,
    "pick": pick,
    "ignore": ignore,
    "int_to_ascii": int_to_ascii,
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
    "is_prime": is_prime,
    "iter": _iter,
    "json_decode": json_decode,
    "json_encode": json_encode,
    "nc_256": nc_256,
    "nc_256_hmac": nc_256_hmac,
    "nc_512": nc_512,
    "nc_512_hmac": nc_512_hmac,
    "order": order,
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
    "zip": _zip,
}


generics = commons.Namespace.make_module("generics", mapping=__extras)

