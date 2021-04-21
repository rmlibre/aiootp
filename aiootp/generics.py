# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
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
    "json",
    "BytesIO",
    "Comprende",
    "Datastream",
    "Domains",
    "Enumerate",
    "Hasher",
    "Padding",
    "comprehension",
    "azip",
    "anext",
    "arange",
    "abytes_range",
    "bytes_range",
    "aunpack",
    "unpack",
    "aecho",
    "echo",
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
    "abytes_count",
    "bytes_count",
    "apop",
    "pop",
    "apopleft",
    "popleft",
    "await_on",
    "wait_on",
    "asha_256",
    "sha_256",
    "asha_256_hmac",
    "sha_256_hmac",
    "asha_512",
    "sha_512",
    "asha_512_hmac",
    "sha_512_hmac",
    "atime_safe_equality",
    "time_safe_equality",
]


__doc__ = (
    "A collection of basic utilities for simplifying & supporting the "
    "rest of the codebase."
)


import hmac
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
from inspect import isfunction as is_function
from inspect import isawaitable as is_awaitable
from inspect import iscoroutinefunction as is_async_function
from inspect import isasyncgenfunction as is_async_gen_function
from inspect import isgeneratorfunction as is_generator_function
from .__aiocontext import async_contextmanager
from .commons import *
from commons import *  # import the module's constants
from .asynchs import *
from .asynchs import time
from .asynchs import this_second
from . import DebugControl


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


class AsyncInit(type):
    """
    A metaclass which allows classes to use asynchronous ``__init__``
    methods. Inspired by David Beazley.
    """

    async def __call__(cls, *args, **kwargs):
        self = cls.__new__(cls, *args, **kwargs)
        await self.__init__(*args, **kwargs)
        return self


class IterableClass(type):
    """
    A metaclass which allows classes, such as enums, to be iterable over
    their non-private values. These capabilities do not extend to the
    instance's of those classes.

    Usage Example:

    class Colors(metaclass=IterableClass):
        red = "e20000"
        green = "00e200"
        blue = "0000e2"

    assert list(Colors) == [
        ("red", "e20000"), ("green", "00e200"), ("blue", "0000e2")
    ]

    assert {**Colors} == {
        "red": "e20000", "green": "00e200", "blue": "0000e2"
    }

    Colors["yellow"] = "fff700"
    assert Colors.yellow == Colors["yellow"]
    """

    async def __aiter__(cls):
        """
        Asynchronously iterates over a class & yields its non-private
        variable-value pairs.
        """
        for variable, item in cls.__dict__.items():
            await asleep(0)
            if not variable.startswith("_") and not is_function(item):
                yield variable, item

    def __iter__(cls):
        """
        Iterates over a class & yields its non-private variable-value
        pairs.
        """
        for variable, item in cls.__dict__.items():
            if not variable.startswith("_") and not is_function(item):
                yield variable, item

    def __setitem__(cls, variable, value):
        """
        Transforms bracket item assignment into dotted assignment on the
        Namespace's mapping.
        """
        setattr(cls, variable, value)

    def __getitem__(cls, variable):
        """
        Allows the subclass's values to be extracted using the mapping
        syntax {**subclass} or function(**subclass). Subsequently,
        transforms bracket lookup into dotted access on the subclass'
        values.
        """
        try:
            return cls.__dict__[variable]
        except KeyError:
            return getattr(self, variable)

    def keys(cls):
        """
        Allows the subclass's values to be extracted using the mapping
        syntax {**subclass} or function(**subclass).
        """
        yield from (name for name, value in cls)

    def values(cls):
        """
        Yields the subclass' values one at a time.
        """
        yield from (value for name, value in cls)

    def items(cls):
        """
        Yields the subclass' variable names one at a time.
        """
        yield from ((name, value) for name, value in cls)


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


def convert_class_method_to_member(
    self, class_method_name, class_method, *args, **kwargs
):
    """
    Overwrites a class method as an object's member function with the
    option to insert custom parameters to the function.
    """
    method = getattr(class_method, "__func__", class_method)

    @wraps(method)
    def wrapped_class_method(*a, **kw):
        """
        Replaces the parameters to the static method or free function
        being turned into a member function of an object.
        """
        new_args = [*args]
        new_args[: len(a) + 1] = [self] + [arg for arg in a]
        new_kwargs = {**kwargs, **kw}
        return method(*new_args, **new_kwargs)

    setattr(self, class_method_name, wrapped_class_method)


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
        new_args = [*args]
        new_args[: len(a)] = a
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


async def atime_safe_equality(value_0=None, value_1=None, *, key=None):
    """
    Tests if ``value_0`` is equal to ``value_1`` with a randomized-time
    comparison. Each value is prepended with a salt, a ``key`` & is
    hashed prior to the comparison. This algorithm reveals no meaningful
    information, even though compared in non-constant time, since an
    adversary wouldn't have access to either. If ``key`` isn't supplied
    then a 256-bit pseudo-random value is generated for the task. This
    scheme is easier to implement correctly than a constant-time
    algorithm, & it's easier to prove infeasibility guarantees regarding
    timing attacks.
    """
    domain = Domains.EQUALITY.hex()
    salt = secrets.token_bytes(32).hex()
    key = key if key else secrets.token_bytes(32).hex()
    if (
        await asha_256(domain, key, salt, value_0)
        == await asha_256(domain, key, salt, value_1)
    ):
        return True
    else:
        return False


def time_safe_equality(value_0=None, value_1=None, *, key=None):
    """
    Tests if ``value_0`` is equal to ``value_1`` with a randomized-time
    comparison. Each value is prepended with a salt, a ``key`` & is
    hashed prior to the comparison. This algorithm reveals no meaningful
    information, even though compared in non-constant time, since an
    adversary wouldn't have access to either. If ``key`` isn't supplied
    then a 256-bit pseudo-random value is generated for the task. This
    scheme is easier to implement correctly than a constant-time
    algorithm, & it's easier to prove infeasibility guarantees regarding
    timing attacks.
    """
    domain = Domains.EQUALITY.hex()
    salt = secrets.token_bytes(32).hex()
    key = key if key else secrets.token_bytes(32).hex()
    if (
        sha_256(domain, key, salt, value_0)
        == sha_256(domain, key, salt, value_1)
    ):
        return True
    else:
        return False


async def acustomize_parameters(
    a=(), kw=(), indexes=(), args=(), kwargs=()
):
    """
    Replaces ``a`` and ``kw`` arguments & keyword arguments with ``args``
    if ``indexes`` is specified, and ``kwargs``.
    """
    await asleep(0)
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
            result = catcher(func, *a, **kw)
            return result

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

    # Here's another illustrative example ->
    @comprehension()
    def echo(initial_value):
        received = initial_value
        while True:
            received = yield received

    value = "some test value"
    coroutine = echo("start")
    assert coroutine() == "start"
    assert coroutine(value) == "some test value"


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

    # Here's another illustrative example ->
    @comprehension()
    async def echo(initial_value):
        received = initial_value
        while True:
            received = yield received

    value = "some test value"
    coroutine = echo("start")
    assert await coroutine() == "start"
    assert await coroutine(value) == "some test value"

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
        "send",
        "asend",
        "_runsum",
        "_return",
        "_thrown",
        "_is_async",
        "_messages",
        "_areturn_cache",
        "_return_cache",
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

    _ASYNC_GEN_DONE = "async generator raised StopAsyncIteration"

    def __init__(self, func=None, *a, chained=False, **kw):
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
        self.args = a
        self.kwargs = kw
        self.func = func
        self._runsum = b""
        self._thrown = deque()
        self._return = deque()

    def _initialize_object_message_chain(self, chained=False):
        """
        Objects in a chain can communicate with each other through this
        `messages` Namespace object. It is also used internally by the
        class to help instance's keep track with each other's state.
        """
        if chained:
            self._messages = self.args[0].messages
            self.args[0].messages._chained_instances.append(self)
        else:
            self._messages = Namespace(_chained_instances=[self])

    @property
    def messages(self):
        """
        Contains a namespace object that can be used within instance
        methods to pass messages in & out of `Comprende` objects.
        """
        return self._messages

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

    async def _acomprehension(self):
        """
        Wraps the user's generator & monitors the values being sent into
        coroutine for the `UserWarning()` signal to halt iteration &
        return the exception's value.
        """
        gen = self.func(*self.args, **self.kwargs)
        catch_UserWarning = self.__aexamine_sent_exceptions(gen)
        await catch_UserWarning.asend(None)
        async with self.acatch():
            got = None
            while True:
                got = yield await gen.asend(got)
                await catch_UserWarning.asend(got)

    def __set_async(self):
        """
        Does the wrapping of user async generators to allow catching
        return values.
        """
        self._is_async = True
        self.gen = self._acomprehension()
        self.send = None
        self.asend = self.gen.asend
        self.iterator = aiter.root(self.gen)

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

    def _comprehension(self):
        """
        Wraps the user's generator & monitors the values being sent into
        coroutine for the `UserWarning()` signal to halt iteration &
        return the exception's value.
        """
        gen = self.func(*self.args, **self.kwargs)
        catch_UserWarning = self.__examine_sent_exceptions(gen)
        catch_UserWarning.send(None)
        with self.catch():
            got = None
            while True:
                got = yield gen.send(got)
                catch_UserWarning.send(got)

    def __set_sync(self):
        """
        Does the wrapping of user generators to allow catching return
        values.
        """
        self._is_async = False
        self.gen = self._comprehension()
        self.asend = None
        self.send = self.gen.send
        self.iterator = iter(self.gen)

    async def areset(self, *, _top_of_the_chain=True):
        """
        Replaces the generator wrapper with a new async wrapper.
        """
        await asleep(0)
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

    async def aprime(self):
        """
        Resets the instance's async wrapper generator & ``asend``s in a
        ``None`` value to prime the generator, i.e. bringing it to the
        first yield statement.
        """
        await self.areset()
        await self.asend(None)
        return self

    def prime(self):
        """
        Resets the instance's sync wrapper generator & ``send``s in a
        ``None`` value to prime the generator, i.e. bringing it to the
        first yield statement.
        """
        self.reset()
        self.send(None)
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
            await asleep(0)
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
                await self.asend(UserWarning())
        elif exit:
            await self.asend(UserWarning())
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
                self.send(UserWarning())
        elif exit:
            self.send(UserWarning())
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

    async def _aset_cache(self):
        """
        Creates a per-instance function that returns precomputed results
        with lru cache turned on to save on speed for instances that have
        called async methods or generators which do eager computation of
        an async generator's entire result set.
        """

        @alru_cache(maxsize=1)
        async def _areturn_cache(runsum=None):
            return [result async for result in self]

        await asleep(0)
        self._areturn_cache = _areturn_cache
        self._runsum = await self._amake_runsum()

    def _set_cache(self):
        """
        Creates a per-instance function that returns precomputed results
        with lru cache turned on to save on speed for instances that have
        called sync methods or generators which do eager computation of
        a generator's entire result set.
        """

        @lru_cache(maxsize=1)
        def _return_cache(runsum=None):
            return [result for result in self]

        self._return_cache = _return_cache
        self._runsum = self._make_runsum()

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
            yield await self._areturn_cache(self.runsum)
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
            yield self._return_cache(self.runsum)
        finally:
            self.__class__._cached[self.runsum] = self

    async def _astored_caches(self):
        """
        Returns the lru cached methods of an instance in an iterable.
        """
        if hasattr(self, "_return_cache"):
            await asleep(0)
            yield self._return_cache
        if hasattr(self, "_areturn_cache"):
            await asleep(0)
            yield self._areturn_cache

    def _stored_caches(self):
        """
        Returns the lru cached methods of an instance in an iterable.
        """
        if hasattr(self, "_return_cache"):
            yield self._return_cache
        if hasattr(self, "_areturn_cache"):
            yield self._areturn_cache

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

    @classmethod
    async def aclear_class(cls):
        """
        Allows users to manually clear the cache of all the class'
        instances.
        """
        for runsum, instance in dict(cls._cached).items():
            del cls._cached[runsum]
            async for cache in instance._astored_caches():
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
            for cache in instance._stored_caches():
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
                async for cache in self._astored_caches():
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
                for cache in self._stored_caches():
                    cache.cache_clear()
            finally:
                self._runsum = b""

    def __del__(self):
        """
        Attempts to cleanup instance caches when deleted or garbage
        collected to reduce memory overhead.
        """
        self.clear()
        if hasattr(self, "gen"):
            del self.gen

    async def atimeout(self, seconds=5, *, probe_frequency=0):
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

    def timeout(self, seconds=5, *, probe_frequency=0):
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

    async def ahalt(self, sentinel="", *, sentinels=()):
        """
        Takes a ``sentinel`` or iterable of ``sentinels`` & halts the
        underlying Comprende async generator if it yields any of those
        sentinels.
        """
        got = None
        asend = self.asend
        sentinels = set(sentinels) if sentinels else {sentinel}
        while True:
            result = await asend(got)
            if result in sentinels:
                break
            got = yield result

    def halt(self, sentinel="", *, sentinels=()):
        """
        Takes a ``sentinel`` or iterable of ``sentinels`` & halts the
        underlying Comprende sync generator if it yields any of those
        sentinels.
        """
        try:
            got = None
            send = self.send
            sentinels = set(sentinels) if sentinels else {sentinel}
            while True:
                result = send(got)
                if result in sentinels:
                    break
                got = yield result
        except StopIteration:
            pass

    async def afeed(self, iterable=None):
        """
        Takes in an sync or async iterable & sends those values into an
        async coroutine which automates the process of driving an async
        generator which is expecting results from a caller.
        """
        asend = self.asend
        yield await asend(None)
        async for food in aunpack.root(iterable):
            yield await asend(food)

    def feed(self, iterable=None):
        """
        Takes in an iterable & sends those values into a sync coroutine
        which automates the process of driving a generator which is
        expecting results from a caller.
        """
        try:
            send = self.send
            yield send(None)
            for food in iterable:
                yield send(food)
        except StopIteration:
            pass

    async def afeed_self(self):
        """
        Recursively feeds the results of an async generator back into
        itself as coroutine values for the ``asend`` function.
        """
        asend = self.asend
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
        try:
            send = self.send
            food = send(None)
            yield food
            while True:
                food = send(food)
                yield food
        except StopIteration:
            pass

    async def atag(self, tags=None):
        """
        By default behaves like ``enumerate`` for each value yielded
        from the underlying Comprende async generator. Optionally,
        ``tags`` can be passed a sync or async iterable & prepends those
        values to the generator's results.
        """
        got = None
        asend = self.asend
        if tags:
            async for name in aunpack.root(tags):
                got = yield name, await asend(got)
        else:
            async for index in acount.root():
                got = yield index, await asend(got)

    def tag(self, tags=None):
        """
        By default behaves like ``enumerate`` for each value yielded
        from the underlying Comprende sync generator. Optionally,
        ``tags`` can be passed an iterable & prepends those values to
        the generator's results.
        """
        got = None
        send = self.send
        try:
            if tags:
                for name in tags:
                    got = yield name, send(got)
            else:
                for index in count.root():
                    got = yield index, send(got)
        except StopIteration:
            pass

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

    def __reversed__(self):
        """
        Allows reversing async/sync generators, but must compute all
        values first to do so.
        """
        if self._is_async:
            return self.areversed()
        else:
            return self.reversed()

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

    async def aresize(self, size=BLOCKSIZE):
        """
        Buffers the output from the underlying Comprende async generator
        to yield the results in chunks of length ``size``.
        """
        asend = self.asend
        result = await asend(None)
        while True:
            while len(result) >= size:
                yield result[:size]
                result = result[size:]
            try:
                result += await asend(None)
            except StopAsyncIteration:
                break
        if result:
            yield result

    def resize(self, size=BLOCKSIZE):
        """
        Buffers the output from the underlying Comprende sync generator
        to yield the results in chunks of length ``size``.
        """
        send = self.send
        result = send(None)
        while True:
            while len(result) >= size:
                yield result[:size]
                result = result[size:]
            try:
                result += send(None)
            except StopIteration:
                break
        if result:
            yield result

    async def adelimit(self, delimiter=" "):
        """
        Adds a user-defined ``delimiter`` to the end of end result
        yielded from the underlying ``Comprende`` async generator.
        """
        got = None
        asend = self.asend
        while True:
            got = yield await asend(got) + delimiter

    def delimit(self, delimiter=" "):
        """
        Adds a user-defined ``delimiter`` to the end of end result
        yielded from the underlying ``Comprende`` generator.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield send(got) + delimiter
        except StopIteration:
            pass

    async def adelimited_resize(self, delimiter=" ", base=""):
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

    def delimited_resize(self, delimiter=" ", base=""):
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
        got = None
        asend = self.asend
        while True:
            got = yield to_b64(await asend(got))

    def to_base64(self):
        """
        Applies ``base64.standard_b64encode`` conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield to_b64(send(got))
        except StopIteration:
            pass

    async def afrom_base64(self):
        """
        Applies ``base64.standard_b64decode`` conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield from_b64(await asend(got))

    def from_base64(self):
        """
        Applies ``base64.standard_b64decode`` conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield from_b64(send(got))
        except StopIteration:
            pass

    async def aint_to_ascii(self):
        """
        Applies a ``binascii`` int-to-ascii conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield (await asend(got)).to_bytes(
                math.ceil(result.bit_length() / 8), "big"
            ).decode()

    def int_to_ascii(self):
        """
        Applies a ``binascii`` int-to-ascii conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield send(got).to_bytes(
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
        asend = self.asend
        while True:
            got = yield int.from_bytes(
                (await asend(got)).encode(), "big"
            )

    def ascii_to_int(self):
        """
        Applies a ``binascii`` ascii-to-int conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield int.from_bytes(send(got).encode(), "big")
        except StopIteration:
            pass

    async def asha_512(self, *, salt=None):
        """
        Applies ``hashlib.sha3_512()`` to each value that's yielded
        from the underlying Comprende async generator before yielding
        the result.
        """
        got = None
        asend = self.asend
        if salt:
            while True:
                got = yield await asha_512(salt, await asend(got))
        else:
            while True:
                got = yield await asha_512(await asend(got))

    def sha_512(self, *, salt=None):
        """
        Applies ``hashlib.sha3_512()`` to each value that's yielded
        from the underlying Comprende sync generator before yielding
        the result.
        """
        got = None
        send = self.send
        try:
            if salt:
                while True:
                    got = yield sha_512(salt, send(got))
            else:
                while True:
                    got = yield sha_512(send(got))
        except StopIteration:
            pass

    async def asha_512_hmac(self, *, key, salt=None):
        """
        Applies a ``hashlib.sha3_512()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        asend = self.asend
        if salt:
            while True:
                got = yield await asha_512_hmac(
                    (salt, await asend(got)), key=key
                )
        else:
            while True:
                got = yield await asha_512_hmac(await asend(got), key=key)

    def sha_512_hmac(self, *, key, salt=None):
        """
        Applies a ``hashlib.sha3_512()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        send = self.send
        try:
            if salt:
                while True:
                    got = yield sha_512_hmac((salt, send(got)), key=key)
            else:
                while True:
                    got = yield sha_512_hmac(send(got), key=key)
        except StopIteration:
            pass

    async def asum_sha_512(self, *, salt=None):
        """
        Cumulatively applies a ``hashlib.sha3_512()`` to each value
        that's yielded from the underlying Comprende async generator
        with the results of prior hashing before yielding the result.
        """
        got = None
        asend = self.asend
        summary = await asha_512(salt)
        while True:
            summary = await asha_512(salt, summary, await asend(got))
            got = yield summary

    def sum_sha_512(self, *, salt=None):
        """
        Cumulatively applies a ``hashlib.sha3_512()`` to each value
        that's yielded from the underlying Comprende sync generator with
        the results of prior hashing before yielding the result.
        """
        got = None
        send = self.send
        summary = sha_512(salt)
        try:
            while True:
                summary = sha_512(salt, summary, send(got))
                got = yield summary
        except StopIteration:
            pass

    async def asha_256(self, *, salt=None):
        """
        Applies ``hashlib.sha3_256()`` to each value that's yielded
        from the underlying Comprende async generator before yielding
        the result.
        """
        got = None
        asend = self.asend
        if salt:
            while True:
                got = yield await asha_256(salt, await asend(got))
        else:
            while True:
                got = yield await asha_256(await asend(got))

    def sha_256(self, *, salt=None):
        """
        Applies ``hashlib.sha3_256()`` to each value that's yielded
        from the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        try:
            if salt:
                while True:
                    got = yield sha_256(salt, send(got))
            else:
                while True:
                    got = yield sha_256(send(got))
        except StopIteration:
            pass

    async def asha_256_hmac(self, *, key, salt=None):
        """
        Applies a ``hashlib.sha3_256()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        asend = self.asend
        if salt:
            while True:
                got = yield await asha_256_hmac(
                    (salt, await asend(got)), key=key
                )
        else:
            while True:
                got = yield await asha_256_hmac(await asend(got), key=key)

    def sha_256_hmac(self, *, key, salt=None):
        """
        Applies a ``hashlib.sha3_256()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        send = self.send
        try:
            if salt:
                while True:
                    got = yield sha_256_hmac((salt, send(got)), key=key)
            else:
                while True:
                    got = yield sha_256_hmac(send(got), key=key)
        except StopIteration:
            pass

    async def asum_sha_256(self, *, salt=None):
        """
        Cumulatively applies a ``hashlib.sha3_256()`` to each value
        that's yielded from the underlying Comprende async generator
        with the results of prior hashing before yielding the result.
        """
        got = None
        asend = self.asend
        summary = await asha_256(salt)
        while True:
            summary = await asha_256(salt, summary, await asend(got))
            got = yield summary

    def sum_sha_256(self, *, salt=None):
        """
        Cumulatively applies a ``hashlib.sha3_256()`` to each value
        that's yielded from the underlying Comprende sync generator with
        the results of prior hashing before yielding the result.
        """
        got = None
        send = self.send
        summary = sha_256(salt)
        try:
            while True:
                summary = sha_256(salt, summary, send(got))
                got = yield summary
        except StopIteration:
            pass

    async def aint(self, *a, **kw):
        """
        Applies ``builtins.int(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield int(await asend(got), *a, **kw)

    def int(self, *a, **kw):
        """
        Applies ``builtins.int(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield builtins.int(send(got), *a, **kw)
        except StopIteration:
            pass

    async def abytes_to_int(self, byte_order="big"):
        """
        Applies ``int.from_bytes(result, byte_order)`` to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield int.from_bytes(await asend(got), byte_order)

    def bytes_to_int(self, byte_order="big"):
        """
        Applies ``int.from_bytes(result, byte_order)`` to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield int.from_bytes(send(got), byte_order)
        except StopIteration:
            pass

    async def aint_to_bytes(self, size=BLOCKSIZE, byte_order="big"):
        """
        Applies ``int.to_bytes(result, size, byte_order)`` to each
        value that's yielded from the underlying Comprende async
        generator before yielding the result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield (await asend(got)).to_bytes(size, byte_order)

    def int_to_bytes(self, size=BLOCKSIZE, byte_order="big"):
        """
        Applies ``int.to_bytes(result, size, byte_order)`` to each
        value that's yielded from the underlying Comprende sync
        generator before yielding the result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield send(got).to_bytes(size, byte_order)
        except StopIteration:
            pass

    async def ahex_to_bytes(self):
        """
        Applies ``bytes.fromhex(result)`` to each value that's yielded
        from the underlying Comprende async generator before yielding
        the result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield bytes.fromhex(await asend(got))

    def hex_to_bytes(self):
        """
        Applies ``bytes.fromhex(result)`` to each value that's yielded
        from the underlying Comprende sync generator before yielding
        the result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield bytes.fromhex(send(got))
        except StopIteration:
            pass

    async def abytes_to_hex(self):
        """
        Applies ``bytes.hex(result)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield (await asend(got)).hex()

    def bytes_to_hex(self):
        """
        Applies ``bytes.hex(result)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield send(got).hex()
        except StopIteration:
            pass

    async def ato_base(self, base=95, table=ASCII_TABLE):
        """
        Converts each integer value that's yielded from the underlying
        Comprende async generator to a string in ``base`` before yielding
        the result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield await aint_to_base(await asend(got), base, table)

    def to_base(self, base=95, table=ASCII_TABLE):
        """
        Converts each integer value that's yielded from the underlying
        Comprende sync generator to a string in ``base`` before yielding
        the result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield int_to_base(send(got), base, table)
        except StopIteration:
            pass

    async def afrom_base(self, base=95, table=ASCII_TABLE):
        """
        Convert string results of generator results in numerical ``base``
        into decimal.
        """
        got = None
        asend = self.asend
        while True:
            got = yield await abase_to_int(await asend(got), base, table)

    def from_base(self, base=95, table=ASCII_TABLE):
        """
        Convert ``string`` in numerical ``base`` into decimal.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield base_to_int(send(got), base, table)
        except StopIteration:
            pass

    async def azfill(self, *a, **kw):
        """
        Applies ``builtins.zfill(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield (await asend(got)).zfill(*a, **kw)

    def zfill(self, *a, **kw):
        """
        Applies ``builtins.zfill(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield send(got).zfill(*a, **kw)
        except StopIteration:
            pass

    async def aslice(self, *a):
        """
        Applies ``builtins.slice(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        asend = self.asend
        selected = slice(*a)
        while True:
            got = yield (await asend(got))[selected]

    def slice(self, *a):
        """
        Applies ``builtins.slice(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        selected = slice(*a)
        try:
            while True:
                got = yield send(got)[selected]
        except StopIteration:
            pass

    async def aindex(self, selected=None):
        """
        Yields the ``selected`` index of each result produced by the
        underlying Comprende async generator.
        """
        got = None
        asend = self.asend
        while True:
            got = yield (await asend(got))[selected]

    def index(self, selected=None):
        """
        Yields the ``selected`` index of each result produced by the
        underlying Comprende sync generator.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield send(got)[selected]
        except StopIteration:
            pass

    async def astr(self, *a, **kw):
        """
        Applies ``builtins.str(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield str(await asend(got), *a, **kw)

    def str(self, *a, **kw):
        """
        Applies ``builtins.str()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        _str = builtins.str
        try:
            while True:
                got = yield _str(send(got), *a, **kw)
        except StopIteration:
            pass

    async def asplit(self, *a, **kw):
        """
        Applies ``value.split()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield (await asend(got)).split(*a, **kw)

    def split(self, *a, **kw):
        """
        Applies ``value.split()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        try:
            while True:
                yield send(got).split(*a, **kw)
        except StopIteration:
            pass

    async def areplace(self, *a, **kw):
        """
        Applies ``value.replace()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield (await asend(got)).replace(*a, **kw)

    def replace(self, *a, **kw):
        """
        Applies ``value.replace()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield send(got).replace(*a, **kw)
        except StopIteration:
            pass

    async def aencode(self, *a, **kw):
        """
        Applies ``value.encode()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield (await asend(got)).encode(*a, **kw)

    def encode(self, *a, **kw):
        """
        Applies ``value.encode()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield send(got).encode(*a, **kw)
        except StopIteration:
            pass

    async def adecode(self, *a, **kw):
        """
        Applies ``value.decode()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield (await asend(got)).decode(*a, **kw)

    def decode(self, *a, **kw):
        """
        Applies ``value.decode()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield send(got).decode(*a, **kw)
        except StopIteration:
            pass

    async def ajson_loads(self, *a, **kw):
        """
        Applies ``json.loads()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield json.loads(await asend(got), *a, **kw)

    def json_loads(self, *a, **kw):
        """
        Applies ``json.loads()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield json.loads(send(got), *a, **kw)
        except StopIteration:
            pass

    async def ajson_dumps(self, *a, **kw):
        """
        Applies ``json.dumps()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield json.dumps(await asend(got), *a, **kw)

    def json_dumps(self, *a, **kw):
        """
        Applies ``json.dumps()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        try:
            while True:
                got = yield json.dumps(send(got), *a, **kw)
        except StopIteration:
            pass

    async def ahex(self, prefix=False):
        """
        Applies ``builtins.hex()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        asend = self.asend
        start = 0 if prefix else 2
        while True:
            got = yield hex(await asend(got))[start:]

    def hex(self, prefix=False):
        """
        Applies ``builtins.hex()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        _hex = builtins.hex
        start = 0 if prefix else 2
        try:
            while True:
                got = yield _hex(send(got))[start:]
        except StopIteration:
            pass

    async def abytes(self, *a, **kw):
        """
        Applies ``builtins.bytes()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield bytes(await asend(got), *a, **kw)

    def bytes(self, *a, **kw):
        """
        Applies ``builtins.bytes()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        _bytes = builtins.bytes
        try:
            while True:
                got = yield _bytes(send(got), *a, **kw)
        except StopIteration:
            pass

    async def abin(self, *a, **kw):
        """
        Applies ``builtins.bin()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        asend = self.asend
        while True:
            got = yield bin(await asend(got), *a, **kw)

    def bin(self, *a, **kw):
        """
        Applies ``builtins.bin()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        send = self.send
        _bin = builtins.bin
        try:
            while True:
                got = yield _bin(send(got), *a, **kw)
        except StopIteration:
            pass

    def _set_index(self, index, _max=bits[128]):
        """
        Interprets the slice or int passed into __getitem__ into an
        iterable of a range object.
        """
        if isinstance(index, int):
            step = 1
            start = index
            stop = index + 1
        else:
            step = index.step if isinstance(index.step, int) else 1
            start = index.start if isinstance(index.start, int) else 0
            stop = index.stop if isinstance(index.stop, int) else _max
        return iter(range(start, stop, step)).__next__

    async def _agetitem(self, index):
        """
        Allows indexing of async generators to yield the values
        associated with the slice or integer passed into the brackets.
        Does not support negative indices.
        """
        got = None
        asend = self.asend
        next_target = self._set_index(index)
        with ignore(StopIteration, StopAsyncIteration):
            target = next_target()
            async for match in acount.root():
                if target == match:
                    got = yield await asend(got)
                    target = next_target()
                else:
                    await asend(got)
                    got = None

    def _getitem(self, index):
        """
        Allows indexing of generators to yield the values associated
        with the slice or integer passed into the brackets. Does not
        support negative indices.
        """
        got = None
        send = self.send
        next_target = self._set_index(index)
        with ignore(StopIteration):
            target = next_target()
            for match in count.root():
                if target == match:
                    got = yield send(got)
                    target = next_target()
                else:
                    send(got)
                    got = None

    def __getitem__(self, index):
        """
        Allows indexing of generators & async generators to yield the
        values associated with the slice or integer passed into the
        brackets. Does not support negative indices.
        """
        if self._is_async:
            return self._agetitem(index)
        else:
            return self._getitem(index)

    async def __aiter__(self, *, got=None):
        """
        Iterates over the wrapped async generator / coroutine & produces
        its values directly, or from alru_cache if an eager calculation
        has already computed the gererators values.
        """
        if self.precomputed:
            async with self.aauto_cache() as results:
                for result in results:
                    await asleep(0)
                    yield result
        else:
            asend = self.asend
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
        if self.precomputed:
            with self.auto_cache() as results:
                for result in results:
                    yield result
        else:
            send = self.send
            while True:
                try:
                    got = yield send(got)
                except StopIteration:
                    break

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

    def __call__(self, got=None):
        """
        Allows the wrapped async & sync coroutine generator to receive
        ``send`` values by calling the instance.
        """
        if self._is_async:
            return self._acall(got)
        else:
            return self._call(got)

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

    def __next__(self):
        """
        Allows calling ``builtins.next`` on async / sync generators &
        coroutines.
        """
        if self._is_async:
            return self.anext()
        else:
            return self.next()

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

    for method in lazy_generators.union(eager_generators):
        vars()[method] = comprehension(chained=True)(vars()[method])


async def anext(coroutine_iterator):
    """
    Creates an asynchronous version of the ``builtins.next`` function.
    """
    return await coroutine_iterator.__anext__()


@comprehension()
async def azip(*iterables):
    """
    Creates an asynchronous version of the ``builtins.zip`` function
    which is wrapped by the ``Comprende`` class.
    """
    coroutines = [aiter.root(iterable).__anext__ for iterable in iterables]
    try:
        while True:
            yield [await coroutine() for coroutine in coroutines]
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
async def aiter(iterable):
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
async def aecho(initial_value, *, buffer=()):
    """
    A coroutine which yields the values the are sent into it. It's most
    useful as a debugger or in Comprende data processing chains.

    Usage Example:

    converstion = aecho(b'{"field_0": 0}').adecode().ajson_loads()
    assert {"field_0": 0} == await converstion()
    assert {"field_1": 1} == await converstion(b'{"field_1": 1}')
    assert {"field_2": 2} == await converstion(b'{"field_2": 2}')
    """
    await asleep(0)
    got = yield initial_value
    for item in buffer:
        await asleep(0)
        got = yield item
    while True:
        await asleep(0)
        got = yield got


@comprehension()
def echo(initial_value, *, buffer=()):
    """
    A coroutine which yields the values the are sent into it. It's most
    useful as a debugger or in Comprende data processing chains.

    Usage Example:

    converstion = echo(b'{"field_0": 0}').decode().json_loads()
    assert {"field_0": 0} == converstion()
    assert {"field_1": 1} == converstion(b'{"field_1": 1}')
    assert {"field_2": 2} == converstion(b'{"field_2": 2}')
    """
    got = yield initial_value
    for item in buffer:
        got = yield item
    while True:
        got = yield got


@comprehension()
async def acycle(iterable):
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
            await asleep(0)
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
async def abytes_count(start=0, *, size=8, byte_order="big"):
    """
    Unendingly yields incrementing numbers starting from ``start``.
    """
    index = start
    while True:
        await asleep(0)
        yield index.to_bytes(length, byte_order)
        index += 1


@comprehension()
def bytes_count(start=0, *, size=8, byte_order="big"):
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
async def adata(sequence="", size=256, *, blocks=ALL_BLOCKS):
    """
    Runs through a sequence & yields ``size`` sized chunks of the
    sequence one chunk at a time. ``blocks`` is the total number of
    chunks allowed to be yielded from the generator. By default this
    generator yields all elements in the sequence.
    """
    length = len(sequence)
    if (blocks == ALL_BLOCKS) or (blocks * size >= length):
        blocks = length + size
    else:
        blocks = (blocks * size) + 1
    async for last, end in azip(
        range(0, blocks, size), range(size, blocks, size)
    ):
        yield sequence[last:end]


@comprehension()
def data(sequence="", size=256, *, blocks=ALL_BLOCKS):
    """
    Runs through a sequence & yields ``size`` sized chunks of the
    sequence one chunk at a time. ``blocks`` is the total number of
    chunks allowed to be yielded from the generator. By default this
    generator yields all elements in the sequence.
    """
    length = len(sequence)
    if (blocks == ALL_BLOCKS) or (blocks * size >= length):
        blocks = length + size
    else:
        blocks = (blocks * size) + 1
    for last, end in zip(range(0, blocks, size), range(size, blocks, size)):
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
    if is_async_iterable(iterable):
        async for result in iterable:
            for _ in range(steps):
                yield
            await asleep(0)
            yield result
    else:
        for result in iterable:
            await asleep(0)
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
async def abytes_range(*a, size=8, byte_order="big", **kw):
    """
    An async version of ``builtins.range`` wrapped by the ``Comprende``
    class, & returns its values as bytes instead.
    """
    for result in range(*a, **kw):
        await asleep(0)
        yield result.to_bytes(size, byte_order)


@comprehension()
def bytes_range(*a, size=8, byte_order="big", **kw):
    """
    A synchronous version of ``builtins.range`` which is wrapped by the
    ``Comprende`` class, & returns its values as bytes instead.
    """
    for result in range(*a, **kw):
        yield result.to_bytes(size, byte_order)


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


class Hasher:
    """
    A class that creates instances to mimmic & add functionality to the
    hashing object passed in during initialization.
    """

    xi_mix = xi_mix
    axi_mix = axi_mix
    _MOD = BasePrimeGroups.MOD_512
    _BASE = UniformPrimes.PRIME_256
    _MASK = UniformPrimes.PRIME_512

    def __init__(self, data=b"", *, obj=sha3_512):
        """
        Copies over the object dictionary of the ``obj`` hashing object.
        """
        self._obj = obj(data)
        for method in dir(obj):
            if not method.startswith("_"):
                setattr(self, method, getattr(self._obj, method))

    def __call__(self, data=b""):
        """
        Allows objects of the class to accept new input data in the
        same way the class of the mimmicked hashing object does during
        initialization.
        """
        self.update(data)
        return self

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
    async def amask_byte_order(cls, sequence, *, base=_BASE, mod=_MOD):
        """
        Uses each byte in a ``sequence`` as multiples along with ``base``
        & takes that result ``mod`` a number to mask the order of the
        bytes in the sequence. This final result is returned back to the
        user as a new bytes sequence. Both ``mod`` & ``base`` should be
        prime numbers.
        """
        if base == mod:
            raise ValueError("``base`` & ``mod`` must be different!")
        product = 3
        await asleep(0)
        for byte in bytes(sequence):
            product *= byte + 1    # <- Ensure non-zero
        await asleep(0)
        masked_value = (base * product * cls._MASK) % mod
        return masked_value.to_bytes(math.ceil(mod.bit_length() / 8), "big")

    @classmethod
    def mask_byte_order(cls, sequence, *, base=_BASE, mod=_MOD):
        """
        Uses each byte in a ``sequence`` as multiples along with ``base``
        & takes that result ``mod`` a number to mask the order of the
        bytes in the sequence. This final result is returned back to the
        user as a new bytes sequence. Both ``mod`` & ``base`` should be
        prime numbers.
        """
        if base == mod:
            raise ValueError("``base`` & ``mod`` must be different!")
        product = 3
        for byte in bytes(sequence):
            product *= byte + 1    # <- Ensure non-zero
        masked_value = (base * product * cls._MASK) % mod
        return masked_value.to_bytes(math.ceil(mod.bit_length() / 8), "big")

    @classmethod
    async def ashrink(cls, *data, size=8, on=b"", base=_BASE, mod=_MOD):
        """
        Hashes an iterable of ``data`` elements joined ``on`` a value
        & returns ``size`` byte `xi_mix` reduction of the result.
        """
        hashed_data = await cls().ahash(*data, on=on)
        return await cls.axi_mix(hashed_data, size=size)

    @classmethod
    def shrink(cls, *data, size=8, on=b"", base=_BASE, mod=_MOD):
        """
        Hashes an iterable of ``data`` elements joined ``on`` a value
        & returns ``size`` byte `xi_mix` reduction of the result.
        """
        hashed_data = cls().hash(*data, on=on)
        return cls.xi_mix(hashed_data, size=size)


class Domains(metaclass=IterableClass):
    """
    A collection of encoded constants which can augment function inputs
    to make their outputs domain specific.
    """

    @staticmethod
    async def aencode_constant(constant):
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
        await asleep(0)
        if type(constant) != bytes:
            constant = str(constant).encode()
        hashed_constant = await ahash_bytes(b"encoded_constant:", constant)
        return await axi_mix(hashed_constant, size=8)

    @staticmethod
    def encode_constant(constant):
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
        if type(constant) != bytes:
            constant = str(constant).encode()
        hashed_constant = hash_bytes(b"encoded_constant:", constant)
        return xi_mix(hashed_constant, size=8)

    _encode_constant = encode_constant.__func__

    DH2: bytes = _encode_constant(DH2)
    DH3: bytes = _encode_constant(DH3)
    KDF: bytes = _encode_constant(KDF)
    SIV: bytes = _encode_constant(SIV)
    HMAC: bytes = _encode_constant(HMAC)
    SEED: bytes = _encode_constant(SEED)
    SALT: bytes = _encode_constant(SALT)
    UUID: bytes = _encode_constant(UUID)
    SHMAC: bytes = _encode_constant(SHMAC)
    KEY_ID: bytes = _encode_constant(KEY_ID)
    DIGEST: bytes = _encode_constant(DIGEST)
    METATAG: bytes = _encode_constant(METATAG)
    SIV_KEY: bytes = _encode_constant(SIV_KEY)
    ENTROPY: bytes = _encode_constant(ENTROPY)
    EQUALITY: bytes = _encode_constant(EQUALITY)
    MANIFEST: bytes = _encode_constant(MANIFEST)
    BLOCK_ID: bytes = _encode_constant(BLOCK_ID)
    FILENAME: bytes = _encode_constant(FILENAME)
    FILE_KEY: bytes = _encode_constant(FILE_KEY)
    KEYSTREAM: bytes = _encode_constant(KEYSTREAM)
    CLIENT_ID: bytes = _encode_constant(CLIENT_ID)
    MESSAGE_ID: bytes = _encode_constant(MESSAGE_ID)
    CHUNKY_2048: bytes = _encode_constant(CHUNKY_2048)
    METATAG_KEY: bytes = _encode_constant(METATAG_KEY)
    MESSAGE_KEY: bytes = _encode_constant(MESSAGE_KEY)
    PADDING_KEY: bytes = _encode_constant(PADDING_KEY)
    SESSION_KEY: bytes = _encode_constant(SESSION_KEY)
    CLIENT_INDEX: bytes = _encode_constant(CLIENT_INDEX)
    REGISTRATION: bytes = _encode_constant(REGISTRATION)
    AUTHENTICATION: bytes = _encode_constant(AUTHENTICATION)
    CLIENT_MESSAGE_KEY: bytes = _encode_constant(CLIENT_MESSAGE_KEY)
    SERVER_MESSAGE_KEY: bytes = _encode_constant(SERVER_MESSAGE_KEY)


async def asha_256(*data):
    """
    A string-based version of ``hashlib.sha3_256``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    await asleep(0)
    return sha3_256(str(data).encode()).hexdigest()


def sha_256(*data):
    """
    A string-based version of ``hashlib.sha3_256``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    return sha3_256(str(data).encode()).hexdigest()


async def asha_256_hmac(data, *, key):
    """
    An HMAC-esque version of the ``hashlib.sha3_512`` function.
    """
    await asleep(0)
    bytes_key = key if isinstance(key, bytes) else repr(key).encode()
    bytes_data = data if isinstance(data, bytes) else repr(data).encode()
    await asleep(0)
    return hmac.new(bytes_key, bytes_data, sha3_256).hexdigest()


def sha_256_hmac(data, *, key):
    """
    An HMAC-esque version of the ``hashlib.sha3_512`` function.
    """
    bytes_key = key if isinstance(key, bytes) else repr(key).encode()
    bytes_data = data if isinstance(data, bytes) else repr(data).encode()
    return hmac.new(bytes_key, bytes_data, sha3_256).hexdigest()


async def asha_512(*data):
    """
    A string-based version of ``hashlib.sha3_512``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    await asleep(0)
    return sha3_512(str(data).encode()).hexdigest()


def sha_512(*data):
    """
    A string-based version of ``hashlib.sha3_512``. Stringifies & places
    all inputs into a tuple before hashing.
    """
    return sha3_512(str(data).encode()).hexdigest()


async def asha_512_hmac(data, *, key):
    """
    An HMAC-esque version of the ``hashlib.sha3_512`` function.
    """
    await asleep(0)
    bytes_key = key if isinstance(key, bytes) else repr(key).encode()
    bytes_data = data if isinstance(data, bytes) else repr(data).encode()
    await asleep(0)
    return hmac.new(bytes_key, bytes_data, sha3_512).hexdigest()


def sha_512_hmac(data, *, key):
    """
    An HMAC-esque version of the ``hashlib.sha3_512`` function.
    """
    bytes_key = key if isinstance(key, bytes) else repr(key).encode()
    bytes_data = data if isinstance(data, bytes) else repr(data).encode()
    return hmac.new(bytes_key, bytes_data, sha3_512).hexdigest()


async def amake_timestamp(*, width=TIMESTAMP_BYTES, byteorder="big"):
    """
    Returns a ``width`` length byte sequence representation of the
    current time in seconds.
    """
    await asleep(0)
    return this_second().to_bytes(width, byteorder)


def make_timestamp(*, width=TIMESTAMP_BYTES, byteorder="big"):
    """
    Returns a ``width`` length byte sequence representation of the
    current time in seconds.
    """
    return this_second().to_bytes(width, byteorder)


async def atimestamp_ttl_delta(timestamp, ttl):
    """
    Takes a ``timestamp`` & returns the difference between now & the
    timestamp & the ``ttl`` time-to-live limit. If the result is
    positive, then the elapsed time from the timestamp has exceeded the
    ttl limit.
    """
    delta = this_second() - int.from_bytes(timestamp, "big")
    return delta - ttl


def timestamp_ttl_delta(timestamp, ttl):
    """
    Takes a ``timestamp`` & returns the difference between now & the
    timestamp & the ``ttl`` time-to-live limit. If the result is
    positive, then the elapsed time from the timestamp has exceeded the
    ttl limit.
    """
    delta = this_second() - int.from_bytes(timestamp, "big")
    return delta - ttl


async def acheck_timestamp(timestamp, ttl):
    """
    Raises ``ValueError`` if ``timestamp`` is more than ``ttl`` seconds
    from the current time.
    """
    is_invalid_timestamp_length = len(timestamp) != TIMESTAMP_BYTES
    seconds = timespan = await atimestamp_ttl_delta(timestamp, ttl)
    timestamp_is_expired = timespan > 0
    await asleep(0)
    if is_invalid_timestamp_length:
        raise ValueError("Invalid timestamp format, must be 8 bytes long.")
    elif not ttl:
        return
    elif timestamp_is_expired:
        error = TimeoutError(f"Timestamp expired by <{seconds}> seconds.")
        error.value = seconds
        raise error


def check_timestamp(timestamp, ttl):
    """
    Raises ``ValueError`` if ``timestamp`` is more than ``ttl`` seconds
    from the current time.
    """
    is_invalid_timestamp_length = len(timestamp) != TIMESTAMP_BYTES
    seconds = timespan = timestamp_ttl_delta(timestamp, ttl)
    timestamp_is_expired = timespan > 0
    if is_invalid_timestamp_length:
        raise ValueError("Invalid timestamp format, must be 8 bytes long.")
    elif not ttl:
        return
    elif timestamp_is_expired:
        error = TimeoutError(f"Timestamp expired by <{seconds}> seconds.")
        error.value = seconds
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

    ``padding``: Y-bytes of pseudo-random bytes derived from a cipher
        rounds particular `key`, `salt` & `pid` using shake_256. Y has
        three categories of potential values:
        When Y == 0-bytes:
            Y can be 0-bytes if the inner-header + body is exactly a
            multiple of the 256-byte blocksize.
        When 32 <= Y <= 256:
            Y can be 32-bytes or more, but less than 256, if the inner-
            header + body is more than 32 bytes less than a multiple of
            the 256-byte blocksize.
        When 256 < Y <= 256 + ε and ε < 32:
            Y can be greater than 256 but less than 256 + 32-bytes if
            the inner-header + body is ε less than a multiple of the 256-
            byte blocksize.
        These rules ensure the padding can reliably be removed after
        decryption since it either doesn't exist or is at least 32 key-
        dependant, unique, pseudo-random, searchable bytes.
    """
    _BLOCKSIZE = BLOCKSIZE
    _TWO_BLOCKS = 2 * BLOCKSIZE
    _SIV_KEY_BYTES = SIV_KEY_BYTES
    _SIV_KEY_NIBBLES = SIV_KEY_NIBBLES
    _TIMESTAMP_BYTES = TIMESTAMP_BYTES
    _TIMESTAMP_NIBBLES = TIMESTAMP_NIBBLES
    _INNER_HEADER_BYTES = INNER_HEADER_BYTES
    _INNER_HEADER_NIBBLES = INNER_HEADER_NIBBLES

    @classmethod
    async def apad_beginning(cls, data):
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
        """
        siv_key = secrets.token_bytes(cls._SIV_KEY_BYTES)
        timestamp = await amake_timestamp()
        return timestamp + siv_key + data

    @classmethod
    def pad_beginning(cls, data):
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
        """
        siv_key = secrets.token_bytes(cls._SIV_KEY_BYTES)
        timestamp = make_timestamp()
        return timestamp + siv_key + data

    @classmethod
    async def apad_ending(cls, data, *, padding_key):
        """
        Pads & returns a plaintext ``data`` with various values that
        improve the package's AEAD cipher security, getting it ready for
        encryption.

        Also, appends padding bytes to ``data`` that are the ``shake_256``
        output of an object fed a ``padding_key`` to aid in CCA security
        / padding oracle attacks. The padding key is derived from the
        hash of the `key`, `salt` & `pid` values. The padding will make
        the plaintext a multiple of 256 bytes.
        """
        await asleep(0)
        remainder = len(data) % cls._BLOCKSIZE
        padding_size = cls._BLOCKSIZE - remainder
        payload = Domains.PADDING_KEY + 2 * padding_key
        padding = shake_256(payload).digest(cls._TWO_BLOCKS)
        await asleep(0)
        if data and not remainder:
            return data
        elif padding_size >= 32:
            return data + padding[:padding_size]
        else:
            return data + padding[: padding_size + cls._BLOCKSIZE]

    @classmethod
    def pad_ending(cls, data, *, padding_key):
        """
        Pads & returns a plaintext ``data`` with various values that
        improve the package's AEAD cipher security, getting it ready for
        encryption.

        Also, appends padding bytes to ``data`` that are the ``shake_256``
        output of an object fed a ``padding_key`` to aid in CCA security
        / padding oracle attacks. The padding key is derived from the
        hash of the `key`, `salt` & `pid` values. The padding will make
        the plaintext a multiple of 256 bytes.
        """
        remainder = len(data) % cls._BLOCKSIZE
        padding_size = cls._BLOCKSIZE - remainder
        payload = Domains.PADDING_KEY + 2 * padding_key
        padding = shake_256(payload).digest(cls._TWO_BLOCKS)
        if data and not remainder:
            return data
        elif padding_size >= 32:
            return data + padding[:padding_size]
        else:
            return data + padding[: padding_size + cls._BLOCKSIZE]

    @classmethod
    async def adepad_beginning(cls, data, *, ttl=0):
        """
        Returns ``data`` after these values are removed:
        - The prepended eight byte timestamp.
        - The prepended 16 byte SIV-key.
        """
        await acheck_timestamp(data[:cls._TIMESTAMP_BYTES], ttl)
        return data[cls._INNER_HEADER_BYTES:]

    @classmethod
    def depad_beginning(cls, data, *, ttl=0):
        """
        Returns ``data`` after these values are removed:
        - The prepended eight byte timestamp.
        - The prepended 16 byte SIV-key.
        """
        check_timestamp(data[:cls._TIMESTAMP_BYTES], ttl)
        return data[cls._INNER_HEADER_BYTES:]

    @classmethod
    async def adepad_ending(cls, data, *, padding_key):
        """
        Returns ``data`` after these values are removed:
        - The appended padding bytes that are built from the ``shake_256``
          output of an object fed a ``padding_key``.
        """
        await asleep(0)
        payload = Domains.PADDING_KEY + 2 * padding_key
        padding = shake_256(payload).digest(32)
        padding_index = data.find(padding)
        await asleep(0)
        if padding_index == -1:
            return data
        else:
            return data[:padding_index]

    @classmethod
    def depad_ending(cls, data, *, padding_key):
        """
        Returns ``data`` after these values are removed:
        - The appended padding bytes that are built from the ``shake_256``
          output of an object fed a ``padding_key``.
        """
        payload = Domains.PADDING_KEY + 2 * padding_key
        padding = shake_256(payload).digest(32)
        padding_index = data.find(padding)
        if padding_index == -1:
            return data
        else:
            return data[:padding_index]

    @classmethod
    async def apad_plaintext(cls, data, *, padding_key):
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

        Also, appends padding bytes to ``data`` that are the ``shake_256``
        output of an object fed a ``padding_key`` to aid in CCA security
        / padding oracle attacks. The padding key is derived from the
        hash of the `key`, `salt` & `pid` values. The padding will make
        the plaintext a multiple of 256 bytes.
        """
        data = await cls.apad_beginning(data=data)
        return await cls.apad_ending(data=data, padding_key=padding_key)

    @classmethod
    def pad_plaintext(cls, data, *, padding_key):
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

        Also, appends padding bytes to ``data`` that are the ``shake_256``
        output of an object fed a ``padding_key`` to aid in CCA security
        / padding oracle attacks. The padding key is derived from the
        hash of the `key`, `salt` & `pid` values. The padding will make
        the plaintext a multiple of 256 bytes.
        """
        data = cls.pad_beginning(data=data)
        return cls.pad_ending(data=data, padding_key=padding_key)

    @classmethod
    async def adepad_plaintext(cls, data, *, padding_key, ttl=0):
        """
        Returns ``data`` after these values are removed:
        - The prepended eight byte timestamp.
        - The prepended 16 byte SIV-key.
        - The appended padding bytes that are built from the ``shake_256``
          output of an object fed a ``padding_key``.
        """
        data = await cls.adepad_beginning(data=data, ttl=ttl)
        return await cls.adepad_ending(data=data, padding_key=padding_key)

    @classmethod
    def depad_plaintext(cls, data, *, padding_key, ttl=0):
        """
        Returns ``data`` after these values are removed:
        - The prepended eight byte timestamp.
        - The prepended 16 byte SIV-key.
        - The appended padding bytes that are built from the ``shake_256``
          output of an object fed a ``padding_key``.
        """
        data = cls.depad_beginning(data=data, ttl=ttl)
        return cls.depad_ending(data=data, padding_key=padding_key)

    @classmethod
    async def _asurpress_stop_iteration(cls, plaintext_stream, *, rounds=4):
        """
        Yields upto ``rounds`` number of plaintext blocks from the
        ``plaintext_stream`` async iterable. It surpresses any raised
        `StopAsyncIteration` to do so. If the stream is empty, then the
        remaining number of empty bytes sequences are yielded instead.
        """
        for _ in range(rounds):
            try:
                yield await plaintext_stream.asend(None)
            except StopAsyncIteration:
                yield b""

    @classmethod
    def _surpress_stop_iteration(cls, plaintext_stream, *, rounds=4):
        """
        Yields upto ``rounds`` number of plaintext blocks from the
        ``plaintext_stream`` iterable by surpressing `StopIteration` if
        it's raised. If the stream is empty, then the remaining number
        of empty bytes sequences are yielded instead.
        """
        for _ in range(rounds):
            try:
                yield plaintext_stream.send(None)
            except StopIteration:
                yield b""

    @classmethod
    async def _abegin_pad_stream(cls, plaintext_stream):
        """
        Returns a stream with its inner header added. It attempts to
        buffer several iterations of output from the ``output_stream``
        which produces unpadded plaintext data.
        """
        buffer = [
            chunk
            async for chunk
            in cls._asurpress_stop_iteration(plaintext_stream, rounds=4)
        ]
        return Datastream(
            await Padding.apad_beginning(b"".join(buffer)), buffer_size=1
        )

    @classmethod
    def _begin_pad_stream(cls, plaintext_stream):
        """
        Returns a stream with its inner header added. It attempts to
        buffer several iterations of output from the ``output_stream``
        which produces unpadded plaintext data.
        """
        buffer = b"".join(
            chunk
            for chunk
            in cls._surpress_stop_iteration(plaintext_stream, rounds=4)
        )
        return Datastream(Padding.pad_beginning(buffer), buffer_size=1)

    @comprehension(chained=True)
    async def _apad_plaintext(self, key, *, salt, pid=0):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in plaintext padding algorithm for binary data. Once
        copied, the ``self`` argument becomes a reference to an instance
        of ``Comprende``.

        Pads & yields the plaintext that is produced from the underlying
        generator with various values that improve the package's online
        AEAD cipher security & converts it into an online MRAE scheme.
        The yielded plaintext is resized to 256 bytes per iteration.

        Prepends an 8-byte timestamp & a 16-byte random & ephemeral SIV-
        key to the stream of data produced. The timestamp allows a time-
        to-live feature to exist for all ciphertexts, aiding replay
        attack resistance. It also, along with the SIV-key, ensures that
        the synthetic IV, which is derived from the keyed-hash of the
        first plaintext block, is globally unique. The SIV therefore
        makes the keystream & resulting ciphertext globally unique &
        salt reuse / misuse resistant.

        Also, appends padding bytes to the stream of data that are the
        ``shake_256`` output of an object fed a ``padding_key`` to aid
        in CCA security / padding oracle attacks. The padding key is
        derived from the hash of the `key`, `salt` & `pid` values. The
        padding will make the plaintext a multiple of 256 bytes.
        """
        try:
            asend = self.asend
            stream = await Padding._abegin_pad_stream(self)
            while True:
                try:
                    stream.append(await asend(None))
                except StopAsyncIteration:
                    pass
                yield await stream.apopleft()
        except StopAsyncIteration:
            padding_key = await Padding.aderive_key(key, salt=salt, pid=pid)
            final_chunks = await Padding.apad_ending(
                stream.buffer.popleft(), padding_key=padding_key
            )
            async for final_chunk in adata.root(final_chunks):
                yield final_chunk

    @comprehension(chained=True)
    def _pad_plaintext(self, key, *, salt, pid=0):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in plaintext padding algorithm for binary data. Once
        copied, the ``self`` argument becomes a reference to an instance
        of ``Comprende``.

        Pads & yields the plaintext that is produced from the underlying
        generator with various values that improve the package's online
        AEAD cipher security & converts it into an online MRAE scheme.
        The yielded plaintext is resized to 256 bytes per iteration.

        Prepends an 8-byte timestamp & a 16-byte random & ephemeral SIV-
        key to the stream of data produced. The timestamp allows a time-
        to-live feature to exist for all ciphertexts, aiding replay
        attack resistance. It also, along with the SIV-key, ensures that
        the synthetic IV, which is derived from the keyed-hash of the
        first plaintext block, is globally unique. The SIV therefore
        makes the keystream & resulting ciphertext globally unique &
        salt reuse / misuse resistant.

        Also, appends padding bytes to the stream of data that are the
        ``shake_256`` output of an object fed a ``padding_key`` to aid
        in CCA security / padding oracle attacks. The padding key is
        derived from the hash of the `key`, `salt` & `pid` values. The
        padding will make the plaintext a multiple of 256 bytes.
        """
        try:
            send = self.send
            stream = Padding._begin_pad_stream(self)
            while True:
                try:
                    stream.append(send(None))
                except StopIteration:
                    pass
                yield stream.popleft()
        except StopIteration:
            padding_key = Padding.derive_key(key, salt=salt, pid=pid)
            final_chunks = Padding.pad_ending(
                stream.buffer.popleft(), padding_key=padding_key
            )
            yield from data.root(final_chunks)

    @classmethod
    async def _abegin_depad_stream(cls, plaintext_stream, ttl=0):
        """
        Returns a stream with its inner header removed. It attempts to
        buffer several iterations of output from the ``output_stream``
        which produces data with padding attached to it.
        """
        buffer = [
            chunk
            async for chunk
            in cls._asurpress_stop_iteration(plaintext_stream, rounds=4)
        ]
        return Datastream(
            await cls.adepad_beginning(b"".join(buffer), ttl=ttl),
            buffer_size=2,
        )

    @classmethod
    def _begin_depad_stream(cls, plaintext_stream, ttl=0):
        """
        Returns a stream with its inner header removed. It attempts to
        buffer several iterations of output from the ``output_stream``
        which produces data with padding attached to it.
        """
        buffer = b"".join(
            chunk
            for chunk
            in cls._surpress_stop_iteration(plaintext_stream, rounds=4)
        )
        return Datastream(
            cls.depad_beginning(buffer, ttl=ttl), buffer_size=2
        )

    @comprehension(chained=True)
    async def _adepad_plaintext(self, key, *, salt, pid=0, ttl=0):
        """
        Returns ``data`` after these values are removed:
        - The prepended eight byte timestamp.
        - The prepended 16 byte SIV-key.
        - The appended padding bytes that are built from the ``shake_256``
          output of an object fed a ``padding_key``.
        """
        try:
            asend = self.asend
            stream = await Padding._abegin_depad_stream(self, ttl)
            while True:
                try:
                    stream.append(await asend(None))
                except StopAsyncIteration:
                    pass
                yield await stream.apopleft()
        except StopAsyncIteration:
            padding_key = await Padding.aderive_key(key, salt=salt, pid=pid)
            final_chunks = await Padding.adepad_ending(
                b"".join(stream.buffer), padding_key=padding_key
            )
            async for final_chunk in adata.root(final_chunks):
                yield final_chunk

    @comprehension(chained=True)
    def _depad_plaintext(self, key, *, salt, pid=0, ttl=0):
        """
        Returns ``data`` after these values are removed:
        - The prepended eight byte timestamp.
        - The prepended 16 byte SIV-key.
        - The appended padding bytes that are built from the ``shake_256``
          output of an object fed a ``padding_key``.
        """
        try:
            send = self.send
            stream = Padding._begin_depad_stream(self, ttl)
            while True:
                try:
                    stream.append(send(None))
                except StopIteration:
                    pass
                yield stream.popleft()
        except StopIteration:
            padding_key = Padding.derive_key(key, salt=salt, pid=pid)
            final_chunks = Padding.depad_ending(
                b"".join(stream.buffer), padding_key=padding_key
            )
            yield from data.root(final_chunks)


class BytesIO:
    """
    A utility class for converting json/dict ciphertext to & from bytes
    objects. Also, provides an interface for transparently writing
    ciphertext as bytes files & reading bytes ciphertext files as json
    dictionaries. This class also has access to the plaintext padding
    algorithm used by the package.
    """
    _SIV = SIV
    _HMAC = HMAC
    _SALT = SALT
    _EQUAL_SIGN = b"%3D"
    _BLOCKSIZE = BLOCKSIZE
    _SIV_BYTES = SIV_BYTES
    _CIPHERTEXT = CIPHERTEXT
    _HMAC_BYTES = HMAC_BYTES
    _SALT_BYTES = SALT_BYTES
    _HEADER_BYTES = HEADER_BYTES
    _MAP_ENCODING = MAP_ENCODING
    _SIV_KEY_BYTES = SIV_KEY_BYTES
    _LIST_ENCODING = LIST_ENCODING
    _URL_SAFE_TABLE = URL_SAFE_TABLE
    _ASCII_TABLE_128 = ASCII_TABLE_128
    _TIMESTAMP_BYTES = TIMESTAMP_BYTES
    _INNER_HEADER_BYTES = INNER_HEADER_BYTES
    pad_plaintext = staticmethod(Padding.pad_plaintext)
    apad_plaintext = staticmethod(Padding.apad_plaintext)
    depad_plaintext = staticmethod(Padding.depad_plaintext)
    adepad_plaintext = staticmethod(Padding.adepad_plaintext)
    check_timestamp = staticmethod(check_timestamp)
    acheck_timestamp = staticmethod(acheck_timestamp)
    amake_timestamp = staticmethod(amake_timestamp)
    make_timestamp = staticmethod(make_timestamp)
    Padding = Padding

    def __init__(self):
        pass

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
    async def _aprocess_json(cls, data):
        """
        Takes in json ``data`` for initial processing. Returns a
        namespace populated with the discovered values.
        """
        await asleep(0)
        obj = cls._make_stack()
        obj.result = b""
        obj.copy = cls._load_json(data)
        await asleep(0)
        obj.hmac = obj.copy.pop(cls._HMAC)
        obj.salt = obj.copy.pop(cls._SALT)
        obj.siv = obj.copy.pop(cls._SIV)
        obj.ciphertext = obj.copy.pop(cls._CIPHERTEXT)
        await asleep(0)
        return obj

    @classmethod
    def _process_json(cls, data):
        """
        Takes in json ``data`` for initial processing. Returns a
        namespace populated with the discovered values.
        """
        obj = cls._make_stack()
        obj.result = b""
        obj.copy = cls._load_json(data)
        obj.hmac = obj.copy.pop(cls._HMAC)
        obj.salt = obj.copy.pop(cls._SALT)
        obj.siv = obj.copy.pop(cls._SIV)
        obj.ciphertext = obj.copy.pop(cls._CIPHERTEXT)
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
            raise TypeError(CIPHERTEXT_IS_NOT_BYTES)
        elif (len(ciphertext) - cls._HEADER_BYTES) % cls._BLOCKSIZE:
            raise ValueError(INVALID_CIPHERTEXT_LENGTH)

    @classmethod
    async def ajson_to_bytes(cls, data):
        """
        Converts json ``data`` of listed ciphertext into a bytes object.
        """
        data = await cls._aprocess_json(data)
        data.result = bytes.fromhex(data.hmac + data.salt + data.siv)
        for chunk in data.ciphertext:
            await asleep(0)
            data.result += chunk.to_bytes(cls._BLOCKSIZE, "big")
        cls._validate_ciphertext_length(data.result)
        return data.result

    @classmethod
    def json_to_bytes(cls, data):
        """
        Converts json ``data`` of listed ciphertext into a bytes object.
        """
        data = cls._process_json(data)
        data.result = bytes.fromhex(data.hmac + data.salt + data.siv)
        data.result += b"".join(
            chunk.to_bytes(cls._BLOCKSIZE, "big")
            for chunk in data.ciphertext
        )
        cls._validate_ciphertext_length(data.result)
        return data.result

    @classmethod
    async def _aprocess_bytes(cls, data, *, encoding=_LIST_ENCODING):
        """
        Takes in bytes ``data`` for initial processing. Returns a
        namespace populated with the discovered ciphertext values.
        `LIST_ENCODING` is the default encoding for all ciphertext.
        Databases used to use the `MAP_ENCODING`, but they now also
        output listed ciphertext.
        """
        await asleep(0)
        cls._validate_ciphertext_length(data)
        obj = cls._make_stack()
        obj.result = {}
        obj.copy = data
        obj.hmac = data[:cls._HMAC_BYTES]
        obj.salt = data[cls._HMAC_BYTES:cls._HMAC_BYTES + cls._SALT_BYTES]
        obj.siv = data[cls._HMAC_BYTES + cls._SALT_BYTES:cls._HEADER_BYTES]
        obj.ciphertext = data[cls._HEADER_BYTES:]
        await asleep(0)
        return obj

    @classmethod
    def _process_bytes(cls, data, *, encoding=_LIST_ENCODING):
        """
        Takes in bytes ``data`` for initial processing. Returns a
        namespace populated with the discovered ciphertext values.
        `LIST_ENCODING` is the default encoding for all ciphertext.
        Databases used to use the `MAP_ENCODING`, but they now also
        output listed ciphertext.
        """
        cls._validate_ciphertext_length(data)
        obj = cls._make_stack()
        obj.result = {}
        obj.copy = data
        obj.hmac = data[:cls._HMAC_BYTES]
        obj.salt = data[cls._HMAC_BYTES:cls._HMAC_BYTES + cls._SALT_BYTES]
        obj.siv = data[cls._HMAC_BYTES + cls._SALT_BYTES:cls._HEADER_BYTES]
        obj.ciphertext = data[cls._HEADER_BYTES:]
        return obj

    @classmethod
    async def abytes_to_json(cls, data, *, encoding=_LIST_ENCODING):
        """
        Converts bytes ``data`` of listed ciphertext back into a json
        dictionary. `LIST_ENCODING` is the default encoding for all
        ciphertext. Databases used to use the `MAP_ENCODING`, but they
        now also output listed ciphertext.
        """
        streamer = adata.root
        obj = await cls._aprocess_bytes(data, encoding=encoding)
        obj.result["ciphertext"] = [
            int.from_bytes(chunk, "big")
            async for chunk in streamer(obj.ciphertext)
        ]
        obj.result[cls._HMAC] = obj.hmac.hex()
        obj.result[cls._SALT] = obj.salt.hex()
        obj.result[cls._SIV] = obj.siv.hex()
        return obj.result

    @classmethod
    def bytes_to_json(cls, data, *, encoding=_LIST_ENCODING):
        """
        Converts bytes ``data`` of listed ciphertext back into a json
        dictionary. `LIST_ENCODING` is the default encoding for all
        ciphertext. Databases used to use the `MAP_ENCODING`, but they
        now also output listed ciphertext.
        """
        streamer = generics.data.root
        obj = cls._process_bytes(data, encoding=encoding)
        obj.result["ciphertext"] = [
            int.from_bytes(chunk, "big")
            for chunk in streamer(obj.ciphertext)
        ]
        obj.result[cls._HMAC] = obj.hmac.hex()
        obj.result[cls._SALT] = obj.salt.hex()
        obj.result[cls._SIV] = obj.siv.hex()
        return obj.result

    @classmethod
    async def abytes_to_urlsafe(cls, byte_string):
        """
        Turns a ``byte_string`` into a url safe string derived from the
        given ``table``.
        """
        await asleep(0)
        urlsafe_token = base64.urlsafe_b64encode(byte_string)
        await asleep(0)
        return urlsafe_token.replace(b"=", cls._EQUAL_SIGN)

    @classmethod
    def bytes_to_urlsafe(cls, byte_string):
        """
        Turns a ``byte_string`` into a url safe string derived from the
        given ``table``.
        """
        urlsafe_token = base64.urlsafe_b64encode(byte_string)
        return urlsafe_token.replace(b"=", cls._EQUAL_SIGN)

    @classmethod
    async def aurlsafe_to_bytes(cls, token):
        """
        Turns a url safe ``token`` into a bytes type string.
        """
        decoded_token = token.replace(cls._EQUAL_SIGN, b"=")
        await asleep(0)
        return base64.urlsafe_b64decode(decoded_token)

    @classmethod
    def urlsafe_to_bytes(cls, token):
        """
        Turns a url safe ``token`` into a bytes type string.
        """
        decoded_token = token.replace(cls._EQUAL_SIGN, b"=")
        return base64.urlsafe_b64decode(decoded_token)

    @classmethod
    async def ajson_to_ascii(cls, data, *, table=ASCII_TABLE_128):
        """
        Converts json ciphertext into ascii consisting of characters
        found inside the ``table`` keyword argument.
        """
        int_data = int.from_bytes(await cls.ajson_to_bytes(data), "big")
        return await aint_to_base(int_data, len(table), table)

    @classmethod
    def json_to_ascii(cls, data, *, table=ASCII_TABLE_128):
        """
        Converts json ciphertext into ascii consisting of characters
        found inside the ``table`` keyword argument.
        """
        int_data = int.from_bytes(cls.json_to_bytes(data), "big")
        return int_to_base(int_data, len(table), table)

    @classmethod
    async def aascii_to_json(cls, data, *, table=ASCII_TABLE_128):
        """
        Converts ascii formated ciphertext, consisting of characters
        from the ``table`` keyword argument, back into json.
        """
        int_data = await abase_to_int(data, len(table), table=table)
        length = math.ceil(int_data.bit_length() / 8)
        return await cls.abytes_to_json(int_data.to_bytes(length, "big"))

    @classmethod
    def ascii_to_json(cls, data, *, table=ASCII_TABLE_128):
        """
        Converts ascii formated ciphertext, consisting of characters
        from the ``table`` keyword argument, back into json.
        """
        int_data = base_to_int(data, base=len(table), table=table)
        length = math.ceil(int_data.bit_length() / 8)
        return cls.bytes_to_json(int_data.to_bytes(length, "big"))

    @classmethod
    async def aread(cls, path, *, encoding=_LIST_ENCODING):
        """
        Reads the bytes file at ``path`` under a certain ``encoding``.
        `LIST_ENCODING` is the default encoding for all ciphertext.
        Databases used to use the `MAP_ENCODING`, but they now also
        output listed ciphertext.
        """
        async with aiofiles.open(path, "rb") as f:
            return await cls.abytes_to_json(
                await f.read(), encoding=encoding
            )

    @classmethod
    def read(cls, path, *, encoding=_LIST_ENCODING):
        """
        Reads the bytes file at ``path`` under a certain ``encoding``.
        `LIST_ENCODING` is the default encoding for all ciphertext.
        Databases used to use the `MAP_ENCODING`, but they now also
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


class Datastream:
    """
    An iterable type which allows for incomplete data to be iterated
    over & extended during iteration. This funcitonality can save on in-
    memory costs while processes large amounts of data. Protocols which
    require logic for the last elements of a stream can be assisted by
    passing a `buffer_size` to the initializer. The size determines the
    number of iteration results will withheld from the end of a stream
    in the `buffer` attribute deque. They can then be yielded processed
    in some custom manner determined by the user

    WARNING: Because of Python quirks around memory management, loading
    up large amounts of data into an instance will fill up a machine's
    memory & not be freed even after being popped out or deleted. This
    is behaviour that occurs in the deque where the sequences are stored
    prior to being processed. If buffering up large amounts of data is
    needed, then a workaround would be to run the data processing using
    this class in a separate process. When the process is complete then
    the memory will be freed up.
    """

    def __init__(self, sequence, size=BLOCKSIZE, *, buffer_size=0):
        """
        Prepare the object to iterate over sequences of any arbitrary
        length, to yield them in ``size``-sized chunks.
        """
        if buffer_size < 0:
            raise ValueError("The ``buffer_size`` must be non-negative.")
        self.index = -1
        self._size = size
        self._buffer_size = buffer_size
        self._sequences = deque([sequence])
        self.append = self._sequences.append
        self._iterator = unpack.root(self.__iter__())
        self._aiterator = aunpack.root(self.__aiter__())
        self.buffer = deque([], maxlen=self._buffer_size + 1)

    def __bool__(self):
        """
        If the datastream is empty then return False, otherwise True.
        """
        return bool(self._sequences or self._buffer)

    async def _afill_buffer(self, stream):
        """
        Fills the instance's buffer with the user defined amount of
        uniformly sized sequences.
        """
        try:
            for _ in range(self._buffer_size):
                self.buffer.append(await stream())
                self.index += 1
        except IndexError:
            pass

    def _fill_buffer(self, stream):
        """
        Fills the instance's buffer with the user defined amount of
        uniformly sized sequences.
        """
        try:
            for _ in range(self._buffer_size):
                self.buffer.append(stream())
                self.index += 1
        except IndexError:
            pass

    async def _astart_stream(self):
        """
        Returns the generator stream which yields & uniformly resizes
        the chunks of user sequences in its collection.
        """
        return apopleft(self._sequences).aresize(self._size)

    def _start_stream(self):
        """
        Returns the generator stream which yields & uniformly resizes
        the chunks of user sequences in its collection.
        """
        return popleft(self._sequences).resize(self._size)

    async def __aiter__(self):
        """
        Runs through a list of sequences & yields ``size`` sized chunks
        of the collected sequences one chunk at a time.
        """
        try:
            stream = await self._astart_stream()
            await self._afill_buffer(stream)
            append = self.buffer.append
            popleft = self.buffer.popleft
            while True:
                append(await stream())
                self.index += 1
                yield popleft()
        except StopAsyncIteration:
            pass

    def __iter__(self):
        """
        Runs through a list of sequences & yields ``size`` sized chunks
        of the collected sequences one chunk at a time.
        """
        try:
            stream = self._start_stream()
            self._fill_buffer(stream)
            append = self.buffer.append
            popleft = self.buffer.popleft
            while True:
                append(stream())
                self.index += 1
                yield popleft()
        except StopIteration:
            pass

    async def apopleft(self):
        """
        Returns the next value in the instance's async iterator object.
        """
        return await self._aiterator.asend(None)

    def popleft(self):
        """
        Returns the next value in the instance's iterator object.
        """
        return self._iterator.send(None)


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


async def abase_to_int(string, base, table=ASCII_ALPHANUMERIC):
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


def base_to_int(string, base, table=ASCII_ALPHANUMERIC):
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


async def aint_to_base(number, base, table=ASCII_ALPHANUMERIC):
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


def int_to_base(number, base, table=ASCII_ALPHANUMERIC):
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


async def abuild_tree(*, depth=4, width=2, leaf=None):
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
            branch: await abuild_tree(
                depth=next_depth, width=width, leaf=leaf
            )
            for branch in range(width)
        }
    else:
        return leaf


def build_tree(*, depth=4, width=2, leaf=None):
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
            branch: build_tree(depth=next_depth, width=width, leaf=leaf)
            for branch in range(width)
        }
    else:
        return leaf


__extras = {
    "AsyncInit": AsyncInit,
    "BytesIO": BytesIO,
    "Comprende": Comprende,
    "Datastream": Datastream,
    "Enumerate": Enumerate,
    "Hasher": Hasher,
    "Domains": Domains,
    "Padding": Padding,
    "IterableClass": IterableClass,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "abase_to_int": abase_to_int,
    "abuild_tree": abuild_tree,
    "abirth": abirth,
    "abytes_count": abytes_count,
    "abytes_range": abytes_range,
    "acompact": acompact,
    "acount": acount,
    "acustomize_parameters": acustomize_parameters,
    "acycle": acycle,
    "adata": adata,
    "aecho": aecho,
    "afrom_b64": afrom_b64,
    "ahash_bytes": ahash_bytes,
    "aignore": aignore,
    "aint_to_base": aint_to_base,
    "aiter": aiter,
    "amake_timestamp": amake_timestamp,
    "anext": anext,
    "aorder": aorder,
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
    "atime_safe_equality": atime_safe_equality,
    "ato_b64": ato_b64,
    "aunpack": aunpack,
    "await_on": await_on,
    "axi_mix": axi_mix,
    "azip": azip,
    "base_to_int": base_to_int,
    "build_tree": build_tree,
    "birth": birth,
    "bytes_count": bytes_count,
    "bytes_range": bytes_range,
    "compact": compact,
    "comprehension": comprehension,
    "convert_class_method_to_member": convert_class_method_to_member,
    "convert_static_method_to_member": convert_static_method_to_member,
    "count": count,
    "customize_parameters": customize_parameters,
    "cycle": cycle,
    "data": data,
    "display_exception_info": display_exception_info,
    "echo": echo,
    "from_b64": from_b64,
    "hash_bytes": hash_bytes,
    "ignore": ignore,
    "int_to_base": int_to_base,
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
    "time_safe_equality": time_safe_equality,
    "to_b64": to_b64,
    "unpack": unpack,
    "wait_on": wait_on,
    "xi_mix": xi_mix,
    "zip": _zip,
}


generics = Namespace.make_module("generics", mapping=__extras)

