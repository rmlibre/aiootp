# This file is part of aiootp, an asynchronous crypto and anonymity
# library. Home of the Chunky2048 psuedo one-time pad stream cipher.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = []


__doc__ = (
    "A module for gathering the package's various utility generators in"
    "to one place for neater organization."
)


import io
import json
import math
import heapq
import builtins
import collections
import hmac as _hmac
from os import linesep
from time import time, sleep
from types import GeneratorType
from types import AsyncGeneratorType
from hashlib import sha3_256 as _sha3_256
from hashlib import sha3_512 as _sha3_512
from collections import deque
from collections.abc import Iterable, Iterator
from collections.abc import AsyncIterable, AsyncIterator
from functools import wraps
from contextlib import contextmanager
from inspect import isasyncgenfunction as is_async_gen_function
from inspect import isgeneratorfunction as is_generator_function
from .__dependencies import async_contextmanager
from .__constants import *
from ._exceptions import *
from ._debuggers import DebugControl
from ._typing import Typing as t
from .asynchs import Threads
from .asynchs import new_task, asleep
from .commons import Namespace, OpenNamespace
from .commons import make_module
from .generics import BytesIO
from .generics import int_as_base, base_as_int


def is_async_iterable(obj: t.Any) -> bool:
    """
    Returns a bool of whether ``obj`` supports async iteration.
    """
    return isinstance(obj, AsyncIterable)


def is_iterable(obj: t.Any) -> bool:
    """
    Returns a bool of whether ``obj`` supports iteration.
    """
    return isinstance(obj, Iterable)


def is_async_iterator(obj: t.Any) -> bool:
    """
    Returns a bool of whether ``obj`` is an async iterator.
    """
    return isinstance(obj, AsyncIterator)


def is_iterator(obj: t.Any) -> bool:
    """
    Returns a bool of whether ``obj`` is an iterator.
    """
    return isinstance(obj, Iterator)


def is_async_generator(obj: t.Any) -> bool:
    """
    Returns a bool of whether ``obj`` is an async generator.
    """
    return isinstance(obj, AsyncGeneratorType)


def is_generator(obj: t.Any) -> bool:
    """
    Returns a bool of whether ``obj`` is an generator.
    """
    return isinstance(obj, GeneratorType)


class Enumerate:
    """
    An ``enumerate`` variant that supports sync & async generators.
    """

    __slots__ = ("gen", "start", "_encoding", "a", "kw")

    _ENCODINGS: t.Callable[[int], t.Any] = OpenNamespace(
        int=lambda index, *a, **kw: index,
        bytes=lambda index, *a, **kw: index.to_bytes(*a, **kw),
    )

    def __init__(
        self,
        gen: t.AsyncOrSyncIterable[t.Any],
        start: int = 0,
        *,
        encoding: str = "int",
        a: t.Iterable[t.Any] = (8, BIG),
        kw: t.Dict[str, t.Any] = {},
    ) -> None:
        self.a = a
        self.kw = kw.copy()
        self.gen = gen
        self.start = start
        self._encoding = self._ENCODINGS[encoding]

    async def __aiter__(
        self,
    ) -> t.AsyncGenerator[None, t.Tuple[t.Union[int, bytes, t.Any], t.Any]]:
        """
        Adds an incrementing number to each yielded result of either an
        async or sync generator.
        """
        if is_async_iterable(self.gen):
            counter = self.start
            async for result in self.gen:
                yield self._encoding(counter, *self.a, **self.kw), result
                counter += 1
        else:
            for result in self.__iter__():
                await asleep()
                yield result

    def __iter__(
        self,
    ) -> t.Generator[
        None, t.Tuple[t.Union[int, bytes, t.Any], t.Any], None
    ]:
        """
        Adds an incrementing number to each yielded result of either a
        synchronous generator.
        """
        counter = self.start
        for result in self.gen:
            yield self._encoding(counter, *self.a, **self.kw), result
            counter += 1


def comprehension(
    **kwargs: t.Dict[str, t.Any]
) -> t.Callable[..., t.Union[t.AsyncGenerator, t.Generator]]:
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
            return Comprende(func, *a, **{**kw, **kwargs})

        return gen_wrapper

    return func_catch


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
        "_args",
        "_func",
        "_gen",
        "_is_async",
        "_kwargs",
        "_return",
        "_thrown",
        "send",
        "asend",
    )

    _ASYNC_GEN_DONE = "async generator raised StopAsyncIteration"

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
        "_acatch",
        "_catch",
    }
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

    decorator = comprehension

    ReturnValue = ReturnValue

    def __init__(self, func, *a, **kw):
        """
        Establishes async / sync properties of new objects & copies
        over wrapped functions' signatures.
        """
        self._args = a
        self._kwargs = kw
        self._func = func
        self._thrown = None
        self._return = None
        if is_async_gen_function(func):
            self.__set_async()
        else:
            self.__set_sync()

    async def __aexamine_sent_exceptions(self, gen: t.Generator):
        """
        Catches ``Comprende.ReturnValue``s which signals that the
        generator, or a subgenerator in the stack, has raised a return
        value.
        """
        ReturnValue = self.ReturnValue
        while True:
            got = yield
            if got.__class__ is ReturnValue:
                if any(got.args):
                    self._thrown = got.args[0]
                await gen.athrow(got)

    async def _acomprehension(self, got: None = None):
        """
        Wraps the user's generator & monitors the values being sent into
        coroutine for the `Comprende.ReturnValue` signal to halt
        iteration & return the exception's value.
        """
        gen = self._func(*self._args, **self._kwargs)
        asend = gen.asend
        catch_ReturnValue = self.__aexamine_sent_exceptions(gen).asend
        await catch_ReturnValue(None)
        async with self._acatch():
            while True:
                got = yield await asend(got)
                await catch_ReturnValue(got)

    def __set_async(self):
        """
        Does the wrapping of user async generators to allow catching
        return values.
        """
        self._is_async = True
        self.send = None
        self._gen = self._acomprehension()
        asend = self.asend = self._gen.asend
        self.__call__ = lambda got=None: asend(got)

    def __examine_sent_exceptions(self, gen: t.Generator):
        """
        Catches ``Comprende.ReturnValue``s which signals that the
        generator, or a subgenerator in the stack, has raised a return
        value.
        """
        ReturnValue = self.ReturnValue
        while True:
            got = yield
            if got.__class__ is ReturnValue:
                if any(got.args):
                    self._thrown = got.args[0]
                gen.throw(got)

    def _comprehension(self, got: None = None):
        """
        Wraps the user's generator & monitors the values being sent into
        coroutine for the `Comprende.ReturnValue` signal to halt
        iteration & return the exception's value.
        """
        gen = self._func(*self._args, **self._kwargs)
        send = gen.send
        catch_ReturnValue = self.__examine_sent_exceptions(gen).send
        catch_ReturnValue(None)
        with self._catch():
            while True:
                got = yield send(got)
                catch_ReturnValue(got)

    def __set_sync(self):
        """
        Does the wrapping of user generators to allow catching return
        values.
        """
        self._is_async = False
        self.asend = None
        self._gen = self._comprehension()
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
        its values.
        """
        while True:
            try:
                got = yield await self(got)
            except StopAsyncIteration:
                break

    def __iter__(self, *, got=None):
        """
        Iterates over the wrapped generator / coroutine and produces its
        values.
        """
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
        """
        if exc_type is StopAsyncIteration:
            return True

    def __exit__(self, exc_type=None, exc_value=None, traceback=None):
        """
        Surpresses StopIteration exceptions within a context.
        """
        if exc_type is StopIteration:
            return True

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

    async def areset(self):
        """
        Replaces the generator wrapper with a new async wrapper, & does
        the same for all chained `Comprende` objects in its args.
        """
        self.__set_async()
        if issubclass(self._args[0].__class__, BaseComprende):
            await self._args[0].areset()
        return self

    def reset(self):
        """
        Replaces the generator wrapper with a new sync wrapper, & does
        the same for all chained `Comprende` objects in its args.
        """
        self.__set_sync()
        if issubclass(self._args[0].__class__, BaseComprende):
            self._args[0].reset()
        return self

    @async_contextmanager
    async def _acatch(self):
        """
        Handles catching the return values passed through exceptions
        from async generators & makes sure other errors are propagated
        correctly up to user code. Asynchronous generators don't already
        have a mechanism for returning values. So this async context
        manager handles catching return values from Comprende.ReturnValue.
        The result is accessible from `self.aresult()`.
        """
        try:
            await asleep()
            yield self
        except self.ReturnValue as done:
            if done.args:
                self._return = done.args[0]
        except RuntimeError as done:
            if self._ASYNC_GEN_DONE not in done.args:
                raise done
        except StopAsyncIteration:
            pass

    @contextmanager
    def _catch(self):
        """
        Handles catching the return values passed through exceptions
        from sync generators & makes sure other errors are propagated
        correctly up to user code. Synchronous generators already have
        a mechanism for returning values. This context manager handles
        catching StopIteration values, & for the sake of parity with
        async generators, it also catches return values from
        Comprende.ReturnValue exceptions. The result is accessible from
        `self.result()`.
        """
        try:
            yield self
        except self.ReturnValue as done:
            if done.args:
                self._return = done.args[0]
        except StopIteration as done:
            if getattr(done, "value", None) != None:
                self._return = done.value

    async def aresult(self, *, exit=False):
        """
        Controls access to instance results. This method can cause an
        async generator to close when ``exit`` is truthy. If it has a
        result it is returned. Returns `None` if no result is present.
        """
        if exit:
            async with aignore(TypeError, StopAsyncIteration):
                await self(self.ReturnValue())
        return self._return

    def result(self, *, exit=False):
        """
        Controls access to instance results. This method can cause a
        sync generator to close when ``exit`` is truthy. If it has a
        result it is returned. Returns `None` if no result is present.
        """
        if exit:
            with ignore(TypeError, StopIteration):
                self(self.ReturnValue())
        return self._return

    async def alist(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a `list` & returns it.
        """
        return [item async for item in self]

    def list(self):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a `list` & returns it.
        """
        return [*self]

    async def adeque(self, *, maxlen=None):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a `collections.deque` & returns it.
        """
        return deque([item async for item in self], maxlen=maxlen)

    def deque(self, *, maxlen=None):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a `collections.deque` & returns it.
        """
        return collections.deque(self, maxlen=maxlen)

    async def aset(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``set`` & returns it.
        """
        return {item async for item in self}

    def set(self):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a ``set`` & returns it.
        """
        return {*self}

    async def adict(self):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together in a ``dict`` & returns it.
        """
        return {key: value async for key, value in self}

    def dict(self):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together in a ``dict`` & returns it.
        """
        return builtins.dict(self)

    async def ajoin(self, on=""):
        """
        Exhausts the underlying Comprende async generator & joins the
        results together ``on`` the string that's passed & returns it.
        """
        return on.join([item async for item in self])

    def join(self, on=""):
        """
        Exhausts the underlying Comprende sync generator & joins the
        results together ``on`` the string that's passed & returns it.
        """
        return on.join(self)

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
        "arandom_sleep",
        "random_sleep",
        "asleep",
        "sleep",
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
        "asha3_512",
        "sha3_512",
        "asha3_512_hmac",
        "sha3_512_hmac",
        "asha3_256",
        "sha3_256",
        "asha3_256_hmac",
        "sha3_256_hmac",
    }

    @staticmethod
    def _unpack_slice(index: t.Index, _max: int = 1 << 128):
        """
        Returns the `start`, `stop` & `step` values from a slice object.
        """
        if index.__class__ is int:
            return index, index + 1, 1
        elif index.__class__ is slice:
            return (
                index.start if index.start.__class__ is int else 0,
                index.stop if index.stop.__class__ is int else _max,
                index.step if index.step.__class__ is int else 1,
            )
        else:
            raise Issue.value_must("``index``", "be int or slice")

    def _set_index(self, index: t.Index):
        """
        Interprets the slice or int passed into __getitem__ into an
        iterator of a range object.
        """
        index = self._unpack_slice(index)
        if not all(
            (value.__class__ is int) and (value >= 0) for value in index
        ):
            raise Issue.value_must_be_value("index", "positive int")
        return iter(range(*index)).__next__

    async def _agetitem(self, index: t.Index):
        """
        Allows indexing of async generators to yield the values
        associated with the slice or integer passed into the brackets.
        Does not support negative indices.
        """
        got = None
        next_target = self._set_index(index)
        try:
            target = next_target()
            for match in count.root():
                if target == match:
                    got = yield await self(got)
                    target = next_target()
                else:
                    await self(None)
        except (StopIteration, StopAsyncIteration):
            pass

    def _getitem(self, index: t.Index):
        """
        Allows indexing of generators to yield the values associated
        with the slice or integer passed into the brackets. Does not
        support negative indices.
        """
        got = None
        next_target = self._set_index(index)
        try:
            target = next_target()
            for match in count.root():
                if target == match:
                    got = yield self(got)
                    target = next_target()
                else:
                    self(None)
        except StopIteration:
            pass

    def __getitem__(self, index: t.Index):
        """
        Allows indexing of generators & async generators to yield the
        values associated with the slice or integer passed into the
        brackets. Does not support negative indices.
        """
        if self._is_async:
            return self._agetitem(index)
        else:
            return self._getitem(index)

    async def areversed(self, span: t.OptionalIndex = None):
        """
        Exhausts the underlying Comprende async generator upto ``span``
        number of iterations, then yields the results in reversed order.
        """
        target = self[:span] if span else self
        async with target as accumulator:
            results = await accumulator.alist()
        for result in reversed(results):
            yield result

    def reversed(self, span: t.OptionalIndex = None):
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
        key: t.Optional[t.Callable] = None,
        span: t.OptionalIndex = None,
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
        key: t.Optional[t.Callable] = None,
        span: t.OptionalIndex = None,
    ):
        """
        Exhausts the underlying Comprende sync generator upto ``span``
        number of iterations, then yields the results in sorted order.
        """
        target = self[:span] if span else self
        yield from sorted(target, key=key)

    async def aheappop(self, span: t.OptionalIndex = None):
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

    def heappop(self, span: t.OptionalIndex = None):
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

    async def asha3_512(self):
        """
        Applies ``hashlib.sha3_512()`` to each value that's yielded
        from the underlying Comprende async generator before yielding
        the result.
        """
        got = None
        try:
            while True:
                got = yield _sha3_512(await self(got)).digest()
        except StopAsyncIteration:
            pass

    def sha3_512(self):
        """
        Applies ``hashlib.sha3_512()`` to each value that's yielded
        from the underlying Comprende sync generator before yielding
        the result.
        """
        got = None
        try:
            while True:
                got = yield _sha3_512(self(got)).digest()
        except StopIteration:
            pass

    async def asha3_512_hmac(self, *, key: bytes):
        """
        Applies a ``hashlib.sha3_512()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        hmac = _hmac.new
        try:
            while True:
                got = yield hmac(key, await self(got), _sha3_512).digest()
        except StopAsyncIteration:
            pass

    def sha3_512_hmac(self, *, key: bytes):
        """
        Applies a ``hashlib.sha3_512()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        hmac = _hmac.new
        try:
            while True:
                got = yield hmac(key, self(got), _sha3_512).digest()
        except StopIteration:
            pass

    async def asha3_256(self):
        """
        Applies ``hashlib.sha3_256()`` to each value that's yielded
        from the underlying Comprende async generator before yielding
        the result.
        """
        got = None
        try:
            while True:
                got = yield _sha3_256(await self(got)).digest()
        except StopAsyncIteration:
            pass

    def sha3_256(self):
        """
        Applies ``hashlib.sha3_256()`` to each value that's yielded
        from the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield _sha3_256(self(got)).digest()
        except StopIteration:
            pass

    async def asha3_256_hmac(self, *, key: bytes):
        """
        Applies a ``hashlib.sha3_256()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        hmac = _hmac.new
        try:
            while True:
                got = yield hmac(key, await self(got), _sha3_256).digest()
        except StopAsyncIteration:
            pass

    def sha3_256_hmac(self, *, key: bytes):
        """
        Applies a ``hashlib.sha3_256()`` based hmac algorithm to each
        value that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        hmac = _hmac.new
        try:
            while True:
                got = yield hmac(key, self(got), _sha3_256).digest()
        except StopIteration:
            pass

    async def arandom_sleep(self, span: t.PositiveRealNumber = 1):
        """
        Applies a random sleep before each yielded value from the
        underlying ``Comprende`` async generator.
        """
        from .randoms import arandom_sleep as _arandom_sleep

        got = None
        try:
            while True:
                await _arandom_sleep(span)
                got = yield await self(got)
        except StopAsyncIteration:
            pass

    def random_sleep(self, span: t.PositiveRealNumber = 1):
        """
        Applies a random sleep before each yielded value from the
        underlying ``Comprende`` sync generator.
        """
        from .randoms import random_sleep as _random_sleep

        got = None
        try:
            while True:
                _random_sleep(span)
                got = yield self(got)
        except StopIteration:
            pass

    async def asleep(self, span: t.PositiveRealNumber = 1):
        """
        Applies an async sleep of ``span`` seconds before each yielded
        value from the underlying ``Comprende`` async generator.
        """
        got = None
        try:
            while True:
                await asleep(span)
                got = yield await self(got)
        except StopAsyncIteration:
            pass

    def sleep(self, span: t.PositiveRealNumber = 1):
        """
        Applies a sleep of ``span`` seconds before each yielded value
        from the underlying ``Comprende`` sync generator.
        """
        got = None
        try:
            while True:
                sleep(span)
                got = yield self(got)
        except StopIteration:
            pass

    async def atimeout(
        self,
        seconds: int = 5,
        *,
        probe_frequency: t.PositiveRealNumber = 0.000001,
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
            iteration = new_task(self.asend(got))
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
        probe_frequency: t.PositiveRealNumber = 0.000001,
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
                iteration = Threads.submit(self.send, got)
                while not iteration.done():
                    sleep(probe_frequency)
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
        sentinel: t.Any = "",
        *,
        sentinels: t.SupportsContains = (),
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
        sentinel: t.Any = "",
        *,
        sentinels: t.SupportsContains = (),
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

    async def afeed(self, iterable: t.Iterable[t.Any]):
        """
        Takes in an sync or async iterable & sends those values into an
        async coroutine which automates the process of driving an async
        generator which is expecting results from a caller.
        """
        try:
            yield await self(None)
            async for food in aunpack.root(iterable):
                yield await self(food)
        except StopAsyncIteration:
            pass

    def feed(self, iterable: t.Iterable[t.Any]):
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
        try:
            food = await self(None)
            yield food
            while True:
                food = await self(food)
                yield food
        except StopAsyncIteration:
            pass

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

    async def atag(self, tags: t.AsyncOrSyncIterable[t.Any] = None):
        """
        By default behaves like ``enumerate`` for each value yielded
        from the underlying Comprende async generator. Optionally,
        ``tags`` can be passed a sync or async iterable & prepends those
        values to the generator's results.
        """
        got = None
        try:
            if tags:
                async for name in aunpack.root(tags):
                    got = yield name, await self(got)
            else:
                for index in count.root():
                    got = yield index, await self(got)
        except StopAsyncIteration:
            pass

    def tag(self, tags: t.Iterable[t.Any] = None):
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

    async def aresize(self, size: int):
        """
        Buffers the output from the underlying Comprende async generator
        to yield the results in chunks of length ``size``.
        """
        try:
            result = await self(None)
            while True:
                for _ in range(len(result) // size):
                    yield result[:size]
                    result = result[size:]
                try:
                    result += await self(None)
                except StopAsyncIteration:
                    break
            if result:
                yield result
        except StopAsyncIteration:
            pass

    def resize(self, size: int):
        """
        Buffers the output from the underlying Comprende sync generator
        to yield the results in chunks of length ``size``.
        """
        try:
            result = self(None)
            while True:
                for _ in range(len(result) // size):
                    yield result[:size]
                    result = result[size:]
                try:
                    result += self(None)
                except StopIteration:
                    break
            if result:
                yield result
        except StopIteration:
            pass

    async def adelimit(self, delimiter: t.AnyStr = " "):
        """
        Adds a user-defined ``delimiter`` to the end of each result
        yielded from the underlying ``Comprende`` async generator.
        """
        got = None
        try:
            while True:
                got = yield await self(got) + delimiter
        except StopAsyncIteration:
            pass

    def delimit(self, delimiter: t.AnyStr = " "):
        """
        Adds a user-defined ``delimiter`` to the end of each result
        yielded from the underlying ``Comprende`` generator.
        """
        got = None
        try:
            while True:
                got = yield self(got) + delimiter
        except StopIteration:
            pass

    async def adelimited_resize(self, delimiter: t.AnyStr = " "):
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

    def delimited_resize(self, delimiter: t.AnyStr = " "):
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
        bytes_to_base64 = BytesIO.bytes_to_base64
        got = None
        try:
            while True:
                got = yield bytes_to_base64(await self(got))
        except StopAsyncIteration:
            pass

    def to_base64(self):
        """
        Applies ``base64.standard_b64encode`` conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        bytes_to_base64 = BytesIO.bytes_to_base64
        got = None
        try:
            while True:
                got = yield bytes_to_base64(self(got))
        except StopIteration:
            pass

    async def afrom_base64(self):
        """
        Applies ``base64.standard_b64decode`` conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        base64_to_bytes = BytesIO.base64_to_bytes
        got = None
        try:
            while True:
                got = yield base64_to_bytes(await self(got))
        except StopAsyncIteration:
            pass

    def from_base64(self):
        """
        Applies ``base64.standard_b64decode`` conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        base64_to_bytes = BytesIO.base64_to_bytes
        got = None
        try:
            while True:
                got = yield base64_to_bytes(self(got))
        except StopIteration:
            pass

    async def aint_to_ascii(self, byte_order: str = BIG):
        """
        Applies a ``binascii`` int-to-ascii conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        try:
            while True:
                item = await self(got)
                size = math.ceil(item.bit_length() / 8)
                result = item.to_bytes(size, byte_order)
                got = yield result.decode()
        except StopAsyncIteration:
            pass

    def int_to_ascii(self, byte_order: str = BIG):
        """
        Applies a ``binascii`` int-to-ascii conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        try:
            while True:
                item = self(got)
                size = math.ceil(item.bit_length() / 8)
                result = item.to_bytes(size, byte_order)
                got = yield result.decode()
        except StopIteration:
            pass

    async def aascii_to_int(self):
        """
        Applies a ``binascii`` ascii-to-int conversion to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        try:
            while True:
                item = (await self(got)).encode()
                got = yield int.from_bytes(item, BIG)
        except StopAsyncIteration:
            pass

    def ascii_to_int(self):
        """
        Applies a ``binascii`` ascii-to-int conversion to each value
        that's yielded from the underlying Comprende sync generator
        before yielding the result.
        """
        got = None
        try:
            while True:
                got = yield int.from_bytes(self(got).encode(), BIG)
        except StopIteration:
            pass

    async def aint(self, *a):
        """
        Applies ``builtins.int(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield int(await self(got), *a)
        except StopAsyncIteration:
            pass

    def int(self, *a):
        """
        Applies ``builtins.int(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield builtins.int(self(got), *a)
        except StopIteration:
            pass

    async def abytes_to_int(self, byte_order: str = BIG):
        """
        Applies ``int.from_bytes(result, byte_order)`` to each value
        that's yielded from the underlying Comprende async generator
        before yielding the result.
        """
        got = None
        try:
            while True:
                got = yield int.from_bytes(await self(got), byte_order)
        except StopAsyncIteration:
            pass

    def bytes_to_int(self, byte_order: str = BIG):
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
        self, size: int = 8, byte_order: str = BIG
    ):
        """
        Applies ``int.to_bytes(result, size, byte_order)`` to each
        value that's yielded from the underlying Comprende async
        generator before yielding the result.
        """
        got = None
        try:
            while True:
                got = yield (await self(got)).to_bytes(size, byte_order)
        except StopAsyncIteration:
            pass

    def int_to_bytes(self, size: int = 8, byte_order: str = BIG):
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
        try:
            while True:
                got = yield bytes.fromhex(await self(got))
        except StopAsyncIteration:
            pass

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
        try:
            while True:
                got = yield (await self(got)).hex()
        except StopAsyncIteration:
            pass

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
        try:
            while True:
                got = yield int_as_base(await self(got), base, table=table)
        except StopAsyncIteration:
            pass

    def to_base(self, base: int = 95, table: str = Tables.ASCII_95):
        """
        Converts each integer value that's yielded from the underlying
        Comprende sync generator to a string in ``base`` before yielding
        the result.
        """
        got = None
        try:
            while True:
                got = yield int_as_base(self(got), base, table=table)
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
        try:
            while True:
                got = yield base_as_int(await self(got), base, table=table)
        except StopAsyncIteration:
            pass

    def from_base(self, base: int = 95, table: str = Tables.ASCII_95):
        """
        Convert ``string`` in numerical ``base`` into decimal.
        """
        got = None
        try:
            while True:
                got = yield base_as_int(self(got), base, table=table)
        except StopIteration:
            pass

    async def azfill(self, size: int):
        """
        Applies ``builtins.zfill(size)`` to each value that's yielded
        from the underlying Comprende async generator before yielding
        the result.
        """
        got = None
        try:
            while True:
                got = yield (await self(got)).zfill(size)
        except StopAsyncIteration:
            pass

    def zfill(self, size: int):
        """
        Applies ``builtins.zfill(size)`` to each value that's yielded
        from the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield self(got).zfill(size)
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
        try:
            while True:
                got = yield (await self(got))[selected]
        except StopAsyncIteration:
            pass

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

    async def aindex(self, selected: t.Union[int, slice]):
        """
        Yields the ``selected`` index of each result produced by the
        underlying Comprende async generator.
        """
        got = None
        try:
            while True:
                got = yield (await self(got))[selected]
        except StopAsyncIteration:
            pass

    def index(self, selected: t.Union[int, slice]):
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

    async def astr(self, *a):
        """
        Applies ``builtins.str(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield str(await self(got), *a)
        except StopAsyncIteration:
            pass

    def str(self, *a):
        """
        Applies ``builtins.str(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        _str = builtins.str
        try:
            while True:
                got = yield _str(self(got), *a)
        except StopIteration:
            pass

    async def asplit(self, *a):
        """
        Applies ``value.split(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield (await self(got)).split(*a)
        except StopAsyncIteration:
            pass

    def split(self, *a):
        """
        Applies ``value.split(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                yield self(got).split(*a)
        except StopIteration:
            pass

    async def areplace(self, *a):
        """
        Applies ``value.replace(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield (await self(got)).replace(*a)
        except StopAsyncIteration:
            pass

    def replace(self, *a):
        """
        Applies ``value.replace(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield self(got).replace(*a)
        except StopIteration:
            pass

    async def aencode(self, *a):
        """
        Applies ``value.encode(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield (await self(got)).encode(*a)
        except StopAsyncIteration:
            pass

    def encode(self, *a):
        """
        Applies ``value.encode(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield self(got).encode(*a)
        except StopIteration:
            pass

    async def adecode(self, *a):
        """
        Applies ``value.decode(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield (await self(got)).decode(*a)
        except StopAsyncIteration:
            pass

    def decode(self, *a):
        """
        Applies ``value.decode(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield self(got).decode(*a)
        except StopIteration:
            pass

    async def ajson_loads(self, **kw):
        """
        Applies ``json.loads(**kw)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield json.loads(await self(got), **kw)
        except StopAsyncIteration:
            pass

    def json_loads(self, **kw):
        """
        Applies ``json.loads(**kw)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield json.loads(self(got), **kw)
        except StopIteration:
            pass

    async def ajson_dumps(self, **kw):
        """
        Applies ``json.dumps(**kw)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield json.dumps(await self(got), **kw)
        except StopAsyncIteration:
            pass

    def json_dumps(self, **kw):
        """
        Applies ``json.dumps(**kw)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield json.dumps(self(got), **kw)
        except StopIteration:
            pass

    async def abin(self, *, prefix: bool = False):
        """
        Applies ``builtins.bin()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        try:
            if prefix:
                while True:
                    got = yield bin(await self(got))
            else:
                trim = slice(2, None)
                while True:
                    got = yield bin(await self(got))[trim]
        except StopAsyncIteration:
            pass

    def bin(self, *, prefix: bool = False):
        """
        Applies ``builtins.bin()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        _bin = builtins.bin
        try:
            if prefix:
                while True:
                    got = yield _bin(self(got))
            else:
                trim = slice(2, None)
                while True:
                    got = yield _bin(self(got))[trim]
        except StopIteration:
            pass

    async def aoct(self, *, prefix: bool = False):
        """
        Applies ``builtins.oct()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        try:
            if prefix:
                while True:
                    got = yield oct(await self(got))
            else:
                trim = slice(2, None)
                while True:
                    got = yield oct(await self(got))[trim]
        except StopAsyncIteration:
            pass

    def oct(self, *, prefix: bool = False):
        """
        Applies ``builtins.oct()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        _oct = builtins.oct
        try:
            if prefix:
                while True:
                    got = yield _oct(self(got))
            else:
                trim = slice(2, None)
                while True:
                    got = yield _oct(self(got))[trim]
        except StopIteration:
            pass

    async def ahex(self, prefix: bool = False):
        """
        Applies ``builtins.hex()`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        try:
            if prefix:
                while True:
                    got = yield hex(await self(got))
            else:
                trim = slice(2, None)
                while True:
                    got = yield hex(await self(got))[trim]
        except StopAsyncIteration:
            pass

    def hex(self, prefix: bool = False):
        """
        Applies ``builtins.hex()`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        _hex = builtins.hex
        try:
            if prefix:
                while True:
                    got = yield _hex(self(got))
            else:
                trim = slice(2, None)
                while True:
                    got = yield _hex(self(got))[trim]
        except StopIteration:
            pass

    async def abytes(self, *a):
        """
        Applies ``builtins.bytes(*a)`` to each value that's yielded from
        the underlying Comprende async generator before yielding the
        result.
        """
        got = None
        try:
            while True:
                got = yield bytes(await self(got), *a)
        except StopAsyncIteration:
            pass

    def bytes(self, *a):
        """
        Applies ``builtins.bytes(*a)`` to each value that's yielded from
        the underlying Comprende sync generator before yielding the
        result.
        """
        got = None
        _bytes = builtins.bytes
        try:
            while True:
                got = yield _bytes(self(got), *a)
        except StopIteration:
            pass

    for method in lazy_generators.union(eager_generators):
        vars()[method] = comprehension()(vars()[method])
    del method


# Provide interfaces to standalone Comprende-wrapped (async) generators
adata = comprehension()(BytesIO.adata)
data = comprehension()(BytesIO.data)


@comprehension()
async def aunpack(iterable: t.AsyncOrSyncIterable[t.Any]):
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
def unpack(iterable: t.Iterable[t.Any]):
    """
    Runs through an iterable & yields elements one at a time.
    """
    yield from iterable


@comprehension()
async def azip(*iterables: t.AsyncOrSyncIterable[t.Any]):
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
def _zip(*iterables: t.Iterable[t.Any]):
    """
    Creates a synchronous version of the zip builtin function which is
    wrapped by the ``Comprende`` class.
    """
    for results in zip(*iterables):
        yield results



@comprehension()
async def aresize(
    sequence: t.Sequence[t.Any], size: int = BLOCKSIZE, *, blocks: int = 0
):
    """
    Runs through a ``sequence`` & yields ``size`` sized chunks of the
    sequence one chunk at a time. ``blocks`` is the total number of
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


@comprehension()
def resize(
    sequence: t.Sequence[t.Any], size: int = BLOCKSIZE, *, blocks: int = 0
):
    """
    Runs through a ``sequence`` & yields ``size`` sized chunks of the
    sequence one chunk at a time. ``blocks`` is the total number of
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


@comprehension()
async def aecho(initial_value: t.Any = None):
    """
    A coroutine which yields the values the are sent into it. It's most
    useful as a debugger or in Comprende data processing chains.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

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
def echo(initial_value: t.Any = None):
    """
    A coroutine which yields the values the are sent into it. It's most
    useful as a debugger or in Comprende data processing chains.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

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
async def acycle(iterable: t.AsyncOrSyncIterable[t.Any]):
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
def cycle(iterable: t.Iterable[t.Any]):
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
    start: int = 0, *, size: int = 8, byte_order: str = BIG
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
def bytes_count(
    start: int = 0, *, size: int = 8, byte_order: str = BIG
):
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
async def abytes_range(*a, size: int = 8, byte_order: str = BIG):
    """
    An async version of ``builtins.range`` wrapped by the ``Comprende``
    class, & returns its values as bytes instead.
    """
    for result in range(*a):
        await asleep()
        yield result.to_bytes(size, byte_order)


@comprehension()
def bytes_range(*a, size: int = 8, byte_order: str = BIG):
    """
    A synchronous version of ``builtins.range`` which is wrapped by the
    ``Comprende`` class, & returns its values as bytes instead.
    """
    for result in range(*a):
        yield result.to_bytes(size, byte_order)


@comprehension()
async def arange(*a):
    """
    An async version of ``builtins.range``.
    """
    for result in range(*a):
        await asleep()
        yield result


@comprehension()
def _range(*a):
    """
    Creates a synchronous version of ``builtins.range`` which is
    wrapped by the ``Comprende`` class.
    """
    for result in range(*a):
        yield result


@comprehension()
async def abirth(base: t.Any, *, stop: bool = True):
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
def birth(base: t.Any, *, stop: bool = True):
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
async def aorder(
    *iterables: t.Iterable[t.AsyncOrSyncIterable[t.Any]],
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
def order(*iterables: t.Iterable[t.Iterable[t.Any]]):
    """
    Takes a collection of iterables & exhausts them one at a time from
    left to right.
    """
    for iterable in iterables:
        for result in iterable:
            yield result


@comprehension()
async def askip(iterable: t.AsyncOrSyncIterable[t.Any], steps: int = 1):
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
def skip(iterable: t.Iterable[t.Any], steps: int = 1):
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
async def abatch(
    iterable: t.AsyncOrSyncIterable[t.Any], batch_size: int = 1
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
def batch(iterable: t.Iterable[t.Any], batch_size: int = 1):
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
async def apopleft(queue: t.SupportsPopleft):
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
def popleft(queue: t.SupportsPopleft):
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
async def apop(queue: t.SupportsPop):
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
def pop(queue: t.SupportsPop):
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
    names: t.AsyncOrSyncIterable[t.Hashable],
    mapping: t.Union[t.Sequence, t.Mapping[t.Hashable, t.Any]],
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
    names: t.Iterable[t.Hashable],
    mapping: t.Union[t.Sequence, t.Mapping[t.Hashable, t.Any]],
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
    queue: t.Container[t.Any],
    *,
    probe_frequency: t.PositiveRealNumber = 0.0001,
    timeout: t.PositiveRealNumber = 1,
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
    queue: t.Container[t.Any],
    *,
    probe_frequency: t.PositiveRealNumber = 0.0001,
    timeout: t.PositiveRealNumber = 1,
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
            sleep(probe_frequency)
        if time() - start > timeout:
            break
        yield queue


extras = dict(
    BaseComprende=BaseComprende,
    Comprende=Comprende,
    Enumerate=Enumerate,
    __all__=__all__[1:],
    __doc__=__doc__,
    __package__=__package__,
    abirth=abirth,
    abytes_count=abytes_count,
    abytes_range=abytes_range,
    abatch=abatch,
    acount=acount,
    acycle=acycle,
    adata=adata,
    aecho=aecho,
    aorder=aorder,
    apick=apick,
    apop=apop,
    apopleft=apopleft,
    arange=arange,
    aresize=aresize,
    askip=askip,
    aunpack=aunpack,
    await_on=await_on,
    azip=azip,
    birth=birth,
    bytes_count=bytes_count,
    bytes_range=bytes_range,
    batch=batch,
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
    resize=resize,
    skip=skip,
    unpack=unpack,
    wait_on=wait_on,
    zip=_zip,
)


gentools = make_module("gentools", mapping=extras)
