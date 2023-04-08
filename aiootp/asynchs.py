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
    "A collection of asyncio & concurrency references to simplify their"
    " standard usage in this package. This module can be used to replac"
    "e the default event loop policy, for instance, to run uvloop or ch"
    "ange async frameworks. The default asyncio loop is available in ``"
    "default_event_loop``."
)


import os
import asyncio
import aiofiles
from time import sleep
from time import time as s_time
from time import time_ns as ns_time
from time import perf_counter as s_counter
from time import perf_counter_ns as ns_counter
from threading import Thread
from functools import wraps, partial
from asyncio import sleep as _asleep
from multiprocessing import Process, Manager
import concurrent.futures.thread as thread
import concurrent.futures.process as process
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from inspect import isawaitable as is_awaitable
from inspect import iscoroutinefunction as is_async_function
from ._exceptions import *
from ._typing import Typing
from ._debuggers import DebugControl
from .commons import OpenNamespace, amake_module


# Can toggle asyncio's debug mode using DebugControl.enable_debugging()
# WARNING: This will also reveal potentially sensitive values in object
# repr's that are omitted by default.
DebugControl._switches.append(
    lambda: event_loop().set_debug(DebugControl.is_debugging())
)


_ONE_NANOSECOND: int = 1
_ONE_MICROSECOND: int = 1_000
_ONE_MILLISECOND: int = 1_000_000
_ONE_SECOND: int = 1_000_000_000
_ONE_MINUTE: int = 60 * _ONE_SECOND
_ONE_HOUR: int = 60 * _ONE_MINUTE
_ONE_DAY: int = 24 * _ONE_HOUR
_ONE_MONTH: int = 30 * _ONE_DAY
_ONE_YEAR: int = 12 * _ONE_MONTH


this_nanosecond = this_ns = lambda epoch=0: (
    ns_time() - (int(epoch) if epoch else 0)
)
this_microsecond = lambda epoch=0: this_ns(epoch) // _ONE_MICROSECOND
this_millisecond = lambda epoch=0: this_ns(epoch) // _ONE_MILLISECOND
this_second = lambda epoch=0: this_ns(epoch) // _ONE_SECOND
this_minute = lambda epoch=0: this_ns(epoch) // _ONE_MINUTE
this_hour = lambda epoch=0: this_ns(epoch) // _ONE_HOUR
this_day = lambda epoch=0: this_ns(epoch) // _ONE_DAY
this_month = lambda epoch=0: this_ns(epoch) // _ONE_MONTH
this_year = lambda epoch=0: this_ns(epoch) // _ONE_YEAR


thread_pool = ThreadPoolExecutor()
process_pool = ProcessPoolExecutor()


event_loop = asyncio.get_event_loop
default_event_loop = event_loop()
gather = asyncio.gather
new_future = asyncio.ensure_future
asleep = lambda delay=0: _asleep(delay)


def reset_event_loop() -> None:
    """
    Sets a new event loops for asyncio.
    """
    asyncio.set_event_loop(asyncio.new_event_loop())


def serve(*a, **kw) -> None:
    """
    Proxy's access to ``asyncio.get_event_loop().run_forever()``.
    """
    return event_loop().run_forever(*a, **kw)


def run(coro) -> Typing.Any:
    """
    Proxy's access to ``asyncio.get_event_loop().run_until_complete()``.
    """
    return event_loop().run_until_complete(coro)


def new_task(coro) -> asyncio.Task:
    """
    Proxy's access to ``asyncio.get_event_loop().create_taksk()``.
    """
    return event_loop().create_task(coro)


def stop() -> None:
    """
    Stops the currently running event loop.
    """
    event_loop().stop()


def wrap_in_executor(
    function
) -> Typing.Coroutine[Typing.Any, Typing.Any, Typing.Any]:
    """
    A decorator that wraps synchronous blocking IO functions so they
    will run in an executor. This was adapted from the ``aiofiles``
    package:

    https://github.com/Tinche/aiofiles/blob/master/aiofiles/os.py

    The license for their code is Apache License 2.0, available here:

    http://www.apache.org/licenses/LICENSE-2.0
    """
    @wraps(function)
    async def runner(*args, **kwargs):
        partial_function = partial(function, *args, **kwargs)
        return await event_loop().run_in_executor(
            executor=None, func=partial_function
        )

    return runner


def make_os_async(namespace=None) -> Typing.Mapping[str, Typing.Coroutine]:
    """
    Wraps file operations from the ``os`` module in a decorator that
    runs those methods in an async executor. This was adapted from the
    ``aiofiles`` package:

    https://github.com/Tinche/aiofiles/blob/master/aiofiles/os.py

    Whose license is Apache License 2.0, available here:

    http://www.apache.org/licenses/LICENSE-2.0
    """
    if namespace == None:
        namespace = OpenNamespace()
    attrs = [
        "chmod",
        "chown",
        "sendfile",
        "stat",
        "rename",
        "remove",
        "mkdir",
        "makedirs",
        "rmdir",
    ]
    for attr in attrs:
        if hasattr(os, attr):
            setattr(namespace, attr, wrap_in_executor(getattr(os, attr)))
    return namespace


# create a version of ``os`` module with asynchronous file IO methods
aos = make_os_async()


class AsyncInit(type):
    """
    A metaclass which allows classes to use asynchronous ``__init__``
    methods. Inspired by David Beazley.
    """

    async def __call__(cls, *args, **kwargs):
        self = cls.__new__(cls, *args, **kwargs)
        await self.__init__(*args, **kwargs)
        return self


class Processes:
    """
    Simplifies spawning & returning the values procuded by `Process` &
    `ProcessPoolExecutor` objects with an interface over these types
    from the `multiprocessing` & `concurrent.futures` packages.
    """

    __slots__ = ()

    _type = Process
    _pool = process_pool
    _state_machine = Manager
    _default_probe_frequency = 0.005

    BrokenPool = process.BrokenProcessPool

    @staticmethod
    def _return_state(runner, func=None, _state=None, *args, **kwargs):
        """
        Used by the class to handle retreiving return values from new
        processes spawned using the process pool.
        """
        runner(func, *args, **kwargs, _state=_state)
        return _state.pop()

    @staticmethod
    def _run_async_func(func=None, *args, _state=None, **kwargs) -> None:
        """
        Used by the class to handle retreiving return values from new
        processes spawned, even if the target function is async.
        """
        if is_async_function(func):
            run = asyncio.new_event_loop().run_until_complete
            _state.append(run(func(*args, **kwargs)))
        else:
            _state.append(func(*args, **kwargs))

    @staticmethod
    def _run_func(func=None, *args, _state=None, **kwargs) -> None:
        """
        Used by the class to handle retreiving return values from new
        processes spawned.
        """
        _state.append(func(*args, **kwargs))

    @classmethod
    async def asubmit(cls, func, *args, probe_frequency=None, **kwargs):
        """
        Submits an async, or synchronous ``func`` to a process pool or
        thread pool, depending on the class that calls this method, with
        the supplied ``*args`` & ``**kwargs``, then returns the `Future`
        object that's created.
        """
        async def aresult():
            while not future.done():
                await asleep(probe_frequency)
            return future.result()

        if not probe_frequency:
            probe_frequency = cls._default_probe_frequency
        if is_async_function(func):
            runner = cls._run_async_func
            state = cls._state_machine().list()
            future = cls.submit(
                cls._return_state, runner, func, state, *args, **kwargs
            )
        else:
            future = cls.submit(func, *args, **kwargs)

        future.aresult = aresult
        return future

    @classmethod
    def submit(cls, func, *args, probe_frequency=None, **kwargs):
        """
        Submits a synchronous ``func`` to a process pool or thread pool,
        depending on the class that calls this method, with the supplied
        ``*args`` & ``**kwargs``, then returns the `Future` object
        that's created. ``probe_frequency`` is a no-op in this method
        for parity with other methods of the class.
        """
        def result():
            while not future.done():
                sleep(probe_frequency)
            return future._original_result()

        if not probe_frequency:
            probe_frequency = cls._default_probe_frequency
        future = cls._pool.submit(func, *args, **kwargs)
        future._original_result = future.result
        future.result = result
        return future

    @classmethod
    async def agather(cls, *functions, args=(), kwargs={}, **kw):
        """
        Sumbits all of the async or synchronous ``functions`` to the
        `Processes._process_pool` or `Threads._thread_pool` with the
        given ``args``, ``kwargs`` &/or any other supplied ``kw``
        arguments.
        """
        tasks = [
            await cls.asubmit(func, *args, **{**kwargs, **kw})
            for func in functions
        ]
        try:
            return [await task.aresult() for task in tasks]
        finally:
            [task.cancel() for task in tasks]

    @classmethod
    def gather(cls, *functions, args=(), kwargs={}, **kw):
        """
        Sumbits all the ``functions`` to the `Processes._process_pool`
        or `Threads._thread_pool` with the given ``args``, ``kwargs``
        &/or any other supplied ``kw`` arguments.
        """
        tasks = [
            cls.submit(func, *args, **{**kwargs, **kw})
            for func in functions
        ]
        try:
            return [task.result() for task in tasks]
        finally:
            [task.cancel() for task in tasks]

    @classmethod
    async def anew(cls, func, *args, probe_frequency=None, **kwargs):
        """
        Runs an async or sync function in another process or thread
        depending on the class calling this method, so that heavy cpu-
        bound computations, or blocking IO operations, can better
        coexist with asynchronous code.
        """
        if not probe_frequency:
            probe_frequency = cls._default_probe_frequency
        state = cls._state_machine().list()
        process = cls._type(
            target=cls._run_async_func,
            args=(func, *args),
            kwargs=dict(**kwargs, _state=state),
        )
        process.start()
        while process.is_alive():
            await asleep(probe_frequency)
        process.join()
        return state.pop()

    @classmethod
    def new(cls, func, *args, probe_frequency=None, **kwargs):
        """
        Runs a sync function in another process or thread depending on
        the class calling this method, so that heavy cpu-bound
        computations, or blocking IO operations, can better coexist with
        asynchronous code.
        """
        if not probe_frequency:
            probe_frequency = cls._default_probe_frequency
        state = cls._state_machine().list()
        process = cls._type(
            target=cls._run_func,
            args=(func, *args),
            kwargs=dict(**kwargs, _state=state),
        )
        process.start()
        while process.is_alive():
            sleep(probe_frequency)
        process.join()
        return state.pop()

    @classmethod
    def reset_pool(cls):
        """
        When a process or thread pool is broken by an abruptly exited,
        this method can be called to reset the class' pool object with
        a new instance.
        """
        cls._pool = cls._pool.__class__()


class Threads(Processes):
    """
    Simplifies spawning & returning the values procuded by `Thread` &
    `ThreadPoolExecutor` objects with an interface over these types from
    the `threading` & `concurrent.futures` packages.
    """

    __slots__ = ()

    class _Manager:
        """
        This type is for parity with the `Processes` class' use of the
        `multiprocessing.Manager`. It returns a list so state can be
        passed around from spawned threads to calling code.
        """

        @staticmethod
        def list():
             return []

    _type = Thread
    _pool = thread_pool
    _state_machine = _Manager
    _default_probe_frequency = 0.001

    BrokenPool = thread.BrokenThreadPool


extras = dict(
    AsyncInit=AsyncInit,
    Processes=Processes,
    Threads=Threads,
    __doc__=__doc__,
    __package__=__package__,
    aiofiles=aiofiles,
    aos=aos,
    asleep=asleep,
    asyncio=asyncio,
    default_event_loop=default_event_loop,
    gather=gather,
    is_async_function=is_async_function,
    is_awaitable=is_awaitable,
    event_loop=event_loop,
    new_future=new_future,
    new_task=new_task,
    ns_counter=ns_counter,
    ns_time=ns_time,
    reset_event_loop=reset_event_loop,
    run=run,
    serve=serve,
    sleep=sleep,
    stop=stop,
    s_counter=s_counter,
    s_time=s_time,
    wrap_in_executor=wrap_in_executor,
)


asynchs = asyncio.new_event_loop().run_until_complete(
    amake_module("asynchs", mapping=extras)
)

