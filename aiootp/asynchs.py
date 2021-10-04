# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["asynchs", "Processes", "Threads"]


__doc__ = (
    "A collection of asyncio & concurrency references to simplify their"
    " standard usage in this package. This module can be used to replac"
    "e the default event loop policy, for instance, to run uvloop or ch"
    "ange async frameworks. The default asyncio loop is available in ``"
    "default_loop``."
)


import os
import asyncio
import aiofiles
from time import time
from time import sleep
from functools import wraps
from functools import partial
from threading import Thread
from asyncio import sleep as _asleep
from multiprocessing import Process, Manager
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import ProcessPoolExecutor
from inspect import iscoroutinefunction as is_async_function
from ._exceptions import *
from ._typing import Typing
from .debuggers import DebugControl
from .commons import commons


# Can toggle asyncio's debug mode using DebugControl.enable_debugging()
# WARNING: This will also reveal potentially sensitive values in object
# repr's that are omitted by default.
DebugControl._switches.append(
    lambda: loop().set_debug(DebugControl.is_debugging())
)


_ONE_MICROSECOND = 1_000_000
_ONE_MILLISECOND = 1_000
_ONE_SECOND = 1
_ONE_MINUTE = _ONE_SECOND * 60
_ONE_HOUR = _ONE_MINUTE * 60
_ONE_DAY = _ONE_HOUR * 24
_ONE_YEAR = _ONE_DAY * 365


this_microsecond = lambda: int(time() * _ONE_MICROSECOND)
this_millisecond = lambda: int(time() * _ONE_MILLISECOND)
this_second = lambda: int(time())
this_minute = lambda: int(time() / _ONE_MINUTE)
this_hour = lambda: int(time() / _ONE_HOUR)
this_day = lambda: int(time() / _ONE_DAY)
this_year = lambda: int(time() / _ONE_YEAR)


thread_pool = ThreadPoolExecutor()
process_pool = ProcessPoolExecutor()


loop = asyncio.get_event_loop
default_loop = loop()
gather = asyncio.gather
new_future = asyncio.ensure_future
asleep = lambda delay=0: _asleep(delay)


def reset_event_loop():
    """
    Sets a new event loops for asyncio.
    """
    asyncio.set_event_loop(asyncio.new_event_loop())


def serve(*a, **kw):
    """
    Proxy's access to ``asyncio.get_event_loop().run_forever()``.
    """
    return loop().run_forever(*a, **kw)


def run(coro):
    """
    Proxy's access to ``asyncio.get_event_loop().run_until_complete()``.
    """
    return loop().run_until_complete(coro)


def new_task(coro):
    """
    Proxy's access to ``asyncio.get_event_loop().create_taksk()``.
    """
    return loop().create_task(coro)


def stop():
    """
    Stops the currently running event loop.
    """
    return loop().stop()


def wrap_in_executor(function):
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
        return await loop().run_in_executor(
            executor=None, func=partial_function
        )

    return runner


def make_os_async(namespace=None):
    """
    Wraps file operations from the ``os`` module in a decorator that
    runs those methods in an async executor. This was adapted from the
    ``aiofiles`` package:

    https://github.com/Tinche/aiofiles/blob/master/aiofiles/os.py

    Whose license is Apache License 2.0, available here:

    http://www.apache.org/licenses/LICENSE-2.0
    """
    if namespace == None:
        namespace = commons.OpenNamespace()
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

    @staticmethod
    def _return_state(runner, func=None, _state=None, *args, **kwargs):
        """
        Used by the class to handle retreiving return values from new
        processes spawned using the process pool.
        """
        runner(func, *args, **kwargs, _state=_state)
        return _state.pop()

    @staticmethod
    def _run_async_func(func=None, *args, _state=None, **kwargs):
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
    def _run_func(func=None, *args, _state=None, **kwargs):
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


extras = dict(
    Processes=Processes,
    Threads=Threads,
    __doc__=__doc__,
    __main_exports__=__all__,
    __package__=__package__,
    aiofiles=aiofiles,
    aos=aos,
    asleep=asleep,
    asyncio=asyncio,
    default_loop=default_loop,
    gather=gather,
    loop=loop,
    new_future=new_future,
    new_task=new_task,
    process_pool=process_pool,
    reset_event_loop=reset_event_loop,
    run=run,
    serve=serve,
    sleep=sleep,
    stop=stop,
    this_day=this_day,
    this_hour=this_hour,
    this_microsecond=this_microsecond,
    this_millisecond=this_millisecond,
    this_minute=this_minute,
    this_second=this_second,
    this_year=this_year,
    time=time,
    thread_pool=thread_pool,
    wrap_in_executor=wrap_in_executor,
)


asynchs = commons.make_module("asynchs", mapping=extras)

