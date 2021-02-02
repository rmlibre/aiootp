# This file is part of aiootp, an asynchronous one-time-pad based crypto
# and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "asynchs",
    "run",
    "gather",
    "switch",
    "asleep",
    "new_task",
    "new_future",
    "Processes",
]


__doc__ = """
A collection of asyncio & concurrency references to simplify their
standard usage in this package. This module can be used to replace the
default event loop policy, for instance, to run uvloop or change async
frameworks. The default asyncio loop is available in ``default_loop``.
"""


import os
import asyncio
from time import time
from time import sleep
from functools import wraps
from functools import partial
from threading import Thread
from multiprocessing import Process, Manager
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import ProcessPoolExecutor
from inspect import iscoroutinefunction as is_async_function
from . import DebugControl
from .commons import Namespace


this_second = lambda: int(time())


thread_pool = ThreadPoolExecutor()
process_pool = ProcessPoolExecutor()
default_loop = asyncio.get_event_loop()


# Optionally, set asyncio's debug mode on / off
DebugControl._switches.append(
    lambda: loop().set_debug(DebugControl.is_debugging())
)


def loop(*a, _default=asyncio.get_event_loop, **kw):
    """
    Proxy's access to ``asyncio.get_event_loop()``.
    """
    return _default(*a, **kw)


def serve(*a, **kw):
    """
    Proxy's access to ``asyncio.get_event_loop().run_forever()``.
    """
    return loop().run_forever(*a, **kw)


def run(coro, **kw):
    """
    Proxy's access to ``asyncio.get_event_loop().run_until_complete()``.
    """
    return loop().run_until_complete(coro, **kw)


def new_task(coro, **kw):
    """
    Proxy's access to ``asyncio.get_event_loop().create_taksk()``.
    """
    return loop().create_task(coro, **kw)


def new_future(coro, **kw):
    """
    Proxy's access to ``asyncio.ensure_future()``.
    """
    return asyncio.ensure_future(coro, **kw)


def gather(*coros, **kw):
    """
    Proxy's access to ``asyncio.gather()``.
    """
    return asyncio.gather(*coros, **kw)


async def asleep(delay=0.0, **kw):
    """
    Proxy's access to ``asyncio.sleep()``.
    """
    return await asyncio.sleep(delay, **kw)


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
    Wraps file operations from the ``os`` module is a decorator that
    runs those methods in an async executor. This was adapted from the
    ``aiofiles`` package:

    https://github.com/Tinche/aiofiles/blob/master/aiofiles/os.py

    Whose license is Apache License 2.0, available here:

    http://www.apache.org/licenses/LICENSE-2.0
    """
    if namespace == None:
        namespace = Namespace()
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


async def _switch():
    """
    A base async generator function used to create an awaitable coroutine
    for efficient async task switching.
    """
    while True:
        yield


# create an awaitable for efficient async task switching
switch = _switch().__aiter__().__anext__


class Processes:
    """
    Simplifies spawning & returning values from ``multiprocessing``
    ``Process`` objects.
    """
    _type = Process
    _pool = process_pool
    _state_machine = Manager

    @staticmethod
    def _return_state(runner, func=None, state=None, *args):
        """
        Used by the class to handle retreiving return values from new
        processes spawned using the process pool.
        """
        runner(func, *args, state=state)
        return state.pop()

    @classmethod
    async def asubmit(cls, func=None, *args, _delay=0.01):
        """
        Submits an async or sync ``func`` to a process pool & returns
        the Future of that submission.
        """
        async def aresult(start=time()):
            while not future.done() or time() - start < _delay:
                await asleep(_delay)
            return future.result()

        if is_async_function(func):
            runner = cls._run_async_func
            state = cls._state_machine().list()
            future = cls.submit(
                cls._return_state, runner, func, state, *args
            )
        else:
            future = cls.submit(func, *args)

        future.aresult = aresult
        return future

    @classmethod
    def submit(cls, func=None, *args, _delay=0.01):
        """
        Submits a sync ``func`` to a process pool & returns the Future
        of that submission.
        """
        def result(start=time()):
            while not future.done() or time() - start < _delay:
                sleep(_delay)
            return future._original_result()

        future = cls._pool.submit(func, *args)
        future._original_result = future.result
        future.result = result
        return future

    @staticmethod
    def _run_async_func(func=None, *args, state=None, **kwargs):
        """
        Used by the class to handle retreiving return values from new
        processes spawned, even if the target function is async.
        """
        if is_async_function(func):
            run = asyncio.new_event_loop().run_until_complete
            state.append(run(func(*args, **kwargs)))
        else:
            state.append(func(*args, **kwargs))

    @classmethod
    async def anew(cls, func=None, *args, _delay=0.01, **kwargs):
        """
        Runs an async or sync function in another process so heavy
        cpu-bound computations can better coexist with asynchronous
        or multithreaded code.
        """
        state = cls._state_machine().list()
        process = cls._type(
            target=cls._run_async_func,
            args=(func, *args),
            kwargs=dict(state=state, **kwargs),
        )
        start = time()
        process.start()
        while process.is_alive() or time() - start < _delay:
            await asleep(_delay)
        process.join()
        return state.pop()

    @staticmethod
    def _run_func(func=None, *args, state=None, **kwargs):
        """
        Used by the class to handle retreiving return values from new
        processes spawned.
        """
        state.append(func(*args, **kwargs))

    @classmethod
    def new(cls, func=None, *args, _delay=0.01, **kwargs):
        """
        Runs a sync function in another process so heavy cpu-bound
        computations can better coexist with multithreaded code.
        """
        state = cls._state_machine().list()
        process = cls._type(
            target=cls._run_func,
            args=(func, *args),
            kwargs=dict(state=state, **kwargs),
        )
        start = time()
        process.start()
        while process.is_alive() or time() - start < _delay:
            sleep(_delay)
        process.join()
        return state.pop()


class Threads(Processes):
    _type = Thread
    _pool = thread_pool
    _state_machine = Manager


__extras = {
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "Processes": Processes,
    "Threads": Threads,
    "asyncio": asyncio,
    "aos": aos,
    "run": run,
    "time": time,
    "stop": stop,
    "loop": loop,
    "serve": serve,
    "sleep": sleep,
    "asleep": asleep,
    "switch": switch,
    "gather": gather,
    "new_task": new_task,
    "new_future": new_future,
    "this_second": this_second,
    "thread_pool": thread_pool,
    "process_pool": process_pool,
    "default_loop": default_loop,
    "wrap_in_executor": wrap_in_executor,
}


asynchs = Namespace.make_module("asynchs", mapping=__extras)

