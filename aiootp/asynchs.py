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
    "asynchs",
    "run",
    "gather",
    "switch",
    "new_task",
    "new_future",
]


__doc__ = """
A collection of asyncio & uvloop references to simplify the standard
usage of those libraries in this package. This module can be used to
replace the default event loop policy, for instance, to run uvloop. The
default asyncio loop is still available in ``default_loop``.
"""


# import uvloop
import asyncio
from time import time
from time import sleep
from .commons import commons


default_loop = asyncio.get_event_loop()


# # Optionally turn on ``uvloop``
# asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


# # Optionally turn off ``uvloop``
# asyncio.set_event_loop(default_loop)


# # Optionally, set asyncio's debug mode on
# loop().set_debug(True)


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


async def _switch():
    """
    A base async generator function used to create an awaitable coroutine
    for efficient async task switching.
    """
    while True:
        yield


# create an awaitable for efficient async task switching
switch = _switch().__aiter__().__anext__


__extras = {
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    # "uvloop": uvloop,
    "asyncio": asyncio,
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
    "default_loop": default_loop,
}


asynchs = commons.Namespace.make_module("asynchs", mapping=__extras)

