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


__all__ = [
    "AsyncInit",
    "asleep",
    "asyncio",
    "gather",
    "event_loop",
    "get_event_loop_id",
    "new_event_loop",
    "new_future",
    "new_task",
    "reset_event_loop",
    "run",
    "serve",
    "sleep",
    "stop",
]


__doc__ = "Asynchrony event loop tools."


import asyncio
from asyncio import run
from time import sleep
from asyncio import sleep as _asleep

from aiootp._typing import Typing as t
from aiootp._debug_control import DebugControl


event_loop = asyncio.get_event_loop
get_event_loop_id = lambda: id(event_loop())
new_event_loop = asyncio.new_event_loop
gather = asyncio.gather
new_future = asyncio.ensure_future


# Can toggle asyncio's debug mode using DebugControl.enable_debugging()
# WARNING: This will also reveal potentially sensitive values in object
# repr's that are omitted by default.
DebugControl._switches.append(
    lambda: event_loop().set_debug(DebugControl.is_debugging())
)


async def asleep(seconds: t.PositiveRealNumber = 0) -> None:
    """
    Async sleep from asyncio.
    """
    await _asleep(seconds)


def reset_event_loop() -> None:
    """
    Sets a new event loops for asyncio.
    """
    asyncio.set_event_loop(new_event_loop())


def serve(*a, **kw) -> None:
    """
    Proxy's access to `asyncio.get_event_loop().run_forever()`.
    """
    event_loop().run_forever(*a, **kw)


def new_task(coro) -> asyncio.Task:
    """
    Proxy's access to `asyncio.get_event_loop().create_task()`.
    """
    return event_loop().create_task(coro)


def stop() -> None:
    """
    Stops the currently running event loop.
    """
    event_loop().stop()


class AsyncInit(type):
    """
    A metaclass which allows classes to use asynchronous `__init__`
    methods. Inspired by David Beazley.
    """

    async def __call__(cls, *args, **kwargs):
        self = cls.__new__(cls, *args, **kwargs)
        await self.__init__(*args, **kwargs)
        return self


module_api = dict(
    AsyncInit=t.add_type(AsyncInit),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    asleep=asleep,
    asyncio=asyncio,
    gather=gather,
    event_loop=event_loop,
    get_event_loop_id=get_event_loop_id,
    new_event_loop=new_event_loop,
    new_future=new_future,
    new_task=new_task,
    reset_event_loop=reset_event_loop,
    run=run,
    serve=serve,
    sleep=sleep,
    stop=stop,
)

