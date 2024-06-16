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
    "get_event_loop",
    "get_event_loop_id",
    "new_event_loop",
    "new_future",
    "new_task",
    "run",
    "set_event_loop",
    "sleep",
    "wrap_in_executor",
]


__doc__ = "Asynchrony event loop tools."


import asyncio
from time import sleep
from functools import wraps, partial
from asyncio import sleep as _asleep
from asyncio import run, set_event_loop

from aiootp._typing import Typing as t
from aiootp._debug_control import DebugControl


gather = asyncio.gather
get_event_loop = asyncio.get_event_loop
get_event_loop_id = lambda: id(get_event_loop())
new_event_loop = asyncio.new_event_loop
new_future = asyncio.ensure_future


# Can toggle asyncio's debug mode using DebugControl.enable_debugging()
# WARNING: This will also reveal potentially sensitive values in object
# repr's that are omitted by default.
DebugControl._switches.append(
    lambda: get_event_loop().set_debug(DebugControl.is_debugging())
)


async def asleep(seconds: t.PositiveRealNumber = 0) -> None:
    """
    Async sleep from asyncio.
    """
    await _asleep(seconds)


def new_task(coro: t.Awaitable) -> asyncio.Task:
    """
    Proxy's access to `asyncio.get_event_loop().create_task()`.
    """
    return get_event_loop().create_task(coro)


def wrap_in_executor(
    function: t.Callable[..., t.Any]
) -> t.Coroutine[t.Any, t.Any, t.Any]:
    """
    A decorator that wraps synchronous blocking IO functions so they
    will run in an async executor.
    """

    @wraps(function)
    async def runner(*args, **kwargs):
        partial_function = partial(function, *args, **kwargs)
        return await get_event_loop().run_in_executor(
            executor=None, func=partial_function
        )

    return runner


class AsyncInit(type):
    """
    A metaclass which allows classes to use asynchronous `__init__`
    methods. Inspired by David Beazley.
    """

    async def __call__(cls, *a: t.Any, **kw: t.Any) -> t.Self:
        self = cls.__new__(cls, *a, **kw)
        await self.__init__(*a, **kw)
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
    get_event_loop=get_event_loop,
    get_event_loop_id=get_event_loop_id,
    new_event_loop=new_event_loop,
    new_future=new_future,
    new_task=new_task,
    run=run,
    set_event_loop=set_event_loop,
    sleep=sleep,
    wrap_in_executor=wrap_in_executor,
)

