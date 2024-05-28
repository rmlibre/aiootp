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


__all__ = []


__doc__ = (
    "Tools for time, asyncio, multi-threading, & multi-processing."
)


import asyncio
import aiofiles
from asyncio import run
from inspect import isawaitable as is_awaitable
from inspect import iscoroutinefunction as is_async_function

from .loops import *
from .clocks import *
from .aos import *
from .concurrency_interface import *
from .processes import *
from .threads import *


modules = dict(
    aos=aos,
    clocks=clocks,
    concurrency_interface=concurrency_interface,
    loops=loops,
    processes=processes,
    threads=threads,
)


module_api = dict(
    AsyncInit=AsyncInit,
    Clock=Clock,
    Processes=Processes,
    Threads=Threads,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    aiofiles=aiofiles,
    asleep=asleep,
    asyncio=asyncio,
    gather=gather,
    is_async_function=is_async_function,
    is_awaitable=is_awaitable,
    get_event_loop_id=get_event_loop_id,
    get_process_id=get_process_id,
    get_thread_id=get_thread_id,
    new_future=new_future,
    new_task=new_task,
    run=run,
    sleep=sleep,
    wrap_in_executor=wrap_in_executor,
)

