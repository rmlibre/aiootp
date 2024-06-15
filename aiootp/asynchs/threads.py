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


__all__ = ["Threads", "get_thread_id"]


__doc__ = "A multi-threading interface."


from threading import Thread
from collections import deque
import concurrent.futures.thread as thread
from _thread import get_ident as get_thread_id
from concurrent.futures import ThreadPoolExecutor

from aiootp._typing import Typing as t

from .concurrency_interface import ConcurrencyInterface


class Threads(ConcurrencyInterface):
    """
    Simplifies spawning & returning the values procuded by `Thread` &
    `ThreadPoolExecutor` objects with an interface over these types from
    the `threading` & `concurrent.futures` packages.
    """

    __slots__ = ()

    class _Manager:
        """
        This type is for parity with the `Processes` class' use of the
        `multiprocessing.Manager`. It returns an atomic list-like
        container so state can be passed around from spawned threads to
        calling code.
        """

        @staticmethod
        def list() -> t.SupportsAppendPop:
             return deque(maxlen=1)

    _default_probe_delay: t.PositiveRealNumber = 0.001
    _pool: t.PoolExecutorType = ThreadPoolExecutor()
    _type: type = Thread

    BrokenPool: type = thread.BrokenThreadPool


module_api = dict(
    Threads=t.add_type(Threads),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    get_thread_id=get_thread_id,
)

