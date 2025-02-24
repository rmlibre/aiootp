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


"""
A multi-processing interface.
"""

__all__ = ["Processes", "get_process_id"]


import multiprocessing
from multiprocessing.context import SpawnContext
from os import getpid as get_process_id
from concurrent.futures import process
from concurrent.futures import ProcessPoolExecutor

from aiootp._typing import Typing as t

from .concurrency_interface import ConcurrencyInterface


class Processes(ConcurrencyInterface):
    """
    Simplifies spawning & returning the values produced by `Process` &
    `ProcessPoolExecutor` objects with an interface over these types
    from the `multiprocessing` & `concurrent.futures` packages.
    """

    __slots__ = ()

    _default_probe_delay: float = 0.005
    _context: SpawnContext = multiprocessing.get_context("spawn")
    _pool: t.PoolExecutorType = ProcessPoolExecutor(mp_context=_context)
    _type: type = _context.Process

    BrokenPool: type = process.BrokenProcessPool

    get_id: t.Callable[[], int] = get_process_id

    @classmethod
    def _get_queue(cls, /, maxsize: int = 1) -> t.QueueType:
        """
        Returns a queue object to retrieve values from spawned workers
        with the class' default multiprocessing context.
        """
        return cls._context.Queue(maxsize=maxsize)

    @classmethod
    def reset_pool(cls, /) -> None:
        """
        When a process pool is broken by being abruptly exited, this
        method can be called to reset the class' pool object with a new
        instance with its default multiprocessing context.
        """
        cls._pool = cls._pool.__class__(mp_context=cls._context)


module_api = dict(
    Processes=t.add_type(Processes),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    get_process_id=get_process_id,
)
