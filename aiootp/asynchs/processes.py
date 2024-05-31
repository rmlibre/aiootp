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


__all__ = ["Processes", "get_process_id"]


__doc__ = "A multi-processing interface."


import multiprocessing
from os import getpid as get_process_id
import concurrent.futures.process as process
from concurrent.futures import ProcessPoolExecutor

from aiootp._typing import Typing as t

from .concurrency_interface import ConcurrencyInterface


class Processes(ConcurrencyInterface):
    """
    Simplifies spawning & returning the values procuded by `Process` &
    `ProcessPoolExecutor` objects with an interface over these types
    from the `multiprocessing` & `concurrent.futures` packages.
    """

    __slots__ = ()

    _Manager: type = multiprocessing.Manager

    _default_probe_delay: t.PositiveRealNumber = 0.005
    _pool: t.PoolExecutorType = ProcessPoolExecutor()
    _type: type = multiprocessing.Process

    BrokenPool: type = process.BrokenProcessPool


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

