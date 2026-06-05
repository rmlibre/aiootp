# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2026 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


"""
A general interface for multi-threading & multi-processing.
"""

__all__ = ["ConcurrencyInterface"]


from aiootp._typing import Typing as t
from aiootp._exceptions import Issue

from . import is_async_function
from .loops import asleep, sleep, new_event_loop


def process_probe_delay(
    value: t.PositiveRealNumber | None,
    /,
    *,
    default: float,
) -> float:
    """
    Ensures the probe frequency is positive & returns it, if it's
    specified. Otherwise, returns `cls`'s default value.
    """
    if value is None:
        return default
    elif value > 0:
        return float(value)
    else:
        raise Issue.value_must("probe_delay", "be > 0")


class ConcurrencyInterface:
    """
    Defines an interface for managing tasks & pools of threads & processes.
    """

    __slots__ = ()

    _default_probe_delay: float
    _type: type

    BrokenPool: type

    get_id: t.Callable[[], int]
    pool: t.PoolExecutorType

    @classmethod
    async def aget_id(cls, /) -> int:
        """
        Retrieves either the current calling environment's process or
        thread ID depending on the subclass being `Processes` or `Threads`.
        """
        await asleep()
        return cls.get_id()

    @staticmethod
    def _arun_func(
        func: t.Callable[..., t.Any],
        queue: t.QueueType,
        /,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        """
        Used by the class to retrieve return values from an async or
        sync `func` run in a new process / thread by storing the result
        in a shared `queue` container.
        """
        if is_async_function(func):
            try:
                loop = new_event_loop()
                run = loop.run_until_complete
                queue.put_nowait(run(func(*args, **kwargs)))
            finally:
                run(loop.shutdown_asyncgens())
                loop.close()
        else:
            queue.put_nowait(func(*args, **kwargs))

    @staticmethod
    def _run_func(
        func: t.Callable[..., t.Any],
        queue: t.QueueType,
        /,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        """
        Used by the class to retrieve return values from a sync `func`
        run in a new process / thread by storing the result in a shared
        `queue` container.
        """
        queue.put_nowait(func(*args, **kwargs))

    @classmethod
    async def anew(
        cls,
        func: t.Callable[..., t.Any],
        /,
        *args: t.Any,
        probe_delay: t.PositiveRealNumber | None = None,
        **kwargs: t.Any,
    ) -> t.Any:
        """
        Runs an async or sync function in another process or thread
        depending on the class calling this method, so that heavy cpu-
        bound computations, or blocking IO operations, can better
        coexist with asynchronous code.
        """
        delay = process_probe_delay(
            probe_delay,
            default=cls._default_probe_delay,
        )
        queue = cls._get_queue()
        task = cls._type(
            target=cls._arun_func,
            args=(func, queue, *args),
            kwargs=kwargs,
        )
        task.start()
        while task.is_alive():
            await asleep(delay)
        task.join()
        return queue.get_nowait()

    @classmethod
    def new(
        cls,
        func: t.Callable[..., t.Any],
        /,
        *args: t.Any,
        probe_delay: t.PositiveRealNumber | None = None,
        **kwargs: t.Any,
    ) -> t.Any:
        """
        Runs a sync function in another process or thread depending on
        the class calling this method, so that heavy cpu-bound
        computations, or blocking IO operations, can better coexist with
        asynchronous code.
        """
        delay = process_probe_delay(
            probe_delay,
            default=cls._default_probe_delay,
        )
        queue = cls._get_queue()
        task = cls._type(
            target=cls._run_func,
            args=(func, queue, *args),
            kwargs=kwargs,
        )
        task.start()
        while task.is_alive():
            sleep(delay)
        task.join()
        return queue.get_nowait()

    @staticmethod
    def _get_result(
        func: t.Callable[..., t.Any],
        /,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> t.Any:
        """
        Returns the result of `func` run in a new process / thread using
        the class' pool.
        """
        if is_async_function(func):
            try:
                loop = new_event_loop()
                run = loop.run_until_complete
                return run(func(*args, **kwargs))
            finally:
                run(loop.shutdown_asyncgens())
                loop.close()
        else:
            return func(*args, **kwargs)

    @staticmethod
    def _package_result_methods(
        future: t.Future,
        /,
        *,
        probe_delay: float,
    ) -> t.Future:
        """
        Inserts methods in the `future` returned from a pool submission
        to provide a consistent interface for retrieving results.
        """

        async def aresult() -> t.Any:
            while not future.done():
                await asleep(probe_delay)
            return future._original_result()

        def result() -> t.Any:
            while not future.done():
                sleep(probe_delay)
            return future._original_result()

        future._original_result = future.result
        future.aresult = aresult
        future.result = result
        return future

    @classmethod
    async def asubmit(
        cls,
        func: t.Callable[..., t.Any],
        /,
        *args: t.Any,
        probe_delay: t.PositiveRealNumber | None = None,
        **kwargs: t.Any,
    ) -> t.Future:
        """
        Submits an async, or synchronous `func` to a process pool or
        thread pool, depending on the class that calls this method, with
        the supplied `*args` & `**kwargs`, then returns the `Future`
        object that's created.
        """
        delay = process_probe_delay(
            probe_delay,
            default=cls._default_probe_delay,
        )
        future = cls.pool.submit(cls._get_result, func, *args, **kwargs)
        return cls._package_result_methods(future, probe_delay=delay)

    @classmethod
    def submit(
        cls,
        func: t.Callable[..., t.Any],
        /,
        *args: t.Any,
        probe_delay: t.PositiveRealNumber | None = None,
        **kwargs: t.Any,
    ) -> t.Future:
        """
        Submits a synchronous `func` to a process pool or thread pool,
        depending on the class that calls this method, with the supplied
        `*args` & `**kwargs`, then returns the `Future` object that's
        created.
        """
        delay = process_probe_delay(
            probe_delay,
            default=cls._default_probe_delay,
        )
        future = cls.pool.submit(func, *args, **kwargs)
        return cls._package_result_methods(future, probe_delay=delay)

    @classmethod
    async def agather(
        cls,
        /,
        *functions: t.Callable[..., t.Any],
        args: t.Iterable[t.Any] = (),
        kwargs: t.Mapping[str, t.Any] = {},
    ) -> list[t.Any]:
        """
        Sumbits all of the async or synchronous `functions` to the
        `Processes.pool` or `Threads.pool` with the given `args` &
        `kwargs`.
        """
        tasks = [
            await cls.asubmit(func, *args, **kwargs) for func in functions
        ]
        try:
            return [await task.aresult() for task in tasks]
        finally:
            for task in tasks:
                task.cancel()

    @classmethod
    def gather(
        cls,
        /,
        *functions: t.Callable[..., t.Any],
        args: t.Iterable[t.Any] = (),
        kwargs: t.Mapping[str, t.Any] = {},
    ) -> list[t.Any]:
        """
        Sumbits all the `functions` to the `Processes.pool` or
        `Threads.pool` with the given `args` & `kwargs`.
        """
        tasks = [cls.submit(func, *args, **kwargs) for func in functions]
        try:
            return [task.result() for task in tasks]
        finally:
            for task in tasks:
                task.cancel()


module_api = dict(
    ConcurrencyInterface=t.add_type(ConcurrencyInterface),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    process_probe_delay=process_probe_delay,
)
