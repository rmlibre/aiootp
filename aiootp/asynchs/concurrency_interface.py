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


__all__ = ["ConcurrencyInterface"]


__doc__ = "A general interface for multi-threading & multi-processing."


from time import sleep

from aiootp._typing import Typing as t
from aiootp._exceptions import Issue

from . import is_async_function
from .loops import asleep, sleep, new_event_loop


class ConcurrencyInterface:
    """
    Defines an interface for managing tasks & pools of threads & processes.
    """

    __slots__ = ()

    _Manager: type

    _default_probe_delay: t.PositiveRealNumber
    _pool: t.PoolExecutorType
    _type: type

    BrokenPool: type

    @classmethod
    def _process_probe_delay(
        cls, value: t.Optional[t.PositiveRealNumber], /
    ) -> t.PositiveRealNumber:
        """
        Ensures the probe frequency is positive & returns it, if it's
        specified. Otherwise, returns the class' default value.
        """
        if value is None:
            return cls._default_probe_delay
        elif value > 0:
            return value
        else:
            raise Issue.value_must("probe_delay", "be > 0")

    @staticmethod
    def _arun_func(
        func: t.Callable[..., t.Any],
        state: t.Sequence[t.Any],
        /,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        """
        Used by the class to retrieve return values from an async or
        sync `func` run in a new process / thread by storing the result
        in a shared `state` container.
        """
        if is_async_function(func):
            run = new_event_loop().run_until_complete
            state.append(run(func(*args, **kwargs)))
        else:
            state.append(func(*args, **kwargs))

    @staticmethod
    def _run_func(
        func: t.Callable[..., t.Any],
        state: t.Sequence[t.Any],
        /,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        """
        Used by the class to retrieve return values from a sync `func`
        run in a new process / thread by storing the result in a shared
        `state` container.
        """
        state.append(func(*args, **kwargs))

    @classmethod
    async def anew(
        cls,
        func: t.Callable[..., t.Any],
        /,
        *args: t.Any,
        probe_delay: t.Optional[t.PositiveRealNumber] = None,
        **kwargs: t.Any,
    ) -> t.Any:
        """
        Runs an async or sync function in another process or thread
        depending on the class calling this method, so that heavy cpu-
        bound computations, or blocking IO operations, can better
        coexist with asynchronous code.
        """
        delay = cls._process_probe_delay(probe_delay)
        state = cls._Manager().list()
        task = cls._type(
            target=cls._arun_func,
            args=(func, state, *args),
            kwargs=kwargs,
        )
        task.start()
        while task.is_alive():
            await asleep(delay)
        task.join()
        return state.pop()

    @classmethod
    def new(
        cls,
        func: t.Callable[..., t.Any],
        /,
        *args: t.Any,
        probe_delay: t.Optional[t.PositiveRealNumber] = None,
        **kwargs: t.Any,
    ) -> t.Any:
        """
        Runs a sync function in another process or thread depending on
        the class calling this method, so that heavy cpu-bound
        computations, or blocking IO operations, can better coexist with
        asynchronous code.
        """
        delay = cls._process_probe_delay(probe_delay)
        state = cls._Manager().list()
        task = cls._type(
            target=cls._run_func,
            args=(func, state, *args),
            kwargs=kwargs,
        )
        task.start()
        while task.is_alive():
            sleep(delay)
        task.join()
        return state.pop()

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
            run = new_event_loop().run_until_complete
            return run(func(*args, **kwargs))
        else:
            return func(*args, **kwargs)

    @staticmethod
    def _package_result_methods(
        future: t.Future, /, *, probe_delay: t.PositiveRealNumber
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
        probe_delay: t.Optional[t.PositiveRealNumber] = None,
        **kwargs: t.Any,
    ) -> t.Future:
        """
        Submits an async, or synchronous `func` to a process pool or
        thread pool, depending on the class that calls this method, with
        the supplied `*args` & `**kwargs`, then returns the `Future`
        object that's created.
        """
        delay = cls._process_probe_delay(probe_delay)
        future = cls._pool.submit(cls._get_result, func, *args, **kwargs)
        return cls._package_result_methods(future, probe_delay=delay)

    @classmethod
    def submit(
        cls,
        func: t.Callable[..., t.Any],
        /,
        *args: t.Any,
        probe_delay: t.Optional[t.PositiveRealNumber] = None,
        **kwargs: t.Any,
    ) -> t.Future:
        """
        Submits a synchronous `func` to a process pool or thread pool,
        depending on the class that calls this method, with the supplied
        `*args` & `**kwargs`, then returns the `Future` object that's
        created.
        """
        delay = cls._process_probe_delay(probe_delay)
        future = cls._pool.submit(func, *args, **kwargs)
        return cls._package_result_methods(future, probe_delay=delay)

    @classmethod
    async def agather(
        cls,
        /,
        *functions: t.Callable[..., t.Any],
        args: t.Iterable[t.Any] = (),
        kwargs: t.Mapping[t.Hashable, t.Any] = {},
    ) -> t.List[t.Any]:
        """
        Sumbits all of the async or synchronous `functions` to the
        `Processes._pool` or `Threads._pool` with the given `args` &
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
        kwargs: t.Mapping[t.Hashable, t.Any] = {},
    ) -> t.List[t.Any]:
        """
        Sumbits all the `functions` to the `Processes._pool` or
        `Threads._pool` with the given `args` & `kwargs`.
        """
        tasks = [cls.submit(func, *args, **kwargs) for func in functions]
        try:
            return [task.result() for task in tasks]
        finally:
            for task in tasks:
                task.cancel()

    @classmethod
    def reset_pool(cls, /) -> None:
        """
        When a process or thread pool is broken by an abruptly exited,
        this method can be called to reset the class' pool object with
        a new instance.
        """
        cls._pool = cls._pool.__class__()


module_api = dict(
    ConcurrencyInterface=t.add_type(ConcurrencyInterface),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

