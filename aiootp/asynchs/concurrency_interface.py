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

__all__ = [
    "ConcurrencyGuard",
    "ConcurrencyInterface",
    "MultiConcurrencyGaurd",
]


from hmac import compare_digest
from secrets import token_bytes
from collections import defaultdict, deque

from aiootp._typing import Typing as t
from aiootp._exceptions import Issue, IncoherentConcurrencyState
from aiootp._exceptions import Metadata, SingleUseObjectWasReused
from aiootp.commons import FrozenTypedSlots

from . import is_async_function
from .loops import asleep, sleep, new_event_loop


def process_probe_delay(
    value: t.Optional[t.PositiveRealNumber], /, *, default: float
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


class ConcurrencyGuard(FrozenTypedSlots):
    """
    An interface for queueing execution contexts given only a shared
    `deque` or `deque`-like double-ended queue. Prevents simultaneous /
    out of order runs of blocks of code. A `deque` is recommended since
    it supports atomic operations. Any atomic, shared datastructure with
    `append`, `popleft`, & `queue[0]` methods would fit the API.

     _____________________________________
    |                                     |
    |         Example As Diagram:         |
    |_____________________________________|

                           ----------------------
                           |   Shared Context   |
                           ----------------------

                               queue = deque()
                           -----------------------
            -----------------         |        -----------------
            |   Context A   |         |        |   Context B   |
            -----------------         |        -----------------
                                      |
    with ConcurrencyGuard(queue):     |  with ConcurrencyGuard(queue):
        mutable_thing[0] = 0          |      assert mutable_thing[0] == "done."
        ...                           |      mutable_thing[0] = 1
        ...                           |
        assert mutable_thing[0] == 0  |
        mutable_thing[0] = "done."    |
                                      |
    --------------------------------------------------------------------
    Context A is called first, and Context B waits for A to finish.
    --------------------------------------------------------------------
    """

    __slots__ = (
        "_append_token_manually",
        "_use_tracker",
        "probe_delay",
        "queue",
        "token",
    )

    slots_types: t.Mapping[str, type] = dict(
        _append_token_manually=bool,
        _use_tracker=deque,
        probe_delay=float,
        queue=t.SupportsAppendPopleft,
        token=bytes,
    )

    _default_probe_delay: float = 0.00001

    IncoherentConcurrencyState: type = IncoherentConcurrencyState

    def __init__(
        self,
        /,
        queue: t.SupportsAppendPopleft,
        *,
        probe_delay: t.Optional[t.PositiveRealNumber] = None,
        token: t.Optional[bytes] = None,
        append_token_manually: bool = False,
    ) -> None:
        """
        `queue`: Atomic, `deque`-like datastructure that supports `append`,
                `popleft`, & `queue[0]` methods.

        `probe_delay`: The float/fractional number of seconds to wait
                before each attempt to detect if the instance's token
                has been authorized to run.

        `token`: The unique authorization token held by this context.

        `append_token_manually`: Signals to the instance that the caller
                will manually append the instance token to the queue to
                acheive the desired ordering of events. This overrides
                the default behavior of the token being automatically
                appended when the instance context manager is entered.
                The instance remains responsible for automatically
                removing the token from the queue when the context
                manager is exited.
                ********
                CAUTION: Care must be taken not to use the same token
                ******** multiple times. Doing so may cause a deadlock,
                incoherent state, or exception if two instances with the
                same token enter their contexts simultaneously, and then
                during exit, pop a token off the queue expecting it to
                be their own.
        """
        self.probe_delay = process_probe_delay(
            probe_delay, default=self._default_probe_delay
        )
        self.queue = queue
        self.token = token or token_bytes(32)
        self._append_token_manually = append_token_manually
        self._use_tracker = deque()

    async def __aenter__(self, /) -> t.Self:
        """
        Prevents entering the context by asynchronously sleeping until
        the instance's unique authorization token is the current token
        in the 0th position of the queue.
        """
        self._use_tracker.append(True)
        if len(self._use_tracker) > 1:
            raise SingleUseObjectWasReused(Metadata(self))

        if not self._append_token_manually:
            self.queue.append(self.token)
        while not compare_digest(self.token, self.queue[0]):
            await asleep(self.probe_delay)
        return self

    def __enter__(self, /) -> t.Self:
        """
        Prevents entering the context by synchronously sleeping until
        the instance's unique authorization token is the current token
        in the 0th position of the queue.
        """
        self._use_tracker.append(True)
        if len(self._use_tracker) > 1:
            raise SingleUseObjectWasReused(Metadata(self))

        if not self._append_token_manually:
            self.queue.append(self.token)
        while not compare_digest(self.token, self.queue[0]):
            sleep(self.probe_delay)
        return self

    async def __aexit__(
        self,
        /,
        exc_type: t.Optional[type] = None,
        exc_value: t.Optional[Exception] = None,
        traceback: t.Optional[t.TracebackType] = None,
    ) -> bool:
        """
        Raises `self.IncoherentConcurrencyState` if another instance's
        authorization token has taken this instance's place in the token
        queue.

        Otherwise, raises any exception raised in the context's code
        block.

        Otherwise, closes the context silently.
        """
        await asleep()
        if not compare_digest(self.token, self.queue.popleft()):
            raise self.IncoherentConcurrencyState from exc_value
        return exc_type is None

    def __exit__(
        self,
        /,
        exc_type: t.Optional[type] = None,
        exc_value: t.Optional[Exception] = None,
        traceback: t.Optional[t.TracebackType] = None,
    ) -> bool:
        """
        Raises `self.IncoherentConcurrencyState` if another instance's
        authorization token has taken this instance's place in the token
        queue.

        Otherwise, raises any exception raised in the context's code
        block.

        Otherwise, closes the context silently.
        """
        if not compare_digest(self.token, self.queue.popleft()):
            raise self.IncoherentConcurrencyState from exc_value
        return exc_type is None


class DefaultDictOfDeques(defaultdict):
    """
    A mapping of target ID keys to deque queues which are used to
    enforce the turn order of distinct execution contexts only if the
    target keys are the same between them.
    """

    __slots__ = ()

    def __init__(self, /) -> None:
        """
        Applies `collections.deque` as the default value type of new
        instances.
        """
        super().__init__(deque)

    def __setitem__(self, name: t.Hashable, value: deque, /) -> None:
        """
        Before adding values to the collection, ensures they're of type
        `collections.deque`.
        """
        if value.__class__ is not deque:
            raise Issue.value_must_be_type("value", deque) from None

        super().__setitem__(name, value)

    def update(
        self,
        targets: t.Mapping[t.Hashable, deque] = {},
        /,
        **target_deque_pairs: deque,
    ) -> None:
        """
        Updates the instance with new key-values from a mapping of
        `targets`, & optional keyword arguments. Operations on targets
        only need concurrency management if the target keys are the same,
        so those on different targets are allowed to run freely &
        independently from each other. Before adding values to the
        collection, ensures they're of type `collections.deque`.
        """
        for name, value in {**dict(targets), **target_deque_pairs}.items():
            self[name] = value  # type enforcement happens here


class MultiConcurrencyGaurd(FrozenTypedSlots):
    """
    Facilitates async/thread-safety for execution contexts which can be
    categorized by a hashable target key from call-sites. Executuion
    contexts which operate on distinct targets are allowed to run freely
    & independently from each other, & those operating on the same
    target will delay their turn to run by appending their unique tokens
    to atomic queues & awaiting their arrival at the front of the queue.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from asyncio import gather
    from pathlib import Path
    from typing import Awaitable, Callable

    from aiootp.asynchs import MultiConcurrencyGuard


    async def do_something(
        target: str,
        guards: MultiConcurrencyGuard,
        mutate_or_read_target: Callable[..., Awaitable],
    ) -> None:
        '''
        Applies protection against race conditions for operations on
        the same target between distinct execution contexts.
        '''
        async with guards.guard(target):
            await mutate_or_read_target(target)


    guards = MultiConcurrencyGuard()
    filenames = list(Path().iterdir())

    tasks = [
        do_something(filename, guards, operation)
        for operation in user_actions
        for filename in filenames
    ]
    await gather(*tasks)
    """

    __slots__ = ("targets",)

    _Guard: type = ConcurrencyGuard
    _Targets: type = DefaultDictOfDeques

    IncoherentConcurrencyState: type = IncoherentConcurrencyState

    slots_types = dict(targets=_Targets)

    def __init__(
        self,
        targets: t.Optional[_Targets] = None,
        /,
        **target_name_deque_pairs: deque,
    ) -> None:
        """
        Initializes the instance with a default mapping of target ID
        keys to deque queues.
        """
        self.targets = self._Targets() if targets is None else targets
        self.targets.update(target_name_deque_pairs)

    def guard(
        self,
        /,
        target: t.Hashable,
        *,
        probe_delay: t.Optional[t.PositiveRealNumber] = None,
        token: t.Optional[bytes] = None,
        append_token_manually: bool = False,
    ) -> _Guard:
        """
        Returns the guard instance which can be entered using either the
        sync or async context manager syntaxes.

        `target`: A hashable index key used to identify resources which
                need the async/thread-safety of atomic turn ordering for
                their execution contexts.

        `probe_delay`: The float/fractional number of seconds to wait
                before each attempt to detect if the instance's token
                has been authorized to run.

        `token`: The unique authorization token held by this context.

        `append_token_manually`: Signals to the instance that the caller
                will manually append the instance token to the queue to
                acheive the desired ordering of events. This overrides
                the default behavior of the token being automatically
                appended when the instance context manager is entered.
                The instance remains responsible for automatically
                removing the token from the queue when the context
                manager is exited.
                ********
                CAUTION: Care must be taken not to use the same token
                ******** multiple times. Doing so may cause a deadlock,
                incoherent state, or exception if two instances with the
                same token enter their contexts simultaneously, and then
                during exit, pop a token off the queue expecting it to
                be their own.

         _____________________________________
        |                                     |
        |           Syntax Example:           |
        |_____________________________________|

        guards = MultiConcurrencyGuard()

        async with guards.guard(target):
            await async_mutate_or_read_target(target)

        with guards.guard(target):
            mutate_or_read_target(target)
        """
        return self._Guard(
            queue=self.targets[target],
            probe_delay=probe_delay,
            token=token,
            append_token_manually=append_token_manually,
        )


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
        probe_delay: t.Optional[t.PositiveRealNumber] = None,
        **kwargs: t.Any,
    ) -> t.Any:
        """
        Runs an async or sync function in another process or thread
        depending on the class calling this method, so that heavy cpu-
        bound computations, or blocking IO operations, can better
        coexist with asynchronous code.
        """
        delay = process_probe_delay(
            probe_delay, default=cls._default_probe_delay
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
        probe_delay: t.Optional[t.PositiveRealNumber] = None,
        **kwargs: t.Any,
    ) -> t.Any:
        """
        Runs a sync function in another process or thread depending on
        the class calling this method, so that heavy cpu-bound
        computations, or blocking IO operations, can better coexist with
        asynchronous code.
        """
        delay = process_probe_delay(
            probe_delay, default=cls._default_probe_delay
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
        future: t.Future, /, *, probe_delay: float
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
        delay = process_probe_delay(
            probe_delay, default=cls._default_probe_delay
        )
        future = cls.pool.submit(cls._get_result, func, *args, **kwargs)
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
        delay = process_probe_delay(
            probe_delay, default=cls._default_probe_delay
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
    ConcurrencyGuard=t.add_type(ConcurrencyGuard),
    ConcurrencyInterface=t.add_type(ConcurrencyInterface),
    DefaultDictOfDeques=t.add_type(DefaultDictOfDeques),
    MultiConcurrencyGaurd=t.add_type(MultiConcurrencyGaurd),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    process_probe_delay=process_probe_delay,
)
