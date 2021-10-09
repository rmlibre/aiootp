# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["debuggers"]


__doc__ = (
    "A collection of tools for helping with profiling and debugging."
)


import inspect
import datetime
from time import time
from functools import wraps
from ._exceptions import *
from ._typing import Typing
from .commons import commons


# Instead of printing, a user can define a custom way to log debugging
# information for this module's debugging decorators.
#
# Usage Example:
#
# import aiootp
#
# log = []
# aiootp.debuggers.add_to_log = lambda entry: log.append(entry)
add_to_log = lambda entry: debuggers.add_to_log(entry)


class DebugControl:
    """
    Enabling debugging reveals omitted values in object ``repr``s &
    turns on asyncio's debugging.
    """

    __slots__ = ()

    _DEBUG_MODE = False

    _switches = []

    @classmethod
    def is_debugging(cls):
        return cls._DEBUG_MODE

    @classmethod
    def enable_debugging(cls):
        """
        WARNING: This will also reveal potentially sensitive values,
        such as cryptographic keys, in object repr's that are omitted by
        default.
        """
        cls._DEBUG_MODE = True
        for toggle in cls._switches:
            toggle()

    @classmethod
    def disable_debugging(cls):
        cls._DEBUG_MODE = False
        for toggle in cls._switches:
            toggle()


class AsyncDebugTools:
    """
    A simple class used for displaying & calculating runtime statistics
    on asynchronous functions.
    """

    __slots__ = (
        "args",
        "func",
        "kwargs",
        "log_entry",
        "return_value",
        "time_after",
        "time_before",
        "time_elapsed",
        "time_total",
        "timer_average",
        "timer_standard_deviation",
        "timer_variance_sum",
        "times_run",
    )

    def __init__(self):
        """
        Sets timing variables.
        """
        self.times_run = 0
        self.time_total = 0.0
        self.timer_variance_sum = 0
        self.return_value = None

    async def ainitialize_run(self, func, *a, **kw):
        """
        Captures the parameters to a wrapped async function & displays
        the incremented call number for the function.
        """
        self.args = a
        self.kwargs = kw
        self.func = func

    async def _aoutput_times_used(self):
        """
        Displays the number of times the wrapped async function has been
        run.
        """
        return f"Test #{self.times_run}"

    @staticmethod
    async def _aoutput_time_start():
        """
        Displays the datetime of when the function has been called.
        """
        return f"Time Start:\t{datetime.datetime.now()}"

    async def _aoutput_happening_now(self):
        """
        Displays the currently running wrapped async function.
        """
        current_func = f"Function:      {self.func.__qualname__}\n"
        current_func += f"{repr(self.func)}"
        return current_func

    async def _aoutput_arguments(self):
        """
        Displays the wrapped async function's supplied parameters.
        """
        for arg in self.args:
            yield f"Argument:      {repr(arg)}"
        for kwarg in self.kwargs.items():
            yield f"KW Argument:   {str(kwarg)}"

    async def _atime_the_function(self):
        """
        Captures the runtime of an async function.
        """
        self.time_before = time()
        self.return_value = await self.func(
            *self.args, **self.kwargs
        )
        self.time_after = time()

    async def _aoutput_time_elapsed(self):
        """
        Displays the captured runtime of the wrapped async funciton.
        """
        self.time_elapsed = self.time_after - self.time_before
        elapsed = f"{self.func.__qualname__}\n"
        elapsed += "Time Elapsed:         "
        elapsed += f"{self.time_elapsed} seconds."
        return elapsed

    async def _astart_timer(self):
        """
        Runs the wrapped async function & displays some runtime stats.
        """
        self.times_run += 1
        self.log_entry = [
            await self._aoutput_times_used(),
            await self._aoutput_time_start(),
            await self._aoutput_happening_now(),
            *[arg async for arg in self._aoutput_arguments()],
        ]
        await self._atime_the_function()
        self.log_entry.append(await self._aoutput_time_elapsed())

    async def _asum_runtimes(self):
        """
        Add the runtime of the current wrapped async function's call.
        """
        self.time_total += self.time_after - self.time_before

    async def _aoutput_average_runtime(self):
        """
        Calculates & displays the average runtime of the wrapped async
        function.
        """
        self.timer_average = self.time_total / float(self.times_run)
        return f"Average Elapsed Time: {self.timer_average} seconds."

    async def _asum_of_variances(self):
        """
        Adds the current runtime variance to the aggregated sum.
        """
        self.timer_variance_sum += (
            self.time_elapsed - self.timer_average
        ) ** 2
        return self.timer_variance_sum

    async def _aaverage_variance(self):
        """
        Calculates the variance of runtimes of the wrapped async
        function.
        """
        return await self._asum_of_variances() / self.times_run

    async def _astandard_deviation(self):
        """
        Calculates the standard deviation of runtimes of the wrapped
        async function.
        """
        return await self._aaverage_variance() ** 0.5

    async def _aoutput_standard_deviation(self):
        """
        Calculates & displays the standard deviation of runtimes of the
        wrapped async function.
        """
        self.timer_standard_deviation = await self._astandard_deviation()
        std_deviation = "Standard Deviation:   "
        std_deviation += f"{self.timer_standard_deviation} seconds."
        return std_deviation

    async def _aoutput_return_value(self, return_value):
        """
        Displays the return value of the wrapped async function.
        """
        return f"Return Value:  {repr(return_value)}"

    @staticmethod
    async def _aoutput_trace_call():
        """
        Displays the name of the function which has called the wrapped
        async function in user code by inspecting the stack.
        """
        calling_function = inspect.stack()[2][3]
        return f"Calling Function: {calling_function}\n\n"

    async def _aclose_timer(self):
        """
        Does final calculations on the aggregate runtime statistics of
        the wrapped async function & displays the results.
        """
        await self._asum_runtimes()
        self.log_entry += [
            await self._aoutput_average_runtime(),
            await self._aoutput_standard_deviation(),
            await self._aoutput_return_value(self.return_value),
            await self._aoutput_trace_call(),
        ]
        add_to_log("\n".join(self.log_entry))

    async def arun(self):
        """
        Runs the timer.
        """
        await self._astart_timer()
        await self._aclose_timer()


class DebugTools:
    """
    A simple class used for displaying & calculating runtime statistics
    on synchronous functions.
    """

    __slots__ = (
        "args",
        "func",
        "kwargs",
        "log_entry",
        "return_value",
        "time_after",
        "time_before",
        "time_elapsed",
        "time_total",
        "timer_average",
        "timer_standard_deviation",
        "timer_variance_sum",
        "times_run",
    )

    def __init__(self):
        """
        Sets timing variables.
        """
        self.times_run = 0
        self.time_total = 0.0
        self.timer_variance_sum = 0
        self.return_value = None

    def initialize_run(self, func, *a, **kw):
        """
        Captures the parameters to a wrapped sync function & displays
        the incremented call number for the function.
        """
        self.args = a
        self.kwargs = kw
        self.func = func

    def _output_times_used(self):
        """
        Displays the number of times the wrapped sync function has been
        run.
        """
        return f"Test #{self.times_run}"

    @staticmethod
    def _output_time_start():
        """
        Displays the datetime of when the function has been called.
        """
        return f"Time Start:    {datetime.datetime.now()}"

    def _output_happening_now(self):
        """
        Displays the currently running wrapped sync function.
        """
        current_func = f"Function:      {self.func.__qualname__}\n"
        current_func += f"{repr(self.func)}"
        return current_func

    def _output_arguments(self):
        """
        Displays the wrapped sync function's supplied parameters.
        """
        for arg in self.args:
            yield f"Argument:      {repr(arg)}"
        for kwarg in self.kwargs.items():
            yield f"KW Argument:   {str(kwarg)}"

    def _time_the_function(self):
        """
        Captures the runtime of an sync function.
        """
        self.time_before = time()
        self.return_value = self.func(
            *self.args, **self.kwargs
        )
        self.time_after = time()

    def _output_time_elapsed(self):
        """
        Displays the captured runtime of the wrapped sync funciton.
        """
        self.time_elapsed = self.time_after - self.time_before
        elapsed = f"{self.func.__qualname__}\n"
        elapsed += "Time Elapsed:         "
        elapsed += f"{self.time_elapsed} seconds."
        return elapsed

    def _start_timer(self):
        """
        Runs the wrapped sync function & displays some runtime stats.
        """
        self.times_run += 1
        self.log_entry = [
            self._output_times_used(),
            self._output_time_start(),
            self._output_happening_now(),
            *self._output_arguments(),
        ]
        self._time_the_function()
        self.log_entry.append(self._output_time_elapsed())

    def _sum_runtimes(self):
        """
        Add the runtime of the current wrapped sync function's call.
        """
        self.time_total += self.time_after - self.time_before

    def _output_average_runtime(self):
        """
        Calculates & displays the average runtime of the wrapped sync
        function.
        """
        self.timer_average = self.time_total / float(self.times_run)
        return f"Average Elapsed Time: {self.timer_average} seconds."

    def _sum_of_variances(self):
        """
        Adds the current runtime variance to the aggregated sum.
        """
        self.timer_variance_sum += (
            self.time_elapsed - self.timer_average
        ) ** 2
        return self.timer_variance_sum

    def _average_variance(self):
        """
        Calculates the variance of runtimes of the wrapped sync
        function.
        """
        return self._sum_of_variances() / self.times_run

    def _standard_deviation(self):
        """
        Calculates the standard deviation of runtimes of the wrapped
        sync function.
        """
        return self._average_variance() ** 0.5

    def _output_standard_deviation(self):
        """
        Calculates & displays the standard deviation of runtimes of the
        wrapped sync function.
        """
        self.timer_standard_deviation = self._standard_deviation()
        std_deviation = "Standard Deviation:   "
        std_deviation += f"{self.timer_standard_deviation} seconds."
        return std_deviation

    def _output_return_value(self, return_value):
        """
        Displays the return value of the wrapped sync function.
        """
        return f"Return Value:  {repr(return_value)}"

    @staticmethod
    def _output_trace_call():
        """
        Displays the name of the function which has called the wrapped
        function in user code by inspecting the stack.
        """
        calling_function = inspect.stack()[2][3]
        return f"Calling Function: {calling_function}\n\n"

    def _close_timer(self):
        """
        Does final calculations on the aggregate runtime statistics of
        the wrapped sync function & displays the results.
        """
        self._sum_runtimes()
        self.log_entry += [
            self._output_average_runtime(),
            self._output_standard_deviation(),
            self._output_return_value(self.return_value),
            self._output_trace_call(),
        ]
        add_to_log("\n".join(self.log_entry))

    def run(self):
        """
        Runs the timer.
        """
        self._start_timer()
        self._close_timer()


class _AsyncGenDebugTools(AsyncDebugTools):

    __slots__ = ("generator",)

    _async_non_none_error = (
        "can't send non-None value to a just-started async generator"
    )

    def _agen_wrapper(self, func, *a, **kw):
        """
        Creates a wrapper for the async generator being timed that's
        able to in turn be wrapped by ``functools.wraps``.
        """

        async def _agen():
            """
            Increments the wrapped async generator then takes runtime
            measurements & displays the results.
            """
            self.func = func
            self.generator = func(*a, **kw)
            while True:
                try:
                    await self.ainitialize_run(func, *a, **kw)
                    await self.arun()
                    yield self.return_value
                except StopAsyncIteration:
                    break

        return _agen

    async def _atime_the_function(self):
        """
        Captures the runtime of an async generator iteration.
        """
        try:
            self.time_before = time()
            self.return_value = await self.generator.asend(self.return_value)
        except TypeError as error:
            if self._async_non_none_error in error.args:
                self.return_value = await self.generator.asend(None)
            else:
                raise error
        finally:
            self.time_after = time()

    @staticmethod
    async def _aoutput_trace_call():
        """
        Displays the name of the function which has called the wrapped
        async function in user code by inspecting the stack.
        """
        calling_function = inspect.stack()[5][3], inspect.stack()[2][3]
        return f"Calling Function: {calling_function}\n\n"


class _GenDebugTools(DebugTools):

    __slots__ = ("generator",)

    _sync_non_none_error = (
        "can't send non-None value to a just-started generator"
    )

    def _gen_wrapper(self, func, *a, **kw):
        """
        Creates a wrapper for the generator being timed that's able to
        in turn be wrapped by ``functools.wraps``.
        """

        def _gen():
            """
            Increments the wrapped generator then takes runtime
            measurements & displays the results.
            """
            self.func = func
            self.generator = func(*a, **kw)
            while True:
                try:
                    self.initialize_run(func, *a, **kw)
                    self.run()
                    yield self.return_value
                except StopIteration:
                    break

        return _gen

    def _time_the_function(self):
        """
        Captures the runtime of a generator iteration.
        """
        try:
            self.time_before = time()
            self.return_value = self.generator.send(self.return_value)
        except TypeError as error:
            if self._sync_non_none_error in error.args:
                self.return_value = self.generator.send(None)
            else:
                raise error
        finally:
            self.time_after = time()

    @staticmethod
    def _output_trace_call():
        """
        Displays the name of the function which has called the wrapped
        async function in user code by inspecting the stack.
        """
        calling_function = inspect.stack()[5][3], inspect.stack()[2][3]
        return f"Calling Function: {calling_function}\n\n"


def agen_timer(func):
    """
    A simple timer decorator that can get timings from per-iteration
    readings over an async generator.

    Usage Example:

    @agen_timer
    async def loop(times=10):
        for time in range(times):
            yield f"This is loop #{time}"

    async for notice in loop():
        # Performance statistics & debug info for the async generator
        # will now be gathered and printed to the screen.
        pass
    """
    debugger = _AsyncGenDebugTools()

    def wrapped_generator_func(*a, **kw):
        return wraps(func)(debugger._agen_wrapper(func, *a, **kw))()

    return wrapped_generator_func


def gen_timer(func):
    """
    A simple timer decorator that can get timings from per-iteration
    readings over a sync generator.

    Usage Example:

    @gen_timer
    def loop(times=10):
        for time in range(times):
            yield f"This is loop #{time}"

    for notice in loop():
        # Performance statistics & debug info for the generator will now
        # be gathered and printed to the screen.
        pass
    """
    debugger = _GenDebugTools()

    def wrapped_generator_func(*a, **kw):
        return wraps(func)(debugger._gen_wrapper(func, *a, **kw))()

    return wrapped_generator_func


def afunc_timer(func):
    """
    A simple decorator for async functions which calculates & displays
    running statistics & introspection details to stdout.

    Usage Example:

    @afunc_timer
    async def add(x=4, y=6):
        return x + y

    # Performance statistics & debug info for the async function will be
    # gathered & printed to the screen whenever it's processed.
    await add()
    """
    debugger = AsyncDebugTools()

    @wraps(func)
    async def wrapped_func(*a, **kw):
        await debugger.ainitialize_run(func, *a, **kw)
        await debugger.arun()
        return debugger.return_value

    return wrapped_func


def func_timer(func):
    """
    A simple decorator for sync functions which calculates & displays
    running statistics & introspection details to stdout.

    Usage Example:

    @func_timer
    def add(x=4, y=6):
        return x + y

    # Performance statistics & debug info for the function will be
    # gathered & printed to the screen whenever it's called.
    add(1, 10)
    """
    debugger = DebugTools()

    @wraps(func)
    def wrapped_func(*a, **kw):
        debugger.initialize_run(func, *a, **kw)
        debugger.run()
        return debugger.return_value

    return wrapped_func


extras = dict(
    AsyncDebugTools=AsyncDebugTools,
    DebugControl=DebugControl,
    DebugTools=DebugTools,
    __doc__=__doc__,
    __main_exports__=__all__,
    __package__=__package__,
    add_to_log=print,
    afunc_timer=afunc_timer,
    agen_timer=agen_timer,
    func_timer=func_timer,
    gen_timer=gen_timer,
)


debuggers = commons.make_module("debuggers", mapping=extras)

