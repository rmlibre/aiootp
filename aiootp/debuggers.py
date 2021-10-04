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


class DebugTools:
    """
    A simple class used for displaying & calculating runtime statistics
    on synchronous functions.
    """

    __slots__ = (
        "arg_tuple",
        "kw_dict",
        "log_entry",
        "return_value",
        "time_after",
        "time_average",
        "time_before",
        "time_elapsed",
        "timed_func",
        "times_run",
        "timer_sum",
        "variance_sum",
    )

    def __init__(self):
        """
        Sets timing variables.
        """
        self.times_run = 0
        self.timer_sum = 0.0
        self.variance_sum = 0
        self.return_value = None

    def initiate_timer_func(self, *a, **kw):
        """
        Captures the parameters to a wrapped sync function & displays
        the incremented call number for the function.
        """
        self.times_run += 1
        self.arg_tuple = a
        self.kw_dict = kw

    def print_times_used(self):
        """
        Displays the number of times the wrapped sync function has been
        run.
        """
        return f"Test #{self.times_run}"

    @staticmethod
    def print_time_start():
        """
        Displays the datetime of when the function has been called.
        """
        return f"Time Start:    {datetime.datetime.now()}"

    def print_happening_now(self, decorated_func):
        """
        Displays the currently running wrapped sync function.
        """
        self.timed_func = decorated_func
        current_func = f"Function:      {decorated_func.__name__}\n"
        current_func += f"{repr(decorated_func)}"
        return current_func

    def print_arguments(self):
        """
        Displays the wrapped sync function's supplied parameters.
        """
        for arg in self.arg_tuple:
            yield f"Argument:      {repr(arg)}"
        for kwarg in self.kw_dict.items():
            yield f"KW Argument:   {str(kwarg)}"

    def time_the_function(self):
        """
        Captures the runtime of an sync function.
        """
        self.time_before = time()
        self.return_value = self.timed_func(
            *self.arg_tuple, **self.kw_dict
        )
        self.time_after = time()

    def print_time_elapsed(self):
        """
        Displays the captured runtime of the wrapped sync funciton.
        """
        self.time_elapsed = self.time_after - self.time_before
        elapsed = f"{self.timed_func.__name__}\n"
        elapsed += "Time Elapsed:         "
        elapsed += f"{self.time_elapsed} seconds."
        return elapsed

    def start_the_timer(self, decorated_func):
        """
        Runs the wrapped sync function & displays some runtime stats.
        """
        self.log_entry = [
            self.print_times_used(),
            self.print_time_start(),
            self.print_happening_now(decorated_func),
            *self.print_arguments(),
        ]
        self.time_the_function()
        self.log_entry.append(self.print_time_elapsed())

    def sum_runtimes(self):
        """
        Add the runtime of the current wrapped sync function's call.
        """
        self.timer_sum += self.time_after - self.time_before

    def print_average_runtime(self):
        """
        Calculates & displays the average runtime of the wrapped sync
        function.
        """
        self.time_average = self.timer_sum / float(self.times_run)
        return f"Average Elapsed Time: {self.time_average} seconds."

    def sum_of_variances(self):
        """
        Adds the current runtime variance to the aggregated sum.
        """
        self.variance_sum += (
            self.time_elapsed - self.time_average
        ) ** 2
        return self.variance_sum

    def average_variance(self):
        """
        Calculates the variance of runtimes of the wrapped sync
        function.
        """
        return self.sum_of_variances() / self.times_run

    def standard_deviation(self):
        """
        Calculates the standard deviation of runtimes of the wrapped
        sync function.
        """
        return self.average_variance() ** 0.5

    def print_standard_deviation(self):
        """
        Calculates & displays the standard deviation of runtimes of the
        wrapped sync function.
        """
        std_deviation = "Standard Deviation:   "
        std_deviation += f"{self.standard_deviation()} seconds."
        return std_deviation

    def print_return_value(self, return_value):
        """
        Displays the return value of the wrapped sync function.
        """
        return f"Return Value:  {repr(return_value)}"

    @staticmethod
    def print_trace_call():
        """
        Displays the name of the function which has called the wrapped
        function in user code by inspecting the stack.
        """
        calling_function = inspect.stack()[2][3]
        return f"Calling Function: {calling_function}\n\n"

    def close_timer(self):
        """
        Does final calculations on the aggregate runtime statistics of
        the wrapped sync function & displays the results.
        """
        self.sum_runtimes()
        self.log_entry += [
            self.print_average_runtime(),
            self.print_standard_deviation(),
            self.print_return_value(self.return_value),
            self.print_trace_call(),
        ]
        add_to_log("\n".join(self.log_entry))


class AsyncDebugTools(DebugTools):
    """
    A simple class used for displaying & calculating runtime statistics
    on asynchronous functions.
    """

    __slots__ = ()

    def __init__(self):
        """
        Sets timing variables.
        """
        self.times_run = 0
        self.timer_sum = 0.0
        self.variance_sum = 0
        self.return_value = None

    async def ainitiate_timer_func(self, *a, **kw):
        """
        Captures the parameters to a wrapped async function & displays
        the incremented call number for the function.
        """
        self.times_run += 1
        self.arg_tuple = a
        self.kw_dict = kw

    async def aprint_times_used(self):
        """
        Displays the number of times the wrapped async function has been
        run.
        """
        return f"Test #{self.times_run}"

    @staticmethod
    async def aprint_time_start():
        """
        Displays the datetime of when the function has been called.
        """
        return f"Time Start:\t{datetime.datetime.now()}"

    async def aprint_happening_now(self, decorated_func):
        """
        Displays the currently running wrapped async function.
        """
        self.timed_func = decorated_func
        current_func = f"Function:\t{decorated_func.__qualname__}\n"
        current_func += f"{repr(decorated_func)}"
        return current_func

    async def aprint_arguments(self):
        """
        Displays the wrapped async function's supplied parameters.
        """
        for arg in self.arg_tuple:
            yield f"Argument:      {repr(arg)}"
        for kwarg in self.kw_dict.items():
            yield f"KW Argument:   {str(kwarg)}"

    async def atime_the_function(self):
        """
        Captures the runtime of an async function.
        """
        self.time_before = time()
        self.return_value = await self.timed_func(
            *self.arg_tuple, **self.kw_dict
        )
        self.time_after = time()

    async def aprint_time_elapsed(self):
        """
        Displays the captured runtime of the wrapped async funciton.
        """
        self.time_elapsed = self.time_after - self.time_before
        elapsed = f"{self.timed_func.__qualname__}\n"
        elapsed += "Time Elapsed:         "
        elapsed += f"{self.time_elapsed} seconds."
        return elapsed

    async def astart_the_timer(self, decorated_func):
        """
        Runs the wrapped async function & displays some runtime stats.
        """
        self.log_entry = [
            await self.aprint_times_used(),
            await self.aprint_time_start(),
            await self.aprint_happening_now(decorated_func),
            *[arg async for arg in self.aprint_arguments()],
        ]
        await self.atime_the_function()
        self.log_entry.append(await self.aprint_time_elapsed())

    async def asum_runtimes(self):
        """
        Add the runtime of the current wrapped async function's call.
        """
        self.timer_sum += self.time_after - self.time_before

    async def aprint_average_runtime(self):
        """
        Calculates & displays the average runtime of the wrapped async
        function.
        """
        self.time_average = self.timer_sum / float(self.times_run)
        return f"Average Elapsed Time: {self.time_average} seconds."

    async def asum_of_variances(self):
        """
        Adds the current runtime variance to the aggregated sum.
        """
        self.variance_sum += (
            self.time_elapsed - self.time_average
        ) ** 2
        return self.variance_sum

    async def aaverage_variance(self):
        """
        Calculates the variance of runtimes of the wrapped async
        function.
        """
        return await self.asum_of_variances() / self.times_run

    async def astandard_deviation(self):
        """
        Calculates the standard deviation of runtimes of the wrapped
        async function.
        """
        return await self.aaverage_variance() ** 0.5

    async def aprint_standard_deviation(self):
        """
        Calculates & displays the standard deviation of runtimes of the
        wrapped async function.
        """
        value = await self.astandard_deviation()
        std_deviation = "Standard Deviation:   "
        std_deviation += f"{value} seconds."
        return std_deviation

    async def aprint_return_value(self, return_value):
        """
        Displays the return value of the wrapped async function.
        """
        return f"Return Value:  {repr(return_value)}"

    @staticmethod
    async def aprint_trace_call():
        """
        Displays the name of the function which has called the wrapped
        async function in user code by inspecting the stack.
        """
        calling_function = inspect.stack()[2][3]
        return f"Calling Function: {calling_function}\n\n"

    async def aclose_timer(self):
        """
        Does final calculations on the aggregate runtime statistics of
        the wrapped async function & displays the results.
        """
        await self.asum_runtimes()
        self.log_entry += [
            await self.aprint_average_runtime(),
            await self.aprint_standard_deviation(),
            await self.aprint_return_value(self.return_value),
            await self.aprint_trace_call(),
        ]
        add_to_log("\n".join(self.log_entry))


class AsyncGenDebugTools(AsyncDebugTools):

    __slots__ = ("generator",)

    _async_non_none_error = (
        "can't send non-None value to a just-started async generator"
    )

    def _agen_wrapper(self, *a, **kw):
        """
        Creates a wrapper for the async generator being timed that's
        able to in turn be wrapped by ``functools.wraps``.
        """

        async def _agen():
            """
            Increments the wrapped async generator then takes runtime
            measurements & displays the results.
            """
            while True:
                try:
                    await self.ainitiate_timer_func(*a, **kw)
                    await self.astart_the_timer(self.timed_func)
                    await self.aclose_timer()
                    yield self.return_value
                except StopAsyncIteration:
                    break

        return _agen

    async def aprint_happening_now(self, decorated_func):
        """
        Displays the currently running wrapped async generator.
        """
        current_func = f"Function:\t{decorated_func.__qualname__}\n"
        current_func += f"{repr(decorated_func)}"
        return current_func

    async def atime_the_function(self):
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
    async def aprint_trace_call():
        """
        Displays the name of the function which has called the wrapped
        async function in user code by inspecting the stack.
        """
        calling_function = inspect.stack()[5][3], inspect.stack()[2][3]
        return f"Calling Function: {calling_function}\n\n"


class GenDebugTools(DebugTools):

    __slots__ = ("generator",)

    _sync_non_none_error = (
        "can't send non-None value to a just-started generator"
    )

    def _gen_wrapper(self, *a, **kw):
        """
        Creates a wrapper for the generator being timed that's able to
        in turn be wrapped by ``functools.wraps``.
        """

        def _gen():
            """
            Increments the wrapped generator then takes runtime
            measurements & displays the results.
            """
            while True:
                try:
                    self.initiate_timer_func(*a, **kw)
                    self.start_the_timer(self.timed_func)
                    self.close_timer()
                    yield self.return_value
                except StopIteration:
                    break

        return _gen

    def print_happening_now(self, decorated_func):
        """
        Displays the currently running wrapped generator.
        """
        current_func = f"Function:\t{decorated_func.__qualname__}\n"
        current_func += f"{repr(decorated_func)}"
        return current_func

    def time_the_function(self):
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
    def print_trace_call():
        """
        Displays the name of the function which has called the wrapped
        async function in user code by inspecting the stack.
        """
        calling_function = inspect.stack()[5][3], inspect.stack()[2][3]
        return f"Calling Function: {calling_function}\n\n"


def agen_timer(decorated_func):
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
    debugger = AsyncGenDebugTools()

    def wrapped_generator_func(*a, **kw):
        debugger.timed_func = decorated_func
        debugger.generator = decorated_func(*a, **kw)
        return wraps(decorated_func)(debugger._agen_wrapper(*a, **kw))()

    return wrapped_generator_func


def afunc_timer(decorated_func):
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

    @wraps(decorated_func)
    async def decorated_func_timed(*a, **kw):
        await debugger.ainitiate_timer_func(*a, **kw)
        await debugger.astart_the_timer(decorated_func)
        await debugger.aclose_timer()
        return debugger.return_value

    return decorated_func_timed


def gen_timer(decorated_func):
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
    debugger = GenDebugTools()

    def wrapped_generator_func(*a, **kw):
        debugger.timed_func = decorated_func
        debugger.generator = decorated_func(*a, **kw)
        return wraps(decorated_func)(debugger._gen_wrapper(*a, **kw))()

    return wrapped_generator_func


def func_timer(decorated_func):
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

    @wraps(decorated_func)
    def decorated_func_timed(*a, **kw):
        debugger.initiate_timer_func(*a, **kw)
        debugger.start_the_timer(decorated_func)
        debugger.close_timer()
        return debugger.return_value

    return decorated_func_timed


async_timers = dict(
    agen_timer=agen_timer, afunc_timer=afunc_timer
)


sync_timers = dict(
    gen_timer=gen_timer, func_timer=func_timer
)


for name, method in  async_timers.items():
    setattr(AsyncDebugTools, name, method)


for name, method in  sync_timers.items():
    setattr(DebugTools, name, method)


extras = dict(
    AsyncDebugGenTools=AsyncGenDebugTools,
    AsyncDebugTools=AsyncDebugTools,
    DebugControl=DebugControl,
    DebugGenTools=GenDebugTools,
    DebugTools=DebugTools,
    __doc__=__doc__,
    __main_exports__=__all__,
    __package__=__package__,
    add_to_log=print,
    **async_timers,
    **sync_timers,
)


debuggers = commons.make_module("debuggers", mapping=extras)

