# This file is part of aiootp, an asynchronous one-time-pad based crypto
# and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["debuggers"]


__doc__ = """
A collection of tools for helping with profiling and debugging.
"""


import inspect
import datetime
from time import time
from functools import wraps
from inspect import isasyncgenfunction
from .commons import Namespace


class DebugTools:
    """
    A simple class used for displaying & calculating runtime statistics
    on synchronous functions.
    """

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
        self.print_times_used()

    def print_times_used(self):
        """
        Displays the number of times the wrapped sync function has been
        run.
        """
        print(f"Test #{self.times_run}")

    def start_the_timer(self, decorated_func):
        """
        Runs the wrapped sync function & displays some runtime stats.
        """
        self.print_time_start()
        self.print_happening_now(decorated_func)
        self.print_arguments()
        self.time_the_function()
        self.print_time_elapsed()

    @staticmethod
    def print_time_start():
        """
        Displays the datetime of when the function has been called.
        """
        print(f"Time Start:    {datetime.datetime.now()}")

    def print_happening_now(self, decorated_func):
        """
        Displays the currently running wrapped sync function.
        """
        self.timed_func = decorated_func
        print_string = f"Function:      {decorated_func.__name__}\n"
        print_string += f"{repr(decorated_func)}"
        print(print_string)

    def print_arguments(self):
        """
        Displays the wrapped sync function's supplied parameters.
        """
        for arg in self.arg_tuple:
            print(f"Argument:      {repr(arg)}")
        for kwarg in self.kw_dict.items():
            print(f"KW Argument:   {str(kwarg)}")

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
        print_string = f"{self.timed_func.__name__}\n"
        print_string += "Time Elapsed:         "
        print_string += f"{self.time_elapsed} seconds."
        print(print_string)

    def close_timer(self):
        """
        Does final calculations on the aggregate runtime statistics of
        the wrapped sync function & displays the results.
        """
        self.sum_runtimes()
        self.print_average_runtime()
        self.print_standard_deviation()
        self.print_return_value(self.return_value)
        self.print_source_code()

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
        print(f"Average Elapsed Time: {self.time_average} seconds.")

    def print_standard_deviation(self):
        """
        Calculates & displays the standard deviation of runtimes of the
        wrapped sync function.
        """
        print_string = "Standard Deviation:   "
        print_string += f"{self.standard_deviation()} seconds."
        print(print_string)

    def standard_deviation(self):
        """
        Calculates the standard deviation of runtimes of the wrapped
        sync function.
        """
        return self.average_variance() ** 0.5

    def average_variance(self):
        """
        Calculates the variance of runtimes of the wrapped sync
        function.
        """
        return self.sum_of_variances() / self.times_run

    def sum_of_variances(self):
        """
        Adds the current runtime variance to the aggregated sum.
        """
        self.variance_sum += (
            self.time_elapsed - self.time_average
        ) ** 2
        return self.variance_sum

    def print_return_value(self, return_value):
        """
        Displays the return value of the wrapped sync function.
        """
        print(f"Return Value:  {return_value}")

    def print_source_code(self):
        """
        Prints the source code of the currently running wrapped function.
        """
        print(f"Source Code:\n{inspect.getsource(self.timed_func)}")

    @staticmethod
    def print_trace_call():
        """
        Displays the name of the function which has called the wrapped
        function in user code by inspecting the stack.
        """
        calling_function = inspect.stack()[2][3]
        print(f"Calling Function: {calling_function}\n\n")


class AsyncDebugTools(DebugTools):
    """
    A simple class used for displaying & calculating runtime statistics
    on asynchronous functions.
    """

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
        await self.aprint_times_used()

    async def aprint_times_used(self):
        """
        Displays the number of times the wrapped async function has been
        run.
        """
        print(f"Test #{self.times_run}")

    async def astart_the_timer(self, decorated_func):
        """
        Runs the wrapped async function & displays some runtime stats.
        """
        await self.aprint_time_start()
        await self.aprint_happening_now(decorated_func)
        await self.aprint_arguments()
        await self.atime_the_function()
        await self.aprint_time_elapsed()

    @staticmethod
    async def aprint_time_start():
        """
        Displays the datetime of when the function has been called.
        """
        print(f"Time Start:\t{datetime.datetime.now()}")

    async def aprint_happening_now(self, decorated_func):
        """
        Displays the currently running wrapped async function.
        """
        self.timed_func = decorated_func
        print_string = f"Function:\t{decorated_func.__qualname__}\n"
        print_string += f"{repr(decorated_func)}"
        print(print_string)

    async def aprint_arguments(self):
        """
        Displays the wrapped async function's supplied parameters.
        """
        for arg in self.arg_tuple:
            print(f"Argument:      {repr(arg)}")
        for kwarg in self.kw_dict.items():
            print(f"KW Argument:   {str(kwarg)}")

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
        print_string = f"{self.timed_func.__qualname__}\n"
        print_string += "Time Elapsed:         "
        print_string += f"{self.time_elapsed} seconds."
        print(print_string)

    async def aclose_timer(self):
        """
        Does final calculations on the aggregate runtime statistics of
        the wrapped async function & displays the results.
        """
        await self.asum_runtimes()
        await self.aprint_average_runtime()
        await self.aprint_standard_deviation()
        await self.aprint_return_value(self.return_value)
        await self.aprint_source_code()

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
        print(f"Average Elapsed Time: {self.time_average} seconds.")

    async def aprint_standard_deviation(self):
        """
        Calculates & displays the standard deviation of runtimes of the
        wrapped async function.
        """
        std_deviation = await self.astandard_deviation()
        print_string = "Standard Deviation:   "
        print_string += f"{std_deviation} seconds."
        print(print_string)

    async def astandard_deviation(self):
        """
        Calculates the standard deviation of runtimes of the wrapped
        async function.
        """
        return await self.aaverage_variance() ** 0.5

    async def aaverage_variance(self):
        """
        Calculates the variance of runtimes of the wrapped async
        function.
        """
        return await self.asum_of_variances() / self.times_run

    async def asum_of_variances(self):
        """
        Adds the current runtime variance to the aggregated sum.
        """
        self.variance_sum += (
            self.time_elapsed - self.time_average
        ) ** 2
        return self.variance_sum

    async def aprint_return_value(self, return_value):
        """
        Displays the return value of the wrapped async function.
        """
        print(f"Return Value:  {return_value}")

    async def aprint_source_code(self):
        """
        Prints the source code of the currently running wrapped function.
        """
        print(f"Source Code:\n{inspect.getsource(self.timed_func)}")

    @staticmethod
    async def aprint_trace_call():
        """
        Displays the name of the function which has called the wrapped
        async function in user code by inspecting the stack.
        """
        calling_function = inspect.stack()[2][3]
        print(f"Calling Function: {calling_function}\n\n")


class AsyncGenDebugTools(AsyncDebugTools):
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
                    await self.aprint_trace_call()
                    yield self.return_value
                except StopAsyncIteration:
                    break

        return _agen

    async def aprint_happening_now(self, decorated_func):
        """
        Displays the currently running wrapped async generator.
        """
        print_string = f"Function:\t{decorated_func.__qualname__}\n"
        print_string += f"{repr(decorated_func)}"
        print(print_string)

    async def atime_the_function(self):
        """
        Captures the runtime of an async generator iteration.
        """
        self.time_before = time()
        try:
            self.return_value = await self.generator.asend(self.return_value)
        except TypeError as error:
            if self._async_non_none_error in error.args:
                self.return_value = await self.generator.asend(None)
            else:
                raise error
        self.time_after = time()

    @staticmethod
    async def aprint_trace_call():
        """
        Displays the name of the function which has called the wrapped
        async function in user code by inspecting the stack.
        """
        calling_function = inspect.stack()[7][3], inspect.stack()[2][3]
        print(f"Calling Function: {calling_function}\n\n")


class GenDebugTools(DebugTools):
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
                    self.print_trace_call()
                    yield self.return_value
                except StopIteration:
                    break

        return _gen

    def print_happening_now(self, decorated_func):
        """
        Displays the currently running wrapped generator.
        """
        print_string = f"Function:\t{decorated_func.__qualname__}\n"
        print_string += f"{repr(decorated_func)}"
        print(print_string)

    def time_the_function(self):
        """
        Captures the runtime of a generator iteration.
        """
        self.time_before = time()
        try:
            self.return_value = self.generator.send(self.return_value)
        except TypeError as error:
            if self._sync_non_none_error in error.args:
                self.return_value = self.generator.send(None)
            else:
                raise error
        self.time_after = time()

    @staticmethod
    def print_trace_call():
        """
        Displays the name of the function which has called the wrapped
        async function in user code by inspecting the stack.
        """
        calling_function = inspect.stack()[5][3], inspect.stack()[2][3]
        print(f"Calling Function: {calling_function}\n\n")


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
    from .generics import comprehension

    debugger = AsyncGenDebugTools()

    def wrapped_generator_func(*a, **kw):
        debugger.timed_func = decorated_func
        debugger.generator = decorated_func(*a, **kw)
        return wraps(decorated_func)(
            comprehension()(debugger._agen_wrapper(*a, **kw))
        )()

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
        await debugger.aprint_trace_call()
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
    from .generics import comprehension

    debugger = GenDebugTools()

    def wrapped_generator_func(*a, **kw):
        debugger.timed_func = decorated_func
        debugger.generator = decorated_func(*a, **kw)
        return wraps(decorated_func)(
            debugger._gen_wrapper(*a, **kw)
        )()

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
        debugger.print_trace_call()
        return debugger.return_value

    return decorated_func_timed


async_timers = {
    "agen_timer": agen_timer,
    "afunc_timer": afunc_timer,
}


sync_timers = {
    "gen_timer": gen_timer,
    "func_timer": func_timer,
}


for name, method in  async_timers.items():
    setattr(AsyncDebugTools, name, method)


for name, method in  sync_timers.items():
    setattr(DebugTools, name, method)


__extras = {
    "AsyncDebugGenTools": AsyncGenDebugTools,
    "AsyncDebugTools": AsyncDebugTools,
    "DebugGenTools": GenDebugTools,
    "DebugTools": DebugTools,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    **async_timers,
    **sync_timers,
}


debuggers = Namespace.make_module("debuggers", mapping=__extras)

