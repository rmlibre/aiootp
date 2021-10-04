#
# This file is copied with minor edits from the asyncio_contextmanager
# package whose license can be found in the /licenses directory of this
# package. The edits prevent warnings from arising in the aiootp package
# when values are retrieved from async generators since they do not stop
# as the class here expects them to. For convenience the license for the
# asyncio_contextmanager package will be copied below:
#
# MIT License
#
# Copyright (c) 2017 Alexander Gorokhov
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#


import functools
import inspect
import sys


__all__ = ['async_contextmanager']


class _AsyncContextManager(object):

    __slots__ = ("async_generator",)

    def __init__(self, func, args, kwargs):
        if not inspect.isasyncgenfunction(func):
            raise TypeError('%s is not async generator function' % func)
        self.async_generator = func(*args, **kwargs)

    async def __aenter__(self):
        try:
            return await self.async_generator.__anext__()
        except StopAsyncIteration as e:
            raise RuntimeError("async generator didn't yield") from None

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type == None:
            try:
                await self.async_generator.__anext__()
            except StopAsyncIteration:
                return
            else:
                raise RuntimeError("async generator didn't stop")
        else:
            if exc_val == None:
                exc_val = exc_type()
            try:
                await self.async_generator.athrow(exc_type, exc_val, exc_tb)
                return True
            except StopAsyncIteration as exc:
                return exc is not exc_val
            except RuntimeError as exc:
                if exc is exc_val:
                    return False
                if exc.__cause__ is exc_val:
                    return False
                raise
            except:
                if sys.exc_info()[1] is not exc_val:
                    raise


def async_contextmanager(func):
    """
    @async_contextmanager decorator.

    Typical usage:

        @async_contextmanager
        async def some_async_generator(<arguments>):
            <setup>
            try:
                yield <value>
            finally:
                <cleanup>

    This makes this:

        async with some_async_generator(<arguments>) as <variable>:
            <body>

    equivalent to this:

        <setup>
        try:
            <variable> = <value>
            <body>
        finally:
            <cleanup>
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return _AsyncContextManager(func, args, kwargs)

    return wrapper

