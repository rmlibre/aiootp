import sys
import pytest
from pathlib import Path

PACKAGE_PATH = str(Path(__file__).absolute().parent.parent)
sys.path.append(PACKAGE_PATH)

from aiootp import *


TEST_STRING = "abcdefghijk"
TEST_STRING_LENGTH = len(TEST_STRING)
assert TEST_STRING_LENGTH == 11


@comprehension()
async def awith_return_coro(*, got=None):
    for _ in range(TEST_STRING_LENGTH):
        got = yield got
        await switch()
    raise UserWarning(got)


@comprehension()
def with_return_coro(*, got=None):
    for _ in range(TEST_STRING_LENGTH):
        got = yield got
    return got


@comprehension()
async def ano_return_coro(*, got=None):
    for _ in range(TEST_STRING_LENGTH):
        await switch()
        got = yield got


@comprehension()
def no_return_coro(*, got=None):
    for _ in range(TEST_STRING_LENGTH):
        got = yield got


@comprehension()
async def awith_return_iterator():
    for char in TEST_STRING:
        await switch()
        yield char
    raise UserWarning(char)


@comprehension()
def with_return_iterator():
    for char in TEST_STRING:
        yield char
    return char


@comprehension()
async def ano_return_iterator():
    for char in TEST_STRING:
        await switch()
        yield char


@comprehension()
def no_return_iterator(got=TEST_STRING):
    for char in TEST_STRING:
        yield char


def test_comprehension():
    @comprehension()
    def is_Comprende_generator():
        yield

    assert is_Comprende_generator().__class__ == Comprende

    @comprehension()
    async def is_async_Comprende_generator():
        yield

    assert is_async_Comprende_generator().__class__ == Comprende

    async def run_test_generators():
        for value in is_Comprende_generator():
            assert value == None

        async for value in is_async_Comprende_generator():
            assert value == None

    run(run_test_generators())


def test_comprehension_context():
    run(comprehension_context_testing())


async def comprehension_context_testing():
    async with awith_return_coro() as asend:
        assert await asend(None) == None
        for test in TEST_STRING:
            assert await asend(test) == test
    assert await asend.aresult() == "k", await asend.aresult()

    with with_return_coro() as send:
        assert send(None) == None
        for test in TEST_STRING:
            assert send(test) == test
    assert send.result() == "k", send.result()

    async with ano_return_coro() as asend:
        assert await asend(None) == None
        for test in TEST_STRING:
            assert await asend(test) == test
    try:
        failed = False
        return_value = await asend.aresult()
        assert return_value != None
    except AssertionError:
        failed = True
    finally:
        assert failed, return_value

    with no_return_coro() as send:
        assert send(None) == None
        for test in TEST_STRING:
            assert send(test) == test
    try:
        failed = False
        return_value = send.result()
        assert return_value != None
    except AssertionError:
        failed = True
    finally:
        assert failed, return_value


def test_comprehension_iter():
    run(comprehension_iteration_testing())


async def comprehension_iteration_testing():
    catcher = awith_return_iterator()
    async for index, value in catcher.atag():
        assert value == TEST_STRING[index], value
    return_value = await catcher.aresult()
    assert return_value == "k", return_value

    catcher = with_return_iterator()
    for index, value in catcher.tag():
        assert value == TEST_STRING[index], value
    return_value = catcher.result()
    assert return_value == "k", return_value

    catcher = ano_return_iterator()
    async for index, value in catcher.atag():
        assert value == TEST_STRING[index], value
    try:
        failed = False
        return_value = await catcher.aresult()
        assert return_value != None
    except AssertionError:
        failed = True
    finally:
        assert failed, return_value

    catcher = no_return_iterator()
    for index, value in catcher.tag():
        assert value == TEST_STRING[index], value
    try:
        failed = False
        return_value = catcher.result()
        assert return_value != None
    except AssertionError:
        failed = True
    finally:
        assert failed, return_value

