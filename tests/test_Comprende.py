# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from init_tests import *


__all__ = [
    "test_comprehension_context",
    "test_comprehension_iter",
    "test_chainable_methods",
    "test_comprehension",
    "__all__",
]


TEST_STRING = "abcdefghijk"
TEST_STRING_LENGTH = len(TEST_STRING)
assert TEST_STRING_LENGTH == 11


@comprehension()
async def awith_return_coro(*, got=None):
    for _ in range(TEST_STRING_LENGTH):
        got = yield got
        await asleep(0)
    raise UserWarning(got)


@comprehension()
def with_return_coro(*, got=None):
    for _ in range(TEST_STRING_LENGTH):
        got = yield got
    return got


@comprehension()
async def ano_return_coro(*, got=None):
    for _ in range(TEST_STRING_LENGTH):
        await asleep(0)
        got = yield got


@comprehension()
def no_return_coro(*, got=None):
    for _ in range(TEST_STRING_LENGTH):
        got = yield got


@comprehension()
async def awith_return_iterator():
    for char in TEST_STRING:
        await asleep(0)
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
        await asleep(0)
        yield char


@comprehension()
def no_return_iterator(got=TEST_STRING):
    for char in TEST_STRING:
        yield char


def test_comprehension():
    """
    Tests the ``comprehension`` decorator which wraps generator
    functions so they return ``Comprende`` objects when the function
    is called to create an async/sync generator.
    """
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
    """
    Testing the accuracy of async/sync ``Comprende``  generator results
    and the class' ability to return values from completed generators.
    """
    run(comprehension_context_testing())


async def comprehension_context_testing():
    """
    Testing the accuracy of async/sync ``Comprende``  generator results
    and the class' ability to return values from completed generators.
    """
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
    """
    Testing the accuracy of async/sync ``Comprende``  generator results
    and the class' ability to return values from completed generators.
    """
    run(comprehension_iteration_testing())


async def comprehension_iteration_testing():
    """
    Testing the accuracy of async/sync ``Comprende``  generator results
    and the class' ability to return values from completed generators.
    """
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


def test_chainable_methods():
    """
    Testing the chainable generator methods of the ``Comprende`` class.
    """
    run(Comprende_chainable_methods())


async def Comprende_chainable_methods():
    """
    Testing the chainable generator methods of the ``Comprende`` class.
    """
    key_bundle = KeyAADBundle.unsafe(key, salt=salt, aad=aad)

    # Check timeout / atimeout
    time_limit = 0.01
    time_start = asynchs.time()
    async for item in acount().arandom_sleep(0.02).atimeout(time_limit):
        time_start = asynchs.time()
    time_elapsed = asynchs.time() - time_start
    assert time_elapsed >= time_limit
    assert time_elapsed < time_limit + 0.02

    time_start = asynchs.time()
    for item in count().random_sleep(0.02).timeout(time_limit):
        time_start = asynchs.time()
    time_elapsed = asynchs.time() - time_start
    assert time_elapsed >= time_limit
    assert time_elapsed < time_limit + 0.02

    # Check halt / ahalt
    sentinel = csprng()
    start_of_data = csprng() + csprng()
    chars = data(start_of_data + sentinel + csprng())
    achars = adata(start_of_data + sentinel + csprng())
    result = b""
    aresult = b""
    for index, val in chars.resize(64).halt(sentinel).tag():
        result += val
    async for aindex, aval in achars.aresize(64).ahalt(sentinel).atag():
        aresult += aval
    assert result == aresult
    assert index == aindex
    assert val == aval
    assert sentinel not in val
    assert sentinel not in aval

    # Check feed / afeed
    akb = await KeyAADBundle.unsafe(key, salt).async_mode()
    kb = KeyAADBundle.unsafe(key, salt).sync_mode()
    mock_kb = KeyAADBundle.unsafe(key, salt).sync_mode()
    mock_keys = bytes_keys(mock_kb)
    mock_food = order([None], bytes_range(4))
    async with abytes_keys(akb).afeed(abytes_range(5)) as altered_keys:
        first_loop = True
        for original_key in bytes_keys(kb):
            altered_key = await altered_keys()
            if first_loop:
                first_loop = False
                assert original_key == altered_key
            else:
                assert original_key != altered_key
            with generics.ignore(StopIteration):
                assert mock_keys(mock_food()) == altered_key

    akb = await KeyAADBundle.unsafe(key, salt).async_mode()
    kb = KeyAADBundle.unsafe(key, salt).sync_mode()
    mock_kb = KeyAADBundle.unsafe(key, salt).sync_mode()
    mock_keys = bytes_keys(mock_kb)
    mock_food = order([None], bytes_range(4))
    with bytes_keys(kb).feed(bytes_range(5)) as altered_keys:
        first_loop = True
        async for original_key in abytes_keys(akb):
            altered_key = altered_keys()
            if first_loop:
                first_loop = False
                assert original_key == altered_key
            else:
                assert original_key != altered_key
            with generics.ignore(StopIteration):
                assert mock_keys(mock_food()) == altered_key

    # Check feed_self / afeed_self
    akb = await KeyAADBundle.unsafe(key, salt).async_mode()
    kb = KeyAADBundle.unsafe(key, salt).sync_mode()
    mock_kb = KeyAADBundle.unsafe(key, salt).sync_mode()
    mock_keys = bytes_keys(mock_kb)
    async with abytes_keys(akb).afeed_self()[:5] as altered_keys:
        first_loop = True
        for original_key in bytes_keys(kb):
            altered_key = await altered_keys()
            if first_loop:
                food = None
                first_loop = False
                assert original_key == altered_key
            else:
                assert original_key != altered_key
            with generics.ignore(StopIteration):
                food = mock_keys(food)
                assert food == altered_key

    akb = await KeyAADBundle.unsafe(key, salt).async_mode()
    kb = KeyAADBundle.unsafe(key, salt).sync_mode()
    mock_kb = KeyAADBundle.unsafe(key, salt).sync_mode()
    mock_keys = bytes_keys(mock_kb)
    with bytes_keys(kb).feed_self()[:5] as altered_keys:
        first_loop = True
        async for original_key in abytes_keys(akb):
            altered_key = altered_keys()
            if first_loop:
                food = None
                first_loop = False
                assert original_key == altered_key
            else:
                assert original_key != altered_key
            with generics.ignore(StopIteration):
                food = mock_keys(food)
                assert food == altered_key

    # Check heappop / aheappop
    akb = await KeyAADBundle.unsafe(key, salt).async_mode()
    amock_kb = await KeyAADBundle.unsafe(key, salt).async_mode()
    mock_keys = await abytes_keys(amock_kb)[:16].alist()
    keys = await abytes_keys(akb).aheappop(16).alist()
    assert keys != mock_keys
    mock_keys.sort()
    assert keys == mock_keys

    kb = KeyAADBundle.unsafe(key, salt).sync_mode()
    mock_kb = KeyAADBundle.unsafe(key, salt).sync_mode()
    mock_keys = bytes_keys(mock_kb)[:16].list()
    keys = bytes_keys(kb).heappop(16).list()
    assert keys != mock_keys
    mock_keys.sort()
    assert keys == mock_keys

    # Check reversed / areversed
    reversed_list = list(reversed(range(5, 10)))
    async for tag, item in reversed(gentools.arange(5, 10)).atag():
        assert item == reversed_list[tag]

    for tag, item in reversed(gentools.range(5, 10)).tag():
        assert item == reversed_list[tag]

