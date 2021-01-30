# This file is part of tiny_onion, a small-as-possible solution for p2p
# networking over tor v3 onion services.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#          © 2019-2020 Richard Machado <rmlibre@riseup.net>
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
    # Check timeout / atimeout
    time_limit = 0.01
    time_start = asynchs.time()
    async for item in generics.arange(100_000_000).atimeout(time_limit):
        pass
    time_elapsed = asynchs.time() - time_start
    assert time_elapsed >= time_limit
    assert time_elapsed < time_limit + 0.001

    time_start = asynchs.time()
    for item in generics.range(100_000_000).timeout(time_limit):
        pass
    time_elapsed = asynchs.time() - time_start
    assert time_elapsed >= time_limit
    assert time_elapsed < time_limit + 0.001

    # Check halt / ahalt
    sentinel = csprng()[:2]
    chars = keys(key, salt=salt, pid=pid)
    achars = akeys(key, salt=salt, pid=pid)
    with keys(key, salt=salt, pid=pid)[:128] as sequence:
        sentinel_check = sequence.join()
    async for letters in achars.aresize(2).ahalt(sentinel):
        pass
    assert letters != sentinel
    assert letters + sentinel in sentinel_check

    for letters in chars.resize(2).halt(sentinel):
        pass
    assert letters != sentinel
    assert letters + sentinel in sentinel_check

    # Check feed / afeed
    mock_keys = keys(key, salt=salt, pid=pid)
    mock_food = order([None], range(4))
    async with akeys(key, salt=salt, pid=pid).afeed(range(5)) as altered_keys:
        first_loop = True
        for original_key in keys(key, salt=salt, pid=pid):
            altered_key = await altered_keys()
            if first_loop:
                first_loop = False
                assert original_key == altered_key
            else:
                assert original_key != altered_key
            with generics.ignore(StopIteration):
                assert mock_keys(mock_food()) == altered_key

    mock_keys = keys(key, salt=salt, pid=pid)
    mock_food = order([None], range(4))
    with keys(key, salt=salt, pid=pid).feed(range(5)) as altered_keys:
        first_loop = True
        async for original_key in akeys(key, salt=salt, pid=pid):
            altered_key = altered_keys()
            if first_loop:
                first_loop = False
                assert original_key == altered_key
            else:
                assert original_key != altered_key
            with generics.ignore(StopIteration):
                assert mock_keys(mock_food()) == altered_key

    # Check feed_self / afeed_self
    mock_keys = keys(key, salt=salt, pid=pid)
    async with akeys(key, salt=salt, pid=pid).afeed_self()[:5] as altered_keys:
        first_loop = True
        for original_key in keys(key, salt=salt, pid=pid):
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

    mock_keys = keys(key, salt=salt, pid=pid)
    with keys(key, salt=salt, pid=pid).feed_self()[:5] as altered_keys:
        first_loop = True
        async for original_key in akeys(key, salt=salt, pid=pid):
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
    mock_tags = generics.range(5)
    mock_keys = keys(key, salt=salt, pid=pid)
    async for tag, hex_number in akeys(key, salt=salt, pid=pid).atag().aheappop(5):
        assert tag == mock_tags()
        assert hex_number == mock_keys()

    mock_tags = generics.range(5)
    mock_keys = keys(key, salt=salt, pid=pid)
    async for hex_number, tag in akeys(key, salt=salt, pid=pid).aheappop(of=range(5)):
        assert tag == mock_tags()
        assert hex_number == mock_keys()

    mock_tags = generics.range(5)
    mock_keys = keys(key, salt=salt, pid=pid)
    for tag, hex_number in keys(key, salt=salt, pid=pid).tag().heappop(5):
        assert tag == mock_tags()
        assert hex_number == mock_keys()

    mock_tags = generics.range(5)
    mock_keys = keys(key, salt=salt, pid=pid)
    for hex_number, tag in keys(key, salt=salt, pid=pid).heappop(of=range(5)):
        assert tag == mock_tags()
        assert hex_number == mock_keys()

    # Check reversed / areversed
    reversed_list = list(reversed(range(5, 10)))
    async for tag, item in reversed(generics.arange(5, 10)).atag():
        assert item == reversed_list[tag]

    async for item, tag in generics.arange(5).areversed(of=range(5, 10)):
        assert tag == reversed_list[item]

    for tag, item in reversed(generics.range(5, 10)).tag():
        assert item == reversed_list[tag]

    for item, tag in generics.range(5).reversed(of=range(5, 10)):
        assert tag == reversed_list[item]

    # Check sort / asort
    tags = generics.arange(5)
    labels = akeys(key, salt=salt, pid=pid)
    mock_tags = generics.arange(5)
    mock_labels = akeys(key, salt=salt, pid=pid).aheappop(5)
    async for tag, label in tags.asort(span=5, of=labels):
        assert tag == await mock_tags()
        assert label == await mock_labels()

    tags = generics.range(5)
    labels = keys(key, salt=salt, pid=pid)
    mock_tags = generics.range(5)
    mock_labels = keys(key, salt=salt, pid=pid).heappop(5)
    for tag, label in tags.sort(span=5, of=labels):
        assert tag == mock_tags()
        assert label == mock_labels()

