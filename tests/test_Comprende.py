# This file is part of aiootp:
# an application agnostic — async-compatible — anonymity & cryptography
# library, providing access to high-level Pythonic utilities to simplify
# the tasks of secure data processing, communication & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


TEST_STRING = "abcdefghijk"
TEST_STRING_LENGTH = len(TEST_STRING)
assert TEST_STRING_LENGTH == 11


@comprehension()
async def awith_return_coro(*, got=None):
    for _ in range(TEST_STRING_LENGTH):
        got = yield got
        await asleep(0)
    raise Comprende.ReturnValue(got)


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
    raise Comprende.ReturnValue(char)


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


async def test_comprehension():
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


    for value in is_Comprende_generator():
        assert value == None

    async for value in is_async_Comprende_generator():
        assert value == None


async def test_comprehension_context():
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
    return_value = await asend.aresult()
    assert return_value == None, return_value


    with no_return_coro() as send:
        assert send(None) == None
        for test in TEST_STRING:
            assert send(test) == test
    return_value = send.result()
    assert return_value == None, return_value


async def test_comprehension_iter():
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
    return_value = await catcher.aresult()
    assert return_value == None, return_value


    catcher = no_return_iterator()
    for index, value in catcher.tag():
        assert value == TEST_STRING[index], value
    return_value = catcher.result()
    assert return_value == None, return_value


async def test_chainable_methods():
    """
    Testing the chainable generator methods of the ``Comprende`` class.
    """
    # Check timeout / atimeout
    time_sleep = 0.02
    time_limit = 0.01
    time_start = asynchs.s_time()
    async for item in acount().asleep(time_sleep).atimeout(time_limit):
        pass
    time_elapsed = asynchs.s_time() - time_start
    assert time_elapsed >= time_limit
    assert time_elapsed < time_sleep

    time_start = asynchs.s_time()
    for item in count().sleep(time_sleep).timeout(time_limit):
        pass
    time_elapsed = asynchs.s_time() - time_start
    assert time_elapsed >= time_limit
    assert time_elapsed < time_sleep


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
    assert start_of_data[64:128] == val
    assert sentinel not in val
    assert sentinel not in aval


    # Check feed / afeed
    @comprehension()
    async def adrbg(key: bytes):
        pool = sha3_256(key)
        while True:
            await asleep()
            food = yield pool.digest()
            pool.update(food if type(food) is bytes else repr(food).encode())

    @comprehension()
    def drbg(key: bytes):
        pool = sha3_256(key)
        while True:
            food = yield pool.digest()
            pool.update(food if type(food) is bytes else repr(food).encode())

    mock_keys = drbg(key)
    mock_food = order([None], bytes_range(4))
    async with adrbg(key).afeed(abytes_range(5)) as altered_keys:
        first_loop = True
        for original_key in drbg(key):
            altered_key = await altered_keys()
            if first_loop:
                first_loop = False
                assert original_key == altered_key
            else:
                assert original_key != altered_key
            with _exceptions.ignore(StopIteration):
                assert mock_keys(mock_food()) == altered_key

    mock_keys = drbg(key)
    mock_food = order([None], bytes_range(4))
    with drbg(key).feed(bytes_range(5)) as altered_keys:
        first_loop = True
        async for original_key in adrbg(key):
            altered_key = altered_keys()
            if first_loop:
                first_loop = False
                assert original_key == altered_key
            else:
                assert original_key != altered_key
            with _exceptions.ignore(StopIteration):
                assert mock_keys(mock_food()) == altered_key


    # Check feed_self / afeed_self
    mock_keys = drbg(key)
    async with adrbg(key).afeed_self()[:5] as altered_keys:
        first_loop = True
        for original_key in drbg(key):
            altered_key = await altered_keys()
            if first_loop:
                food = None
                first_loop = False
                assert original_key == altered_key
            else:
                assert original_key != altered_key
            with _exceptions.ignore(StopIteration):
                food = mock_keys(food)
                assert food == altered_key

    mock_keys = drbg(key)
    with drbg(key).feed_self()[:5] as altered_keys:
        first_loop = True
        async for original_key in adrbg(key):
            altered_key = altered_keys()
            if first_loop:
                food = None
                first_loop = False
                assert original_key == altered_key
            else:
                assert original_key != altered_key
            with _exceptions.ignore(StopIteration):
                food = mock_keys(food)
                assert food == altered_key


    # Check heappop / aheappop
    mock_keys = await adrbg(key)[:16].alist()
    keys = await adrbg(key).aheappop(16).alist()
    assert keys != mock_keys
    mock_keys.sort()
    assert keys == mock_keys

    mock_keys = drbg(key)[:16].list()
    keys = drbg(key).heappop(16).list()
    assert keys != mock_keys
    mock_keys.sort()
    assert keys == mock_keys


    # Check reversed / areversed
    reversed_list = list(reversed(range(5, 10)))
    async for tag, item in reversed(gentools.arange(5, 10)).atag():
        assert item == reversed_list[tag]

    for tag, item in reversed(gentools.range(5, 10)).tag():
        assert item == reversed_list[tag]


    # check zfill / azfill
    intakes = [32 * "a", 32 * b"a"]
    outputs = [64 * "0" + 32 * "a", 64 * b"0" + 32 * b"a"]
    results = gentools.aunpack(intakes).azfill(96).atag()
    async for index, result in results:
        assert result == outputs[index]

    results = gentools.unpack(intakes).zfill(96).tag()
    for index, result in results:
        assert result == outputs[index]


    # check to_base64 / ato_base64
    intakes = [b"test vector 0", b"", aad]
    outputs = [
        base64.standard_b64encode(b"test vector 0"),
        base64.standard_b64encode(b""),
        base64.standard_b64encode(aad),
    ]
    results = gentools.aunpack(intakes).ato_base64().atag()
    async for index, result in results:
        assert result == outputs[index]

    results = gentools.unpack(intakes).to_base64().tag()
    for index, result in results:
        assert result == outputs[index]


    # check to_base / ato_base
    intakes = [55, 1312, 9000]
    outputs = [
        generics.int_as_base(55, base=16, table=Tables.HEX),
        generics.int_as_base(1312, base=95, table=Tables.ASCII_95),
        generics.int_as_base(9000, base=256, table=Tables.BYTES),
    ]
    results = gentools.aunpack(intakes)
    assert outputs[0] == await results.ato_base(16, table=Tables.HEX)()
    assert outputs[1] == await results.ato_base(95, table=Tables.ASCII_95)()
    assert outputs[2] == await results.ato_base(256, table=Tables.BYTES)()

    results = gentools.unpack(intakes)
    assert outputs[0] == results.to_base(16, table=Tables.HEX)()
    assert outputs[1] == results.to_base(95, table=Tables.ASCII_95)()
    assert outputs[2] == results.to_base(256, table=Tables.BYTES)()


    # check from_base / afrom_base
    intakes = [
        generics.int_as_base(55, base=16, table=Tables.HEX),
        generics.int_as_base(1312, base=95, table=Tables.ASCII_95),
        generics.int_as_base(9000, base=256, table=Tables.BYTES),
    ]
    outputs = [55, 1312, 9000]
    results = gentools.aunpack(intakes)
    assert outputs[0] == await results.afrom_base(16, table=Tables.HEX)()
    assert outputs[1] == await results.afrom_base(95, table=Tables.ASCII_95)()
    assert outputs[2] == await results.afrom_base(256, table=Tables.BYTES)()

    results = gentools.unpack(intakes)
    assert outputs[0] == results.from_base(16, table=Tables.HEX)()
    assert outputs[1] == results.from_base(95, table=Tables.ASCII_95)()
    assert outputs[2] == results.from_base(256, table=Tables.BYTES)()


    # check split / asplit
    intakes = [
        b"aaaabcccc",
        b"aaaa cccc",
        b"aaaacccc",
        "aaaabcccc",
        "aaaa cccc",
        "aaaacccc",
    ]
    outputs = [
        [b"aaaa", b"cccc"],
        [b"aaaa", b"cccc"],
        [b"aaaacccc"],
        ["aaaa", "cccc"],
        ["aaaa", "cccc"],
        ["aaaacccc"],
    ]
    results = gentools.aunpack(intakes)
    assert outputs[0] == await results.asplit(b"b")()
    assert outputs[1] == await results.asplit(b" ")()
    assert outputs[2] == await results.asplit()()
    assert outputs[3] == await results.asplit("b")()
    assert outputs[4] == await results.asplit(" ")()
    assert outputs[5] == await results.asplit()()

    results = gentools.unpack(intakes)
    assert outputs[0] == results.split(b"b")()
    assert outputs[1] == results.split(b" ")()
    assert outputs[2] == results.split()()
    assert outputs[3] == results.split("b")()
    assert outputs[4] == results.split(" ")()
    assert outputs[5] == results.split()()


    # check slice / aslice
    intakes = [
        b"0123",
        b"0011",
        [b"0", b"1", b"2", b"3"],
        "0123",
        "0011",
        ["0", "1", "2", "3"],
    ]
    outputs = [
        b"02",
        b"00",
        [b"3", b"2", b"1", b"0"],
        "02",
        "00",
        ["3", "2", "1", "0"],
    ]
    results = gentools.aunpack(intakes)
    assert outputs[0] == await results.aslice(0, None, 2)()
    assert outputs[1] == await results.aslice(2)()
    assert outputs[2] == await results.aslice(None, None, -1)()
    assert outputs[3] == await results.aslice(0, None, 2)()
    assert outputs[4] == await results.aslice(2)()
    assert outputs[5] == await results.aslice(None, None, -1)()

    results = gentools.unpack(intakes)
    assert outputs[0] == results.slice(0, None, 2)()
    assert outputs[1] == results.slice(2)()
    assert outputs[2] == results.slice(None, None, -1)()
    assert outputs[3] == results.slice(0, None, 2)()
    assert outputs[4] == results.slice(2)()
    assert outputs[5] == results.slice(None, None, -1)()


    # check _getitem / _agetitem
    intakes = [
        "abcdefghijklmnop",
        b"\x00\x01\x02\x03\x04\x05",
        [*range(32)],
        [*range(32)],
    ]
    outputs = [
        "acegikmo",
        [2],
        [16, 20, 24, 28],
        [22, 23, 24, 25],
    ]
    results = gentools.aunpack(intakes[0])
    assert outputs[0] == await results[::2].ajoin("")

    results = gentools.aunpack(intakes[1])
    assert outputs[1] == await results[2].alist()

    results = gentools.aunpack(intakes[2])
    assert outputs[2] == await results[16:29:4].alist()

    results = gentools.aunpack(intakes[3])
    assert outputs[3] == await results[22:26].alist()

    results = gentools.unpack(intakes[0])
    assert outputs[0] == results[::2].join("")

    results = gentools.unpack(intakes[1])
    assert outputs[1] == results[2].list()

    results = gentools.unpack(intakes[2])
    assert outputs[2] == results[16:29:4].list()

    results = gentools.unpack(intakes[3])
    assert outputs[3] == results[22:26].list()


    # check debugger / adebugger
    gentools.range(1).debugger().exhaust()
    await gentools.arange(1).adebugger().aexhaust()


async def test_endpoint_methods():
    # async list
    # async list endpoint doesn't fail
    g = await gentools.aecho(0).afeed([*range(128)]).aint_to_bytes(size=1).adecode().astr().aprime()
    result = await g.alist()

    # async list endpoint produces a list
    assert type(result) is list

    # async list endpoint results return correct data
    assert all(Tables.ASCII_128[i] == char for i, char in enumerate(result))

    # async list endpoint is equivalent to unpacking async generator
    # into a list
    assert result == [char async for char in await g.aprime()]

    # sync list
    # list endpoint doesn't fail
    g = gentools.echo(0).feed([*range(128)]).int_to_bytes(size=1).decode().str().prime()
    result = g.list()

    # list endpoint produces a list
    assert type(result) is list

    # list endpoint results return correct data
    assert all(Tables.ASCII_128[i] == char for i, char in enumerate(result))

    # list endpoint is equivalent to unpacking async generator into a
    # list
    assert result == list(g.prime())


    # async set
    # async set endpoint doesn't fail
    g = gentools.acycle(gentools.arange(16))[:32]
    result = await g.aset()

    # async set endpoint produces a set
    assert type(result) is set
    assert len(result) == 16
    assert 32 == len(await gentools.acycle(range(16))[:32].alist())

    # async set endpoint results return correct data
    assert all(i == item for i, item in enumerate(result))

    # async set endpoint is equivalent to unpacking async generator
    # into a set
    assert result == {char async for char in await g.areset()}

    # sync set
    # set endpoint doesn't fail
    g = gentools.cycle(gentools.range(16))[:32]
    result = g.set()

    # set endpoint produces a set
    assert type(result) is set
    assert len(result) == 16
    assert 32 == len(gentools.cycle(range(16))[:32].list())

    # set endpoint results return correct data
    assert all(i == item for i, item in enumerate(result))

    # set endpoint is equivalent to unpacking async generator into a
    # set
    assert result == set(g.reset())


    # async deque
    # async deque endpoint doesn't fail
    g = gentools.azip(atest_data.keys(), atest_data.values())
    result = await g.adeque()

    # async deque endpoint produces a deque
    assert type(result) is deque

    # async deque endpoint results return correct data
    assert all(atest_data[k] == v for k, v in result)

    # async deque endpoint is equivalent to unpacking async generator
    # into a deque
    assert result == deque([item async for item in await g.areset()])

    # sync deque
    # deque endpoint doesn't fail
    g = gentools.zip(test_data.keys(), test_data.values())
    result = g.deque()

    # deque endpoint produces a deque
    assert type(result) is deque

    # deque endpoint results return correct data
    assert all(test_data[k] == v for k, v in result)

    # deque endpoint is equivalent to unpacking async generator into a
    # deque
    assert result == deque(g.reset())


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

