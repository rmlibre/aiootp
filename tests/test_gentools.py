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


import io
from collections import deque

from conftest import *

from aiootp import _gentools as gentools


class TestInspectTools:
    async def test_is_async_iterable(self) -> None:
        async_iterable = gentools.aunpack("test")
        iterable = gentools.unpack("test")

        assert gentools.is_async_iterable(async_iterable)
        assert not gentools.is_async_iterable(iterable)

    async def test_is_async_iterator(self) -> None:
        async_iterator = gentools.aunpack("test").__aiter__()
        iterator = gentools.unpack("test").__iter__()

        assert gentools.is_async_iterator(async_iterator)
        assert not gentools.is_async_iterator(iterator)

    async def test_is_async_generator(self) -> None:
        async_generator = gentools.aunpack("test")
        generator = gentools.unpack("test")

        assert gentools.is_async_generator(async_generator)
        assert not gentools.is_async_generator(generator)

    async def test_is_async_gen_function(self) -> None:
        async_generator_function = gentools.aunpack
        generator_function = gentools.unpack

        assert gentools.is_async_gen_function(async_generator_function)
        assert not gentools.is_async_gen_function(generator_function)

    async def test_is_generator(self) -> None:
        async_generator = gentools.aunpack("test")
        generator = gentools.unpack("test")

        assert not gentools.is_generator(async_generator)
        assert gentools.is_generator(generator)

    async def test_is_generator_function(self) -> None:
        async_generator_function = gentools.aunpack
        generator_function = gentools.unpack

        assert not gentools.is_generator_function(async_generator_function)
        assert gentools.is_generator_function(generator_function)

    async def test_is_iterable(self) -> None:
        async_iterable = gentools.aunpack("test")
        iterable = gentools.unpack("test")

        assert not gentools.is_iterable(async_iterable)
        assert gentools.is_iterable(iterable)

    async def test_is_iterator(self) -> None:
        async_iterator = gentools.aunpack("test").__aiter__()
        iterator = gentools.unpack("test").__iter__()

        assert not gentools.is_iterator(async_iterator)
        assert gentools.is_iterator(iterator)


class TestGenerators:
    @pytest.mark.parametrize("first,second", [(0, 1), (1, 0)])
    @pytest.mark.parametrize("order", ["little", "big"])
    @given(start=st.integers(min_value=0))
    async def test_bytes_count(
        self, start: int, order: str, first: int, second: int
    ) -> None:
        count = start
        size = (start.bit_length() // 8) + 2
        funcs = [gentools.abytes_count, gentools.bytes_count]
        async for index_0, index_1 in gentools.azip(
            funcs[first](start=start, size=size, byte_order=order),
            funcs[second](start=start, size=size, byte_order=order),
        ):
            assert index_0 == index_1
            assert index_0 == count.to_bytes(size, order)
            count += 1
            if count > start + 4:
                break

    @pytest.mark.parametrize("first,second", [(0, 1), (1, 0)])
    @given(start=st.integers())
    async def test_counts(
        self, start: int, first: int, second: int
    ) -> None:
        count = start
        funcs = [gentools.acount, gentools.count]
        async for index_0, index_1 in gentools.azip(
            funcs[first](start=start), funcs[second](start=start)
        ):
            assert index_0 == index_1
            assert index_0 == count
            count += 1
            if count > start + 4:
                break

    async def test_start_must_be_int_for_counts(self) -> None:
        problem = (  # fmt: skip
            "A non-int `start` value was allowed."
        )
        for start in (0.0, None, "test", b"test"):
            with Ignore(TypeError, if_else=violation(problem)):
                async for _ in gentools.acount(start=start):
                    pass
            with Ignore(TypeError, if_else=violation(problem)):
                for _ in gentools.count(start=start):
                    pass

    @pytest.mark.parametrize("first,second", [(0, 1), (1, 0)])
    @pytest.mark.parametrize("order", ["little", "big"])
    @pytest.mark.parametrize("size", [4, 8])
    @pytest.mark.parametrize("skip", [1, 2])
    @pytest.mark.parametrize("start", [0, 33, 256])
    async def test_bytes_ranges(
        self,
        start: int,
        skip: int,
        size: int,
        order: str,
        first: int,
        second: int,
    ) -> None:
        count = start
        end = start + 4
        funcs = [gentools.abytes_range, gentools.bytes_range]
        async for index_0, index_1 in gentools.azip(
            funcs[first](start, end, skip, size=size, byte_order=order),
            funcs[second](start, end, skip, size=size, byte_order=order),
        ):
            assert index_0 == index_1
            assert index_0 == count.to_bytes(size, order)
            assert start <= count < end
            count += skip
        assert (count - start) // skip == len([*range(start, end, skip)])

    @pytest.mark.parametrize("skip", [1, 2])
    @pytest.mark.parametrize("start", [0, 33, 256])
    async def test_ranges(self, start: int, skip: int) -> None:
        count = start
        end = start + 4
        async for index_0, index_1 in gentools.azip(
            gentools.arange(start, end, skip),
            range(start, end, skip),
        ):
            assert index_0 == index_1
            assert index_0 == count
            assert start <= count < end
            count += skip
        assert (count - start) // skip == len([*range(start, end, skip)])

    @pytest.mark.parametrize("first,second", [(0, 1), (1, 0)])
    @pytest.mark.parametrize("size", [4, 8, 13])
    @pytest.mark.parametrize("blocks", [1, 2, 3])
    async def test_batches(
        self, blocks: int, size: int, first: int, second: int
    ) -> None:
        for unit, cls in ((b"a", io.BytesIO), ("a", io.StringIO)):
            result = unit.__class__()
            data = blocks * size * unit
            funcs = [gentools.abatch, gentools.batch]
            async for block_0, block_1 in gentools.azip(
                funcs[first](data, size=size, buffer_type=cls),
                funcs[second](data, size=size, buffer_type=cls),
            ):
                assert block_0 == block_1
                assert len(block_0) == size
                result += block_0
            assert result == data

    @pytest.mark.parametrize("first,second", [(0, 1), (1, 0)])
    @pytest.mark.parametrize("unit", [[None], (None,), "a"])
    @pytest.mark.parametrize("size", [-1, 0, 1, 2, 3, 16])
    @pytest.mark.parametrize("blocks", [-1, 0, None, 1, 2, 3])
    async def test_resizes(
        self,
        blocks: t.Optional[int],
        size: int,
        unit: t.Any,
        first: int,
        second: int,
    ) -> None:
        data = 16 * unit
        result = unit.__class__()
        funcs = [gentools.aresize, gentools.resize]
        is_not_positive = lambda _: (
            (size < 1) or (isinstance(blocks, int) and blocks < 1)
        )
        with Ignore(ValueError, if_except=is_not_positive):
            item_count = 0
            async for block_0, block_1 in gentools.azip(
                funcs[first](data, size=size, blocks=blocks),
                funcs[second](data, size=size, blocks=blocks),
            ):
                item_count += (block_size := len(block_0))
                assert block_0 == block_1
                if block_size < size:
                    assert data == result + block_0
                else:
                    assert size == block_size
                result = result + block_0
                assert result == data[:item_count]
            portion = None if blocks is None else size * blocks
            assert result == data[:portion]

    @pytest.mark.parametrize("first,second", [(0, 1), (1, 0)])
    async def test_poplefts(self, first: int, second: int) -> None:
        size = 32
        count = 0
        funcs = [gentools.apopleft, gentools.popleft]
        inputs = [adeq := deque(range(size)), deq := deque(range(size))]
        async for item_0, item_1 in gentools.azip(
            funcs[first](inputs[first]), funcs[second](inputs[second])
        ):
            assert item_0 == item_1
            assert item_0 == count
            count += 1
            assert len(adeq) == len(deq)
            assert len(adeq) == size - count
        assert not adeq

    @pytest.mark.parametrize(
        "first,second,third", [(0, 1, 2), (1, 2, 0), (2, 1, 0)]
    )
    async def test_unpacks(
        self, first: int, second: int, third: int
    ) -> None:
        count = 0
        size = 32
        iterable = tuple(range(size))
        funcs = [gentools.aunpack, gentools.aunpack, gentools.unpack]
        inputs = [gentools.arange(size), iterable, iterable]
        async for index_0, index_1, index_2 in gentools.azip(
            funcs[first](inputs[first]),
            funcs[second](inputs[second]),
            funcs[third](inputs[third]),
        ):
            assert index_0 == index_1
            assert index_0 == index_2
            assert index_0 == count
            count += 1
        assert count == size

    @given(size=st.integers(min_value=0, max_value=16))
    @pytest.mark.parametrize(
        "first,second,third", [(0, 1, 2), (1, 2, 0), (2, 1, 0)]
    )
    async def test_cycles(
        self, first: int, second: int, third: int, size: int
    ) -> None:
        count = 0
        iteration = 0
        iterable = tuple(range(size))
        funcs = [gentools.acycle, gentools.acycle, gentools.cycle]
        inputs = [gentools.arange(size), iterable, iterable]
        async for index_0, index_1, index_2 in gentools.azip(
            funcs[first](inputs[first]),
            funcs[second](inputs[second]),
            funcs[third](inputs[third]),
        ):
            if size == 0:
                pytest.fail("Empty iterables produced outputs.")
            assert index_0 == index_1
            assert index_0 == index_2
            assert index_0 == count
            count = (count + 1) % size
            if count == 0:
                iteration += 1
            if iteration > 2:
                break

    @pytest.mark.parametrize("first,second", [(0, 1), (1, 0)])
    async def test_collates(self, first: int, second: int) -> None:
        arange = gentools.arange
        funcs = [gentools.acollate, gentools.collate]
        inputs = [
            (arange(0, 3), (3, 4, 5), arange(6, 9)),
            ((0, 1, 2), (3, 4, 5), (6, 7, 8)),
        ]
        count = 0
        async for index_0, index_1 in gentools.azip(
            funcs[first](*inputs[first]),
            funcs[second](*inputs[second]),
        ):
            assert index_0 == index_1
            assert index_0 == count
            count += 1
        assert count == len(inputs[1][0] + inputs[1][1] + inputs[1][2])


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
