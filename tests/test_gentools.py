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

from test_initialization import *

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

    async def test_bytes_count(self) -> None:
        for start in (0, 33, 256, 1024):
            for size in (4, 8):
                for order in ("little", "big"):
                    count = start
                    async for index, aindex in gentools.azip(
                        gentools.bytes_count(start=start, size=size, byte_order=order),
                        gentools.abytes_count(start=start, size=size, byte_order=order),
                    ):
                        assert index == aindex
                        assert index == count.to_bytes(size, order)

                        count += 1
                        if count > start + 4:
                            break

    async def test_counts(self) -> None:
        for start in (0, 33, 256, 1024):
            count = start
            async for index, aindex in gentools.azip(
                gentools.count(start=start),
                gentools.acount(start=start),
            ):
                assert index == aindex
                assert index == count

                count += 1
                if count > start + 4:
                    break

    async def test_start_must_be_int_for_counts(self) -> None:
        problem = "A non-int `start` value was allowed."
        for start in (0.0, None, "test", b"test"):
            with Ignore(TypeError, if_else=violation(problem)):
                async for aindex in gentools.acount(start=start):
                    pass
            with Ignore(TypeError, if_else=violation(problem)):
                for index in gentools.count(start=start):
                    pass

    async def test_bytes_ranges(self) -> None:
        for start in (0, 33, 256):
            end = start + 4
            for size in (4, 8):
                for order in ("little", "big"):
                    for skip in (1, 2):
                        count = start
                        async for index, aindex in gentools.azip(
                            gentools.bytes_range(start, end, skip, size=size, byte_order=order),
                            gentools.abytes_range(start, end, skip, size=size, byte_order=order),
                        ):
                            assert index == aindex
                            assert index == count.to_bytes(size, order)
                            assert start <= count < end
                            count += skip

    async def test_ranges(self) -> None:
        for start in (0, 33, 256):
            end = start + 4
            for skip in (1, 2):
                count = start
                async for index, aindex in gentools.azip(
                    range(start, end, skip),
                    gentools.arange(start, end, skip),
                ):
                    assert index == aindex
                    assert index == count
                    assert start <= count < end
                    count += skip

    async def test_batches(self) -> None:
        for blocks in (1, 2, 3):
            for size in (4, 8, 13):
                for unit, cls in ((b"a", io.BytesIO), ("a", io.StringIO)):
                    result = unit.__class__()
                    data = blocks * size * unit
                    async for block, ablock in gentools.azip(
                        gentools.batch(data, size=size, buffer_type=cls),
                        gentools.abatch(data, size=size, buffer_type=cls),
                    ):
                        assert block == ablock
                        assert len(block) == size
                        result += block
                    assert result == data

    async def test_resizes(self) -> None:
        for blocks in (1, 2, 3):
            for size in (4, 6, 8):
                for unit, cls in (([None], list), ((None,), tuple), ("a", str)):
                    result = cls()
                    data = 3 * size * unit
                    async for block, ablock in gentools.azip(
                        gentools.resize(data, size=size, blocks=blocks),
                        gentools.aresize(data, size=size, blocks=blocks),
                    ):
                        assert block == ablock
                        assert len(block) == size
                        result = result + block
                    assert result == data[: blocks * size]

    async def test_poplefts(self) -> None:
        size = 32
        count = 0
        container = deque(range(size))
        acontainer = deque(range(size))
        for ordering in (
            (gentools.popleft(container), gentools.apopleft(acontainer)),
            (gentools.apopleft(acontainer), gentools.popleft(container)),
        ):
            async for item, aitem in gentools.azip(*ordering):
                assert item == aitem
                assert item == count
                count += 1
                assert len(container) == len(acontainer)
                assert len(container) == size - count

    async def test_unpacks(self) -> None:
        count = 0
        size = 32
        iterable = tuple(range(size))
        aiterable = gentools.arange(size)
        async for index, aindex, aaindex in gentools.azip(
            gentools.unpack(iterable),
            gentools.aunpack(iterable),
            gentools.aunpack(aiterable),
        ):
            assert index == aindex
            assert index == aaindex
            assert index == count
            count += 1

    async def test_cycles(self) -> None:
        count = 0
        size = 16
        iteration = 0
        iterable = tuple(range(size))
        aiterable = gentools.arange(size)
        async for index, aindex, aaindex in gentools.azip(
            gentools.cycle(iterable),
            gentools.acycle(iterable),
            gentools.acycle(aiterable),
        ):
            assert index == aindex
            assert index == aaindex
            assert index == count
            count = (count + 1) % size
            if count == 0:
                iteration += 1
            if iteration > 2:
                break

    async def test_collates(self) -> None:
        count = 0
        arange = gentools.arange
        iterable = ((0, 1, 2), (3, 4, 5), (6, 7, 8))
        aiterable = (arange(0, 3), (3, 4, 5), arange(6, 9))
        async for index, aindex in gentools.azip(
            gentools.collate(*iterable),
            gentools.acollate(*aiterable),
        ):
            assert index == aindex
            assert index == count
            count += 1


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

