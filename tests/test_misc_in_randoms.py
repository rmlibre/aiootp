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


from hashlib import shake_128

from test_initialization import *

from aiootp.asynchs.clocks import s_counter
from aiootp.randoms.simple import arandom_sleep, random_sleep
from aiootp.randoms.threading_safe_entropy_pool import ThreadingSafeEntropyPool
from aiootp.randoms.rng import arandom_number_generator, random_number_generator


class TestRandomSleeps:
    span = 0.001
    variance = 0.002

    async def test_async_random_sleep(self) -> None:
        for _ in range(32):
            ts = s_counter()
            await arandom_sleep(self.span)
            te = s_counter()
            assert (self.span + self.variance) >= (te - ts) >= 0

    async def test_sync_random_sleep(self) -> None:
        for _ in range(32):
            ts = s_counter()
            random_sleep(self.span)
            te = s_counter()
            assert (self.span + self.variance) >= (te - ts) >= 0


class TestThreadingSafeEntropyPool:
    cls = ThreadingSafeEntropyPool

    async def test_hasher_methods(self) -> None:
        token = token_bytes(32)
        obj = self.cls(token, obj=shake_128, pool=[token])
        hasher = obj._obj.copy()
        obj_copy = obj.copy()
        assert obj.name == hasher.name
        assert obj.name == obj_copy.name
        assert obj.block_size == hasher.block_size
        assert obj.block_size == obj_copy.block_size
        assert obj.digest_size == hasher.digest_size
        assert obj.digest_size == obj_copy.digest_size
        assert obj.digest(32) == hasher.digest(32)
        assert obj.digest(32) == obj_copy.digest(32)
        assert obj.hexdigest(32) == hasher.hexdigest(32)
        assert obj.hexdigest(32) == obj_copy.hexdigest(32)

        obj.update(token)
        obj_copy.update(token)
        hasher.update(token)
        assert obj.digest(32) == hasher.digest(32)
        assert obj.digest(32) == obj_copy.digest(32)
        assert obj.hexdigest(32) == hasher.hexdigest(32)
        assert obj.hexdigest(32) == obj_copy.hexdigest(32)


class TestCSPRNG:
    kw = dict(entropy=token_bytes(16))

    async def test_declared_output_sizes_are_respected(self) -> None:
        for size in range(8, 257, 32):
            result = await acsprng(size, **self.kw)
            assert size == len(result)

            result = csprng(size, **self.kw)
            assert size == len(result)

    async def test_userland_entropy_can_be_any_type(self) -> None:
        for datum in (token_bytes(32).hex(), token_bits(32), [None, "test"]):
            await acsprng(entropy=datum)
            csprng(entropy=datum)

    async def test_async_thread_safe_entropy(self) -> None:

        async def try_to_make_duplicate_readouts() -> None:
            for i in range(runs):
                entropy_pool.add(await acsprng())

        runs = 32
        entropy_pool = set()
        await Threads.agather(*[try_to_make_duplicate_readouts for _ in range(runs)])
        assert runs**2 == len(entropy_pool)

    async def test_sync_thread_safe_entropy(self) -> None:

        def try_to_make_duplicate_readouts() -> None:
            for i in range(runs):
                entropy_pool.add(csprng())

        runs = 32
        entropy_pool = set()
        Threads.gather(*[try_to_make_duplicate_readouts for _ in range(runs)])
        assert runs**2 == len(entropy_pool)


class TestRandomNumberGenerator:
    kw = dict(freshness=0, entropy=token_bytes(16))

    async def test_async_declared_output_sizes_are_respected(self) -> None:
        for size in range(8, 257, 32):
            result = await arandom_number_generator(size, **self.kw)
            assert size == len(result)

    def test_sync_declared_output_sizes_are_respected(self) -> None:
        for size in range(8, 257, 32):
            result = random_number_generator(size, **self.kw)
            assert size == len(result)

    async def test_async_userland_entropy_can_be_any_type(self) -> None:
        for datum in (token_bytes(32).hex(), token_bits(32), [None, "test"]):
            await arandom_number_generator(**self.kw)

    def test_sync_userland_entropy_can_be_any_type(self) -> None:
        for datum in (token_bytes(32).hex(), token_bits(32), [None, "test"]):
            random_number_generator(**self.kw)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

