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


import warnings
from hashlib import shake_128
from collections import deque

from test_initialization import *

from aiootp.asynchs.clocks import s_counter
from aiootp.randoms.entropy_daemon import EntropyDaemon
from aiootp.randoms.simple import arandom_sleep, random_sleep
from aiootp.randoms.threading_safe_entropy_pool import ThreadingSafeEntropyPool
from aiootp.randoms.rng import arandom_number_generator, random_number_generator


class TestRandomSleeps:
    runs = 32
    span = 0.001
    max_overhead = 0.02
    max_ideal_overhead = 0.001

    async def test_async_random_sleep(self) -> None:
        MAX = (0.6 * self.span) + self.max_overhead
        total = 0
        for _ in range(self.runs):
            start = s_counter()
            await arandom_sleep(self.span)
            end = s_counter()
            total += end - start

        average_arandom_sleep = total / self.runs
        assert MAX >= average_arandom_sleep >= 0
        if average_arandom_sleep >= (0.6 * self.span + self.max_ideal_overhead):
            warnings.warn(f"NOTICE: span={self.span} : {average_arandom_sleep=}")

    async def test_sync_random_sleep(self) -> None:
        MAX = (0.6 * self.span) + self.max_overhead
        total = 0
        for _ in range(self.runs):
            start = s_counter()
            random_sleep(self.span)
            end = s_counter()
            total += end - start

        average_random_sleep = total / self.runs
        assert MAX >= average_random_sleep >= 0
        if average_random_sleep >= (0.6 * self.span + self.max_ideal_overhead):
            warnings.warn(f"NOTICE: span={self.span} : {average_random_sleep=}")


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


class TestEntropyDaemon:
    pool = deque([csprng(32), csprng(32)], maxlen=32)
    gadget = ThreadingSafeEntropyPool(csprng(), obj=shake_128, pool=pool)
    daemon = EntropyDaemon(
        entropy_pool=pool, gadget=gadget, max_delay=0.025
    )

    async def test_aaa_start_daemon(self) -> None:
        assert not hasattr(self.daemon, "_daemon")
        self.daemon.start()
        assert hasattr(self.daemon, "_daemon")
        assert self.daemon._daemon.is_alive()

    async def test_max_delay_limits(self) -> None:
        problem = (
            "A negative delay was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            self.daemon.set_max_delay(-1)

    async def test_temporary_max_delay_limits(self) -> None:
        problem = (
            "A negative temporary delay was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            self.daemon.set_temporary_max_delay(-1)

    async def test_temporary_max_delay_reverts_after_duration(self) -> None:
        duration = 0.001
        initial_delay = self.daemon._max_delay
        new_delay = initial_delay / 2
        self.daemon.set_temporary_max_delay(new_delay, duration=duration)

        assert new_delay == self.daemon._max_delay
        max_wait_time = initial_delay + new_delay + duration
        await asleep(max_wait_time)
        assert initial_delay == self.daemon._max_delay

    async def test_zzz_cancel_stops_daemon(self) -> None:
        assert self.daemon._daemon.is_alive()
        self.daemon.cancel()
        await asleep(3 * self.daemon._max_delay)
        assert not self.daemon._daemon.is_alive()


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

    async def test_freshness_must_be_positive_int(self) -> None:
        problem = (
            "A non-positive int `freshness` value was allowed."
        )
        for bad_freshness in (b"-2", "1.0"):
            with Ignore(TypeError, if_else=violation(problem)):
                await arandom_number_generator(freshness=bad_freshness)
        for bad_freshness in (-1, False, 1.0):
            with Ignore(ValueError, if_else=violation(problem)):
                await arandom_number_generator(freshness=bad_freshness)

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
            await arandom_number_generator(freshness=0, entropy=datum)

    def test_sync_userland_entropy_can_be_any_type(self) -> None:
        for datum in (token_bytes(32).hex(), token_bits(32), [None, "test"]):
            random_number_generator(freshness=0, entropy=datum)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

