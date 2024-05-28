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

from aiootp.randoms.threading_safe_entropy_pool import ThreadingSafeEntropyPool


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


async def test_acsprng():
    entropy = await randoms.arandom_number_generator(entropy=test_data, freshness=1)
    assert len(entropy) == 64
    assert entropy.__class__ is bytes

    entropy = await randoms.arandom_number_generator(128, freshness=0)
    assert len(entropy) == 128
    assert entropy.__class__ is bytes

    for datum in (token_bytes(32), token_bytes(32).hex(), token_bits(32)):
        for size in (32, 64, 128, 256):
            entropy = await acsprng(size, entropy=datum)
            assert len(entropy) == size
            assert entropy.__class__ is bytes

    async def try_to_make_duplicate_readouts():
        """
        The async csprng doesn't produce duplicate outputs when run in
        a multithreaded environment.
        """
        for i in range(32):
            await arandom_sleep(0.00001)
            entropy = await acsprng()

            assert entropy not in entropy_pool

            entropy_pool.add(entropy)

    entropy_pool = set()
    await Threads.agather(
        *[try_to_make_duplicate_readouts for _ in range(32)]
    )


def test_csprng():
    entropy = randoms.random_number_generator(entropy=test_data, freshness=1)
    assert len(entropy) == 64
    assert entropy.__class__ is bytes

    entropy = randoms.random_number_generator(128, freshness=0)
    assert len(entropy) == 128
    assert entropy.__class__ is bytes

    for datum in (token_bytes(32), token_bytes(32).hex(), token_bits(32)):
        for size in (32, 64, 128, 256):
            entropy = csprng(size, entropy=datum)
            assert len(entropy) == size
            assert entropy.__class__ is bytes

    def try_to_make_duplicate_readouts():
        """
        The async csprng doesn't produce duplicate outputs when run in
        a multithreaded environment.
        """
        for i in range(32):
            random_sleep(0.00001)
            entropy = csprng()

            assert entropy not in entropy_pool

            entropy_pool.add(entropy)

    entropy_pool = set()
    Threads.gather(
        *[try_to_make_duplicate_readouts for _ in range(32)]
    )


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

