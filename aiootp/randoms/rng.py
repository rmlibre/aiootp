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


__all__ = [
    "acsprng",
    "arandom_number_generator",
    "csprng",
    "random_number_generator",
]


__doc__ = (
    "Cryptographically secure random number generation for the package."
)


import io
from collections import deque
from hashlib import shake_256

from aiootp._typing import Typing as t
from aiootp._constants import PRIMES, BIG, SHAKE_256_BLOCKSIZE
from aiootp._exceptions import Issue
from aiootp._paths import update_salt_file
from aiootp.asynchs import Threads, asleep, gather, new_event_loop
from aiootp.generics import acanonical_pack

from .simple import atoken_bits, token_bytes, arandom_sleep
from .simple import acanonical_token, canonical_token, achoice
from .threading_safe_entropy_pool import ThreadingSafeEntropyPool
from .entropy_daemon import EntropyDaemon
from ._early_salts import _salt, _asalt, _asalt_multiply
from ._early_salts import _package_seed, _package_seed_path


# initialize rudimentary global entropy pool
_pool = deque((token_bytes(32) for _ in range(32)), maxlen=32)


# initialize the global SHA3 hashing object that also collects entropy
_gadget = ThreadingSafeEntropyPool(
    _package_seed + token_bytes(3 * SHAKE_256_BLOCKSIZE),
    obj=shake_256,
    pool=_pool,
)


# begin the entropy gathering daemon
_entropy_daemon = EntropyDaemon(
    gadget=_gadget, entropy_pool=_pool, max_delay=1
).start()
_entropy_daemon.set_temporary_max_delay(max_delay=0.001, duration=2)


# avert event loop clashes
_run = new_event_loop().run_until_complete


async def acsprng(
    size: int = 64,
    *,
    entropy: t.Any = _gadget.hash(
        _salt(pool=_pool, gadget=_gadget).to_bytes(32, BIG), size=16
    ),
) -> bytes:
    """
    Returns a `size`-byte cryptographically secure pseudo-random value.
    Optionally seeds the internal entropy pools with user-provided
    `entropy`.
    """
    if entropy.__class__ is bytes:
        token = await acanonical_token() + entropy
    else:
        token = await acanonical_token() + repr(entropy).encode()
    _gadget.update(token)
    thread_safe_entropy = _gadget._obj.copy()
    thread_safe_entropy.update(token + _pool[0])
    return thread_safe_entropy.digest(size)


def csprng(
    size: int = 64,
    *,
    entropy: t.Any = _gadget.hash(
        _salt(pool=_pool, gadget=_gadget).to_bytes(32, BIG), size=16
    ),
) -> bytes:
    """
    Returns a `size`-byte cryptographically secure pseudo-random value.
    Optionally seeds the internal entropy pools with user-provided
    `entropy`.
    """
    if entropy.__class__ is bytes:
        token = canonical_token() + entropy
    else:
        token = canonical_token() + repr(entropy).encode()
    _gadget.update(token)
    thread_safe_entropy = _gadget._obj.copy()
    thread_safe_entropy.update(token + _pool[0])
    return thread_safe_entropy.digest(size)


async def arandom_number_generator(
    size: int = 64, *, entropy: t.Any = csprng(32), freshness: int = 8
) -> bytes:
    """
    Returns a `size`-byte random bytestring derived from the package's
    entropy pools, the provided `entropy` value, a persistent sha3
    hashing object, & a multithreaded + asynchronous chaotic algorithm.
    The integer `freshness` parameter adjusts the number of concurrent
    asynchronous tasks that will be spawned to gather entropy.

     _____________________________________
    |                                     |
    |        Algorithm Explanation:       |
    |_____________________________________|

    The methods used to implement a non-deterministic CSPRNG are given
    below.

    0. Utilize various component PRNGs whose designs & entropy sources
    differ.

    1. Keep the sizes of seeds, intermediate & output entropy values at
    least as large as the minumum acceptable security strength.

    2. Generate new seeds before & after each use.

    3. Use a persistent `shake_256` object on the input, intermediate &
    output values of component PRNGs for backtracking resistance,
    prediction resistance & as an efficient entropy pool.

    4. Ensure an order prediction attack must be carried out on internal
    calculations by using nanosecond timestamps, non-commutative
    operations, & hashing between & internally to each component PRNG.

    5. Make order-prediction more difficult by running a background
    entropy collection thread to asynchronously gather PRNG tasks in
    pseudo-random order in between pseudo-random sleeps, all the while
    ratcheting internal states.

    6. Save, retrieve & update entropy saved to the filesystem every
    time the package is imported.

    7. Hash userland entropy into the entropy pools.

    8. Incorporate function call context into seeds for thread safety &
    domain separation.

    9. Enable the iteration & interleaving of these methods a variable
    amount of times as needed with a `freshness` parameter.

    If we can assume each initial 32-byte internal state produced by the
    CSPRNG only adds 8-bits of entropy to the pool, then by initializing
    the pool to 32 ratcheting states, & hashing it with the persistent
    `shake_256` object, then 256-bits of entropy will have been reached.
    """
    _entropy_daemon.set_temporary_max_delay(0.001, duration=1)

    if freshness < 0 or freshness.__class__ is not int:
        raise Issue.value_must("freshness", "be a non-negative int")
    elif not freshness:
        _pool.appendleft(await acsprng(32, entropy=entropy))
    else:
        async def create_unique_multiple(seed: int) -> int:
            return await _asalt_multiply(
                size, seed, await atoken_bits(256), pool=_pool
            )

        async def modular_multiplication() -> None:
            seed = await _asalt(pool=_pool, gadget=_gadget)
            await arandom_sleep(0.003)
            multiples = (create_unique_multiple(seed) for _ in range(3))
            multiples = [await multiple for multiple in multiples]
            element = await _asalt_multiply(seed, *multiples, pool=_pool)
            result = seed.to_bytes(32, BIG) + element.to_bytes(32, BIG)
            _pool.appendleft(await acsprng(32, entropy=result))

        async def add_to_pool() -> None:
            seed = await acsprng(32, entropy=entropy)
            await arandom_sleep(0.003)
            _pool.appendleft(await acsprng(32, entropy=seed))

        async def start_generator() -> None:
            tasks = deque()
            for _ in range(freshness):
                await asleep()
                tasks.appendleft(modular_multiplication())
                for _ in range(10):
                    tasks.appendleft(add_to_pool())
            reader = io.BytesIO(await acsprng(16 * len(tasks))).read
            await gather(*sorted(tasks, key=lambda _: reader(16)))

        entropy = await acsprng(16, entropy=entropy)
        await start_generator()

    return await acsprng(size, entropy=await acanonical_pack(*_pool))


def random_number_generator(
    size: int = 64, *, entropy: t.Any = csprng(32), freshness: int = 8
) -> bytes:
    """
    Returns a `size`-byte random bytestring derived from the package's
    entropy pools, the provided `entropy` value, a persistent sha3
    hashing object, & a multithreaded + asynchronous chaotic algorithm.
    The integer `freshness` parameter adjusts the number of concurrent
    asynchronous tasks that will be spawned to gather entropy.

     _____________________________________
    |                                     |
    |        Algorithm Explanation:       |
    |_____________________________________|

    The methods used to implement a non-deterministic CSPRNG are given
    below.

    0. Utilize various component PRNGs whose designs & entropy sources
    differ.

    1. Keep the sizes of seeds, intermediate & output entropy values at
    least as large as the minumum acceptable security strength.

    2. Generate new seeds before & after each use.

    3. Use a persistent `shake_256` object on the input, intermediate &
    output values of component PRNGs for backtracking resistance,
    prediction resistance & as an efficient entropy pool.

    4. Ensure an order prediction attack must be carried out on internal
    calculations by using nanosecond timestamps, non-commutative
    operations, & hashing between & internally to each component PRNG.

    5. Make order-prediction more difficult by running a background
    entropy collection thread to asynchronously gather PRNG tasks in
    pseudo-random order in between pseudo-random sleeps, all the while
    ratcheting internal states.

    6. Save, retrieve & update entropy saved to the filesystem every
    time the package is imported.

    7. Hash userland entropy into the entropy pools.

    8. Incorporate function call context into seeds for thread safety &
    domain separation.

    9. Enable the iteration & interleaving of these methods a variable
    amount of times as needed with a `freshness` parameter.

    If we can assume each initial 32-byte internal state produced by the
    CSPRNG only adds 8-bits of entropy to the pool, then by initializing
    the pool to 32 ratcheting states, & hashing it with the persistent
    `shake_256` object, then 256-bits of entropy will have been reached.
    """
    return _run(
        arandom_number_generator(size, entropy=entropy, freshness=freshness)
    )


# update the device seed with new entropy
update_salt_file(
    path=_package_seed_path,
    salt=_run(arandom_number_generator(32, freshness=1)),
)


module_api = dict(
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    acsprng=acsprng,
    arandom_number_generator=arandom_number_generator,
    csprng=csprng,
    random_number_generator=random_number_generator,
)

