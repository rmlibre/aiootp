# This file is part of aiootp, an asynchronous one-time-pad based crypto
# and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "randoms",
    "arandom_256",
    "random_256",
    "arandom_512",
    "random_512",
    "asafe_symm_keypair",
    "safe_symm_keypair",
    "aseeder",
    "seeder",
    "acsprng",
    "csprng",
]


__doc__ = """
A collection of functions which use & create varying levels of entropy
for end-user cryptographic applications.
"""


import os
import math
from random import choice
from random import uniform
from random import randrange as random_range
from hashlib import sha3_256
from hashlib import sha3_512
from collections import deque
from sympy import prevprime as prev_prime
from sympy import nextprime as next_prime
from sympy import randprime as random_prime
from .asynchs import *
from .asynchs import sleep
from .asynchs import asleep
from .commons import bits
from .commons import primes
from .commons import commons
from .generics import aint
from .generics import astr
from .generics import arange
from .generics import nc_512
from .generics import anc_512
from .generics import sha_256
from .generics import sha_512
from .generics import asha_256
from .generics import asha_512
from .generics import Enumerate
from .generics import Comprende
from .generics import comprehension
from .generics import bytes_to_int
from .generics import abytes_to_int
from .generics import sha_512_hmac
from .generics import asha_512_hmac
from .generics import is_async_iterable


async def acreate_prime(bits=2048):
    """
    Asynchronous wrapper around a ``sympy.randprime`` abstraction which
    locates primes based on a user-defined amount of ``bits``.
    """
    return random_prime(2 ** bits, 2 ** (bits + 1))


def create_prime(bits=2048):
    """
    Synchronous wrapper around a ``sympy.randprime`` abstraction which
    locates primes based on a user-defined amount of ``bits``.
    """
    return random_prime(2 ** bits, 2 ** (bits + 1))


async def arandom_prime(low=None, high=None, **kw):
    """
    Asynchronous wrapper around ``sympy.randprime``.
    """
    return random_prime(low, high, **kw)


async def aprime_table(
    low=None, high=None, step=1, depth=10, depth_error=25
):
    """
    Create a dictionary with `depth` number of random primes per group,
    where range(low, high, step) determines the number of groups, and
    each value and value + 1 in this range represents the minimum and
    maximum number of bits, respectively, each prime in the group will
    be.

    If low or high are passed without the other, then high is assumed to
    be low + 1, and low is assumed to be high - 1, respectively. By
    default, if low and high are not passed, this function produces a
    dictionary with 64 groups of primes from 64 to 128 bits each, with
    groups of size 10 each.

    The depth_error argument is used when attempting to populate a prime
    group with `depth` number of elements, and `depth_error` iterations
    have elapsed which produced a prime that's already in the table.
    This throws an error indicating either that the function may be in
    an infinite loop because the prime group has been completely
    consumed of unique elements, or that the threshhold has been reached
    where the user no longer wants to search the group for unique
    elements.

    Usage Examples:

    table = prime_table(low=128, depth=3)
    print(table[128])
    [
        493533133190526841522032284522322968107,
        388191793051351746548745812175673076809,
        592596411378307857279359758985424061099,
    ]

    table = prime_table(low=128, high=1029, step=128, depth=1)
    print(128 in table)
    >>> True
    print(256 in table)
    >>> True
    print(384 in table)
    >>> True
    print(512 in table)
    >>> True
    print(513 in table)
    >>> False
    """
    if low == None and high == None:
        low = 64
        high = 129
    elif low == None:
        low = high - 1
    elif high == None:
        high = low + 1
    elif low >= high:
        raise ValueError("Lower bound isn't less than the upper bound.")
    table = {}
    for prime_group in range(low, high, step):
        min_bits = 2 ** prime_group
        max_bits = 2 ** (prime_group + 1)
        table.update({prime_group: []})
        for loop in range(depth):
            prime = await arandom_prime(min_bits, max_bits)
            infinite_loop_checker = 0
            while prime in table[prime_group]:
                infinite_loop_checker += 1
                if infinite_loop_checker >= depth_error:
                    problem = "Max recursion depth reached because "
                    cause = "not enough unique primes could be found "
                    cause += f"within the prime group of {prime_group} "
                    cause += f"bits to fill a list of length {depth}."
                    error = RuntimeError(problem + cause)
                    error.value = table
                    raise error
                prime = await arandom_prime(min_bits, max_bits)
            table[prime_group].append(prime)
    return table


def prime_table(low=None, high=None, step=1, depth=10, depth_error=25):
    """
    Create a dictionary with `depth` number of random primes per group,
    where range(low, high, step) determines the number of groups, and
    each value and value + 1 in this range represents the minimum and
    maximum number of bits, respectively, each prime in the group will
    be.

    If low or high are passed without the other, then high is assumed to
    be low + 1, and low is assumed to be high - 1, respectively. By
    default, if low and high are not passed, this function produces a
    dictionary with 64 groups of primes from 64 to 128 bits each, with
    groups of size 10 each.

    The depth_error argument is used when attempting to populate a prime
    group with `depth` number of elements, and `depth_error` iterations
    have elapsed which produced a prime that's already in the table.
    This throws an error indicating either that the function may be in
    an infinite loop because the prime group has been completely
    consumed of unique elements, or that the threshhold has been reached
    where the user no longer wants to search the group for unique
    elements.

    Usage Examples:

    table = prime_table(low=128, depth=3)
    print(table[128])
    [
        493533133190526841522032284522322968107,
        388191793051351746548745812175673076809,
        592596411378307857279359758985424061099,
    ]

    table = prime_table(low=128, high=1029, step=128, depth=1)
    print(128 in table)
    >>> True
    print(256 in table)
    >>> True
    print(384 in table)
    >>> True
    print(512 in table)
    >>> True
    print(513 in table)
    >>> False
    """
    if low == None and high == None:
        low = 64
        high = 129
    elif low == None:
        low = high - 1
    elif high == None:
        high = low + 1
    elif low >= high:
        raise ValueError("Lower bound isn't less than the upper bound.")
    table = {}
    for prime_group in range(low, high, step):
        min_bits = 2 ** prime_group
        max_bits = 2 ** (prime_group + 1)
        table.update({prime_group: []})
        for loop in range(depth):
            prime = random_prime(min_bits, max_bits)
            infinite_loop_checker = 0
            while prime in table[prime_group]:
                infinite_loop_checker += 1
                if infinite_loop_checker >= depth_error:
                    problem = "Max recursion depth reached because "
                    cause = "not enough unique primes could be found "
                    cause += f"within the prime group of {prime_group} "
                    cause += f"bits to fill a list of length {depth}."
                    error = RuntimeError(problem + cause)
                    error.value = table
                    raise error
                prime = random_prime(min_bits, max_bits)
            table[prime_group].append(prime)
    return table


async def auniform(*a, **kw):
    """
    Asynchronous version of the standard library's ``random.uniform``.
    """
    return uniform(*a, **kw)


async def achoice(iterable):
    """
    Asynchronous version of the standard library's ``random.choice``.
    """
    return choice(iterable)


async def arandom_range(*a, **kw):
    """
    Asynchronous version of the standard library's ``random.randrange``.
    """
    return random_range(*a, **kw)


@comprehension()
async def arandom_range_gen(low=1, high=10):
    """
    A generator which produces values from ``random.randrange`` from
    ``low`` to ``high``.
    """
    while True:
        yield random_range(low, high)


@comprehension()
def random_range_gen(low=1, high=10):
    """
    A generator which produces values from ``random.randrange`` from
    ``low`` to ``high``.
    """
    while True:
        yield random_range(low, high)


async def arandom_sleep(span=2):
    """
    Asynchronously sleeps for a psuedo-random portion of ``span`` time.
    """
    return await asleep(span * await auniform(0, 1))


def random_sleep(span=2):
    """
    Synchronously sleeps for a psuedo-random portion of ``span`` time.
    """
    return sleep(span * uniform(0, 1))


async def aurandom_hash(size):
    """
    Returns ``size`` bytes of ``os.urandom`` entropy as a ``sha3_512``
    hash.
    """
    return sha3_512(await aurandom(size)).hexdigest()


def urandom_hash(size):
    """
    Returns ``size`` bytes of ``os.urandom`` entropy as a ``sha3_512``
    hash.
    """
    return sha3_512(urandom(size)).hexdigest()


async def aurandom_number(size):
    """
    Returns ``size`` bytes of ``os.urandom`` entropy as an integer.
    """
    return await abytes_to_int(await aurandom(size))


def urandom_number(size):
    """
    Returns ``size`` bytes of ``os.urandom`` entropy as an integer.
    """
    return bytes_to_int(urandom(size))


async def aurandom(size):
    """
    Returns ``size`` bytes of ``os.urandom`` entropy.
    """
    return os.urandom(size)


def urandom(size):
    """
    Returns ``size`` bytes of ``os.urandom`` entropy.
    """
    return os.urandom(size)


@comprehension()
async def asalted_multiply(mod=primes[258][-1], offset=None):
    """
    Allows for non-communitive multiplication. This assists pseudo-random
    number generators in turning combinations of low entropy number
    sources into permutations. This greatly increases the amount of
    knowledge an attacker must have to perform pre-image or known-
    plaintext attacks on the hashes of those permutations.

    ``mod``:    Should be a prime of bit-size matching the key space
        needs of its use case. Defaults to the last 258-bit prime
        number.
    ``offset``: A number which is used to salt the calculations. It
        should be a pseudo-random number >128-bits larger than ``mod``.

    Usage Example:

    numbers = list(range(10))
    multiply = await asalted_multiply().aprime()
    randomized_number = await multiply(numbers)
    """
    if offset == None:
        offset = await arandom_range(
            bits[128] * mod + 1, (bits[128] + 1) * mod
        )
    mix = offset * next_prime(math.log2(offset)) % mod
    start = seed = int(await asha_256(mix, offset), 16)
    numbers = (offset * seed,)
    while True:
        mix ^= abs(sum((seed, offset, *numbers)))
        mix %= mod
        seed ^= mix
        offset ^= seed
        (*numbers,) = yield start ^ seed
        start %= mod
        for number in numbers:
            mix += offset
            start *= number ^ mix
            await switch()


@comprehension()
def salted_multiply(mod=primes[258][-1], offset=None):
    """
    Allows for non-communitive multiplication. This assists pseudo-random
    number generators in turning combinations of low entropy number
    sources into permutations. This greatly increases the amount of
    knowledge an attacker must have to perform pre-image or known-
    plaintext attacks on the hashes of those permutations.

    ``mod``:    Should be a prime of bit-size matching the key space
        needs of its use case. Defaults to the last 258-bit prime
        number.
    ``offset``: A number which is used to salt the calculations. It
        should be a pseudo-random number >128-bits larger than ``mod``.

    Usage Example:

    numbers = list(range(10))
    multiply = salted_multiply().prime()
    randomized_number = multiply(numbers)
    """
    if offset == None:
        offset = random_range(bits[128] * mod + 1, (bits[128] + 1) * mod)
    mix = offset * next_prime(math.log2(offset)) % mod
    start = seed = int(sha_256(mix, offset), 16)
    numbers = (offset * seed,)
    while True:
        mix ^= abs(sum((seed, offset, *numbers)))
        mix %= mod
        seed ^= mix
        offset ^= seed
        (*numbers,) = yield start ^ seed
        start %= mod
        for number in numbers:
            mix += offset
            start *= number ^ mix


#  initializing weakly entropic coroutines
mod = primes[512][0]

_asalt_multiply = run(asalted_multiply(mod).aprime())
_salt_multiply = salted_multiply(mod).prime()

_initial_entropy = deque(
    [urandom_number(128), urandom_number(128)], maxlen=2
)
del mod


async def asalt(*, _entropy=_initial_entropy):
    """
    Returns a low-grade entropy number from cached & ratcheted system
    entropy.
    """
    _entropy.appendleft(int(await asha_512(_entropy), 16))
    return await _asalt_multiply(_entropy)


def salt(*, _entropy=_initial_entropy):
    """
    Returns a low-grade entropy number from cached & ratcheted system
    entropy.
    """
    _entropy.appendleft(int(sha_512(_entropy), 16))
    return _salt_multiply(_entropy)


async def arandom_256(entropy=salt(), runs=26, refresh=False):
    """
    Returns a 256-bit hash produced by ``random_number_generator``.
    Users can pass ``entropy`` into the function. ``runs`` determines
    how many internal iterations ``random_number_generator`` will crank
    on when deriving a new key. ``refresh`` is ``False`` by default,
    since generating new entropy can be quite slow -- it can be toggled
    to ``True`` to generate new entropy.
    """
    return await asha_256(
        await arandom_number_generator(
            entropy=entropy, runs=runs, refresh=refresh
        ),
        await aurandom(32),
    )


def random_256(entropy=salt(), runs=26, refresh=False):
    """
    Returns a 256-bit hash produced by ``random_number_generator``.
    Users can pass ``entropy`` into the function. ``runs`` determines
    how many internal iterations ``random_number_generator`` will crank
    on when deriving a new key. ``refresh`` is ``False`` by default,
    since generating new entropy can be quite slow -- it can be toggled
    to ``True`` to generate new entropy.
    """
    return sha_256(
        random_number_generator(
            entropy=entropy, runs=runs, refresh=refresh
        ),
        urandom(32),
    )


async def arandom_512(entropy=salt(), runs=26, refresh=False):
    """
    Returns a 512-bit hash produced by ``random_number_generator``.
    Users can pass ``entropy`` into the function. ``runs`` determines
    how many internal iterations ``random_number_generator`` will crank
    on when deriving a new key. ``refresh`` is ``False`` by default,
    since generating new entropy can be quite slow -- it can be toggled
    to ``True`` to generate new entropy.
    """
    return await asha_512(
        await arandom_number_generator(
            entropy=entropy, runs=runs, refresh=refresh
        ),
        await aurandom(64),
    )


def random_512(entropy=salt(), runs=26, refresh=False):
    """
    Returns a 512-bit hash produced by ``random_number_generator``.
    Users can pass ``entropy`` into the function. ``runs`` determines
    how many internal iterations ``random_number_generator`` will crank
    on when deriving a new key. ``refresh`` is ``False`` by default,
    since generating new entropy can be quite slow -- it can be toggled
    to ``True`` to generate new entropy.
    """
    return sha_512(
        random_number_generator(
            entropy=entropy, runs=runs, refresh=refresh
        ),
        urandom(64),
    )


async def arandom_number_generator(
    entropy=salt(),
    runs=26,
    refresh=False,
    *,
    _completed=deque([], maxlen=256),
):
    """
    We propose several methods for producing cryptographically secure
    pseudo-random numbers, and implement them in this function.

    1. Greatly increase the space an attacker must search by using
    pseudo-random seeds that are very large numbers (> 256-bits and
    < 2048-bits) as the range arguments for random.randrange.

    2. Recursively use cryptographic hashing on the results of our
    pseudo-random number generators to unlink their mathematical
    associations from their seeds.

    3. Frustrate attempts to learn the internal state of the PRNGs by
    making separate seeds at each import-time & function call, as well
    as, incorporating forward-secure key ratcheting algorithms within
    several of this package's pseudo-random number generators. They work
    together, with proper coordination, to produce randomness in a way
    that alone they wouldn't. Using a combination of PRNGs also spreads
    out the impact of an attacker predicting CSPRNG output by requiring
    all of the PRNGs be broken at import time, or for the user machine's
    memory to be maliciously analyzed, to predict outputs from the
    CSPRNGs.

    4. Use three randrange function abstractions where for each function
    call: one produces 2 new small pseudo-random seeds from a pair of
    smaller seeds (256-bits - 512-bits); the second produces 2 new
    large pseudo-random seeds from the pair of larger seeds (1536-bits -
    2048-bits); the third to produce a large pseudo-random number from
    ``random.randrange`` with the lower bound being the two small seeds
    multiplied together and salted, and the upper bound being the two
    large seeds being multiplied together and salted.

    5. Further frustrate an attacker by necessitating that they perform
    an order prediction attack on the results of the CSPRNG's component
    PRNGs. We do this by using asynchrony entirely throughout the CSPRNG
    with random sleeps.

    6. Iteratively use a salted modular multiplication on the CSPRNG's
    component PRNG states, then hashing & caching the results.

    7. Use the powerful sha3_512 hashing algorithm for all hashing.

    8. Iterate and interleave all these methods enough times such that if
    we assume each time the CSPRNG produces a 512-bit internal state,
    that only 1-bit of entropy is produced. Then, by initializing up to
    a cache of 256 ratcheting states, then the ``random_number_generator``
    algorithm here would have at least 256-bits of entropy.

    **** **** **** **** **** **** **** **** **** **** **** **** ****
    Our implementation analysis is NOT vigorous or conclusive, though
    soley based on the constraints stated above, our assumptions of
    randomness should be a reasonable estimate.
    **** **** **** **** **** **** **** **** **** **** **** **** ****
    """
    if refresh or not _completed:

        async def start_generator(runs, tasks=deque()):
            for _ in range(runs):
                await switch()
                tasks.appendleft(new_task(modular_exponentiation()))
                for _ in range(10):
                    tasks.appendleft(new_task(hash_cache()))
            await gather(*tasks)

        async def hash_cache(seed=await aurandom(64)):
            await arandom_sleep(0.001)
            _completed.appendleft(await asha_512(_completed, entropy, seed))

        async def modular_exponentiation(seed=await asalt()):
            multiples = deque()
            for _ in range(3):
                await arandom_sleep(0.001)
                multiples.appendleft(
                    new_task(create_unique_multiple(seed))
                )
            result = await big_modulation(
                seed, *[await calculation for calculation in multiples]
            )
            _completed.appendleft(await asha_512(result, seed))

        async def create_unique_multiple(seed):
            return await big_multiply(
                seed,
                await aunique_integer(),
                await aunique_integer(),
                await aunique_integer(),
            )

        async def big_modulation(seed, multiple_0, multiple_1, multiple_2):
            return await big_multiply(
                seed,
                multiple_0,
                multiple_1,
                multiple_2,
                await aunique_big_int(),
            ) % await achoice(primes[4096])

        async def big_multiply(*args):
            return await _asalt_multiply(args)

        await agenerate_unique_range_bounds()
        await start_generator(runs)
        await agenerate_unique_range_bounds()
    else:
        _completed.appendleft(
            await asha_512_hmac((_completed, await aurandom(64)), entropy)
        )

    return await asha_512_hmac((_completed, salt()), entropy)


def random_number_generator(
    entropy=salt(),
    runs=26,
    refresh=False,
    *,
    _completed=deque([], maxlen=256),
):
    """
    We propose several methods for producing cryptographically secure
    pseudo-random numbers, and implement them in this function.

    1. Greatly increase the space an attacker must search by using
    pseudo-random seeds that are very large numbers (> 256-bits and
    < 2048-bits) as the range arguments for random.randrange.

    2. Recursively use cryptographic hashing on the results of our
    pseudo-random number generators to unlink their mathematical
    associations from their seeds.

    3. Frustrate attempts to learn the internal state of the PRNGs by
    making separate seeds at each import-time & function call, as well
    as, incorporating forward-secure key ratcheting algorithms within
    several of this package's pseudo-random number generators. They work
    together, with proper coordination, to produce randomness in a way
    that alone they wouldn't. Using a combination of PRNGs also spreads
    out the impact of an attacker predicting CSPRNG output by requiring
    all of the PRNGs be broken at import time, or for the user machine's
    memory to be maliciously analyzed, to predict outputs from the
    CSPRNGs.

    4. Use three randrange function abstractions where for each function
    call: one produces 2 new small pseudo-random seeds from a pair of
    smaller seeds (256-bits - 512-bits); the second produces 2 new
    large pseudo-random seeds from the pair of larger seeds (1536-bits -
    2048-bits); the third to produce a large pseudo-random number from
    ``random.randrange`` with the lower bound being the two small seeds
    multiplied together and salted, and the upper bound being the two
    large seeds being multiplied together and salted.

    5. Further frustrate an attacker by necessitating that they perform
    an order prediction attack on the results of the CSPRNG's component
    PRNGs. We do this by using asynchrony entirely throughout the CSPRNG
    with random sleeps.

    6. Iteratively use a salted modular multiplication on the CSPRNG's
    component PRNG states, then hashing & caching the results.

    7. Use the powerful sha3_512 hashing algorithm for all hashing.

    8. Iterate and interleave all these methods enough times such that,
    we assume each time the CSPRNG produces a 512-bit internal state,
    that only 1-bit of entropy is produced. Then, by initializing up to
    a cache of 256 ratcheting states then the ``random_number_generator``
    algorithm here would have at least 256-bits of entropy.

    **** **** **** **** **** **** **** **** **** **** **** **** ****
    Our implementation analysis is NOT vigorous or conclusive, though
    soley based on the constraints stated above, our assumptions of
    randomness should be a reasonable estimate.
    **** **** **** **** **** **** **** **** **** **** **** **** ****
    """
    if refresh or not _completed:

        async def start_generator(runs, tasks=deque()):
            for _ in range(runs):
                await switch()
                tasks.appendleft(new_task(modular_exponentiation()))
                for _ in range(10):
                    tasks.appendleft(new_task(hash_cache()))
            await gather(*tasks)

        async def hash_cache(seed=urandom(64)):
            await arandom_sleep(0.001)
            _completed.appendleft(await asha_512(_completed, entropy, seed))

        async def modular_exponentiation(seed=salt()):
            multiples = deque()
            for _ in range(3):
                await arandom_sleep(0.001)
                multiples.appendleft(
                    new_task(create_unique_multiple(seed))
                )
            result = await big_modulation(
                seed, *[await calculation for calculation in multiples]
            )
            _completed.appendleft(await asha_512(result, seed))

        async def create_unique_multiple(seed):
            return await big_multiply(
                seed,
                await aunique_integer(),
                await aunique_integer(),
                await aunique_integer(),
            )

        async def big_modulation(seed, multiple_0, multiple_1, multiple_2):
            return await big_multiply(
                seed,
                multiple_0,
                multiple_1,
                multiple_2,
                await aunique_big_int(),
            ) % await achoice(primes[4096])

        async def big_multiply(*args):
            return await _asalt_multiply(args)

        generate_unique_range_bounds()
        run(start_generator(runs))
        generate_unique_range_bounds()
    else:
        _completed.appendleft(
            sha_512_hmac((_completed, urandom(64)), entropy)
        )

    return sha_512_hmac((_completed, salt()), entropy)


async def aunique_integer():
    """
    Returns an ``int(hex_hash, 16)`` value of a unique hexidecimal hash.
    """
    return int(await aunique_hash(), 16)


def unique_integer():
    """
    Returns an ``int(hex_hash, 16)`` value of a unique hexidecimal hash.
    """
    return int(unique_hash(), 16)


async def aunique_hash():
    """
    Returns a ``hashlib.sha3_512`` string hash of an integer which is
    greater than a 512-bit number by many orders of magnitude.
    """
    return sha_512(await aunique_big_int())


def unique_hash():
    """
    Returns a ``hashlib.sha3_512`` string hash of an integer which is
    greater than a 512-bit number by many orders of magnitude.
    """
    return sha_512(unique_big_int())


async def aunique_big_int():
    """
    Uses unique lower & upper bound integers to feed into the standard
    library's ``randrange`` function & returns the result.
    """
    return await arandom_range(
        *(await gather(aunique_lower_bound(), aunique_upper_bound()))
    )


def unique_big_int():
    """
    Uses unique lower & upper bound integers to feed into the standard
    library's ``randrange`` function & returns the result.
    """
    return random_range(unique_lower_bound(), unique_upper_bound())


async def aunique_lower_bound():
    """
    Returns a unique number where 2**1536 < number < 2**2048 from a pair
    of global, semi-constant 256-bit - 512-bit seeds.
    """
    global SMALL_UPPER_BOUND
    global SMALL_LOWER_BOUND
    number_0 = arandom_range(SMALL_LOWER_BOUND, SMALL_UPPER_BOUND)
    number_1 = arandom_range(SMALL_LOWER_BOUND, SMALL_UPPER_BOUND)
    return await _asalt_multiply(await gather(number_0, number_1))


def unique_lower_bound():
    """
    Returns a unique number where 2**1536 < number < 2**2048 from a pair
    of global, semi-constant 256-bit - 512-bit seeds.
    """
    global SMALL_UPPER_BOUND
    global SMALL_LOWER_BOUND
    return _salt_multiply(
        [
            random_range(SMALL_LOWER_BOUND, SMALL_UPPER_BOUND),
            random_range(SMALL_LOWER_BOUND, SMALL_UPPER_BOUND),
        ]
    )


async def aunique_upper_bound():
    """
    Returns a unique number where 2**4096 < number < 2**4608 from a pair
    of global, semi-constant 1536-bit - 2048-bit seeds.
    """
    global BIG_UPPER_BOUND
    global BIG_LOWER_BOUND
    number_0 = arandom_range(BIG_LOWER_BOUND, BIG_UPPER_BOUND)
    number_1 = arandom_range(BIG_LOWER_BOUND, BIG_UPPER_BOUND)
    return await _asalt_multiply(await gather(number_0, number_1))


def unique_upper_bound():
    """
    Returns a unique number where 2**4096 < number < 2**4608 from a pair
    of global, semi-constant 1536-bit - 2048-bit seeds.
    """
    global BIG_UPPER_BOUND
    global BIG_LOWER_BOUND
    return _salt_multiply(
        [
            random_range(BIG_LOWER_BOUND, BIG_UPPER_BOUND),
            random_range(BIG_LOWER_BOUND, BIG_UPPER_BOUND),
        ]
    )


async def agenerate_unique_range_bounds():
    """
    Generates two pairs of unique global, semi-constant seeds which
    feed uniqueness into ``random.randrange``, with the consideration
    that guessing its output is aided by knowing what its inputs were.
    Making its inputs unknown should then help keep its outputs unknown.
    """
    await gather(
        agenerate_small_range_bounds(), agenerate_big_range_bounds()
    )


def generate_unique_range_bounds():
    """
    Generates two pairs of unique global, semi-constant seeds which
    feed uniqueness into ``random.randrange``, with the consideration
    that guessing its output is aided by knowing what its inputs were.
    Making its inputs unknown should then help keep its outputs unknown.
    """
    generate_small_range_bounds()
    generate_big_range_bounds()


async def agenerate_small_range_bounds():
    """
    Generates a pair of unique global, semi-constant seeds which feed
    uniqueness into the lower bound of ``random.randrange``, with the
    consideration that guessing its output is aided by knowing what its
    inputs were. Making its inputs unknown should then help keep its
    outputs unknown.
    """
    global SMALL_UPPER_BOUND
    global SMALL_LOWER_BOUND
    SMALL_UPPER_BOUND = await atemplate_unique_number(bits[512])
    SMALL_LOWER_BOUND = await atemplate_unique_number(bits[256])


def generate_small_range_bounds():
    """
    Generates a pair of unique global, semi-constant seeds which feed
    uniqueness into the lower bound of ``random.randrange``, with the
    consideration that guessing its output is aided by knowing what its
    inputs were. Making its inputs unknown should then help keep its
    outputs unknown.
    """
    global SMALL_UPPER_BOUND
    global SMALL_LOWER_BOUND
    SMALL_UPPER_BOUND = template_unique_number(bits[512])
    SMALL_LOWER_BOUND = template_unique_number(bits[256])


async def agenerate_big_range_bounds():
    """
    Generates a pair of unique global, semi-constant seeds which feed
    uniqueness into the upper bound of ``random.randrange``, with the
    consideration that guessing its output is aided by knowing what its
    inputs were. Making its inputs unknown should then help keep its
    outputs unknown.
    """
    global BIG_UPPER_BOUND
    global BIG_LOWER_BOUND
    BIG_UPPER_BOUND = await atemplate_unique_number(bits[2048])
    BIG_LOWER_BOUND = await atemplate_unique_number(bits[1536])


def generate_big_range_bounds():
    """
    Generates a pair of unique global, semi-constant seeds which feed
    uniqueness into the upper bound of ``random.randrange``, with the
    consideration that guessing its output is aided by knowing what its
    inputs were. Making its inputs unknown should then help keep its
    outputs unknown.
    """
    global BIG_UPPER_BOUND
    global BIG_LOWER_BOUND
    BIG_UPPER_BOUND = template_unique_number(bits[2048])
    BIG_LOWER_BOUND = template_unique_number(bits[1536])


async def atemplate_unique_number(number):
    """
    A pseudo-random number generator helper function. An alternative
    method of constructing unique numbers. The length of the number
    argument will be the same as the length of the number that's
    returned. This function is used to produce pseudo-random numbers for
    the ranges passed to random.randrange. We assume that, alone, the
    output of random.randrange can be determined by an attacker using
    several known or unknown attack vectors. So this function is to be
    used in conjunction with other, vigorous methods of producing
    cryptographically secure pseudo-random numbers.
    """
    seed = await asalt()
    number = await aint(number)  # throw if not a number
    while seed < number:
        seed *= await asalt()
    return await aint(str(seed)[: len(str(number))])


def template_unique_number(number):
    """
    A pseudo-random number generator helper function. An alternative
    method of constructing unique numbers. The length of the number
    argument will be the same as the length of the number that's
    returned. This function is used to produce pseudo-random numbers for
    the ranges passed to random.randrange. We assume that, alone, the
    output of random.randrange can be determined by an attacker using
    several known or unknown attack vectors. So this function is to be
    used in conjunction with other, vigorous methods of producing
    cryptographically secure pseudo-random numbers.
    """
    seed = salt()
    number = int(number)  # throw if not a number
    while seed < number:
        seed *= salt()
    return int(str(seed)[: len(str(number))])


async def asafe_symm_keypair(entropy=salt(), refresh=False, runs=26):
    """
    Returns two ``bytes`` type, 512-bit hexidecimal keys. This function
    updates the package's static random seeds before & after deriving
    the returned key pair.
    """
    global global_seed
    global global_seed_key

    await agenerate_unique_range_bounds()
    seed_key = sha_512(
        global_seed,
        global_seed_key,
        await arandom_512(refresh=refresh, runs=runs),
    ).encode()
    seed = sha_512_hmac((global_seed, seed_key), key=entropy).encode()
    global_seed_key = sha_512_hmac(seed, global_seed_key)
    global_seed = sha_512_hmac(global_seed, global_seed_key)
    await agenerate_unique_range_bounds()
    return seed, seed_key


def safe_symm_keypair(entropy=salt(), refresh=False, runs=26):
    """
    Returns two ``bytes`` type, 512-bit hexidecimal keys. This function
    updates the package's static random seeds before & after deriving
    the returned key pair.
    """
    global global_seed
    global global_seed_key

    generate_unique_range_bounds()
    seed_key = sha_512(
        global_seed, global_seed_key, random_512(refresh=refresh, runs=runs)
    ).encode()
    seed = sha_512_hmac((global_seed, seed_key), key=entropy).encode()
    global_seed_key = sha_512_hmac(seed, global_seed_key)
    global_seed = sha_512_hmac(global_seed, global_seed_key)
    generate_unique_range_bounds()
    return seed, seed_key


@comprehension()
async def aseeder(entropy=salt(), refresh=False, runs=26):
    """
    A fast random number generator that supports adding entropy during
    async iteration. It's based on the randomness produced from combining
    a key ratchet algorithm, os psuedo randomness, and this module's
    cryptographically secure pseudo-random number generator (csprng).

    Usage examples:

    # In async for loops ->
    async for seed in aseeder():
        # do something with ``seed``, a random hash

    # By calling anext ->
    from aiootp import anext
    from aioitertools import iter as aiter

    csprng = aseeder()
    seed = await next(csprng)

    # By sending in entropy ->
    entropy = "any object whose str() representation has randomness"
    csprng = aseeder(entropy)  # entropy can be added here
    await csprng(None)
    seed = await csprng(entropy)  # &/or entropy can be added here
    """
    seed, seed_key = await asafe_symm_keypair(entropy, refresh)
    kdf = sha3_512(seed + seed_key)
    while True:
        entropy = (await astr(entropy)).encode()
        kdf.update(seed + seed_key + entropy)
        seed_key = kdf.digest()
        kdf.update(seed + seed_key + entropy)
        seed = kdf.digest()
        kdf.update(seed + seed_key + entropy)
        entropy = yield kdf.hexdigest()


@comprehension()
def seeder(entropy=salt(), refresh=False, runs=26):
    """
    A fast random number generator that supports adding entropy during
    iteration. It's based on the randomness produced from combining a
    key ratchet algorithm, os psuedo randomness, and this module's
    cryptographically secure pseudo-random number generator (csprng).

    Usage examples:

    # In for loops ->
    for seed in seeder():
        # do something with ``seed``, a random hash

    # By calling next ->
    csprng = seeder()
    seed = next(csprng)

    # By sending in entropy ->
    entropy = "any object whose str() representation has randomness"
    csprng = seeder(entropy)  # entropy can be added here
    csprng(None)
    seed = csprng(entropy)  # &/or entropy can be added here
    """
    seed, seed_key = safe_symm_keypair(entropy, refresh, runs)
    kdf = sha3_512(seed + seed_key)
    while True:
        entropy = str(entropy).encode()
        kdf.update(seed + seed_key + entropy)
        seed_key = kdf.digest()
        kdf.update(seed + seed_key + entropy)
        seed = kdf.digest()
        kdf.update(seed + seed_key + entropy)
        entropy = yield kdf.hexdigest()


@comprehension()
async def anon0_digit_stream(key=salt(), stream_key=""):
    """
    Creates a deterministic stream of non-zero digits from a key.
    """
    seed = await asha_512(key)
    while True:
        stream_key = await aint(await anc_512(seed, key, stream_key), 16)
        for char in (await astr(stream_key))[4:].replace("0", ""):
            yield await aint(char)


@comprehension()
def non0_digit_stream(key=salt(), stream_key=""):
    """
    Creates a deterministic stream of non-zero digits from a key.
    """
    seed = sha_512(key)
    while True:
        stream_key = int(nc_512(seed, key, stream_key), 16)
        for char in (str(stream_key)[4:]).replace("0", ""):
            yield int(char)


@comprehension()
async def adigit_stream(key=salt(), stream_key=""):
    """
    Creates a deterministic stream of digits from a key.
    """
    seed = await asha_512(key)
    while True:
        stream_key = await aint(await anc_512(seed, key, stream_key), 16)
        for char in (await astr(stream_key))[4:]:
            yield await aint(char)


@comprehension()
def digit_stream(key=salt(), stream_key=""):
    """
    Creates a deterministic stream of digits from a key.
    """
    seed = sha_512(key)
    while True:
        stream_key = int(nc_512(seed, key, stream_key), 16)
        for char in str(stream_key)[4:]:
            yield int(char)


@comprehension()
async def aleaf_walk(
    stamp="", left=frozenset("02468ace"), right=frozenset("13579bdf")
):
    """
    Walks a binary choice tree according to membership tests for each
    item in ``stamp`` on the two iterables ``left `` & ``right``. Yields
    the current step number and a boolean value, ``True`` if the current
    item of ``stamp`` is in ``left``, else ``False`` if it's in ``right``.
    """
    async for num, turn in Enumerate(stamp, start=1):
        if turn in left:
            yield num, True
        elif turn in right:
            yield num, False


@comprehension()
def leaf_walk(
    stamp="", left=frozenset("02468ace"), right=frozenset("13579bdf")
):
    """
    Walks a binary choice tree according to membership tests for each
    item in ``stamp`` on the two iterables ``left `` & ``right``. Yields
    the current step number and a boolean value, ``True`` if the current
    item of ``stamp`` is in ``left``, else ``False`` if it's in ``right``.
    """
    for num, turn in enumerate(stamp, start=1):
        if turn in left:
            yield num, True
        elif turn in right:
            yield num, False


async def aleaf(
    stamp="",
    mod=bits[256],
    left=frozenset("02468ace"),
    right=frozenset("13579bdf"),
    total=primes[256][0],
):
    """
    Returns a unique name of type ``int`` based on the permutations of
    ``stamp``'s elements' membership in ``left`` and ``right``.
    """
    prime = primes[16][0]
    async for num, turn in aleaf_walk(stamp, left, right):
        if turn:
            total += num
        else:
            total *= prime
    return total % mod


def leaf(
    stamp="",
    max_binary_choices=bits[256],
    left=frozenset("02468ace"),
    right=frozenset("13579bdf"),
    prime_strength_bits=primes[256][0],
):
    """
    Returns a unique name of type ``int`` based on the permutations of
    ``stamp``'s elements' membership in ``left`` and ``right``.
    """
    total = prime_strength_bits
    prime_multiple = primes[16][0]
    for step, turn in leaf_walk(stamp, left, right):
        if turn:
            total += step
        else:
            total *= prime_multiple
    return total % max_binary_choices


@comprehension()
async def amake_uuid(length=16, salt=None):
    """
    Creates a deterministic, unique user id from a ``salt`` & a ``stamp``
    sent into coroutine.
    """
    stamp = None
    multiple = (length // 512) + 1
    salt = salt if salt != None else await acsprng(global_seed)
    async with Comprende().arelay(result=salt):
        while True:
            uuid = ""
            async for growth in arange(multiple):
                uuid += sha_512(uuid, stamp, salt)
            stamp = yield uuid[-1:-(1 + length):-1]


@comprehension()
def make_uuid(length=16, salt=None):
    """
    Creates a deterministic, unique user id from a ``salt`` & a ``stamp``
    sent into coroutine.
    """
    stamp = None
    multiple = (length // 512) + 1
    salt = salt if salt != None else csprng(global_seed)
    with Comprende().relay(result=salt):
        while True:
            uuid = ""
            for growth in range(multiple):
                uuid += sha_512(uuid, stamp, salt)
            stamp = yield uuid[-1:-(1 + length):-1]


try:
    # Initalize package entropy pool & cryptographically secure pseudo-
    # random number generators.
    global_seed_key = random_512(entropy=salt())
    global_seed = random_512(entropy=global_seed_key)
    csprng = seeder(global_seed).send
    acsprng = aseeder(csprng()).asend
    global_seed_key = run(acsprng())
    global_seed = run(acsprng(csprng(csprng())))
except RuntimeError as error:
    problem = "package's random seed initialization failed likely because "
    location = f"{__name__} from {__package__} "
    reason = f"was imported from within an async event loop."
    failure = RuntimeError(problem + location + reason)
    raise failure from error


__extras = {
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "achoice": achoice,
    "acsprng": acsprng,
    "adigit_stream": adigit_stream,
    "agenerate_big_range_bounds": agenerate_big_range_bounds,
    "agenerate_small_range_bounds": agenerate_small_range_bounds,
    "agenerate_unique_range_bounds": agenerate_unique_range_bounds,
    "aleaf": aleaf,
    "aleaf_walk": aleaf_walk,
    "amake_uuid": amake_uuid,
    "anon0_digit_stream": anon0_digit_stream,
    "aprime_table": aprime_table,
    "arandom_256": arandom_256,
    "arandom_512": arandom_512,
    "arandom_number_generator": arandom_number_generator,
    "arandom_prime": arandom_prime,
    "arandom_range": arandom_range,
    "arandom_range_gen": arandom_range_gen,
    "arandom_sleep": arandom_sleep,
    "asafe_symm_keypair": asafe_symm_keypair,
    "asalt": asalt,
    "asalted_multiply": asalted_multiply,
    "aseeder": aseeder,
    "atemplate_unique_number": atemplate_unique_number,
    "auniform": auniform,
    "aunique_big_int": aunique_big_int,
    "aunique_hash": aunique_hash,
    "aunique_integer": aunique_integer,
    "aunique_lower_bound": aunique_lower_bound,
    "aunique_upper_bound": aunique_upper_bound,
    "aurandom": aurandom,
    "aurandom_hash": aurandom_hash,
    "aurandom_number": aurandom_number,
    "choice": choice,
    "csprng": csprng,
    "digit_stream": digit_stream,
    "generate_big_range_bounds": generate_big_range_bounds,
    "generate_small_range_bounds": generate_small_range_bounds,
    "generate_unique_range_bounds": generate_unique_range_bounds,
    "leaf": leaf,
    "leaf_walk": leaf_walk,
    "make_uuid": make_uuid,
    "next_prime": next_prime,
    "non0_digit_stream": non0_digit_stream,
    "prev_prime": prev_prime,
    "prime_table": prime_table,
    "random_256": random_256,
    "random_512": random_512,
    "random_number_generator": random_number_generator,
    "random_prime": random_prime,
    "random_range": random_range,
    "random_range_gen": random_range_gen,
    "random_sleep": random_sleep,
    "safe_symm_keypair": safe_symm_keypair,
    "salt": salt,
    "salted_multiply": salted_multiply,
    "seeder": seeder,
    "template_unique_number": template_unique_number,
    "uniform": uniform,
    "unique_big_int": unique_big_int,
    "unique_hash": unique_hash,
    "unique_integer": unique_integer,
    "unique_lower_bound": unique_lower_bound,
    "unique_upper_bound": unique_upper_bound,
    "urandom": urandom,
    "urandom_hash": urandom_hash,
    "urandom_number": urandom_number,
}


randoms = commons.Namespace.make_module("randoms", mapping=__extras)

