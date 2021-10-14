# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "randoms",
    "abytes_seeder",
    "acsprng",
    "agenerate_salt",
    "amake_uuids",
    "arandom_256",
    "arandom_512",
    "bytes_seeder",
    "csprng",
    "generate_salt",
    "make_uuids",
    "random_256",
    "random_512",
]


__doc__ = (
    "A collection of functions which use & create varying levels of ent"
    "ropy for end-user cryptographic applications."
)


import math
import base64
from os import getpid
import random as _random
from collections import deque
from hashlib import sha3_256, sha3_512, shake_256
from secrets import choice, token_bytes
from secrets import randbits as token_bits
from ._exceptions import *
from ._typing import Typing
from .commons import PrimeGroups
from .commons import *
from commons import *
from .asynchs import *
from .asynchs import asleep, asyncio, gather, sleep, time, run
from .generics import Domains, Hasher
from .generics import sha3__256, asha3__256
from .generics import sha3__512, asha3__512
from .generics import Comprende, comprehension
from .generics import sha3__512_hmac, asha3__512_hmac


def _load_sympy():
    """
    Sympy is terribly slow to import. So, we only import the package if
    its prime number functionalities are desired by the user.
    """
    global sympy, _is_prime, _prev_prime, _next_prime, _unique_prime

    import sympy
    from sympy import isprime as _is_prime
    from sympy import prevprime as _prev_prime
    from sympy import nextprime as _next_prime
    from sympy import randprime as _unique_prime


def is_prime(number: int):
    """
    Pass through function for the `sympy.isprime` function.
    """
    if "sympy" not in globals():
        _load_sympy()
    return _is_prime(number)


def prev_prime(number: int):
    """
    Pass through function for the `sympy.prevprime` function.
    """
    if "sympy" not in globals():
        _load_sympy()
    return _prev_prime(number)


def next_prime(number: int):
    """
    Pass through function for the `sympy.nextprime` function.
    """
    if "sympy" not in globals():
        _load_sympy()
    return _next_prime(number)


async def acreate_prime(bits: int = 2048):
    """
    Asynchronous wrapper around a `sympy.randprime` abstraction which
    locates primes based on a user-defined amount of ``bits``.
    """
    return await aunique_prime(1 << (bits - 1), 1 << bits)


def create_prime(bits: int = 2048):
    """
    Synchronous wrapper around a `sympy.randprime` abstraction which
    locates primes based on a user-defined amount of ``bits``.
    """
    return unique_prime(1 << (bits - 1), 1 << bits)


async def aunique_prime(low: int, high: int, **kw):
    """
    Asynchronous wrapper around `sympy.randprime`.
    """
    await asleep()
    return unique_prime(low, high, **kw)


def unique_prime(low: int, high: int, **kw):
    """
    Pass through function for the `sympy.randprime` function.
    """
    if "sympy" not in globals():
        _load_sympy()
    return _unique_prime(low, high, **kw)


class PrimeTools(PrimeGroups):
    """
    A collection of mostly small prime moduli & each of their respective
    primitive roots organized by bit length.
    """

    __slots__ = ()

    UniformPrimes = UniformPrimes

    acreate_prime = staticmethod(acreate_prime)
    aunique_prime = staticmethod(aunique_prime)
    create_prime = staticmethod(create_prime)
    is_prime = staticmethod(is_prime)
    next_prime = staticmethod(next_prime)
    prev_prime = staticmethod(prev_prime)
    unique_prime = staticmethod(unique_prime)


async def auniform(*a, **kw):
    """
    Asynchronous version of the standard library's `random.uniform`.
    """
    await asleep()
    return uniform(*a, **kw)


async def achoice(iterable):
    """
    Asynchronous version of the standard library's `secrets.choice`.
    """
    await asleep()
    return choice(iterable)


async def aunique_range(*a, **kw):
    """
    Asynchronous version of the standard library's `random.randrange`.
    """
    await asleep()
    return unique_range(*a, **kw)


async def arandom_sleep(span: Typing.PositiveRealNumber = 2):
    """
    Asynchronously sleeps for a psuedo-random portion of ``span`` time,
    measured in seconds.
    """
    return await asleep(span * await auniform(0, 1))


def random_sleep(span: Typing.PositiveRealNumber = 2):
    """
    Synchronously sleeps for a psuedo-random portion of ``span`` time,
    measured in seconds.
    """
    return sleep(span * uniform(0, 1))


async def atoken_bits(size: int):
    """
    Returns ``size`` number of bits from `secrets.randbits`.
    """
    await asleep()
    return token_bits(size)


async def atoken_bytes(size: int):
    """
    Returns ``size`` bytes of `secrets.token_bytes` entropy.
    """
    await asleep()
    return token_bytes(size)


async def atoken_hash(size: int):
    """
    Feeds ``size`` bytes of `secrets.token_bytes` entropy into a
    `sha3_512` object that carries one of the package's entropy pools &
    returns the hash. If ``size`` is smaller than 64 (bytes), then 64 is
    used instead. This ensures the entropy object receives at least its
    bitrate of 72 on each call.
    """
    domain = Domains.ENTROPY  # 8 bytes
    size = size if size >= 64 else 64  # at least the sha3_512 bitrate
    result = await _entropy.ahash(domain, await atoken_bytes(size))
    return result.hex()


def token_hash(size: int):
    """
    Feeds ``size`` bytes of `secrets.token_bytes` entropy into a
    `sha3_512` object that carries one of the package's entropy pools &
    returns the hash. If ``size`` is smaller than 64 (bytes), then 64 is
    used instead. This ensures the entropy object receives at least its
    bitrate of 72 on each call.
    """
    domain = Domains.ENTROPY  # 8 bytes
    size = size if size >= 64 else 64  # at least the sha3_512 bitrate
    return _entropy.hash(domain, token_bytes(size)).hex()


async def _aunique_hash():
    """
    Returns a ``hashlib.sha3_512`` string hash of an integer which is
    greater than a 64-byte number by many orders of magnitude.
    """
    number = await _aunique_big_int()
    hashed_number = await _entropy.ahash(number.to_bytes(576, "big"))
    return hashed_number.hex()


def _unique_hash():
    """
    Returns a ``hashlib.sha3_512`` string hash of an integer which is
    greater than a 64-byte number by many orders of magnitude.
    """
    number = _unique_big_int()
    return _entropy.hash(number.to_bytes(576, "big")).hex()


async def _aunique_integer():
    """
    Returns an ``int(hex_hash, 16)`` value of a unique hexadecimal hash.
    """
    return int(await _aunique_hash(), 16)


def _unique_integer():
    """
    Returns an ``int(hex_hash, 16)`` value of a unique hexadecimal hash.
    """
    return int(_unique_hash(), 16)


async def _aunique_big_int():
    """
    Uses unique lower & upper bound integers to feed into the standard
    library's ``randrange`` function & returns the result.
    """
    upper_bound = _aunique_upper_bound()
    lower_bound = _aunique_lower_bound()
    ranges = [await lower_bound, await upper_bound]
    return await aunique_range(*ranges) ^ await atoken_bits(256)


def _unique_big_int():
    """
    Uses unique lower & upper bound integers to feed into the standard
    library's ``randrange`` function & returns the result.
    """
    upper_bound = _unique_upper_bound()
    lower_bound = _unique_lower_bound()
    return unique_range(lower_bound, upper_bound) ^ token_bits(256)


async def _aunique_lower_bound():
    """
    Returns a unique number where 2**1536 < number < 2**2048 from a pair
    of global, semi-constant 256-bit - 512-bit seeds.
    """
    global SMALL_UPPER_BOUND
    global SMALL_LOWER_BOUND
    number_0 = await aunique_range(SMALL_LOWER_BOUND, SMALL_UPPER_BOUND)
    number_1 = await aunique_range(SMALL_LOWER_BOUND, SMALL_UPPER_BOUND)
    return await _asalt_multiply(number_0, number_1)


def _unique_lower_bound():
    """
    Returns a unique number where 2**1536 < number < 2**2048 from a pair
    of global, semi-constant 256-bit - 512-bit seeds.
    """
    global SMALL_UPPER_BOUND
    global SMALL_LOWER_BOUND
    number_0 = unique_range(SMALL_LOWER_BOUND, SMALL_UPPER_BOUND)
    number_1 = unique_range(SMALL_LOWER_BOUND, SMALL_UPPER_BOUND)
    return _salt_multiply(number_0, number_1)


async def _aunique_upper_bound():
    """
    Returns a unique number where 2**4096 < number < 2**4608 from a pair
    of global, semi-constant 1536-bit - 2048-bit seeds.
    """
    global BIG_UPPER_BOUND
    global BIG_LOWER_BOUND
    number_0 = await aunique_range(BIG_LOWER_BOUND, BIG_UPPER_BOUND)
    number_1 = await aunique_range(BIG_LOWER_BOUND, BIG_UPPER_BOUND)
    return await _asalt_multiply(number_0, number_1)


def _unique_upper_bound():
    """
    Returns a unique number where 2**4096 < number < 2**4608 from a pair
    of global, semi-constant 1536-bit - 2048-bit seeds.
    """
    global BIG_UPPER_BOUND
    global BIG_LOWER_BOUND
    number_0 = unique_range(BIG_LOWER_BOUND, BIG_UPPER_BOUND)
    number_1 = unique_range(BIG_LOWER_BOUND, BIG_UPPER_BOUND)
    return _salt_multiply(number_0, number_1)


async def _atemplate_unique_number(number: int):
    """
    A pseudo-random number generator helper function. An alternative
    method of constructing unique numbers. The length of the number
    argument will be the same as the length of the number that's
    returned.
    """
    seed = await _asalt()
    number = int(number)  # throw if not a number
    while seed < number:
        seed *= await _asalt()
    return int(str(seed)[: len(str(number))])


def _template_unique_number(number: int):
    """
    A pseudo-random number generator helper function. An alternative
    method of constructing unique numbers. The length of the number
    argument will be the same as the length of the number that's
    returned.
    """
    seed = _salt()
    number = int(number)  # throw if not a number
    while seed < number:
        seed *= _salt()
    return int(str(seed)[: len(str(number))])


async def _agenerate_small_range_bounds():
    """
    Generates a pair of unique global, semi-constant seeds which feed
    uniqueness into the lower bound of ``random.randrange``, with the
    consideration that guessing its output is aided by knowing what its
    inputs were. Making its inputs unknown should then help keep its
    outputs unknown.
    """
    global SMALL_UPPER_BOUND
    global SMALL_LOWER_BOUND
    SMALL_UPPER_BOUND = await _atemplate_unique_number(1 << 512)
    SMALL_LOWER_BOUND = await _atemplate_unique_number(1 << 256)


def _generate_small_range_bounds():
    """
    Generates a pair of unique global, semi-constant seeds which feed
    uniqueness into the lower bound of ``random.randrange``, with the
    consideration that guessing its output is aided by knowing what its
    inputs were. Making its inputs unknown should then help keep its
    outputs unknown.
    """
    global SMALL_UPPER_BOUND
    global SMALL_LOWER_BOUND
    SMALL_UPPER_BOUND = _template_unique_number(1 << 512)
    SMALL_LOWER_BOUND = _template_unique_number(1 << 256)


async def _agenerate_big_range_bounds():
    """
    Generates a pair of unique global, semi-constant seeds which feed
    uniqueness into the upper bound of ``random.randrange``, with the
    consideration that guessing its output is aided by knowing what its
    inputs were. Making its inputs unknown should then help keep its
    outputs unknown.
    """
    global BIG_UPPER_BOUND
    global BIG_LOWER_BOUND
    BIG_UPPER_BOUND = await _atemplate_unique_number(1 << 2048)
    BIG_LOWER_BOUND = await _atemplate_unique_number(1 << 1536)


def _generate_big_range_bounds():
    """
    Generates a pair of unique global, semi-constant seeds which feed
    uniqueness into the upper bound of ``random.randrange``, with the
    consideration that guessing its output is aided by knowing what its
    inputs were. Making its inputs unknown should then help keep its
    outputs unknown.
    """
    global BIG_UPPER_BOUND
    global BIG_LOWER_BOUND
    BIG_UPPER_BOUND = _template_unique_number(1 << 2048)
    BIG_LOWER_BOUND = _template_unique_number(1 << 1536)


async def _agenerate_unique_range_bounds():
    """
    Generates two pairs of unique global, semi-constant seeds which
    feed uniqueness into ``random.randrange``, with the consideration
    that guessing its output is aided by knowing what its inputs were.
    Making its inputs unknown should then help keep its outputs unknown.
    """
    random.seed(token_bytes(2500))
    await _agenerate_small_range_bounds()
    await _agenerate_big_range_bounds()


def _generate_unique_range_bounds():
    """
    Generates two pairs of unique global, semi-constant seeds which
    feed uniqueness into ``random.randrange``, with the consideration
    that guessing its output is aided by knowing what its inputs were.
    Making its inputs unknown should then help keep its outputs unknown.
    """
    random.seed(token_bytes(2500))
    _generate_small_range_bounds()
    _generate_big_range_bounds()


async def _asalt_multiply(*numbers: Typing.Iterable[int]):
    """
    Allows for non-commutative multiplication. This assists pseudo-
    random number generators in turning combinations of low entropy
    number sources into permutations. This greatly increases the amount
    of knowledge an attacker must have to perform pre-image or known-
    plaintext attacks on the calculations usings the hashes of those
    permutations.
    """
    global _mix, _mod, _seed, _offset

    _mix ^= abs(sum((_seed, _offset, *numbers)))
    mix = _mix = _mix % _mod
    _seed ^= mix
    start = _seed
    _offset ^= _seed
    await asleep()
    for number in numbers:
        mix += _offset
        start *= number ^ mix
    await asleep()
    return start ^ _seed


def _salt_multiply(*numbers: Typing.Iterable[int]):
    """
    Allows for non-commutative multiplication. This assists pseudo-
    random number generators in turning combinations of low entropy
    number sources into permutations. This greatly increases the amount
    of knowledge an attacker must have to perform pre-image or known-
    plaintext attacks on the calculations usings the hashes of those
    permutations.
    """
    global _mix, _mod, _seed, _offset

    _mix ^= abs(sum((_seed, _offset, *numbers)))
    mix = _mix = _mix % _mod
    _seed ^= mix
    start = _seed
    _offset ^= _seed
    for number in numbers:
        mix += _offset
        start *= number ^ mix
    return start ^ _seed


class WeakEntropy:
    """
    Creates objects which can produce any user specified amount of
    entropic bytes using a fast, but not very strong PRNG.
    """

    __slots__ = ("_raw_seed", "_prng")

    _make_pid = staticmethod(lambda: getpid().to_bytes(6, "big"))
    _make_timestamp = staticmethod(
        lambda: int(1_000_000 * time()).to_bytes(12, "big")
    )

    def __init__(self):
        """
        Creates the starting seed entropy & the weak PRNG.
        """
        self._raw_seed = token_bytes(136)
        self._prng = Hasher(b"".join(self._seed()), obj=shake_256)

    def _seed(self, salt: bytes = token_bytes(56)):
        """
        Yields a series of fresh entropic values which are fed into the
        instance's PRNG, which also more safely differentiate instance
        outputs between possible forked processes.
        """
        yield self._make_timestamp()
        yield self._make_pid()
        yield salt
        yield _entropy.hash(Domains.SEED, _pool[0])
        yield self._raw_seed

    async def atoken_bytes(self, size: int):
        """
        Returns ``output_size`` number of pseudo-random bytes.
        """
        return await self._prng.ahash(*self._seed(), size=size)

    def token_bytes(self, size: int):
        """
        Returns ``output_size`` number of pseudo-random bytes.
        """
        return self._prng.hash(*self._seed(), size=size)


class EntropyDaemon:
    """
    Creates & manages a background thread which asynchronously extracts
    from & seeds new entropy into this module's entropy pools. Mixing
    background threading, asynchrony, pseudo random sleeps & sha3_512
    hashing with a single, shared global object results in highly
    unpredictable & non-deterministic effects on entropy generation for
    the whole package.
    """

    __slots__ = (
        "_cancel",
        "_currently_mutating_frequency",
        "_daemon",
        "_frequency",
        "_initial_frequency",
        "_pool",
    )

    def __init__(
        self,
        entropy_pool: Typing.SupportsAppendleft,
        *,
        frequency: Typing.PositiveRealNumber = 1,
    ):
        """
        Prepares an instance to safely start a background thread.
        """
        self._pool = entropy_pool
        self._daemon = None
        self._cancel = False
        self._currently_mutating_frequency = False
        self.set_frequency(frequency)

    async def _anew_snapshot(self):
        """
        Returns 144-bytes of pseudo-random values from the instance's
        entropy pool & the `secrets.token_bytes` function.
        """
        await asleep()
        return await atoken_bytes(32) + self._pool[0] + self._pool[-1][:48]

    def _set_temporary_frequency(
        self,
        frequency: Typing.PositiveRealNumber,
        duration: Typing.PositiveRealNumber,
    ):
        """
        Sets a temporary maximum number of seconds a started entropy
        daemon will pseudo-randomly sleep in-between each iteration. The
        frequency will return to its initial value after ``duration``
        number of seconds.
        """
        try:
            self._frequency = frequency
            sleep(duration)
        finally:
            self._frequency = self._initial_frequency
            self._currently_mutating_frequency = False

    def set_temporary_frequency(
        self,
        frequency: Typing.PositiveRealNumber = 0.001,
        *,
        duration: Typing.PositiveRealNumber = 1,
    ):
        """
        Sets a temporary maximum number of seconds a started entropy
        daemon will pseudo-randomly sleep in-between each iteration. The
        frequency will return to its initial value after ``duration``
        number of seconds.
        """
        if not self._currently_mutating_frequency:
            self._currently_mutating_frequency = True
            Threads.submit(
                self._set_temporary_frequency, frequency, duration
            )
        return self

    def set_frequency(self, frequency: Typing.PositiveRealNumber = 1):
        """
        Sets the maximum number of seconds a started entropy daemon will
        pseudo-randomly sleep in-between each iteration. Setting the
        ``frequency`` to smaller numbers will cause more cpu power &
        to be consumed by the background daemon thread.
        """
        self._frequency = frequency
        self._initial_frequency = frequency
        return self

    async def _araw_loop(self):
        """
        Takes snapshots of & feeds entropy into the module's entropy
        pools before & after sleeping for a pseudo-random amount of time.
        This is done asynchronously & in a background thread to increase
        the unpredictability & non-determinism of entropy generation.
        """
        while True:
            seed = await self._anew_snapshot()
            self._pool.appendleft(await _entropy.ahash(seed))
            await arandom_sleep(self._frequency)
            self._pool.appendleft(await _entropy.ahash(seed))
            if self._cancel:
                break

    def start(self):
        """
        Runs an entropy updating & gathering thread in the background.

        This supports the package by asynchronously & continuously
        seeding into & extracting new entropy from its entropy pools.
        """
        state = Threads._state_machine().list()
        self._daemon = Threads._type(
            target=Threads._run_async_func,
            args=[self._araw_loop],
            kwargs=dict(_state=state),
        )
        self._daemon.daemon = True
        self._daemon.start()
        return self

    def cancel(self):
        """
        Cancels the background thread.
        """
        self._cancel = True
        return self


#  initialize a global entropy pool
_pool = deque([token_bytes(64), token_bytes(64)], maxlen=256)

#  initialize the global hashing object that also collects entropy
_entropy = Hasher(token_bytes(304) + b"".join(_pool))

#  avert event loop clashes
run = asyncio.new_event_loop().run_until_complete

#  initializing weakly entropic functions
random = _random.Random(token_bytes(2500))
uniform = random.uniform
unique_range = random.randrange

_mod = primes[256][-1]
_offset = token_bits(256)
_mix = int(sha3__256(token_hash(64), _mod, _offset), 16)
_seed = int(sha3__256(token_hash(64), _mix, _offset), 16)
_numbers = (_mix, _seed, _offset)

_ = _salt_multiply(*_numbers)
run(_asalt_multiply(_, *_numbers))

_initial_entropy = deque(
    [token_bits(1024), token_bits(1024)], maxlen=2
)

# begin the entropy gathering daemon
_entropy_daemon = EntropyDaemon(_pool).start()
_entropy_daemon.set_temporary_frequency(0.001, duration=2)


async def _asalt(*, _entropy: deque = _initial_entropy):
    """
    Returns a low-grade entropy number from cached & ratcheted system
    entropy.
    """
    _entropy.appendleft(int(await asha3__256(_entropy, token_hash(64)), 16))
    return await _asalt_multiply(*_entropy)


def _salt(*, _entropy: deque = _initial_entropy):
    """
    Returns a low-grade entropy number from cached & ratcheted system
    entropy.
    """
    _entropy.appendleft(int(sha3__256(_entropy, token_hash(64)), 16))
    return _salt_multiply(*_entropy)


async def arandom_number_generator(
    entropy: Typing.Any = sha3__512(_salt(), hex=False),
    *,
    refresh: bool = False,
    rounds: int = 0,
):
    """
    We propose several methods for producing cryptographically secure
    pseudo-random numbers, and implement them in this function. This
    function is implemented to securely produce entropy under threat
    models that don't include attackers that can maliciously analyze
    users' machines' memory. Such a capability represents a serious
    threat to the unpredictability of the CSPRNG, as it suggests the
    ability to read any arbitrary secrets stored by the machine.

    0. Use many component PRNGs with differing designs & sources to
    spread the risk of any particularly weak ones & benefit from the
    most reliable ones by securely mixing the entropy bits they may
    produce together.

    1. Make the search space for an attacker to guess the inputs to any
    of the component PRNGs intractibly large. We can do this by using
    pseudo-random seeds that are very large numbers (anywhere from
    256-bits to 4600-bits).

    2. Make new seeds after &/or before each use, import-time &/or
    function call.

    3. Use cryptographic hashing on the inputs & outputs of component
    PRNGs to unlink internal states from their outputs.

    4. Incorporate forward-secure key ratcheting algorithms at key
    points along the PRNGs' communications routes with themselves & the
    user. They work together, with proper coordination, to produce
    randomness in a way that alone they wouldn't.

    5. Use the powerful sha3_256 or sha3_512 hashing algorithms for all
    hashing.

    6. Persist & use a sha3_512 hashing object for hidden &/or internal
    procedures across the module for the automatic & non-deterministic
    collection of entropy throughout normal use of the module.

    7. Further frustrate an attacker by necessitating that they perform
    an order prediction attack on the results of the CSPRNG's component
    PRNGs. We do this by using asynchrony entirely throughout the CSPRNG
    with random sleeps, and using a non-commutative, salted, modular
    multiplication to combine internal states into a single element in
    its ratcheting internal state.

    8. Allow the user to securely mix any extra entropy they have access
    to into the CSPRNG's state machine. This mitigates some impacts of
    the malicious analysis of memory by an adversary.

    9. Iterate and interleave all these methods enough times such that,
    if we assume each time the CSPRNG produces a 64-byte internal state,
    that only 1-bit of entropy is produced. Then, by initializing up to
    a cache of 256 ratcheting states then the ``random_number_generator``
    algorithm here would have at least 256-bits of entropy.

    10. Use a background thread which continuously hashes & updates two
    of the package's entropy pools with new entropic material & their
    internal states. This adds unpredictable alterations to the pools
    concurrently with the running of the package.

    **** **** **** **** **** **** **** **** **** **** **** **** ****
    Our implementation analysis is NOT rigorous or conclusive, though
    soley based on the constraints stated above, our assumptions of
    randomness should be reasonable estimates within the threat model
    where an attacker cannot arbitrarily analyze users' machines'
    memory.
    **** **** **** **** **** **** **** **** **** **** **** **** ****
    """
    domain = Domains.ENTROPY
    refresh = True if (rounds or refresh) else False
    rounds = rounds if rounds else 26
    _entropy_daemon.set_temporary_frequency(0.001, duration=1)

    if entropy.__class__ is not bytes:
        entropy = str(entropy).encode()

    if refresh or not _pool:

        async def create_unique_multiple(seed: int):
            return await _asalt_multiply(
                seed, await _aunique_integer(), await atoken_bits(256)
            )

        async def big_modulation(*args):
            return await _asalt_multiply(
                *args, await atoken_bits(256)
            ) % await achoice([primes[512][-1], primes[513][0]])

        async def modular_multiplication():
            seed = await _asalt() % await achoice(primes[512])
            await arandom_sleep(0.003)
            multiples = (create_unique_multiple(seed) for _ in range(3))
            multiples = [await multiple for multiple in multiples]
            result = await big_modulation(seed, *multiples)
            await _entropy.ahash(
                domain, result.to_bytes(64, "big"), seed.to_bytes(64, "big")
            )

        async def add_to_pool():
            seed = await atoken_bytes(32)
            await arandom_sleep(0.003)
            _pool.appendleft(await _entropy.ahash(domain, entropy, seed))

        async def start_generator(rounds, tasks=deque()):
            for _ in range(rounds):
                await asleep()
                tasks.appendleft(modular_multiplication())
                for _ in range(10):
                    tasks.appendleft(add_to_pool())
            await gather(
                *sorted(tasks, key=lambda val: token_bytes(16)),
                return_exceptions=True,
            )

        await _agenerate_unique_range_bounds()
        await start_generator(rounds)
        await _agenerate_unique_range_bounds()
    else:
        _pool.appendleft(
            await _entropy.ahash(domain, await atoken_bytes(64), entropy)
        )

    return await _entropy.ahash(domain, token_bytes(32), entropy, *_pool)


def random_number_generator(
    entropy: Typing.Any = sha3__512(_salt(), hex=False),
    *,
    refresh: bool = False,
    rounds: int = 0,
):
    """
    We propose several methods for producing cryptographically secure
    pseudo-random numbers, and implement them in this function. This
    function is implemented to securely produce entropy under threat
    models that don't include attackers that can maliciously analyze
    users' machines' memory. Such a capability represents a serious
    threat to the unpredictability of the CSPRNG, as it suggests the
    ability to read any arbitrary secrets stored by the machine.

    0. Use many component PRNGs with differing designs & sources to
    spread the risk of any particularly weak ones & benefit from the
    most reliable ones by securely mixing the entropy bits they may
    produce together.

    1. Make the search space for an attacker to guess the inputs to any
    of the component PRNGs intractibly large. We can do this by using
    pseudo-random seeds that are very large numbers (anywhere from
    256-bits to 4600-bits).

    2. Make new seeds after &/or before each use, import-time &/or
    function call.

    3. Use cryptographic hashing on the inputs & outputs of component
    PRNGs to unlink internal states from their outputs.

    4. Incorporate forward-secure key ratcheting algorithms at key
    points along the PRNGs' communications routes with themselves & the
    user. They work together, with proper coordination, to produce
    randomness in a way that alone they wouldn't.

    5. Use the powerful sha3_256 or sha3_512 hashing algorithms for all
    hashing.

    6. Persist & use a sha3_512 hashing object for hidden &/or internal
    procedures across the module for the automatic & non-deterministic
    collection of entropy throughout normal use of the module.

    7. Further frustrate an attacker by necessitating that they perform
    an order prediction attack on the results of the CSPRNG's component
    PRNGs. We do this by using asynchrony entirely throughout the CSPRNG
    with random sleeps, and using a non-commutative, salted, modular
    multiplication to combine internal states into a single element in
    its ratcheting internal state.

    8. Allow the user to securely mix any extra entropy they have access
    to into the CSPRNG's state machine. This mitigates some impacts of
    the malicious analysis of memory by an adversary.

    9. Iterate and interleave all these methods enough times such that,
    if we assume each time the CSPRNG produces a 64-byte internal state,
    that only 1-bit of entropy is produced. Then, by initializing up to
    a cache of 256 ratcheting states then the ``random_number_generator``
    algorithm here would have at least 256-bits of entropy.

    10. Use a background thread which continuously hashes & updates two
    of the package's entropy pools with new entropic material & their
    internal states. This adds unpredictable alterations to the pools
    concurrently with the running of the package.

    **** **** **** **** **** **** **** **** **** **** **** **** ****
    Our implementation analysis is NOT rigorous or conclusive, though
    soley based on the constraints stated above, our assumptions of
    randomness should be reasonable estimates within the threat model
    where an attacker cannot arbitrarily analyze users' machines'
    memory.
    **** **** **** **** **** **** **** **** **** **** **** **** ****
    """
    domain = Domains.ENTROPY
    refresh = True if (rounds or refresh) else False
    rounds = rounds if rounds else 26
    _entropy_daemon.set_temporary_frequency(0.001, duration=1)

    if entropy.__class__ is not bytes:
        entropy = str(entropy).encode()

    if refresh or not _pool:

        async def create_unique_multiple(seed: int):
            return await _asalt_multiply(
                seed, await _aunique_integer(), await atoken_bits(256)
            )

        async def big_modulation(*args):
            return await _asalt_multiply(
                *args, await atoken_bits(256)
            ) % await achoice([primes[512][-1], primes[513][0]])

        async def modular_multiplication():
            seed = await _asalt() % await achoice(primes[512])
            await arandom_sleep(0.003)
            multiples = (create_unique_multiple(seed) for _ in range(3))
            multiples = [await multiple for multiple in multiples]
            result = await big_modulation(seed, *multiples)
            await _entropy.ahash(
                domain, result.to_bytes(64, "big"), seed.to_bytes(64, "big")
            )

        async def add_to_pool():
            seed = await atoken_bytes(32)
            await arandom_sleep(0.003)
            _pool.appendleft(await _entropy.ahash(domain, entropy, seed))

        async def start_generator(rounds, tasks=deque()):
            for _ in range(rounds):
                await asleep()
                tasks.appendleft(modular_multiplication())
                for _ in range(10):
                    tasks.appendleft(add_to_pool())
            await gather(
                *sorted(tasks, key=lambda val: token_bytes(16)),
                return_exceptions=True,
            )

        _generate_unique_range_bounds()
        run(start_generator(rounds))  # <- RuntimeError in event loops
        _generate_unique_range_bounds()
    else:
        _pool.appendleft(_entropy.hash(domain, token_bytes(64), entropy))

    return _entropy.hash(domain, token_bytes(32), entropy, *_pool)


async def arandom_256(
    entropy: Typing.Any = sha3__512(_salt(), hex=False),
    *,
    refresh: bool = False,
    rounds: int = 0,
):
    """
    A high-level public interface to simultaneously retreive from, &
    seed new user-defined amounts of entropy into the package's internal
    random number generator. This function then returns 32 random bytes.

    Users can pass any ``entropy`` they have access to into the function.
    If a user sets ``refresh`` or ``rounds`` to a truthy value, then the
    package's `random_number_generator` will iterate ``rounds`` number
    of times over its internal entropy pools & generators, cranking more
    entropy into the package the higher the number. Generating new
    entropy can be quite slow, so by default ``refresh`` is set to
    ``False``, & ``rounds`` is only set to 26, which fully replaces the
    contents of one of the package's entropy pools.
    """
    return sha3_256(
        Domains.ENTROPY
        + bytes.fromhex(await atoken_hash(64))
        + await arandom_number_generator(
            entropy=entropy, rounds=rounds, refresh=refresh
        )
    ).digest()


def random_256(
    entropy: Typing.Any = sha3__512(_salt(), hex=False),
    *,
    refresh: bool = False,
    rounds: int = 0,
):
    """
    A high-level public interface to simultaneously retreive from &,
    seed new user-defined amounts of entropy into the package's internal
    random number generator. This function then returns 32 random bytes.

    Users can pass any ``entropy`` they have access to into the function.
    If a user sets ``refresh`` or ``rounds`` to a truthy value, then the
    package's `random_number_generator` will iterate ``rounds`` number
    of times over its internal entropy pools & generators, cranking more
    entropy into the package the higher the number. Generating new
    entropy can be quite slow, so by default ``refresh`` is set to
    ``False``, & ``rounds`` is only set to 26, which fully replaces the
    contents of one of the package's entropy pools.
    """
    return sha3_256(
        Domains.ENTROPY
        + bytes.fromhex(token_hash(64))
        + random_number_generator(
            entropy=entropy, rounds=rounds, refresh=refresh
        )
    ).digest()


async def arandom_512(
    entropy: Typing.Any = sha3__512(_salt(), hex=False),
    *,
    refresh: bool = False,
    rounds: int = 0,
):
    """
    A high-level public interface to simultaneously retreive from &,
    seed new user-defined amounts of entropy into the package's internal
    random number generator. This function then returns 64 random bytes.

    Users can pass any ``entropy`` they have access to into the function.
    If a user sets ``refresh`` or ``rounds`` to a truthy value, then the
    package's `random_number_generator` will iterate ``rounds`` number
    of times over its internal entropy pools & generators, cranking more
    entropy into the package the higher the number. Generating new
    entropy can be quite slow, so by default ``refresh`` is set to
    ``False``, & ``rounds`` is only set to 26, which fully replaces the
    contents of one of the package's entropy pools.
    """
    return sha3_512(
        Domains.ENTROPY
        + bytes.fromhex(await atoken_hash(64))
        + await arandom_number_generator(
            entropy=entropy, rounds=rounds, refresh=refresh
        )
    ).digest()


def random_512(
    entropy: Typing.Any = sha3__512(_salt(), hex=False),
    *,
    refresh: bool = False,
    rounds: int = 0,
):
    """
    A high-level public interface to simultaneously retreive from &,
    seed new user-defined amounts of entropy into the package's internal
    random number generator. This function then returns 64 random bytes.

    Users can pass any ``entropy`` they have access to into the function.
    If a user sets ``refresh`` or ``rounds`` to a truthy value, then the
    package's `random_number_generator` will iterate ``rounds`` number
    of times over its internal entropy pools & generators, cranking more
    entropy into the package the higher the number. Generating new
    entropy can be quite slow, so by default ``refresh`` is set to
    ``False``, & ``rounds`` is only set to 26, which fully replaces the
    contents of one of the package's entropy pools.
    """
    return sha3_512(
        Domains.ENTROPY
        + bytes.fromhex(token_hash(64))
        + random_number_generator(
            entropy=entropy, rounds=rounds, refresh=refresh
        )
    ).digest()


async def _asymmetric_keypair( # misnomer: asynchronous symmetric keypair!
    entropy: Typing.Any = sha3__512(_salt(), hex=False),
    refresh: bool = False,
    rounds: int = 0,
):
    """
    Returns two 64-byte symmetric keys. This function updates the
    package's static random seeds before & after deriving the returned
    key pair. It also ratchets & pulls from the module's RNG.
    """
    global global_seed
    global global_seed_key

    await _agenerate_unique_range_bounds()
    seed_key = sha3__512(
        entropy,
        global_seed,
        global_seed_key,
        await arandom_512(refresh=refresh, rounds=rounds),
        hex=False,
    )
    seed = await asha3__512_hmac(global_seed, key=seed_key, hex=False)
    global_seed_key = sha3__512_hmac(
        global_seed_key, key=seed_key, hex=False
    )
    global_seed = sha3__512_hmac(global_seed, key=seed, hex=False)
    await _agenerate_unique_range_bounds()
    return seed, seed_key


def _symmetric_keypair(
    entropy: Typing.Any = sha3__512(_salt(), hex=False),
    refresh: bool = False,
    rounds: int = 0,
):
    """
    Returns two 64-byte symmetric keys. This function updates the
    package's static random seeds before & after deriving the returned
    key pair. It also ratchets & pulls from the module's RNG.
    """
    global global_seed
    global global_seed_key

    _generate_unique_range_bounds()
    seed_key = sha3__512(
        entropy,
        global_seed,
        global_seed_key,
        random_512(refresh=refresh, rounds=rounds),
        hex=False,
    )
    seed = sha3__512_hmac(global_seed, key=seed_key, hex=False)
    global_seed_key = sha3__512_hmac(
        global_seed_key, key=seed_key, hex=False
    )
    global_seed = sha3__512_hmac(global_seed, key=seed, hex=False)
    _generate_unique_range_bounds()
    return seed, seed_key


@comprehension()
async def abytes_seeder(
    entropy: Typing.Any = sha3__512(_salt(), hex=False),
    *,
    refresh: bool = False,
    rounds: int = 0,
):
    """
    A fast cryptographically secure pseudo-random number generator that
    supports adding entropy during iteration. It securely hashes
    together the randomness produced from a key ratchet algorithm, OS
    psuedo-randomness, & this module's cpu-intensive & chaotic random
    number generator.

    Usage examples:

    # In async for loops ->
    async for seed in abytes_seeder():
        # do something with `seed`, a strong pseudo-random 64-byte hash

    # By awaiting next ->
    acsprng = abytes_seeder()
    seed = await next(acsprng)

    # By sending in entropy ->
    entropy = "any object as a source of randomness"
    acsprng = abytes_seeder(entropy)  # entropy can be added here
    await acsprng(None)
    seed = await acsprng(entropy)  # &/or entropy can be added here
    """
    domain = Domains.ENTROPY
    # misnomer: asynchronous symmetric keypair!
    seed, seed_key = await _asymmetric_keypair(entropy, refresh, rounds)
    output = sha3_512(domain + seed_key + seed).digest()
    rotation_key = await asha3__256(seed, seed_key, entropy, hex=False)
    while True:
        if not entropy:
            entropy = rotation_key
        elif entropy.__class__ is not bytes:
            entropy = repr(entropy).encode()
        output = await _entropy.ahash(
            domain, token_bytes(32), entropy, output
        )
        entropy = yield output


@comprehension()
def bytes_seeder(
    entropy: Typing.Any = sha3__512(_salt(), hex=False),
    *,
    refresh: bool = False,
    rounds: int = 0,
):
    """
    A fast cryptographically secure pseudo-random number generator that
    supports adding entropy during iteration. It securely hashes
    together the randomness produced from a key ratchet algorithm, OS
    psuedo-randomness, & this module's cpu-intensive & chaotic random
    number generator.

    Usage examples:

    # In for loops ->
    for seed in bytes_seeder():
        # do something with `seed`, a strong pseudo-random 64-byte hash

    # By calling next ->
    csprng = bytes_seeder()
    seed = next(csprng)

    # By sending in entropy ->
    entropy = "any object as a source of randomness"
    csprng = bytes_seeder(entropy)  # entropy can be added here
    csprng(None)
    seed = csprng(entropy)  # &/or entropy can be added here
    """
    domain = Domains.ENTROPY
    seed, seed_key = _symmetric_keypair(entropy, refresh, rounds)
    output = sha3_512(domain + seed_key + seed).digest()
    rotation_key = sha3__256(seed, seed_key, entropy, hex=False)
    while True:
        if not entropy:
            entropy = rotation_key
        elif entropy.__class__ is not bytes:
            entropy = repr(entropy).encode()
        output = _entropy.hash(domain, token_bytes(32), entropy, output)
        entropy = yield output


async def agenerate_salt(
    entropy: Typing.Any = sha3__512(_salt(), hex=False), *, size: int
):
    """
    Returns ``size`` cryptographically secure pseudo-random bytes &
    seeds new entropy into the acsprng generator.
    """
    if size > 64 or size < 8:
        raise Issue.invalid_length("salt", "min(8):max(64)")
    return (await acsprng(entropy))[:size]


def generate_salt(
    entropy: Typing.Any = sha3__512(_salt(), hex=False), *, size: int
):
    """
    Returns ``size`` cryptographically secure pseudo-random bytes &
    seeds new entropy into the acsprng generator.
    """
    if size > 64 or size < 8:
        raise Issue.invalid_length("salt", "min(8):max(64)")
    return csprng(entropy)[:size]


async def acsprng(entropy: Typing.Any = sha3__512(_salt(), hex=False)):
    """
    Takes in an arbitrary ``entropy`` value from the user to seed then
    return a 64-byte cryptographically secure pseudo-random value. This
    function also restarts the package's CSPRNG if it stalls, which,
    for example, can happen when CTRL-Cing in the middle of the
    generator's runtime. This makes sure the whole package doesn't come
    crashing down for users when the generator is halted unexpectedly.
    """
    global _acsprng
    try:
        return await _acsprng(entropy)
    except (StopAsyncIteration, ValueError):
        _acsprng = abytes_seeder.root(entropy).asend
        return await _acsprng(None)


def csprng(entropy: Typing.Any = sha3__512(_salt(), hex=False)):
    """
    Takes in an arbitrary ``entropy`` value from the user to seed then
    return a 64-byte cryptographically secure pseudo-random value. This
    function also restarts the package's CSPRNG if it stalls, which,
    for example, can happen when CTRL-Cing in the middle of the
    generator's runtime. This makes sure the whole package doesn't come
    crashing down for users when the generator is halted unexpectedly.
    """
    global _csprng
    try:
        return _csprng(entropy)
    except (StopIteration, ValueError):
        _csprng = bytes_seeder.root(entropy).send
        return _csprng(None)


@comprehension()
async def amake_uuids(*, size: int = 24, salt: Typing.Any = None):
    """
    Creates deterministic, ``size``-byte unique user ids from a ``salt``
    & a ``stamp`` sent into coroutine.
    """
    stamp = None
    salt = salt if salt else (await agenerate_salt(size=32)).hex()
    UUID = await asha3__512(Domains.UUID.hex(), salt)
    async with Comprende.aclass_relay(salt):
        while True:
            uuid = b""
            while len(uuid) < size:
                uuid += await asha3__512(UUID, salt, uuid, stamp, hex=False)
            stamp = yield base64.urlsafe_b64encode(uuid)[:size]


@comprehension()
def make_uuids(*, size: int = 24, salt: Typing.Any = None):
    """
    Creates deterministic, ``size``-byte unique user ids from a ``salt``
    & a ``stamp`` sent into coroutine.
    """
    stamp = None
    salt = salt if salt else generate_salt(size=32).hex()
    UUID = sha3__512(Domains.UUID.hex(), salt)
    with Comprende.class_relay(salt):
        while True:
            uuid = b""
            while len(uuid) < size:
                uuid += sha3__512(UUID, salt, uuid, stamp, hex=False)
            stamp = yield base64.urlsafe_b64encode(uuid)[:size]


global_seed_key = random_512(entropy=sha3__512(_salt(), hex=False))
global_seed = run(arandom_512(entropy=global_seed_key))
_csprng = bytes_seeder.root(global_seed).send
_acsprng = abytes_seeder.root(_csprng(None)).asend
global_seed_key = run(_acsprng(None))
global_seed = _csprng(global_seed_key)
run(_acsprng(global_seed))


extras = dict(
    EntropyDaemon=EntropyDaemon,
    PrimeTools=PrimeTools,
    WeakEntropy=WeakEntropy,
    __doc__=__doc__,
    __main_exports__=__all__,
    __package__=__package__,
    abytes_seeder=abytes_seeder,
    achoice=achoice,
    acsprng=acsprng,
    agenerate_salt=agenerate_salt,
    amake_uuids=amake_uuids,
    arandom_256=arandom_256,
    arandom_512=arandom_512,
    arandom_number_generator=arandom_number_generator,
    arandom_sleep=arandom_sleep,
    atoken_bits=atoken_bits,
    atoken_bytes=atoken_bytes,
    atoken_hash=atoken_hash,
    auniform=auniform,
    aunique_range=aunique_range,
    bytes_seeder=bytes_seeder,
    choice=choice,
    csprng=csprng,
    generate_salt=generate_salt,
    make_uuids=make_uuids,
    random_256=random_256,
    random_512=random_512,
    random_number_generator=random_number_generator,
    random_sleep=random_sleep,
    token_bits=token_bits,
    token_bytes=token_bytes,
    token_hash=token_hash,
    uniform=uniform,
    unique_range=unique_range,
)


randoms = commons.make_module("randoms", mapping=extras)

