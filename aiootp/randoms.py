# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["GUID", "acsprng", "csprng"]


__doc__ = (
    "A collection of functions which use & create varying levels of ent"
    "ropy for end-user cryptographic applications."
)


import math
import random as _random
from collections import deque
from secrets import choice, token_bytes
from secrets import randbits as token_bits
from hashlib import sha3_256, sha3_512, shake_256
from .__constants import *
from ._exceptions import *
from ._containers import UnmaskedGUID
from ._typing import Typing as t
from .commons import OpenNamespace
from .commons import make_module
from .asynchs import Threads
from .asynchs import (
    asleep,
    asyncio,
    gather,
    sleep,
    run,
    ns_time,
    ns_counter,
)
from .paths import SecurePath
from .paths import read_salt_file
from .generics import Domains, Hasher, Clock, BytesIO
from .generics import bytes_as_int, int_as_bytes


async def auniform(*a, **kw) -> float:
    """
    Asynchronous version of the standard library's `random.uniform`.
    """
    await asleep()
    return uniform(*a, **kw)


async def achoice(iterable: t.Iterable[t.Any]) -> t.Any:
    """
    Asynchronous version of the standard library's `secrets.choice`.
    """
    await asleep()
    return choice(iterable)


async def aunique_range(*a, **kw) -> int:
    """
    Asynchronous version of the standard library's `random.randrange`.
    """
    await asleep()
    return unique_range(*a, **kw)


async def arandom_sleep(span: t.PositiveRealNumber = 2) -> None:
    """
    Asynchronously sleeps for a psuedo-random portion of ``span`` time,
    measured in seconds.
    """
    await asleep(span * uniform(0, 1))


def random_sleep(span: t.PositiveRealNumber = 2) -> None:
    """
    Synchronously sleeps for a psuedo-random portion of ``span`` time,
    measured in seconds.
    """
    sleep(span * uniform(0, 1))


async def atoken_bits(size: int) -> int:
    """
    Returns ``size`` number of bits from `secrets.randbits`.
    """
    await asleep()
    return token_bits(size)


async def atoken_bytes(size: int) -> bytes:
    """
    Returns ``size`` bytes of `secrets.token_bytes` entropy.
    """
    await asleep()
    return token_bytes(size)


async def _asalt_multiply(*numbers: t.Iterable[int]) -> int:
    """
    Allows for non-commutative multiplication. This assists pseudo-
    random number generators in turning combinations of low entropy
    number sources into permutations. This greatly increases the amount
    of knowledge an attacker must have to perform pre-image or known-
    plaintext attacks on the calculations usings the hashes of those
    permutations.
    """
    global _mix, _mod, _seed, _offset

    _mix ^= abs(sum((_seed, _offset, ns_time(), ns_counter(), *numbers)))
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


def _salt_multiply(*numbers: t.Iterable[int]) -> int:
    """
    Allows for non-commutative multiplication. This assists pseudo-
    random number generators in turning combinations of low entropy
    number sources into permutations. This greatly increases the amount
    of knowledge an attacker must have to perform pre-image or known-
    plaintext attacks on the calculations usings the hashes of those
    permutations.
    """
    global _mix, _mod, _seed, _offset

    _mix ^= abs(sum((_seed, _offset, ns_time(), ns_counter(), *numbers)))
    mix = _mix = _mix % _mod
    _seed ^= mix
    start = _seed
    _offset ^= _seed
    for number in numbers:
        mix += _offset
        start *= number ^ mix
    return start ^ _seed


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
        entropy_pool: t.Deque[bytes],
        *,
        frequency: t.PositiveRealNumber = 1,
    ) -> "self":
        """
        Prepares an instance to safely start a background thread.
        """
        self._pool = entropy_pool
        self._daemon = None
        self._cancel = False
        self._currently_mutating_frequency = False
        self.set_frequency(frequency)

    async def _anew_snapshot(self) -> bytes:
        """
        Returns 144-bytes of pseudo-random values from the instance's
        entropy pool & the `secrets.token_bytes` function.
        """
        await asleep()
        return await atoken_bytes(32) + self._pool[0] + self._pool[-1][:48]

    def _set_temporary_frequency(
        self,
        frequency: t.PositiveRealNumber,
        duration: t.PositiveRealNumber,
    ) -> None:
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
        frequency: t.PositiveRealNumber = 0.001,
        *,
        duration: t.PositiveRealNumber = 1,
    ) -> "self":
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

    def set_frequency(
        self, frequency: t.PositiveRealNumber = 1
    ) -> "self":
        """
        Sets the maximum number of seconds a started entropy daemon will
        pseudo-randomly sleep in-between each iteration. Setting the
        ``frequency`` to smaller numbers will cause more cpu power &
        to be consumed by the background daemon thread.
        """
        self._frequency = frequency
        self._initial_frequency = frequency
        return self

    async def _araw_loop(self) -> None:
        """
        Takes snapshots of & feeds entropy into the module's entropy
        pools before & after sleeping for a pseudo-random amount of time.
        This is done asynchronously & in a background thread to increase
        the unpredictability & non-determinism of entropy generation.
        """
        while True:
            seed = await self._anew_snapshot()
            await _add_to_pool(await _entropy.ahash(seed), self._pool)
            _xof.update(self._pool[0])
            await arandom_sleep(self._frequency)
            await _add_to_pool(await _entropy.ahash(seed), self._pool)
            _xof.update(self._pool[0])
            if self._cancel:
                break

    def start(self) -> "self":
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

    def cancel(self) -> "self":
        """
        Cancels the background thread.
        """
        self._cancel = True
        return self


#  initialize a global entropy pool
_pool = deque([token_bytes(64), token_bytes(64)], maxlen=32)


async def _add_to_pool(
    entropy: bytes, entropy_pool: t.Sequence[bytes] = _pool
) -> None:
    """
    Prevents writes of the same `_entropy.hash` outputs to the global
    entropy pool.
    """
    while entropy in entropy_pool:
        entropy = _entropy.hash(entropy)
        await arandom_sleep(0.001)
    entropy_pool.appendleft(entropy)


# initialize the global hashing objects that also collect entropy
_entropy = Hasher(token_bytes(304) + b"".join(_pool))
_xof = Hasher(token_bytes(208) + b"".join(_pool), obj=shake_256)

# avert event loop clashes
run = asyncio.new_event_loop().run_until_complete

# initializing weakly entropic functions
random = _random.Random(token_bytes(2500))
uniform = random.uniform
unique_range = random.randrange

_mod = PRIMES[256][-1]
_offset = token_bits(256)
_mix = int.from_bytes(_entropy.hash(*_pool), BYTE_ORDER)
_seed = int.from_bytes(_entropy.hash(*_pool)[:32], BYTE_ORDER)
_numbers = (_mix, _seed, _offset)

_ = _salt_multiply(*_numbers)
run(_asalt_multiply(_, *_numbers))

_initial_entropy = deque([token_bits(1024), token_bits(1024)], maxlen=2)

# ensure the device has created a static salt for GUID creation
_static_salt_name = Domains.encode_constant(b"default_guid_name", size=16)
_device_salt_path = SecurePath(key=_static_salt_name, _admin=True)
_device_salt = read_salt_file(_device_salt_path)

# begin the entropy gathering daemon
_entropy_daemon = EntropyDaemon(_pool).start()
_entropy_daemon.set_temporary_frequency(0.001, duration=2)


async def _asalt() -> int:
    """
    Returns a low-grade entropy number from cached & ratcheted system
    entropy.
    """
    entropy = _entropy.hash(token_bytes(32), *_pool)[:32]
    _initial_entropy.appendleft(int.from_bytes(entropy, BYTE_ORDER))
    return await _asalt_multiply(*_initial_entropy)


def _salt() -> int:
    """
    Returns a low-grade entropy number from cached & ratcheted system
    entropy.
    """
    entropy = _entropy.hash(token_bytes(32), *_pool)[:32]
    _initial_entropy.appendleft(int.from_bytes(entropy, BYTE_ORDER))
    return _salt_multiply(*_initial_entropy)


async def arandom_number_generator(
    size: int = 64,
    *,
    entropy: t.Any = _entropy.hash(run(_asalt()).to_bytes(2048, BYTE_ORDER)),
    freshness: int = 8,
) -> bytes:
    """
    Returns a ``size``-byte random bytestring derived from very large
    entropy pools, the provided ``entropy`` value, persistent sha3
    hashing objects, & a multithreaded + asynchronous chaotic algorithm.
    The number of ``freshness`` dictates how long the chain of
    asynchronous tasks will be set in motion gathering entropy to seed
    the output function.

     _____________________________________
    |                                     |
    |        Algorithm Explanation:       |
    |_____________________________________|

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
    of the component PRNGs intractibly large by using seeds at least as
    large as the minumum acceptable security strength.

    2. Make new seeds after &/or before each use, import-time &/or
    function call.

    3. Use cryptographic hashing on the inputs & outputs of component
    PRNGs to unlink them from their internal states.

    4. Incorporate forward-secure key ratcheting algorithms at key
    points along the PRNGs' communications routes with themselves & the
    user.

    5. Use the powerful sha3_256, sha3_512 or shake_256 algorithms for
    all hashing.

    6. Persist & use a sha3_512 & shake_256 hashing object for hidden
    &/or internal procedures across the module for the automatic & non-
    deterministic collection of entropy throughout normal use of the
    module.

    7. Further frustrate an attacker by necessitating that they perform
    an order prediction attack on the results of the CSPRNG's component
    PRNGs. We do this by using asynchrony entirely throughout the CSPRNG
    with random sleeps, and using a non-commutative, salted, modular
    multiplication to combine internal states into a single element in
    its ratcheting internal state.

    8. Allow the user to securely mix any extra entropy they have access
    to into the CSPRNG's state machine. This mitigates some impacts of
    the malicious analysis of memory by an adversary.

    9. Use a background thread which continuously hashes & updates two
    of the package's entropy pools with new entropic material & their
    internal states. This adds unpredictable alterations to the pools
    concurrently with the running of the package.

    10. Iterate and interleave all these methods enough times such that,
    if we assume each time the CSPRNG produces a 64-byte internal state,
    that only 8-bits of entropy are produced. Then, initializing up to
    a cache of 32 ratcheting states, the ``random_number_generator``
    algorithm here would have at least 256-bits of entropy.

    **** **** **** **** **** **** **** **** **** **** **** **** ****

    Our implementation analysis is NOT rigorous or conclusive. Though
    soley based on the constraints stated above, our assumptions of
    randomness should be reasonable estimates within the threat model
    where an attacker cannot arbitrarily analyze users' machines'
    memory.

    **** **** **** **** **** **** **** **** **** **** **** **** ****
    """
    xof = _xof.copy()
    _entropy_daemon.set_temporary_frequency(0.001, duration=1)

    if entropy.__class__ is not bytes:
        entropy = repr(entropy).encode()

    if freshness or not _pool:

        async def create_unique_multiple(seed: int) -> int:
            return await _asalt_multiply(size, seed, token_bits(256))

        async def big_modulation(*args) -> int:
            return await _asalt_multiply(
                size, *args, await atoken_bits(256)
            ) % await achoice(PRIMES[512])

        async def modular_multiplication() -> None:
            seed = await _asalt() % await achoice(PRIMES[512])
            await arandom_sleep(0.003)
            multiples = (create_unique_multiple(seed) for _ in range(3))
            multiples = [await multiple for multiple in multiples]
            result = await big_modulation(seed, *multiples)
            await _add_to_pool(
                await _entropy.ahash(
                    seed.to_bytes(64, "big"), result.to_bytes(64, "big")
                )
            )

        async def add_to_pool() -> None:
            seed = await xof.ahash(await atoken_bytes(32), size=32)
            await arandom_sleep(0.003)
            await _add_to_pool(await _entropy.ahash(entropy, seed))

        async def start_generator() -> None:
            tasks = deque()
            rounds = 8 if not freshness else freshness
            for _ in range(rounds):
                await asleep()
                tasks.appendleft(modular_multiplication())
                for _ in range(10):
                    tasks.appendleft(add_to_pool())
            await gather(
                *sorted(tasks, key=lambda val: token_bytes(32)),
                return_exceptions=True,
            )

        await start_generator()
    else:
        await _add_to_pool(
            await _entropy.ahash(await atoken_bytes(32), entropy)
        )

    # Prevent the possibility that multiple threads will retrieve the
    # same result if they each happen to interrupt each other multiple
    # times in between their update of _xof & their call for its digest
    # by using a unique copy.
    return await xof.ahash(token_bytes(xof.block_size), *_pool, size=size)


def random_number_generator(
    size: int = 64,
    *,
    entropy: t.Any = _entropy.hash(_salt().to_bytes(2048, BYTE_ORDER)),
    freshness: int = 8,
) -> bytes:
    """
    Returns a ``size``-byte random bytestring derived from very large
    entropy pools, the provided ``entropy`` value, persistent sha3
    hashing objects, & a multithreaded + asynchronous chaotic algorithm.
    The number of ``freshness`` dictates how long the chain of
    asynchronous tasks will be set in motion gathering entropy to seed
    the output function.

     _____________________________________
    |                                     |
    |        Algorithm Explanation:       |
    |_____________________________________|

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
    of the component PRNGs intractibly large by using seeds at least as
    large as the minumum acceptable security strength.

    2. Make new seeds after &/or before each use, import-time &/or
    function call.

    3. Use cryptographic hashing on the inputs & outputs of component
    PRNGs to unlink them from their internal states.

    4. Incorporate forward-secure key ratcheting algorithms at key
    points along the PRNGs' communications routes with themselves & the
    user.

    5. Use the powerful sha3_256, sha3_512 or shake_256 algorithms for
    all hashing.

    6. Persist & use a sha3_512 & shake_256 hashing object for hidden
    &/or internal procedures across the module for the automatic & non-
    deterministic collection of entropy throughout normal use of the
    module.

    7. Further frustrate an attacker by necessitating that they perform
    an order prediction attack on the results of the CSPRNG's component
    PRNGs. We do this by using asynchrony entirely throughout the CSPRNG
    with random sleeps, and using a non-commutative, salted, modular
    multiplication to combine internal states into a single element in
    its ratcheting internal state.

    8. Allow the user to securely mix any extra entropy they have access
    to into the CSPRNG's state machine. This mitigates some impacts of
    the malicious analysis of memory by an adversary.

    9. Use a background thread which continuously hashes & updates two
    of the package's entropy pools with new entropic material & their
    internal states. This adds unpredictable alterations to the pools
    concurrently with the running of the package.

    10. Iterate and interleave all these methods enough times such that,
    if we assume each time the CSPRNG produces a 64-byte internal state,
    that only 8-bits of entropy are produced. Then, initializing up to
    a cache of 32 ratcheting states, the ``random_number_generator``
    algorithm here would have at least 256-bits of entropy.

    **** **** **** **** **** **** **** **** **** **** **** **** ****

    Our implementation analysis is NOT rigorous or conclusive, though
    soley based on the constraints stated above, our assumptions of
    randomness should be reasonable estimates within the threat model
    where an attacker cannot arbitrarily analyze users' machines'
    memory.

    **** **** **** **** **** **** **** **** **** **** **** **** ****
    """
    xof = _xof.copy()
    _entropy_daemon.set_temporary_frequency(0.001, duration=1)

    if entropy.__class__ is not bytes:
        entropy = repr(entropy).encode()

    if freshness or not _pool:

        async def create_unique_multiple(seed: int) -> int:
            return await _asalt_multiply(size, seed, token_bits(256))

        async def big_modulation(*args) -> int:
            return await _asalt_multiply(
                size, *args, await atoken_bits(256)
            ) % await achoice(PRIMES[512])

        async def modular_multiplication() -> None:
            seed = await _asalt() % await achoice(PRIMES[512])
            await arandom_sleep(0.003)
            multiples = (create_unique_multiple(seed) for _ in range(3))
            multiples = [await multiple for multiple in multiples]
            result = await big_modulation(seed, *multiples)
            await _add_to_pool(
                await _entropy.ahash(
                    seed.to_bytes(64, "big"), result.to_bytes(64, "big")
                )
            )

        async def add_to_pool() -> None:
            seed = await xof.ahash(await atoken_bytes(32), size=32)
            await arandom_sleep(0.003)
            await _add_to_pool(await _entropy.ahash(entropy, seed))

        async def start_generator() -> None:
            tasks = deque()
            rounds = 8 if not freshness else freshness
            for _ in range(rounds):
                await asleep()
                tasks.appendleft(modular_multiplication())
                for _ in range(10):
                    tasks.appendleft(add_to_pool())
            await gather(
                *sorted(tasks, key=lambda val: token_bytes(32)),
                return_exceptions=True,
            )

        run(start_generator())  # <- RuntimeError in event loops
    else:
        run(_add_to_pool(_entropy.hash(token_bytes(32), entropy)))

    # Prevent the possibility that multiple threads will retrieve the
    # same result if they each happen to interrupt each other multiple
    # times in between their update of _xof & their call for its digest
    # by using a unique copy.
    return xof.hash(token_bytes(xof.block_size), *_pool, size=size)


async def agenerate_salt(size: int = SALT_BYTES) -> bytes:
    """
    Returns ``size`` random bytes for use as an ephemeral, uniform salt.
    """
    if size < 8 or size > 64:
        raise Issue.invalid_value("salt size", "<8 or >64")
    return await atoken_bytes(size)


def generate_salt(size: int = SALT_BYTES) -> bytes:
    """
    Returns ``size`` random bytes for use as an ephemeral, uniform salt.
    """
    if size < 8 or size > 64:
        raise Issue.invalid_value("salt size", "<8 or >64")
    return token_bytes(size)


async def agenerate_iv(size: int = IV_BYTES) -> bytes:
    """
    Returns ``size`` random bytes for use as an ephemeral, uniform IV.
    """
    if size < 8 or size > 64:
        raise Issue.invalid_value("iv size", "<8 or >64")
    return await atoken_bytes(size)


def generate_iv(size: int = IV_BYTES) -> bytes:
    """
    Returns ``size`` random bytes for use as an ephemeral, uniform IV.
    """
    if size < 8 or size > 64:
        raise Issue.invalid_value("iv size", "<8 or >64")
    return token_bytes(size)


async def agenerate_siv_key(size: int = SIV_KEY_BYTES) -> bytes:
    """
    Returns ``size`` random bytes for use as an ephemeral, uniform
    SIV-key.
    """
    if size < 8 or size > 64:
        raise Issue.invalid_value("siv_key size", "<8 or >64")
    return await atoken_bytes(size)


def generate_siv_key(size: int = SIV_KEY_BYTES) -> bytes:
    """
    Returns ``size`` random bytes for use as an ephemeral, uniform
    SIV-key.
    """
    if size < 8 or size > 64:
        raise Issue.invalid_value("siv_key size", "<8 or >64")
    return token_bytes(size)


async def agenerate_raw_guid(
    size: int = GUID_BYTES,
    *,
    clock: Clock = Clock(NANOSECONDS, epoch=EPOCH_NS),
    encode: bool = False,
) -> bytes:
    """
    Returns a raw ``size``-byte globally unique identifier. If ``encode``
    is set to `True`, then a `base64.urlsafe_b64encode` guid without
    b"=" characters is returned instead. The first raw 8-bytes are a
    nanosecond timestamp, & the rest are random bytes. A custom ``clock``
    can be specified, which produces timestamps from its `amake_timestamp`
    method.
    --------
    WARNING: DO NOT use if timestamp information, for security or
    -------- anonymity purposes, is supposed to be kept secret from the
    contexts where these guids are exposed. One example: creating a
    guid, then performing an operation on some sensitive or secret
    information, & then exposing the guid, could leak information about
    those secrets to an observer calculating the time difference between
    the timestamp & the moment it was exposed. DO NOT DO THIS. USE WITH
    CAUTION, in contexts where the guids remain secret or where secret
    information is NOT being touched AND the time information DOES NOT
    harm anonymity or security!
    """
    if size < 10 or size > 64:
        raise Issue.invalid_value("guid size", "<10 or >64")
    timestamp = await clock.amake_timestamp()
    randomness = await atoken_bytes(size - len(timestamp))
    if encode:
        return await BytesIO.abytes_to_urlsafe(timestamp + randomness)
    return timestamp + randomness


def generate_raw_guid(
    size: int = GUID_BYTES,
    *,
    clock: Clock = Clock(NANOSECONDS, epoch=EPOCH_NS),
    encode: bool = False,
) -> bytes:
    """
    Returns a raw ``size``-byte globally unique identifier. If ``encode``
    is set to `True`, then a `base64.urlsafe_b64encode` guid without
    b"=" characters is returned instead. The first raw 8-bytes are a
    nanosecond timestamp, & the rest are random bytes. A custom ``clock``
    can be specified, which produces timestamps from its `make_timestamp`
    method.
    --------
    WARNING: DO NOT use if timestamp information, for security or
    -------- anonymity purposes, is supposed to be kept secret from the
    contexts where these guids are exposed. One example: creating a
    guid, then performing an operation on some sensitive or secret
    information, & then exposing the guid, could leak information about
    those secrets to an observer calculating the time difference between
    the timestamp & the moment it was exposed. DO NOT DO THIS. USE WITH
    CAUTION, in contexts where the guids remain secret or where secret
    information is NOT being touched AND the time information DOES NOT
    harm anonymity or security!
    """
    if size < 10 or size > 64:
        raise Issue.invalid_value("guid size", "<10 or >64")
    timestamp = clock.make_timestamp()
    randomness = token_bytes(size - len(timestamp))
    if encode:
        return BytesIO.bytes_to_urlsafe(timestamp + randomness)
    return timestamp + randomness


class SequenceID:
    """
    A class for producing unique, deterministic pseudo-random sequential
    identifiers that do not suffer from birthday bound collisions if all
    input indexes fall within two multiples of the prime used for the
    size of outputs specified by the user. Each prime used for each
    output-size is the largest possible prime of that byte-size. Each
    primitive root used for each prime is the smallest prime primitive
    root >= 7 for that prime.

    The produced identifiers are randomized by unique, secret, uniform
    salts. Any instance created using the same salt is able to create
    the same sequence of identifiers. Normal birthday-bound collision
    probabilities apply when different salts are used between callers.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp.randoms import SequenceID, token_bytes
    from aiootp.ciphers import ChaCha20Poly1305
    from aiootp.keygens import DomainKDF


    seed = token_bytes(32)
    kdf = DomainKDF(b"movie-collection", seed, key=session.shared_key)
    cipher = ChaCha20Poly1305(kdf.sha3_256(context=b"server-encryption-key"))
    sid = SequenceID(
        salt=kdf.shake_256(12, context=b"server-sequence-ids"), size=12
    )

    yield seed
    for i, movie in enumerate(movie_collection):
        yield cipher.encrypt(sid.new(i), movie, session.associated_data)

    """

    __slots__ = ("_size", "_gen", "_prime", "_subprime", "_salt", "_key")

    _IPAD: bytes = b"\xa3"
    _OPAD: bytes = b"\x1b"
    _XPAD: bytes = b"\x8d"
    _MIN_SIZE: int = 4
    _MAX_SIZE: int = 32
    _MIN_SALT_SIZE: int = 16

    _primes: PrimeGroups = PrimeGroups()

    @classmethod
    def _encode_salt(
        cls, salt: bytes, prime: int, size: int
    ) -> t.Tuple[int, int]:
        """
        Returns three integer copies of a bytes-type ``salt`` value
        xored with different constants which have an optimal hamming
        distance of half their bit-length. The first two copies returned
        are not multiples of the ``prime`` & are one byte longer than
        the original salt. The last copy is ``size`` bytes long.
        """
        subprime = cls._primes[f"o{8 * size}"]
        pad_size = len(salt) + 1
        integer_salt = bytes_as_int(salt)
        short_integer_salt = bytes_as_int(salt[:size])
        isalt = bytes_as_int(pad_size * cls._IPAD) ^ integer_salt
        osalt = bytes_as_int(pad_size * cls._OPAD) ^ integer_salt
        xsalt = bytes_as_int(size * cls._XPAD) ^ short_integer_salt
        while (not isalt % prime) or (not isalt % subprime):
            isalt += 1
        while (not osalt % prime) or (not osalt % subprime):
            osalt += 1
        return isalt, osalt, xsalt

    def __init__(self, salt: bytes, *, size: int = 12) -> "self":
        """
        Prepares the instance to run the algorithm after checking that
        the provided ``size`` of outputs & uniform ``salt`` are
        supported & work together to safely run the algorithm.
        """
        self._install_configuration(size)
        self._install_salt(salt)
        self._install_obfuscator()

    @property
    def _session_configuration(self) -> t.Tuple[int, int, int, int]:
        """
        A utility for improving the readability of getting access to all
        the configuartion values of the instance.
        """
        return self._size, self._gen, self._prime, self._subprime

    def _install_configuration(self, size: int) -> None:
        """
        Sets the prime & associated values which form the groups used
        for the specified ``size`` of outputs.
        """
        if size.__class__ is not int:
            raise Issue.value_must_be_type("size", int)
        elif size < self._MIN_SIZE or size > self._MAX_SIZE:
            raise Issue.value_must(
                "size", f"be >= {self._MIN_SIZE} and <= {self._MAX_SIZE}"
            )
        bit_size = 8 * size
        self._size = size
        self._gen = self._primes[f"g{bit_size}"]
        self._prime = self._primes[f"p{bit_size}"]
        self._subprime = self._primes[f"o{bit_size}"]

    def _install_salt(self, salt: bytes) -> None:
        """
        Stores a uniform bytes-type ``salt`` after checking if it's
        the correct type & is sufficiently large to safely work with the
        algorithm.
        """
        min_size = max((self._size, self._MIN_SALT_SIZE))
        if salt.__class__ is not bytes:
            raise Issue.value_must_be_type("salt", bytes)
        elif len(salt) < min_size:
            raise Issue.value_must("len(salt)", f"be >= {min_size}")
        self._salt = salt

    def _install_obfuscator(self) -> None:
        """
        Stores a group element generator function which ensures each
        output is unique for all inputs between two multiples of the
        isntance's subprime. The inputs & outputs are also obfuscated by
        the secrecy of the user-defined salt.
        """
        size, gen, prime, subprime = self._session_configuration
        isalt, osalt, xsalt = self._encode_salt(self._salt, prime, size)
        self._key = lambda index: (
            xsalt ^ pow(gen, (osalt * (isalt + index)) % subprime, prime)
        ).to_bytes(size, BYTE_ORDER)

    async def anew(
        self,
        index: int,
        *,
        encode: bool = False,
        encoder: t.Callable[..., bytes] = BytesIO.bytes_to_urlsafe,
    ) -> bytes:
        """
        Produces a raw-bytes pseudo-random identifier that is guaranteed
        to be unique if each call uses a different ``index``, each
        ``index`` is congruent to a distinct sequential natural number
        from a start index to an end index whose difference is smaller
        than the instance's subprime (determined by the instance `size`
        parameter), & each is produced using the same instance `salt`.
        The produced identifiers are randomized by unique, secret,
        uniform salts. Any instance created using the same salt is able
        to create the same sequence of identifiers. Normal birthday-
        bound collision probabilities apply when different salts are
        used between callers.

        If ``encode`` is set to `True`, then the result is first passed
        as an argument to the ``encoder`` callable before being returned.
        By default, the ``encoder`` transforms the raw bytes into a url
        safe base64 value without b"=" characters.
        """
        await asleep()
        if index < 0:
            raise Issue.value_must("index", "be >= 0")
        elif encode:
            return encoder(self._key(index))
        return self._key(index)

    def new(
        self,
        index: int,
        *,
        encode: bool = False,
        encoder: t.Callable[..., bytes] = BytesIO.bytes_to_urlsafe,
    ) -> bytes:
        """
        Produces a raw-bytes pseudo-random identifier that is guaranteed
        to be unique if each call uses a different ``index``, each
        ``index`` is congruent to a distinct sequential natural number
        from a start index to an end index whose difference is smaller
        than the instance's subprime (determined by the instance `size`
        parameter), & each is produced using the same instance `salt`.
        The produced identifiers are randomized by unique, secret,
        uniform salts. Any instance created using the same salt is able
        to create the same sequence of identifiers. Normal birthday-
        bound collision probabilities apply when different salts are
        used between callers.

        If ``encode`` is set to `True`, then the result is first passed
        as an argument to the ``encoder`` callable before being returned.
        By default, the ``encoder`` transforms the raw bytes into a url
        safe base64 value without b"=" characters.
        """
        if index < 0:
            raise Issue.value_must("index", "be >= 0")
        elif encode:
            return encoder(self._key(index))
        return self._key(index)


class GUID(SequenceID):
    r"""
    A class for producing pseudo-random identifiers that are guaranteed
    to be unique if all calls occur on a different nanosecond & use the
    same instance `node_number` & `salt`. Additionally, the above, AND
    any calls which utilize the same `salt` but a different `node_number`
    will always produce unique outputs from each other even if they
    occur on the same nanosecond. The probability of per-nanosecond
    uniqueness can be increased exponentially with linear increases to
    the instance `size` parameter.

    By default only 256 different `node_number`s are supported, as they
    are represented in one byte, but as demonstrated in an example below,
    subclasses can customize how many bytes to allocate for node numbers.
    --------
    WARNING: The produced identifiers are randomized & obfuscated but
    -------- they are also invertible. The user must beware not to
    expose the guids if the `node_number`, `salt` or the current time in
    nanoseconds must remain secret from the audiences able to view the
    guids.

    Normal birthday-bound collision probabilities apply when different
    salts are used between callers.

     _____________________________________
    |                                     |
    |     Usage Example: Primary Keys     |
    |_____________________________________|

    import aiootp

    dds = distributed_database_system
    shared_salt = dds.shared_salt
    guid = aiootp.GUID(shared_salt, node_number=local_db.id, size=16)

    for table in local_db.tables:
        for record in table.new_records:
            record.dds_primary_key = guid.new()
            dds.merge(table, record)

     _____________________________________
    |                                     |
    |     Usage Example: Node Numbers     |
    |_____________________________________|

    import aiootp

    class LargeNetworkGUID(aiootp.GUID, node_number_bytes=4):
        pass

    for i, node in enumerate(network.nodes):  # 256**4 possible nodes
        node.install_guid_generator(
            guid=LargeNetworkGUID(network.salt, node_number=i, size=16)
        )

     _____________________________________
    |                                     |
    |  Usage Example: Configuration Demo  |
    |_____________________________________|

    import aiootp
    from io import StringIO

    # 16 raw bytes without encoding ->
    guid = aiootp.GUID(size=16)
    print(repr(guid.new()))
    b'x]\xd2\xe6\x0c\xb2F\xf9\x05\x02\xa9\xf1\x84\xa3\x0c&'

    # urlsafe base64 encoding ->
    print(repr(guid.new(encode=True)))
    b'3umIg-hZ2J_g8malraZpnw'

    # custom encoding ->
    TRADITIONAL_LAYOUT = (8, 4, 4, 4, 12)

    def hex_segment_guid(guid: bytes) -> str:
        read = StringIO(guid.hex()).read
        return "-".join(read(size) for size in TRADITIONAL_LAYOUT)

    print(repr(guid.new(encode=True, encoder=hex_segment_guid)))
    '5e152c91-2f27-8ac6-fa4c-4041ba23d93d'
    """

    __slots__ = ("_node_number", "_offset_npad", "_unmask")

    _NODE_NUMBER_BYTES: int = NODE_NUMBER_BYTES
    _NPAD = int.from_bytes(NODE_NUMBER_BYTES * b"i", BYTE_ORDER)

    _COUNTER_BYTES: int = 1
    _MIN_SIZE: int = MIN_GUID_BYTES
    _MIN_RAW_SIZE: int = MIN_RAW_GUID_BYTES
    _SAFE_TIMESTAMP_BYTES: int = SAFE_TIMESTAMP_BYTES

    def __init_subclass__(
        cls, node_number_bytes: int = NODE_NUMBER_BYTES, **kw
    ) -> None:
        """
        Allows subclasses to only define a number of bytes to assign for
        node numbers so the padding it's xored with will be automatically
        extended to match.
        """
        super().__init_subclass__(**kw)
        cls._NODE_NUMBER_BYTES = node_number_bytes
        cls._NPAD = int.from_bytes(node_number_bytes * b"i", BYTE_ORDER)

    def __init__(
        self,
        salt: t.Optional[bytes] = None,
        *,
        size: int = GUID_BYTES,
        node_number: int = 0,
    ) -> "self":
        """
        Prepares the instance to run the algorithm after checking that
        the provided ``size`` of outputs & ``salt`` are supported & work
        together to safely run the algorithm. If no ``salt`` is provided,
        then the automatically generated salt which is stored on the
        device is used.
        """
        salt = salt if salt else _device_salt
        self._install_node_number(node_number, size=size)
        super().__init__(salt=salt, size=size)

    def _install_node_number(self, node_number: int, size: int) -> None:
        """
        Stores an 'N'-byte ``node_number`` that's xor'd with a constant
        which shares an optimal hamming distance of half its bit-length
        with the class' `_IPAD` & `_OPAD` values. 'N' is the class'
        `_NODE_NUMBER_BYTES` value, which assigns a size (& maximum
        possible unique values) for the node_number. By default 'N' is
        1, & subclasses can customize this parameter in the subclass
        initializer.
        """
        node_bytes = self._NODE_NUMBER_BYTES
        min_size = node_bytes + self._MIN_RAW_SIZE + self._COUNTER_BYTES
        if size < min_size:
            raise Issue.value_must(
                "size", f"be at least {min_size} to fit the node number"
            )
        self._offset_npad = self._NPAD << (8 * size - 8 * node_bytes)
        self._node_number = int_as_bytes(
            node_number ^ self._NPAD, size=node_bytes
        )

    def _obfuscator_shortcuts(
        self, size: int, prime: int, isalt: int
    ) -> t.Tuple[int, int, int, bytes, callable, int]:
        """
        Aggregates the calculated values used to run the algorithm for
        efficient referencing.
        """
        guid_size = size - self._NODE_NUMBER_BYTES - self._COUNTER_BYTES
        node_size = self._NODE_NUMBER_BYTES
        offset_npad = self._offset_npad
        node = self._node_number
        _int = int.from_bytes
        inverse = pow(isalt, prime - 2, prime)
        return guid_size, node_size, offset_npad, node, _int, inverse

    def _install_obfuscator(self) -> None:
        """
        Stores an efficient guid generator function that obfuscates the
        outputs of affine-group operations on the user-defined salt, a
        user-defined node number, & a nanosecond-time & random-bytes raw
        guid.
        """
        def counter() -> int:
            nonlocal i

            i = (i + 1) % 256
            return i

        i, size, gen, prime, subprime = 0, *self._session_configuration
        isalt, osalt, xsalt = self._encode_salt(self._salt, prime, size)
        (
            guid_size, node_size, offset_npad, node, _int, inverse
        ) = self._obfuscator_shortcuts(size, prime, isalt)
        inner_guid = lambda: (
            counter()
            + _int(node + generate_raw_guid(guid_size) + b"\0", BYTE_ORDER)
        )
        self._key = lambda: (
            xsalt ^ ((isalt * inner_guid() + osalt) % prime)
        ).to_bytes(size, BYTE_ORDER)
        self._unmask = lambda guid: (
            offset_npad
            ^ (inverse * ((xsalt ^ _int(guid, BYTE_ORDER)) - osalt) % prime)
        ).to_bytes(size, BYTE_ORDER)

    async def anew(
        self,
        *,
        encode: bool = False,
        encoder: t.Callable[..., bytes] = BytesIO.abytes_to_urlsafe,
    ) -> bytes:
        r"""
        Produces a raw-bytes pseudo-random identifier that is guaranteed
        to be unique if each call occurs on a different nanosecond & is
        produced using the same instance `node_number` & `salt`.

        Additionally, the above, AND any calls which utilize the same
        `salt` but a different `node_number` will always produce unique
        outputs from each other even if they occur the same nanosecond.
        The probability of per-nanosecond uniqueness can be increased
        exponentially with linear increases to the instance's `size`
        parameter.
        --------
        WARNING: The produced identifiers are randomized & obfuscated
        -------- but they are also invertible. The user must beware not
        to expose the guids if the `node_number`, `salt` or the current
        time in nanoseconds must remain secret from the audiences able
        to view the guids.

        Normal birthday-bound collision probabilities apply when
        different salts are used between callers.

        If ``encode`` is set to `True`, then the result is first passed
        as an argument to the ``encoder`` async callable before being
        returned. By default, the ``encoder`` transforms the raw bytes
        into a url safe base64 value without b"=" characters.

         _____________________________________
        |                                     |
        |     Usage Example: Primary Keys     |
        |_____________________________________|

        import aiootp

        dds = distributed_database_system
        shared_salt = dds.shared_salt
        guid = aiootp.GUID(shared_salt, node_number=local_db.id, size=16)

        for table in local_db.tables:
            for record in table.new_records:
                record.dds_primary_key = await guid.anew()
                dds.merge(table, record)

         _____________________________________
        |                                     |
        |     Usage Example: Node Numbers     |
        |_____________________________________|

        import aiootp

        class LargeNetworkGUID(aiootp.GUID, node_number_bytes=4):
            pass

        for i, node in enumerate(network.nodes):  # 256**4 possible nodes
            node.install_guid_generator(
                guid=LargeNetworkGUID(network.salt, node_number=i, size=16)
            )

         _____________________________________
        |                                     |
        |  Usage Example: Configuration Demo  |
        |_____________________________________|

        import aiootp
        from io import StringIO

        # 16 raw bytes without encoding ->
        guid = aiootp.GUID(size=16)
        print(repr(guid.new()))
        b'x]\xd2\xe6\x0c\xb2F\xf9\x05\x02\xa9\xf1\x84\xa3\x0c&'

        # urlsafe base64 encoding ->
        print(repr(guid.new(encode=True)))
        b'3umIg-hZ2J_g8malraZpnw'

        # custom encoding ->
        TRADITIONAL_LAYOUT = (8, 4, 4, 4, 12)

        async def hex_segment_guid(guid: bytes) -> str:
            await asyncio.sleep(0)
            read = StringIO(guid.hex()).read
            return "-".join(read(size) for size in TRADITIONAL_LAYOUT)

        print(repr(await guid.anew(encode=True, encoder=hex_segment_guid)))
        '5e152c91-2f27-8ac6-fa4c-4041ba23d93d'
        """
        if encode:
            return await encoder(self._key())
        await asleep()
        return self._key()

    def new(
        self,
        *,
        encode: bool = False,
        encoder: t.Callable[..., bytes] = BytesIO.bytes_to_urlsafe,
    ) -> bytes:
        r"""
        Produces a raw-bytes pseudo-random identifier that is guaranteed
        to be unique if each call occurs on a different nanosecond & is
        produced using the same instance `node_number` & `salt`.

        Additionally, the above, AND any calls which utilize the same
        `salt` but a different `node_number` will always produce unique
        outputs from each other even if they occur the same nanosecond.
        The probability of per-nanosecond uniqueness can be increased
        exponentially with linear increases to the instance's `size`
        parameter.
        --------
        WARNING: The produced identifiers are randomized & obfuscated
        -------- but they are also invertible. The user must beware not
        to expose the guids if the `node_number`, `salt` or the current
        time in nanoseconds must remain secret from the audiences able
        to view the guids.

        Normal birthday-bound collision probabilities apply when
        different salts are used between callers.

        If ``encode`` is set to `True`, then the result is first passed
        as an argument to the ``encoder`` callable before being returned.
        By default, the ``encoder`` transforms the raw bytes into a url
        safe base64 value without b"=" characters.

         _____________________________________
        |                                     |
        |     Usage Example: Primary Keys     |
        |_____________________________________|

        import aiootp

        dds = distributed_database_system
        shared_salt = dds.shared_salt
        guid = aiootp.GUID(shared_salt, node_number=local_db.id, size=16)

        for table in local_db.tables:
            for record in table.new_records:
                record.dds_primary_key = guid.new()
                dds.merge(table, record)

         _____________________________________
        |                                     |
        |  Usage Example: Configuration Demo  |
        |_____________________________________|

        import aiootp
        from io import StringIO

        # 16 raw bytes without encoding ->
        guid = aiootp.GUID(size=16)
        print(repr(guid.new()))
        b'x]\xd2\xe6\x0c\xb2F\xf9\x05\x02\xa9\xf1\x84\xa3\x0c&'

        # urlsafe base64 encoding ->
        print(repr(guid.new(encode=True)))
        b'3umIg-hZ2J_g8malraZpnw'

        # custom encoding ->
        TRADITIONAL_LAYOUT = (8, 4, 4, 4, 12)

        def hex_segment_guid(guid: bytes) -> str:
            read = StringIO(guid.hex()).read
            return "-".join(read(size) for size in TRADITIONAL_LAYOUT)

        print(repr(guid.new(encode=True, encoder=hex_segment_guid)))
        '5e152c91-2f27-8ac6-fa4c-4041ba23d93d'
        """
        if encode:
            return encoder(self._key())
        return self._key()

    async def aunmask(
        self,
        guid: bytes,
        *,
        decode: bool = False,
        decoder: t.Callable[..., bytes] = BytesIO.aurlsafe_to_bytes,
    ) -> UnmaskedGUID:
        """
        Unmasks & optionally, if encoded, decodes, a guid generated by
        an instance which utilized the same instance `salt`, returned in
        an object where the `node_number`, nanosecond `timestamp`, &
        ephemeral `entropy` are accessible via dotted attribute lookup.
        The returned objects are also sortable, which sorts according to
        the nanosecond timestamp.
        """
        if decode:
            guid = await decoder(guid)
        return UnmaskedGUID(self._unmask(guid), self._NODE_NUMBER_BYTES)

    def unmask(
        self,
        guid: bytes,
        *,
        decode: bool = False,
        decoder: t.Callable[..., bytes] = BytesIO.urlsafe_to_bytes,
    ) -> UnmaskedGUID:
        """
        Unmasks & optionally, if encoded, decodes, a guid generated by
        an instance which utilized the same instance `salt`, returned in
        an object where the `node_number`, nanosecond `timestamp`, &
        ephemeral `entropy` are accessible via dotted attribute lookup.
        The returned objects are also sortable, which sorts according to
        the nanosecond timestamp.
        """
        if decode:
            guid = decoder(guid)
        return UnmaskedGUID(self._unmask(guid), self._NODE_NUMBER_BYTES)


async def agenerate_key(
    size: int = KEY_BYTES, *, freshness: int = 8
) -> bytes:
    """
    Returns a random ``size``-byte cryptographically secure key >= 64
    bytes. Defaults to 168-bytes. More entropy can be gathered for
    creating the key using the ``freshness`` parameter. It tells the
    package's chaotic & cpu-intensive `random_number_generator` how many
    concurrent internal asynchronous tasks to sprout for the process of
    gathering entropy.
    """
    if size < MIN_KEY_BYTES or size.__class__ is not int:
        raise Issue.invalid_value("key size", "<64")
    return await arandom_number_generator(
        size, entropy=csprng(), freshness=freshness
    )


def generate_key(size: int = KEY_BYTES, *, freshness: int = 8) -> bytes:
    """
    Returns a random ``size``-byte cryptographically secure key >= 64
    bytes. Defaults to 168-bytes. More entropy can be gathered for
    creating the key using the ``freshness`` parameter. It tells the
    package's chaotic & cpu-intensive `random_number_generator` how many
    concurrent internal asynchronous tasks to sprout for the process of
    gathering entropy.
    """
    if size < MIN_KEY_BYTES or size.__class__ is not int:
        raise Issue.invalid_value("key size", "<64")
    return random_number_generator(
        size, entropy=csprng(), freshness=freshness
    )


async def acsprng(
    entropy: t.Any = run(arandom_number_generator(freshness=1))
) -> bytes:
    """
    Takes in an arbitrary ``entropy`` value from the user to seed then
    return a 64-byte cryptographically secure pseudo-random value.
    """
    if entropy.__class__ is not bytes:
        entropy = repr(entropy).encode() + _pool[0]
    elif not entropy:
        entropy = _pool[0]
    token = await atoken_bytes(32)
    output = await _entropy.ahash(token, entropy)
    thread_safe_entropy = _entropy.copy()
    return await thread_safe_entropy.ahash(token, entropy, output)


def csprng(entropy: t.Any = random_number_generator(freshness=1)) -> bytes:
    """
    Takes in an arbitrary ``entropy`` value from the user to seed then
    return a 64-byte cryptographically secure pseudo-random value.
    """
    if entropy.__class__ is not bytes:
        entropy = repr(entropy).encode() + _pool[0]
    elif not entropy:
        entropy = _pool[0]
    token = token_bytes(32)
    output = _entropy.hash(token, entropy)
    thread_safe_entropy = _entropy.copy()
    return thread_safe_entropy.hash(token, entropy, output)


extras = dict(
    GUID=GUID,
    SequenceID=SequenceID,
    _EntropyDaemon=EntropyDaemon,
    __doc__=__doc__,
    __package__=__package__,
    _agenerate_raw_guid=agenerate_raw_guid,
    _generate_raw_guid=generate_raw_guid,
    achoice=achoice,
    acsprng=acsprng,
    agenerate_salt=agenerate_salt,
    arandom_number_generator=arandom_number_generator,
    arandom_sleep=arandom_sleep,
    atoken_bits=atoken_bits,
    atoken_bytes=atoken_bytes,
    auniform=auniform,
    aunique_range=aunique_range,
    choice=choice,
    csprng=csprng,
    generate_salt=generate_salt,
    random_number_generator=random_number_generator,
    random_sleep=random_sleep,
    token_bits=token_bits,
    token_bytes=token_bytes,
    uniform=uniform,
    unique_range=unique_range,
)


randoms = make_module("randoms", mapping=extras)

