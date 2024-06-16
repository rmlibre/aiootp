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


__all__ = []


__doc__ = "Manages the early secrets used by the package."


from collections import deque

from aiootp._typing import Typing as t
from aiootp._constants import PRIMES, BIG
from aiootp._paths import SecurePath, read_salt_file
from aiootp.asynchs import asleep, ns_counter
from aiootp.generics import Domains

from .simple import token_bits, token_bytes


# initialize rudimentary global entropy pool
_int_pool = deque((token_bits(256), token_bits(256)), maxlen=2)


# create and/or retrieve the device seed stored on the filesystem
_package_seed_name = Domains.encode_constant(b"package_seed", size=16)
_package_seed_path = SecurePath(key=_package_seed_name, _admin=True)
_package_seed = read_salt_file(_package_seed_path)


# prepare global salted multiply values
_MOD = 1 << 256
_offset = (0x99 << 256) | token_bits(256)  # ensure always a non-zero offset
_mix = int.from_bytes(_package_seed, BIG)
_seed = int.from_bytes(token_bytes(32), BIG)


async def _asalt_multiply(*numbers: int, pool: t.Sequence[bytes]) -> int:
    """
    Allows for non-commutative multiplication. This assists pseudo-
    random number generators in turning combinations of low entropy
    number sources into permutations. This greatly increases the amount
    of knowledge an attacker must have to perform pre-image or known-
    plaintext attacks on the calculations usings the hashes of those
    permutations.
    """
    global _mix, _seed, _offset

    await asleep()
    start = ns_counter() * _offset
    mix = _mix ^ abs(sum((start, *_int_pool, *numbers)))
    mix = _mix = (mix ^ int.from_bytes(pool[0], BIG)) % _MOD
    _seed ^= mix
    _offset ^= _seed
    for number in numbers:
        await asleep()
        mix += _offset
        start = (start ^ mix) * (number ^ mix)
    return _seed ^ ((start ^ mix) % _MOD)


def _salt_multiply(*numbers: int, pool: t.Sequence[bytes]) -> int:
    """
    Allows for non-commutative multiplication. This assists pseudo-
    random number generators in turning combinations of low entropy
    number sources into permutations. This greatly increases the amount
    of knowledge an attacker must have to perform pre-image or known-
    plaintext attacks on the calculations usings the hashes of those
    permutations.
    """
    global _mix, _seed, _offset

    start = ns_counter() * _offset
    mix = _mix ^ abs(sum((start, *_int_pool, *numbers)))
    mix = _mix = (mix ^ int.from_bytes(pool[0], BIG)) % _MOD
    _seed ^= mix
    _offset ^= _seed
    for number in numbers:
        mix += _offset
        start = (start ^ mix) * (number ^ mix)
    return _seed ^ ((start ^ mix) % _MOD)


async def _asalt(
    *, pool: t.Sequence[bytes], gadget: t.EntropyHashingType
) -> int:
    """
    Returns a 256-bit number derived from cached & ratcheted system
    entropy.
    """
    entropy = gadget.hash(size=32)
    _int_pool.appendleft(int.from_bytes(entropy, BIG))
    return await _asalt_multiply(*_int_pool, pool=pool)


def _salt(*, pool: t.Sequence[bytes], gadget: t.EntropyHashingType) -> int:
    """
    Returns a 256-bit number derived from cached & ratcheted system
    entropy.
    """
    entropy = gadget.hash(size=32)
    _int_pool.appendleft(int.from_bytes(entropy, BIG))
    return _salt_multiply(*_int_pool, pool=pool)


module_api = dict(
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

