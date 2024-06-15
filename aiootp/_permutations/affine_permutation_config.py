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


__all__ = ["AffinePermutationConfig"]


__doc__ = "A configuration type for `AffinePermutation`."


import io
from math import log2

from aiootp._typing import Typing as t
from aiootp._constants import datasets, BIG
from aiootp._exceptions import Issue
from aiootp._gentools import count as counter
from aiootp.commons import Config
from aiootp.generics import Domains


class AffinePermutationConfig(Config):
    """
    Configuration type for `AffinePermutation`.
    """

    __slots__ = (
        "AAD",
        "SIZE",
        "KEY_SIZE",
        "MAX",
        "PRIME",
        "MULTIPLICATIVE_KEY",
        "INVERSE_KEY",
    )

    slots_types: t.Mapping[str, type] = dict(
        AAD=bytes,
        SIZE=int,
        KEY_SIZE=int,
        MAX=int,
        PRIME=int,
        MULTIPLICATIVE_KEY=int,
        INVERSE_KEY=int,
    )

    def _process_size(self, size: int) -> int:
        """
        Returns `size` only if it passes non-type based validity checks,
        otherwise raises `ValueError`.
        """
        if 4096 >= size > 0:
            return size
        else:
            raise Issue.value_must("size", "be > 0 and <= 4096")

    @staticmethod
    def _make_multiplier_mask(bit_length: int) -> int:
        """
        Returns an integer mask to remove half of the most significant
        bits of a multiplier. This will reduce the side-channel leakage
        of the product when it's combined with the addition key before
        modular reduction.
        """
        top_bit = 1 << (bit_length // 2)
        mask = top_bit - 1
        return top_bit, mask

    @staticmethod
    def _count_bit_switches(number) -> int:
        """
        Allows determining if the provided number has a sufficiently
        distributed number of set bits.
        """
        count = 0
        binary = bin(number)[2:]
        current = binary[:1]
        for bit in binary:
            if bit != current:
                count += 1
                current = bit
        return count

    @classmethod
    def is_likely_safe_multiplier(cls, multiplier: int, prime: int) -> bool:
        """
        Returns `True` if a `multiplier` key is odd, about ~half the bit-
        length of the `prime`, & has a bit pattern with about an equal
        number of 1s & 0s with some clumping. Otherwise returns `False`.
        """
        if prime < 257:
            raise Issue.value_must("prime", "be > 256")
        prime_size = prime.bit_length()
        sqrt_prime = 1 << (prime_size // 2)
        bit_flips = cls._count_bit_switches(multiplier)
        span = int(log2(prime_size) - 1)
        max_flips, min_flips = bit_flips + span, bit_flips - span
        return bool(
            (multiplier & 1)
            and ((sqrt_prime << 2) > multiplier > sqrt_prime)
            and (max_flips > (prime_size / 4) > min_flips)
        )

    def _derive_new_multiplier(self, prime: int) -> int:
        """
        Derives the static multiplicative key for a provided `prime`
        number, the size of the instance permutation, & its associated
        data. This amortizes the relatively expensive derivation costs
        of finding the multiplicative key, & its inverse.
        """
        encode = lambda i: Domains.encode_constant(
            f"multiplicative_key_{i}_{prime}",
            domain=b"affine_permutation_constant",
            aad=self.AAD,
            size=self.SIZE,
        )
        top_bit, mask = self._make_multiplier_mask(prime.bit_length())
        for i in counter():
            key = top_bit | (int.from_bytes(encode(i), BIG) & mask)
            if self.is_likely_safe_multiplier(key, prime):
                return key

    def __init__(self, *, size: int, aad: bytes = b"") -> None:
        """
        Each instance generates the dynamic values determined by its
        specific `SIZE` & `AAD`.
        """
        self.AAD = aad
        self.SIZE = self._process_size(size)
        self.KEY_SIZE = 2 * self.SIZE
        self.MAX = (1 << (8 * self.SIZE)) - 1
        self.PRIME = datasets.PRIMES[8 * self.SIZE + 1][0]
        self.MULTIPLICATIVE_KEY = self._derive_new_multiplier(self.PRIME)
        self.INVERSE_KEY = pow(
            self.MULTIPLICATIVE_KEY, -1, self.PRIME
        )


module_api = dict(
    AffinePermutationConfig=t.add_type(AffinePermutationConfig),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

