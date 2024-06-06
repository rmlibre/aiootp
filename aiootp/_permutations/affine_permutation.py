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


__all__ = ["AffinePermutation"]


__doc__ = (
    "A bijective, keyed permutation type based on affine cipher "
    "arithmetic of varying domain sizes."
)


from aiootp._typing import Typing as t
from aiootp._constants import BIG
from aiootp._exceptions import Issue
from aiootp.asynchs import asleep
from aiootp.commons import ConfigMap, FrozenInstance

from .affine_permutation_config import AffinePermutationConfig


class AffinePermutation(FrozenInstance):
    """
    Creates instances which perform invertible, bijective, keyed affine
    permutations on integers within a given byte-domain.
    --------
    WARNING: Alone, this permutation is insufficient to mask inputs, or
    -------- protect from key recovery upon viewing outputs.
     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp._permutations.affine_permutation import AffinePermutation

    domain_size = 1
    key = token_bytes(AffinePermutation.key_size(domain_size))
    aff = AffinePermutation(key=key, config_id=domain_size)

    domain = tuple(range(256 * domain_size))
    permutation = tuple(aff.permute(i) for i in domain)
    assert domain != permutation
    assert len(domain) == len(set(permutation))
    assert domain == tuple(aff.invert(i) for i in permutation)
    """

    __slots__ = (
        "_MAX",
        "_PRIME",
        "_additive_key",
        "config",
    )

    _configs = ConfigMap(
        mapping={
            config_id: AffinePermutationConfig(size=config_id)
            for config_id in [*range(1, 33), 64, 128, 192, 256]
        },
        config_type=AffinePermutationConfig,
    )

    @classmethod
    def key_size(cls, config_id: t.Hashable) -> int:
        """
        Returns the integer size of the keys an instance uses which is
        defined by the configuration indexed by the `config_id`.
        """
        return cls._configs[config_id].KEY_SIZE

    def _process_additive_key(self, key: bytes, size: int) -> int:
        """
        Returns the bytes-type `key` as an integer after it's assured to
        be the correct `size`, which for blinding purposes, must be
        twice the domain size.
        """
        if len(key) == size:
            return int.from_bytes(key, BIG)
        else:
            raise Issue.invalid_length("additive_key", size)

    def __init__(self, *, key: bytes, config_id: t.Hashable = 16) -> None:
        """
        Ensures the input keys are the correct size, stores them as
        integers, & loads the instance with the configuration indexed by
        the `config_id`.
        """
        self.config = c = self._configs[config_id]
        self._additive_key = self._process_additive_key(key, c.KEY_SIZE)
        self._MAX = c.MAX
        self._PRIME = c.PRIME

    async def apermute(self, value: int) -> int:
        """
        The conditional function which forms a bijective permutation on
        inputs within the domain by cycle walking until its output
        doesn't fall outside of the domain.
        """
        await asleep()
        return self.permute(value)

    def permute(self, value: int) -> int:
        """
        The conditional function which forms a bijective permutation on
        inputs within the domain by cycle walking until its output
        doesn't fall outside of the domain.
        """
        value = (
            self.config.MULTIPLICATIVE_KEY * value + self._additive_key
        ) % self._PRIME
        while value > self._MAX:
            value = (
                self.config.MULTIPLICATIVE_KEY * value + self._additive_key
            ) % self._PRIME
        return value

    async def ainvert(self, value: int) -> int:
        """
        Inverts the conditional function which forms a bijective
        permutation on inputs within the domain by cycle walking until
        its output doesn't fall outside of the domain.
        """
        await asleep()
        return self.invert(value)

    def invert(self, value: int) -> int:
        """
        Inverts the conditional function which forms a bijective
        permutation on inputs within the domain by cycle walking until
        its output doesn't fall outside of the domain.
        """
        value = (
            self.config.INVERSE_KEY * (value - self._additive_key)
        ) % self._PRIME
        while value > self._MAX:
            value = (
                self.config.INVERSE_KEY * (value - self._additive_key)
            ) % self._PRIME
        return value


module_api = dict(
    AffinePermutation=t.add_type(AffinePermutation),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

