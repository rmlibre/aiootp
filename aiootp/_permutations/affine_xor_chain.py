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


__all__ = ["AffineXORChain"]


__doc__ = (
    "A chain of `AffinePermutation` objects with distinct keys & which "
    "have their inputs & outputs XOR'd with key material."
)


import io

from aiootp._typing import Typing as t
from aiootp._constants import BIG
from aiootp._exceptions import Issue
from aiootp.asynchs import asleep
from aiootp.commons import ConfigMap, FrozenInstance

from .affine_permutation import AffinePermutation
from .affine_xor_chain_config import AffineXORChainConfig


class AffineXORChain(FrozenInstance):
    """
    Creates instances which perform invertible, bijective, keyed affine
    permutations on integers within a given byte-domain. XORing keys
    with the inputs & outputs of chained affine permutations helps to
    break the algebraic structure of the permutation.

    The `(a)step` methods adjust the permutation such that repeat inputs
    within the domain will never result in a repeated output if no input
    is repeated prior to a call of the methods & the number of calls to
    the methods doesn't exceed the size of the domain.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp._permutations.affine_xor_chain import AffineXORChain

    domain_size = 1
    key = token_bytes(AffineXORChain.key_size(domain_size))
    aff = AffineXORChain(key=key, config_id=domain_size)

    latin_square = []
    domain = tuple(range(256 * domain_size))
    for _ in domain:
        row = tuple(aff.permute(element) for element in domain)
        latin_square.append(row)
        aff.step()

    assert len(set(latin_square)) == len(domain)
    assert all(len(set(row)) == len(domain) for row in latin_square)
    columns = [[row[column] for row in latin_square] for column in domain]
    assert all(len(set(column)) == len(domain) for column in columns)
    """

    __slots__ = (
        "_aff_in",
        "_aff_mid",
        "_aff_out",
        "_in_key",
        "_in_mid_key",
        "_out_mid_key",
        "_out_key",
        "_increment",
        "config",
    )

    _configs = ConfigMap(
        mapping={
            config_id: AffineXORChainConfig(
                config_id=config_id,
                size=config_id,
                permutation_type=AffinePermutation,
                permutation_config_id=config_id,
            ) for config_id in [*range(1, 33), 64, 128, 192, 256]
        },
        config_type=AffineXORChainConfig,
    )

    @classmethod
    def key_size(cls, config_id: t.Hashable) -> int:
        """
        Returns the integer size of the initialization key an instance
        uses which is defined by the configuration indexed by the
        `config_id`.
        """
        return cls._configs[config_id].KEY_SIZE

    def _ingest_key(self, key: bytes) -> t.Callable[[int], bytes]:
        """
        Returns a byte reader that's used to segment the input `key` if
        it's the correct size, otherwise raises `ValueError`.
        """
        key_size = self.key_size(self.config.CONFIG_ID)
        if len(key) == key_size:
            return io.BytesIO(key).read
        else:
            cls = self.__class__.__qualname__
            raise Issue.invalid_length(f"{cls} key", key_size)

    def _process_in_key(
        self, key_reader: t.Callable[[int], bytes], size: int
    ) -> int:
        """
        Returns an integer version of a segment of the instance's key
        if the segment retrieved is the correct size, otherwise raises
        `ValueError`.
        """
        key = key_reader(size)
        if len(key) == size:
            return int.from_bytes(key, BIG)
        else:
            raise Issue.invalid_length("in xor key", size)

    def _process_mid_key(
        self, key_reader: t.Callable[[int], bytes], size: int
    ) -> t.Tuple[int, int]:
        """
        Returns two integer versions with optimal hamming distance of a
        segment of the instance's key. If the segment retrieved isn't
        the correct size, `ValueError` is raised. It's ensured that at
        least one of these keys is non-zero, with a sufficient amount of
        bits set, so they can't incidentally fail at removing algebraic
        structure from the permutation.
        """
        c = self.config
        key = key_reader(size)
        if len(key) == size:
            preprocessed_key = int.from_bytes(key, BIG)
            return preprocessed_key ^ c.IPAD, preprocessed_key ^ c.OPAD
        else:
            raise Issue.invalid_length("mid xor key", size)

    def _process_out_key(
        self, key_reader: t.Callable[[int], bytes], size: int
    ) -> int:
        """
        Returns an integer version of a segment of the instance's key
        if the segment retrieved is the correct size, otherwise raises
        `ValueError`.
        """
        key = key_reader(size)
        if len(key) == size:
            return int.from_bytes(key, BIG)
        else:
            raise Issue.invalid_length("out xor key", size)

    def _initialize_keys(
        self, key_reader: t.Callable[[int], bytes], size: int
    ) -> t.Tuple[bytes, bytes, bytes, bytes]:
        """
        Returns the instance's integer keys that are used to XOR the
        inputs & outputs between the chained calls to its component
        affine permutations.
        """
        return (
            self._process_in_key(key_reader, size),
            *self._process_mid_key(key_reader, size),
            self._process_out_key(key_reader, size),
        )

    def _initialize_permutations(
        self, key_reader: t.Callable[[int], bytes], size: int
    ) -> t.Tuple[t.PermutationType]:
        """
        Uses the permutation configuration ID saved in the instance's
        config to initialize & return the affine permutations which will
        be chained together.
        """
        config_id = self.config.PERMUTATION_CONFIG_ID
        Permutation = self.config.Permutation
        return (
            Permutation(key=key_reader(size), config_id=config_id),
            Permutation(key=key_reader(size), config_id=config_id),
            Permutation(key=key_reader(), config_id=config_id),
        )

    def __init__(self, *, key: bytes, config_id: t.Hashable = 16) -> None:
        """
        Uses a bytes-type `key`, which is the correct size as defined
        by the configuration object that's indexed by the `config_id`,
        to set up the keys & permutations to be chained together.
        """
        self.config = c = self._configs[config_id]
        self._increment = c.XPAD
        key_reader = self._ingest_key(key)
        self._in_key, self._in_mid_key, self._out_mid_key, self._out_key = (
            self._initialize_keys(key_reader, c.XOR_KEY_SIZE)
        )
        self._aff_in, self._aff_mid, self._aff_out = (
            self._initialize_permutations(key_reader, c.ADD_KEY_SIZE)
        )

    async def aupdate_increment(self, value: int, /) -> None:
        """
        Augments the instance's step function increment with `value`.
        """
        await asleep()
        self.update_increment(value)

    def update_increment(self, value: int, /) -> None:
        """
        Augments the instance's step function increment with `value`.
        """
        if self.config.DOMAIN > value > 0:
            new_increment = (self._increment ^ value) | 1  # Ensure non-even
            object.__setattr__(self, "_increment", new_increment)
        else:
            raise Issue.value_must("adjustment", "be < DOMAIN & > 0")

    async def astep(self) -> None:
        """
        Tweaks the permutation in a way which can fill a complete latin
        square when the number of distinct consecutive inputs between
        each step, & the number of steps, is equal to the size of the
        domain.
        """
        await asleep()
        self.step()

    def step(self) -> None:
        """
        Tweaks the permutation in a way which can fill a complete latin
        square when the number of distinct consecutive inputs between
        each step, & the number of steps, is equal to the size of the
        domain.
        """
        new_in_key = (self._in_key + self._increment) % self.config.DOMAIN
        object.__setattr__(self, "_in_key", new_in_key)

    async def auncapped_permute(self, value: int, /) -> int:
        """
        Chains keyed bijective affine permutations together while
        XORing each result between the components with keys designed to
        break up the algebraic structure of the permutation.
        """
        return await self._aff_out.apermute(
            await self._aff_mid.apermute(
                await self._aff_in.apermute(value) ^ self._in_mid_key
            ) ^ self._out_mid_key
        )

    def uncapped_permute(self, value: int, /) -> int:
        """
        Chains keyed bijective affine permutations together while
        XORing each result between the components with keys designed to
        break up the algebraic structure of the permutation.
        """
        return self._aff_out.permute(
            self._aff_mid.permute(
                self._aff_in.permute(value) ^ self._in_mid_key
            ) ^ self._out_mid_key
        )

    async def apermute(self, value: int, /) -> int:
        """
        Chains keyed bijective affine permutations together while
        additionally XORing each of their inputs & outputs with keys
        designed to break up the algebraic structure of the permutation.
        """
        return await self._aff_out.apermute(
            await self._aff_mid.apermute(
                await self._aff_in.apermute(value ^ self._in_key)
                ^ self._in_mid_key
            ) ^ self._out_mid_key
        ) ^ self._out_key

    def permute(self, value: int, /) -> int:
        """
        Chains keyed bijective affine permutations together while
        additionally XORing each of their inputs & outputs with keys
        designed to break up the algebraic structure of the permutation.
        """
        return self._aff_out.permute(
            self._aff_mid.permute(
                self._aff_in.permute(value ^ self._in_key)
                ^ self._in_mid_key
            ) ^ self._out_mid_key
        ) ^ self._out_key

    async def auncapped_invert(self, value: int, /) -> int:
        """
        Inverts the modified chained keyed bijective affine permutation
        done without XORs to the in & out values of the chain.
        """
        return await self._aff_in.ainvert(
            await self._aff_mid.ainvert(
                await self._aff_out.ainvert(value) ^ self._out_mid_key
            ) ^ self._in_mid_key
        )

    def uncapped_invert(self, value: int, /) -> int:
        """
        Inverts the modified chained keyed bijective affine permutation
        done without XORs to the in & out values of the chain.
        """
        return self._aff_in.invert(
            self._aff_mid.invert(
                self._aff_out.invert(value) ^ self._out_mid_key
            ) ^ self._in_mid_key
        )

    async def ainvert(self, value: int, /) -> int:
        """
        Inverts the modified chained keyed bijective affine permutation.
        """
        return await self._aff_in.ainvert(
            await self._aff_mid.ainvert(
                await self._aff_out.ainvert(value ^ self._out_key)
                ^ self._out_mid_key
            ) ^ self._in_mid_key
        ) ^ self._in_key

    def invert(self, value: int, /) -> int:
        """
        Inverts the modified chained keyed bijective affine permutation.
        """
        return self._aff_in.invert(
            self._aff_mid.invert(
                self._aff_out.invert(value ^ self._out_key)
                ^ self._out_mid_key
            ) ^ self._in_mid_key
        ) ^ self._in_key


module_api = dict(
    AffineXORChain=t.add_type(AffineXORChain),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

