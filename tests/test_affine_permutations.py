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


from test_initialization import *

from aiootp._permutations.affine_permutation import AffinePermutation
from aiootp._permutations.affine_xor_chain import AffineXORChain


_key = token_bytes(2048)
_plaintexts = [*range(0, 256, 32), 255]
_test_sizes = {1, 8, 16, 32}
while len(_test_sizes) != 8:
    _test_sizes.add(choice(range(1, 33)))


class TestAffinePermutation:
    _type: type = AffinePermutation

    async def test_additive_key_remains_unchanged(self):
        for size in _test_sizes:
            key = _key[:self._type.key_size(size)]
            aff = self._type(key=key, config_id=size)
            assert key == _key[:aff.key_size(size)]
            assert key == aff._additive_key.to_bytes(2 * size, BIG)

    async def test_multiplicative_key_creates_correct_inverse_key(self):
        for size in _test_sizes:
            bitsize = 1 << (8 * size)
            add_key = _key[:self._type.key_size(size)]
            aff = self._type(key=add_key, config_id=size)
            elements = [(aff.config.MULTIPLICATIVE_KEY * i) % aff._PRIME for i in _plaintexts]
            assert elements != _plaintexts
            inversions = [(aff.config.INVERSE_KEY * i) % aff._PRIME for i in elements]
            assert inversions == _plaintexts

    async def test_permutation_size_mapped_from_config_id(self):
        for size in _test_sizes:
            bitsize = 1 << (8 * size)
            key = _key[:self._type.key_size(size)]
            aff = self._type(key=key, config_id=size)
            assert bitsize == aff.config.MAX + 1
            assert size == aff.config.SIZE
            assert 2 * size == aff.key_size(size)
            assert PRIMES[(8 * size) + 1][0] == aff.config.PRIME
            assert bitsize >= aff.permute(token_bits(8 * size)) >= 0
            assert bitsize >= await aff.apermute(token_bits(8 * size)) >= 0

    async def test_permutation_is_correctly_invertible(self):
        for size in _test_sizes:
            key = _key[:self._type.key_size(size)]
            aff = self._type(key=key, config_id=size)
            permutations = [aff.permute(i) for i in _plaintexts]
            apermutations = [await aff.apermute(i) for i in _plaintexts]
            assert permutations == apermutations
            assert _plaintexts != permutations
            inversions = [aff.invert(i) for i in permutations]
            ainversions = [await aff.ainvert(i) for i in permutations]
            assert inversions == ainversions
            assert _plaintexts == inversions


class TestAffineXORChain:
    _type: type = AffineXORChain

    def recomposed_key(self, aff) -> bytes:
        size = aff.config.SIZE
        add_key_size = 2 * size
        return (
            aff._in_key.to_bytes(size, BIG)
            + (aff._in_mid_key ^ aff.config.IPAD).to_bytes(size, BIG)
            + aff._out_key.to_bytes(size, BIG)
            + aff._aff_in._additive_key.to_bytes(add_key_size, BIG)
            + aff._aff_mid._additive_key.to_bytes(add_key_size, BIG)
            + aff._aff_out._additive_key.to_bytes(add_key_size, BIG)
        )

    async def test_subpermutations_are_affine_permutation_types(self):
        for size in _test_sizes:
            key = _key[:self._type.key_size(config_id=size)]
            aff = self._type(key=key, config_id=size)
            for permutation in (aff._aff_in, aff._aff_mid, aff._aff_out):
                assert issubclass(permutation.__class__, AffinePermutation)

    async def test_subkeys_non_overlapping_slices_of_input_key(self):
        for size in _test_sizes:
            key = _key[:self._type.key_size(config_id=size)]
            aff = self._type(key=key, config_id=size)
            assert (
                (aff._in_mid_key ^ aff.config.IPAD) == (aff._out_mid_key ^ aff.config.OPAD)
            )
            assert key == self.recomposed_key(aff)

    async def test_permutation_is_correctly_invertible(self):
        for size in _test_sizes:
            key = _key[:self._type.key_size(config_id=size)]
            aff = self._type(key=key, config_id=size)
            uncapped_permutations = [aff.uncapped_permute(i) for i in _plaintexts]
            auncapped_permutations = [await aff.auncapped_permute(i) for i in _plaintexts]
            permutations = [aff.permute(i) for i in _plaintexts]
            apermutations = [await aff.apermute(i) for i in _plaintexts]
            assert permutations == apermutations
            assert uncapped_permutations == auncapped_permutations
            assert _plaintexts != permutations
            assert _plaintexts != uncapped_permutations
            uncapped_inversions = [aff.uncapped_invert(i) for i in uncapped_permutations]
            auncapped_inversions = [await aff.auncapped_invert(i) for i in auncapped_permutations]
            inversions = [aff.invert(i) for i in permutations]
            ainversions = [await aff.ainvert(i) for i in apermutations]
            assert inversions == ainversions
            assert uncapped_inversions == auncapped_inversions
            assert _plaintexts == inversions
            assert _plaintexts == uncapped_inversions

    async def validate_latin_square_property(self, aff, SIZE, DOMAIN):
        latin_square = set()
        for step in range(DOMAIN):
            row = tuple(aff.permute(i) for i in range(DOMAIN))
            assert all((0 <= element < DOMAIN) for element in row)
            latin_square.add(row)
            await aff.astep()
        assert len(latin_square) == DOMAIN
        assert all(len(set(row)) == DOMAIN for row in latin_square)
        columns = set()
        for column_index in range(DOMAIN):
            column = tuple(row[column_index] for row in latin_square)
            columns.add(column)
        assert len(columns) == DOMAIN
        assert all(len(set(column)) == DOMAIN for column in columns)

    async def test_step_causes_full_domain_evaluation_to_fill_a_latin_square(self):
        SIZE = 1
        DOMAIN = 256 * SIZE
        key = _key[:self._type.key_size(config_id=SIZE)]
        aff = self._type(key=key, config_id=SIZE)
        assert aff.config.DOMAIN == DOMAIN == (aff._aff_in._MAX + 1)
        await self.validate_latin_square_property(aff, SIZE, DOMAIN)
        await aff.aupdate_increment(choice(list(range(1, DOMAIN))))
        await self.validate_latin_square_property(aff, SIZE, DOMAIN)
        # # Optional Extended Full-Domain Tests
        # failures = []
        # for i in range(256):
            # try:
                # aff.update_increment(i)
                # await self.validate_latin_square_property(aff, SIZE, DOMAIN)
            # except AssertionError as error:
                # failures.append(i)
        # assert not any(failures), failures


class TestFastAffineXORChain(TestAffineXORChain):
    _type: type = FastAffineXORChain

    def recomposed_key(self, aff) -> bytes:
        size = aff.config.SIZE
        add_key_size = 2 * size
        assert aff._aff_in is aff._aff_mid
        assert aff._aff_mid is aff._aff_out
        return (
            aff._in_key.to_bytes(size, BIG)
            + (aff._in_mid_key ^ aff.config.IPAD).to_bytes(size, BIG)
            + aff._out_key.to_bytes(size, BIG)
            + aff._aff_in._additive_key.to_bytes(add_key_size, BIG)
        )


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

