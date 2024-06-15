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


class TestAffinePermutationConfig:
    kw = dict(aad=b"testing")

    async def test_size_must_be_within_bounded_limits(self) -> None:
        problem = (
            "A size out of bounds was allowed."
        )
        for bad_size in (-1, 0, 4097):
            with Ignore(ValueError, if_else=violation(problem)):
                t.AffinePermutationConfig(size=bad_size, **self.kw)

    async def test_smallest_allowed_prime(self) -> None:
        problem = (
            "A prime below 257 was allowed."
        )
        config_id = size = 1
        config = t.AffinePermutation._configs[config_id]
        config.is_likely_safe_multiplier(
            config.MULTIPLICATIVE_KEY, prime=257
        )
        for bad_prime in (2, 23, 59, 97, 137, 179, 251):
            with Ignore(ValueError, if_else=violation(problem)):
                config.is_likely_safe_multiplier(
                    config.MULTIPLICATIVE_KEY, prime=bad_prime
                )


class TestAffinePermutation:
    _type: type = AffinePermutation

    async def test_additive_key_size_is_enforced(self) -> None:
        problem = (
            "An invalid key size was allowed."
        )
        for size in _test_sizes:
            key = _key[:self._type.key_size(size) + 1]
            with Ignore(ValueError, if_else=violation(problem)):
                self._type(key=key, config_id=size)

    async def test_additive_key_remains_unchanged(self) -> None:
        for size in _test_sizes:
            key = _key[:self._type.key_size(size)]
            aff = self._type(key=key, config_id=size)
            assert key == _key[:aff.key_size(size)]
            assert key == aff._additive_key.to_bytes(2 * size, BIG)

    async def test_multiplicative_key_creates_correct_inverse_key(self) -> None:
        for size in _test_sizes:
            bitsize = 1 << (8 * size)
            add_key = _key[:self._type.key_size(size)]
            aff = self._type(key=add_key, config_id=size)
            elements = [(aff.config.MULTIPLICATIVE_KEY * i) % aff._PRIME for i in _plaintexts]
            assert elements != _plaintexts
            inversions = [(aff.config.INVERSE_KEY * i) % aff._PRIME for i in elements]
            assert inversions == _plaintexts

    async def test_permutation_size_mapped_from_config_id(self) -> None:
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

    async def test_permutation_is_correctly_invertible(self) -> None:
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


class TestAffineXORChainConfig:
    kw = dict(permutation_type=AffinePermutation)

    async def test_size_must_be_within_bounded_limits(self) -> None:
        problem = (
            "A size out of bounds was allowed."
        )
        for bad_size in (-1, 0, 4097):
            with Ignore(ValueError, if_else=violation(problem)):
                t.AffineXORChainConfig(
                    config_id=32,
                    size=bad_size,
                    permutation_config_id=32,
                    **self.kw,
                )

    async def test_key_types_is_iterable_of_identifier_int_tuples(
        self
    ) -> None:
        problem = (
            "Invalid `key_types` argmuent value was allowed."
        )
        good_name = "in_key"
        good_int = 2
        t.AffineXORChainConfig(
            config_id=32,
            size=32,
            permutation_config_id=32,
            key_types=((good_name, good_int),),
            **self.kw,
        )
        for bad_name in ("1312non_identifier", "non-identifier"):
            with Ignore(ValueError, if_else=violation(problem)):
                t.AffineXORChainConfig(
                    config_id=32,
                    size=32,
                    permutation_config_id=32,
                    key_types=((bad_name, good_int),),
                    **self.kw,
                )
        for bad_int in (0, "zero", 2.0, "16", 33):
            with Ignore(ValueError, if_else=violation(problem)):
                t.AffineXORChainConfig(
                    config_id=32,
                    size=32,
                    permutation_config_id=32,
                    key_types=((good_name, bad_int),),
                    **self.kw,
                )

    async def test_permutation_cid_defaults_to_instance_cid(self) -> None:
        config = t.AffineXORChainConfig(
            config_id=32,
            size=32,
            **self.kw,
        )
        assert 32 == config.PERMUTATION_CONFIG_ID

    async def test_permutation_type_is_enforced(self) -> None:
        problem = (
            "An invalid permutation type was allowed."
        )

        class InvalidPermutationType:

            def permute(self, value: int) -> int:
                pass

            def invert(self, value: int) -> int:
                pass

        with Ignore(TypeError, if_else=violation(problem)):
            t.AffineXORChainConfig(
                config_id=32,
                size=32,
                permutation_type=InvalidPermutationType,
            )
        with Ignore(TypeError, if_else=violation(problem)):
            t.AffineXORChainConfig(
                config_id=32,
                size=32,
                permutation_type=None,
            )


class TestAffineXORChain:
    _type: type = AffineXORChain

    async def test_in_out_xor_key_sizes_are_enforced(self) -> None:
        problem = (
            "An invalid XOR key size was allowed."
        )
        key_reader = lambda size: size * b"A"
        bad_key_reader = lambda size: (size + 1) * b"A"
        for size in _test_sizes:
            aff = self._type.__new__(self._type)
            aff.config = self._type._configs[size]
            for tested_method in (aff._process_in_key, aff._process_out_key):
                assert aff.config.XOR_KEY_SIZE * b"A" == tested_method(
                    key_reader=key_reader, size=aff.config.XOR_KEY_SIZE
                ).to_bytes(aff.config.XOR_KEY_SIZE, BIG)

                with Ignore(ValueError, if_else=violation(problem)):
                    tested_method(key_reader=bad_key_reader, size=size)

    async def test_mid_xor_key_size_is_enforced(self) -> None:
        problem = (
            "An invalid mid XOR key size was allowed."
        )
        key_reader = lambda size: size * b"A"
        bad_key_reader = lambda size: (size + 1) * b"A"
        for size in _test_sizes:
            aff = self._type.__new__(self._type)
            aff.config = self._type._configs[size]
            tested_method = aff._process_mid_key
            IPAD, OPAD = aff.config.IPAD, aff.config.OPAD
            raw_key = int.from_bytes(aff.config.XOR_KEY_SIZE * b"A", BIG)

            assert (IPAD ^ raw_key, OPAD ^ raw_key) == tested_method(
                key_reader=key_reader, size=aff.config.XOR_KEY_SIZE
            )

            with Ignore(ValueError, if_else=violation(problem)):
                tested_method(key_reader=bad_key_reader, size=size)

    async def test_increment_update_value_must_be_within_the_domain(
        self
    ) -> None:
        problem = (
            "An increment update value outside of the domain was allowed."
        )
        for size in _test_sizes:
            key = _key[:self._type.key_size(config_id=size)]
            aff = self._type(key=key, config_id=size)
            DOMAIN = aff.config.DOMAIN

            await aff.aupdate_increment(DOMAIN - 1)
            aff.update_increment(DOMAIN - 1)

            await aff.aupdate_increment(int(randoms.uniform(2, DOMAIN)))
            aff.update_increment(int(randoms.uniform(2, DOMAIN)))

            await aff.aupdate_increment(1)
            aff.update_increment(1)

            with Ignore(ValueError, if_else=violation(problem)):
                await aff.aupdate_increment(DOMAIN)
            with Ignore(ValueError, if_else=violation(problem)):
                aff.update_increment(DOMAIN)
            with Ignore(ValueError, if_else=violation(problem)):
                await aff.aupdate_increment(0)
            with Ignore(ValueError, if_else=violation(problem)):
                aff.update_increment(0)
            with Ignore(ValueError, if_else=violation(problem)):
                await aff.aupdate_increment(-1)
            with Ignore(ValueError, if_else=violation(problem)):
                aff.update_increment(-1)

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

    async def test_subpermutations_are_affine_permutation_types(self) -> None:
        for size in _test_sizes:
            key = _key[:self._type.key_size(config_id=size)]
            aff = self._type(key=key, config_id=size)
            for permutation in (aff._aff_in, aff._aff_mid, aff._aff_out):
                assert issubclass(permutation.__class__, AffinePermutation)

    async def test_subkeys_non_overlapping_slices_of_input_key(self) -> None:
        for size in _test_sizes:
            key = _key[:self._type.key_size(config_id=size)]
            aff = self._type(key=key, config_id=size)
            assert (
                (aff._in_mid_key ^ aff.config.IPAD) == (aff._out_mid_key ^ aff.config.OPAD)
            )
            assert key == self.recomposed_key(aff)

    async def test_permutation_is_correctly_invertible(self) -> None:
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

    async def validate_latin_square_property(self, aff, SIZE, DOMAIN) -> None:
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

    async def test_step_causes_full_domain_evaluation_to_fill_a_latin_square(
        self
    ) -> None:
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

