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


import io
from collections import deque

from test_initialization import *

from aiootp._constants.misc import BIG
from aiootp._constants.datasets import Tables
from aiootp.generics.transform import abase_as_int, base_as_int
from aiootp.generics.transform import aint_as_base, int_as_base


class TestBaseConversions:

    async def test_base_as_int_correctness(self) -> None:
        for string, answer, table in (
            ("0", 0, Tables.HEX),
            ("a31b", 41755, Tables.HEX),
            ("ff", 255, Tables.HEX),
            (b"\x00", 0, Tables.BYTES),
            (b"\xa3\x1b", 41755, Tables.BYTES),
            (b"\xff", 255, Tables.BYTES),
        ):
            assert answer == await abase_as_int(string, table=table)
            assert answer == base_as_int(string, table=table)

        problem = (
            "A character not a part of the base's table didn't error."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            await abase_as_int("g", table=Tables.HEX)
        with Ignore(ValueError, if_else=violation(problem)):
            base_as_int("g", table=Tables.HEX)

    async def test_int_as_base_correctness(self) -> None:
        for number, answer, table in (
            (0, "0", Tables.HEX),
            (41755, "a31b", Tables.HEX),
            (255, "ff", Tables.HEX),
            (0, b"\x00", Tables.BYTES),
            (41755, b"\xa3\x1b", Tables.BYTES),
            (255, b"\xff", Tables.BYTES),
        ):
            assert answer == await aint_as_base(number, table=table)
            assert answer == int_as_base(number, table=table)


class TestDomains:

    async def test_encoding_methods(self) -> None:
        for constant in (b"", "string constant...", b"bytes constant..."):
            for aad in (b"", b"associated data..."):
                for domain in (b"", b"domain..."):
                    assert (
                        await Domains.aencode_constant(constant, aad=aad, domain=domain)
                        ==  Domains.encode_constant(constant, aad=aad, domain=domain)
                    )


class TestEncodingUtilities:

    async def test_key_must_not_be_falsey(self) -> None:
        problem = (
            "A falsey key was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            await generics.canon.aencode_key(key=b"", blocksize=32)
        with Ignore(ValueError, if_else=violation(problem)):
            generics.canon.encode_key(key=b"", blocksize=32)

    async def test_item_size_mismatches_caught_during_decoding(
        self
    ) -> None:
        problem = (
            "A mismatch between item length & declared length was allowed."
        )
        int_bytes = 1
        item = b"test"
        item_length = len(item).to_bytes(int_bytes, BIG)
        single_encoded_item = item_length + item[:-1]
        with Ignore(ValueError, if_else=violation(problem)):
            [item async for item in generics.canon.adecode_items(
                read=io.BytesIO(single_encoded_item).read,
                item_count=1,
                int_bytes=1,
            )]
        with Ignore(ValueError, if_else=violation(problem)):
            list(generics.canon.decode_items(
                read=io.BytesIO(single_encoded_item).read,
                item_count=1,
                int_bytes=1,
            ))

    async def test_missing_padding_metadata_throws_error(self) -> None:
        problem = (
            "Padding test ran without the necessary metadata."
        )
        blocksize = (32).to_bytes(1, BIG)
        pad = b"\x00"
        with Ignore(ValueError, if_else=violation(problem)):
            generics.canon.test_canonical_padding(
                read=io.BytesIO().read,
                items=deque([blocksize]),
                total_size=64,
            )

    async def test_non_blocksize_multiple_declared_length_throws_error(
        self
    ) -> None:
        problem = (
            "Padding test ran with a length declaration not equal to a "
            "multiple of the blocksize."
        )
        blocksize = (32).to_bytes(1, BIG)
        pad = b"\x00"
        with Ignore(ValueError, if_else=violation(problem)):
            generics.canon.test_canonical_padding(
                read=io.BytesIO().read,
                items=deque([blocksize, pad]),
                total_size=67,
            )

    async def test_declared_pad_value_must_be_all_that_remains(self) -> None:
        problem = (
            "Padding test ran with an invalid padding value."
        )
        blocksize = (32).to_bytes(1, BIG)
        pad = b"\x00"
        generics.canon.test_canonical_padding(
            read=io.BytesIO(32 * pad).read,
            items=deque([blocksize, pad]),
            total_size=64,
        )
        with Ignore(ValueError, if_else=violation(problem)):
            generics.canon.test_canonical_padding(
                read=io.BytesIO(32 * b"A").read,
                items=deque([blocksize, pad]),
                total_size=64,
            )


class TestCanonicalPack:

    async def test_empty_pad_is_invalid(self):
        problem = (
            "An empty padding value didn't raise a `TypeError`."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            canonical_pack(b"test", pad=b"")
        async with Ignore(TypeError, if_else=violation(problem)):
            await acanonical_pack(b"test", pad=b"")

    async def test_zero_blocksize_is_invalid(self):
        problem = (
            "A negative blocksize value didn't raise a `OverflowError`."
        )
        with Ignore(ZeroDivisionError, if_else=violation(problem)):
            canonical_pack(b"test", blocksize=0)
        async with Ignore(ZeroDivisionError, if_else=violation(problem)):
            await acanonical_pack(b"test", blocksize=0)

    async def test_negative_integer_blocksize_is_invalid(self):
        problem = (
            "A negative blocksize value didn't raise a `OverflowError`."
        )
        test_values = (-168, -136, -2, -1)
        for blocksize in test_values:
            with Ignore(OverflowError, if_else=violation(problem)):
                canonical_pack(b"test", blocksize=blocksize)
            async with Ignore(OverflowError, if_else=violation(problem)):
                await acanonical_pack(b"test", blocksize=blocksize)

    async def test_float_blocksize_is_invalid(self):
        problem = (
            "A float blocksize value didn't raise an `AttributeError`."
        )
        test_values = (-2.0, -1.0, 0.0, 1.0, 2.0)
        for blocksize in test_values:
            with Ignore(AttributeError, if_else=violation(problem)):
                canonical_pack(b"test", blocksize=blocksize)
            async with Ignore(AttributeError, if_else=violation(problem)):
                await acanonical_pack(b"test", blocksize=blocksize)

    async def test_minimum_size_given_by_item_count_declaration(self):
        problem = (
            "An item count declaration which exceeds the count which is"
            "possible given the small size of the packing was allowed."
        )
        minimum_inputs = ((), (b"",), (b"", b""), (b"", b"", b""))
        tested_int_bytes = (1, 4, 8)
        for data in minimum_inputs:
            for int_bytes in tested_int_bytes:
                test = canonical_pack(*data, int_bytes=int_bytes)
                with Ignore(CanonicalEncodingError, if_else=violation(problem)):
                    canonical_unpack((test[0] + 1).to_bytes(1, BIG) + test[1:])
                test = canonical_pack(*data, int_bytes=int_bytes)
                async with Ignore(CanonicalEncodingError, if_else=violation(problem)):
                    await acanonical_unpack((test[0] + 1).to_bytes(1, BIG) + test[1:])



async def test_canonical_packs():
    PACK_PAD_INDEX = 33

    TEST_KEYS = [token_bytes(64) for _ in range(4)]
    HASHERS = (sha3_256, sha3_512, shake_128, shake_256)

    DEFAULT_PAD = b"\x00"
    DEFAULT_BLOCKSIZE = 1
    DEFAULT_INT_BYTES = 8

    DEFAULT_PACKING = canonical_pack()
    DEFAULT_ASYNC_PACKING = await acanonical_pack()

    # the default packing is the same for async & sync
    assert DEFAULT_PACKING == DEFAULT_ASYNC_PACKING
    assert (
        DEFAULT_PACKING
        == await acanonical_pack(pad=DEFAULT_PAD, blocksize=DEFAULT_BLOCKSIZE, int_bytes=DEFAULT_INT_BYTES)
    )

    # the options can be used together
    assert (
        canonical_unpack(canonical_pack(b"", pad=b"0", blocksize=127, int_bytes=16))
        == await acanonical_unpack(await acanonical_pack(b"", pad=b"0", blocksize=127, int_bytes=16))
    )

    test_inputs = [
        [token_bytes(token_bits(8)) for _ in range(2 + token_bits(2))]
        for _ in range(4)
    ]
    test_int_bytes = [1, 2, 3, 4]
    test_blocksizes = [SHA3_256_BLOCKSIZE, SHA3_512_BLOCKSIZE, SHAKE_128_BLOCKSIZE, SHAKE_256_BLOCKSIZE]
    test_pads = [b"\x01", b"\x80", b"\xff"]

    for inputs in test_inputs:
        # similar inputs do no produce the same output
        for int_bytes in test_int_bytes:
            result = canonical_pack(*inputs)
            aresult = await acanonical_pack(*inputs, int_bytes=int_bytes)
            assert result != aresult

            # but the items are still packed correctly & interoperably
            assert inputs == list(canonical_unpack(aresult))
            assert inputs == list(await acanonical_unpack(result))
        for blocksize in test_blocksizes:
            result = canonical_pack(*inputs)
            aresult = await acanonical_pack(*inputs, blocksize=blocksize)
            assert result != aresult
            assert 0 == len(aresult) % blocksize

            # but the items are still packed correctly & interoperably
            assert inputs == list(canonical_unpack(aresult))
            assert inputs == list(await acanonical_unpack(result))
        for pad, hasher, key in zip(test_pads, HASHERS, TEST_KEYS):
            result = canonical_pack(*inputs)
            aresult = await acanonical_pack(*inputs, pad=pad)
            assert result != aresult

            # but the items are still packed correctly & interoperably
            assert inputs == list(canonical_unpack(aresult))
            assert inputs == list(await acanonical_unpack(result))

            if not pad:
                continue

            # and the items & pads are used correctly in hashers
            obj = hasher()
            keyed_obj = obj.copy()
            digest_size = obj.digest_size
            encoded_key = encode_key(key, obj.block_size, pad=pad)
            packing = canonical_pack(
                (digest_size if digest_size else 64).to_bytes(DEFAULT_INT_BYTES, BIG),
                *inputs,
                blocksize=obj.block_size,
                pad=pad,
            )
            keyed_obj.update(encoded_key + packing)
            obj.update(packing)
            if digest_size:
                # keyed hashing of packed items works as expected
                assert keyed_obj.digest() == hash_bytes(*inputs, pad=pad, key=key, hasher=hasher)
                assert keyed_obj.digest() == await ahash_bytes(*inputs, pad=pad, key=key, hasher=hasher)

                # un-keyed hashing of packed items works as expected
                assert obj.digest() == hash_bytes(*inputs, pad=pad, hasher=hasher)
                assert obj.digest() == await ahash_bytes(*inputs, pad=pad, hasher=hasher)
            else:
                # keyed hashing of packed items works as expected
                assert keyed_obj.digest(64) == hash_bytes(*inputs, pad=pad, key=key, hasher=hasher, size=64)
                assert keyed_obj.digest(64) == await ahash_bytes(*inputs, pad=pad, key=key, hasher=hasher, size=64)

                # un-keyed hashing of packed items works as expected
                assert obj.digest(64) == hash_bytes(*inputs, pad=pad, hasher=hasher, size=64)
                assert obj.digest(64) == await ahash_bytes(*inputs, pad=pad, hasher=hasher, size=64)

        # the same inputs produce the same outputs
        for int_bytes in test_int_bytes:
            result = canonical_pack(*inputs, int_bytes=int_bytes)
            aresult = await acanonical_pack(*inputs, int_bytes=int_bytes)
            assert result == aresult

            # the relative location of the default pad declaration is
            # dependent on the size of integers used to represent item
            # lengths
            assert type(result) is bytes
            assert result[4 * int_bytes + 1] == DEFAULT_PAD[0]
        for blocksize in test_blocksizes:
            result = canonical_pack(*inputs, blocksize=blocksize)
            aresult = await acanonical_pack(*inputs, blocksize=blocksize)
            assert result == aresult
            assert 0 == len(result) % blocksize
        for pad in test_pads:
            result = canonical_pack(*inputs, pad=pad)
            aresult = await acanonical_pack(*inputs, pad=pad)
            assert result == aresult

            # the default integer size of 8 bytes puts the pad item at
            # the default location
            assert (result[PACK_PAD_INDEX] == pad[0]) if pad else 1

            # the relative location of the pad declaration is dependent
            # on the size of integers used to represent item lengths
            for int_bytes in test_int_bytes:
                result = canonical_pack(*inputs, pad=pad, int_bytes=int_bytes)
                aresult = await acanonical_pack(*inputs, pad=pad, int_bytes=int_bytes)
                assert result == aresult
                assert (result[4 * int_bytes + 1] == pad[0]) if pad else 1

    pad = b"Z"
    items = (b"testing", b"pad", b"character", b"location", b"in", b"result")
    packing = bytearray(canonical_pack(*items, pad=pad))
    assert packing[PACK_PAD_INDEX] == pad[0]


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

