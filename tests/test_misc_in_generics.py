# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


async def test_canonical_packs():
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
        canonical_unpack(canonical_pack(b"", pad=b"0", blocksize=127, int_bytes=16), int_bytes=16)
        == await acanonical_unpack(await acanonical_pack(b"", pad=b"0", blocksize=127, int_bytes=16), int_bytes=16)
    )

    test_inputs = [
        [token_bytes(token_bits(8)) for _ in range(2 + token_bits(2))]
        for _ in range(4)
    ]
    test_int_bytes = [1, 2, 3, 4]
    test_blocksizes = [SHA3_256_BLOCKSIZE, SHA3_512_BLOCKSIZE, SHAKE_128_BLOCKSIZE, SHAKE_256_BLOCKSIZE]
    test_pads = [b"", b"\x01", b"\x80", b"\xff"]

    for inputs in test_inputs:
        # similar inputs do no produce the same output
        for int_bytes in test_int_bytes:
            result = canonical_pack(*inputs)
            aresult = await acanonical_pack(*inputs, int_bytes=int_bytes)
            assert result != aresult

            # but the items are still packed correctly & interoperably
            assert inputs == list(canonical_unpack(aresult, int_bytes=int_bytes))
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
            assert result[4 * int_bytes] == DEFAULT_PAD[0]
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
                assert (result[4 * int_bytes] == pad[0]) if pad else 1

    pad = b"Z"
    items = (b"testing", b"pad", b"character", b"location", b"in", b"result")
    packing = bytearray(canonical_pack(*items, pad=pad))
    assert packing[PACK_PAD_INDEX] == pad[0]


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

