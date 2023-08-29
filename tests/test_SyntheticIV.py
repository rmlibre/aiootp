# This file is part of aiootp:
# an application agnostic — async-compatible — anonymity & cryptography
# library, providing access to high-level Pythonic utilities to simplify
# the tasks of secure data processing, communication & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


class TestSyntheticIV:
    async def test_block_masking(self):
        """
        Setup: 1) create a single padded block of plaintext

        Test: 2) show the padded plaintext is exactly one block long

        Setup: 3) initialize a deterministic key_bundle

        Test: 4) Show that allowing iv to be chosen for encryption creates
        deterministic key material

        Test: 5) show that masking the first block is the xor of the
        primer_key and the padded plaintext

        Test: 6) show that unmasking inverts the xor
        """
        # 1
        pt = b"testing SyntheticIV"
        padded_pt = Padding.pad_plaintext(pt)
        ipadded_pt = int.from_bytes(padded_pt, BIG)

        # 2
        # only one block of padded plaintext has been made
        assert BLOCKSIZE == len(padded_pt)
        assert pt == padded_pt[INNER_HEADER_BYTES:INNER_HEADER_BYTES + len(pt)]

        # 3
        iv = token_bytes(IV_BYTES)
        key_bundle = KeyAADBundle(key, salt=salt, aad=aad, iv=iv).sync_mode()
        akey_bundle = await KeyAADBundle(key, salt=salt, aad=aad, iv=iv).async_mode()
        primer_key = key_bundle._primer_key
        iprimer_key = int.from_bytes(primer_key, BIG)

        # 4
        # the primer key is exactly the length of the blocksize
        assert BLOCKSIZE == len(primer_key)
        assert primer_key == akey_bundle._primer_key

        # 5
        # masking a block is the XOR of the primer_key & the padded plaintext
        inner_header, imasked_pt = SyntheticIV._mask_block(padded_pt, primer_key)
        masked_pt = imasked_pt.to_bytes(BLOCKSIZE, BIG)
        assert masked_pt != padded_pt
        assert not INNER_HEADER_BYTES % 2
        assert len(inner_header) == INNER_HEADER_BYTES
        assert inner_header == padded_pt[INNER_HEADER_SLICE]
        assert masked_pt[INNER_HEADER_SLICE] != padded_pt[INNER_HEADER_SLICE]
        assert imasked_pt == ipadded_pt ^ iprimer_key

        # 6
        # unmasking reveals the inner_header & the XOR of the block passed
        # in with the primer_key
        unmasked_inner_header, iunmasked_pt = SyntheticIV._unmask_block(masked_pt, primer_key)
        unmasked_pt = iunmasked_pt.to_bytes(BLOCKSIZE, BIG)
        assert padded_pt == unmasked_pt
        assert inner_header == unmasked_inner_header

    async def test_unique_cipher(self):
        """
        Setup: 1) force the unsafe deterministic initialization of a
        key_bundle for encryption with a simulated user-defined iv, to
        enable the testing of salt reuse/misuse resistance given only by
        the randomization of the plaintext padding

        Setup: 2) flip the private flag which ensures users cannot supply
        an iv during encryption to force-enable unsafe determinism

        Test: 3) show the plaintext padding works as expected & is the
        only non-deterministic aspect of the test

        Test: 4) show the non-deterministic key derived by SyntheticIV
        is made from the keystream being seeded with the plaintext
        padding's inner_header & a slice of the shmac's current digest
        such that the siv is the length of the shake_128 block size.

        Test: 5) show uniqueness of ciphertexts is produced by the
        SyntheticIV algorithm, & that ciphertexts are the XOR of masked
        plaintexts with the key from the keystream after being seeded
        by the synthesized siv

        Test: 6) show the manual procedure outlined in the test produces
        the same results as the builtin method provided by the SyntheticIV
        class
        """
        # 1
        iv = token_bytes(IV_BYTES)

        pt = b"testing SyntheticIV"
        padded_pt = Padding.pad_plaintext(pt)
        ipadded_pt = int.from_bytes(padded_pt, BIG)
        apadded_pt = await Padding.apad_plaintext(pt)
        aipadded_pt = int.from_bytes(apadded_pt, BIG)

        key_bundle = KeyAADBundle(key, salt=salt, aad=aad, iv=iv).sync_mode()
        akey_bundle = await KeyAADBundle(key, salt=salt, aad=aad, iv=iv).async_mode()

        primer_key = key_bundle._primer_key
        iprimer_key = int.from_bytes(primer_key, BIG)
        aprimer_key = akey_bundle._primer_key
        aiprimer_key = int.from_bytes(aprimer_key, BIG)

        keystream = key_bundle._keystream.send
        akeystream = akey_bundle._keystream.asend

        # 2
        key_bundle._iv_given_by_user = False
        akey_bundle._iv_given_by_user = False
        shmac = StreamHMAC(key_bundle)._for_encryption()
        ashmac = StreamHMAC(akey_bundle)._for_encryption()

        # 3
        assert primer_key == aprimer_key
        assert padded_pt != apadded_pt
        assert pt == padded_pt[INNER_HEADER_BYTES:INNER_HEADER_BYTES + len(pt)]
        assert pt == apadded_pt[INNER_HEADER_BYTES:INNER_HEADER_BYTES + len(pt)]
        assert (
            padded_pt[:INNER_HEADER_BYTES] != apadded_pt[:INNER_HEADER_BYTES]
        )
        assert (
            padded_pt[INNER_HEADER_BYTES + len(pt):]
            != apadded_pt[INNER_HEADER_BYTES + len(pt):]
        )

        # 4
        inner_header, imasked_pt = SyntheticIV._mask_block(padded_pt, primer_key)
        ainner_header, aimasked_pt = SyntheticIV._mask_block(apadded_pt, aprimer_key)
        masked_pt = imasked_pt.to_bytes(BLOCKSIZE, BIG)
        amasked_pt = aimasked_pt.to_bytes(BLOCKSIZE, BIG)

        siv = inner_header + shmac._current_digest[:-INNER_HEADER_BYTES]
        asiv = ainner_header + ashmac._current_digest[:-INNER_HEADER_BYTES]

        key_chunk = keystream(siv)[INNER_HEADER_BYTES//2 : BLOCKSIZE - INNER_HEADER_BYTES//2]
        akey_chunk = (await akeystream(asiv))[INNER_HEADER_BYTES//2 : BLOCKSIZE - INNER_HEADER_BYTES//2]
        ikey_chunk = int.from_bytes(key_chunk, BIG)
        aikey_chunk = int.from_bytes(akey_chunk, BIG)
        assert siv != asiv
        assert len(siv) == SHAKE_128_BLOCKSIZE
        assert len(asiv) == SHAKE_128_BLOCKSIZE
        assert len(key_chunk) == BLOCKSIZE - INNER_HEADER_BYTES
        assert len(akey_chunk) == BLOCKSIZE - INNER_HEADER_BYTES
        assert key_chunk != akey_chunk

        # 5
        iunique_ciphertext = imasked_pt ^ ikey_chunk
        aiunique_ciphertext = aimasked_pt ^ aikey_chunk
        unique_ciphertext = iunique_ciphertext.to_bytes(BLOCKSIZE, BIG)
        aunique_ciphertext = aiunique_ciphertext.to_bytes(BLOCKSIZE, BIG)
        assert unique_ciphertext != aunique_ciphertext
        assert (
            masked_pt[INNER_HEADER_SLICE]
            == unique_ciphertext[INNER_HEADER_SLICE]
        )
        assert (
            amasked_pt[INNER_HEADER_SLICE]
            == aunique_ciphertext[INNER_HEADER_SLICE]
        )
        assert BLOCKSIZE == len(unique_ciphertext)
        assert BLOCKSIZE == len(aunique_ciphertext)

        # 6
        key_bundle = KeyAADBundle(key, salt=salt, aad=aad, iv=iv).sync_mode()
        akey_bundle = await KeyAADBundle(key, salt=salt, aad=aad, iv=iv).async_mode()
        keystream = key_bundle._keystream.send
        akeystream = akey_bundle._keystream.asend
        key_bundle._iv_given_by_user = False
        akey_bundle._iv_given_by_user = False
        shmac = StreamHMAC(key_bundle)._for_encryption()
        ashmac = StreamHMAC(akey_bundle)._for_encryption()
        assert unique_ciphertext == SyntheticIV._unique_cipher(padded_pt, keystream, shmac)
        assert aunique_ciphertext == await SyntheticIV._aunique_cipher(apadded_pt, akeystream, ashmac)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

