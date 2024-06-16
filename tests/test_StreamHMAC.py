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


from random import randrange

from test_initialization import *

from aiootp._gentools import abatch, batch


class TestStreamHMACStates:

    async def test_key_bundle_must_be_correct_subclass(self) -> None:
        class FalseKeyAADBundle:
            pass

        problem = (
            "An invalid key_bundle type was allowed."
        )
        for (config, cipher, *_) in all_ciphers:
            key_bundle = FalseKeyAADBundle()
            with Ignore(TypeError, if_else=violation(problem)):
                cipher._StreamHMAC(key_bundle)

    async def test_sync_shmac_cant_be_registered_more_than_once(
        self
    ) -> None:
        problem = (
            "A SHMAC object was allowed to be used more than once."
        )
        for (config, cipher, *_) in all_ciphers:
            key_bundle = cipher._KeyAADBundle(cipher._kdfs).sync_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_encryption()
            plaintext = cipher._padding.pad_plaintext(b"")
            data = batch(plaintext, size=config.BLOCKSIZE)
            b"".join(cipher._Junction.bytes_encipher(data, shmac=shmac))
            data = batch(plaintext, size=config.BLOCKSIZE)
            with Ignore(PermissionError, if_else=violation(problem)):
                b"".join(cipher._Junction.bytes_encipher(data, shmac=shmac))

    async def test_result_cant_be_retrieved_before_finalization(self) -> None:
        problem = (
            "Retrieving a result before finalization was allowed."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            key_bundle = cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad
            ).sync_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_encryption()
            with Ignore(PermissionError, if_else=violation(problem)):
                shmac.result

    async def test_cant_finalize_more_than_once(self) -> None:
        problem = (
            "Multiple finalization calls were allowed."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            key_bundle = cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad
            ).sync_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_encryption()
            shmac.finalize()
            with Ignore(PermissionError, if_else=violation(problem)):
                shmac.finalize()
            with Ignore(PermissionError, if_else=violation(problem)):
                await shmac.afinalize()

    async def test_untrusted_shmac_must_be_bytes(self) -> None:
        problem = (
            "A non-bytes untrusted shmac was allowed."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            key_bundle = cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad
            ).sync_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_encryption()
            shmac.finalize()
            with Ignore(TypeError, if_else=violation(problem)):
                shmac.test_shmac(shmac.result.hex())
            with Ignore(TypeError, if_else=violation(problem)):
                await shmac.atest_shmac(shmac.result.hex())


async def test_detection_of_ciphertext_modification():

    for (config, cipher, *_) in all_ciphers:
        aciphertext = Ciphertext(
            await cipher.abytes_encrypt(plaintext_bytes), config=config
        )

        ######
        ###### ciphertext container packs async ciphertexts correctly
        act = b"".join(aciphertext.values())
        assert all(aciphertext.values())
        assert act == b"".join(
            [aciphertext.shmac, aciphertext.salt, aciphertext.iv, aciphertext.ciphertext]
        )

        # async ciphertext doesn't obviously contain plaintext
        for chunk in batch(plaintext_bytes, size=10):
            assert chunk not in act
        byte_leakage not in act

        # async decryption of correct data doesn't fail
        assert plaintext_bytes == await cipher.abytes_decrypt(act)

        # sync decryption of async ciphertext doesn't fail
        assert plaintext_bytes == cipher.bytes_decrypt(act)

        ######
        ###### async decryption of altered ciphertext fails
        aict = int.from_bytes(act, BIG)
        problem = (
            "Async ciphertext alteration not caught."
        )
        for abit in range(0, aict.bit_length(), 16):
            with Ignore(cipher.InvalidSHMAC, if_else=violation(problem)):
                altered_act = (aict ^ (1 << abit)).to_bytes(len(act), BIG)
                await cipher.abytes_decrypt(altered_act)

        # async decryption of ciphertext lengthened to invalid size fails
        problem = (
            "Invalid size lengthened sync ciphertext allowed."
        )
        for extra_bytes in range(1, config.BLOCKSIZE):
            with Ignore(cipher._Ciphertext.InvalidCiphertextSize, if_else=violation(problem)):
                await cipher.abytes_decrypt(act + token_bytes(extra_bytes))

        # sync decryption of ciphertext shortened to invalid size fails
        problem = (
            "Invalid size shortened sync ciphertext allowed."
        )
        for fewer_bytes in range(1, config.BLOCKSIZE):
            with Ignore(cipher._Ciphertext.InvalidCiphertextSize, if_else=violation(problem)):
                await cipher.abytes_decrypt(act[:-fewer_bytes])

        ######
        ###### test the ciphertext container class
        ciphertext = Ciphertext(
            cipher.bytes_encrypt(plaintext_bytes), config=config
        )

        # ciphertext container packs sync ciphertexts correctly
        ct = b"".join(ciphertext.values())
        assert all(ciphertext.values())
        assert ct == b"".join(
            [ciphertext.shmac, ciphertext.salt, ciphertext.iv, ciphertext.ciphertext]
        )

        # sync ciphertext doesn't obviously contain plaintext
        for chunk in batch(plaintext_bytes, size=10):
            assert chunk not in ct
        byte_leakage not in ct

        # sync decryption of correct data doesn't fail
        assert plaintext_bytes == cipher.bytes_decrypt(ct)

        # async decryption of sync ciphertext doesn't fail
        assert plaintext_bytes == await cipher.abytes_decrypt(ct)

        ######
        ###### sync decryption of altered ciphertext fails
        ict = int.from_bytes(ct, BIG)
        problem = (
            "Sync ciphertext alteration not caught."
        )
        for bit in range(0, ict.bit_length(), 16):
            with Ignore(cipher.InvalidSHMAC, if_else=violation(problem)):
                altered_ct = (ict ^ (1 << bit)).to_bytes(len(ct), BIG)
                cipher.bytes_decrypt(altered_ct)

        # sync decryption of ciphertext lengthened to invalid size fails
        problem = (
            "Invalid size lengthened sync ciphertext allowed."
        )
        for extra_bytes in range(1, config.BLOCKSIZE):
            with Ignore(ValueError, if_else=violation(problem)):
                cipher.bytes_decrypt(ct + token_bytes(extra_bytes))

        # sync decryption of ciphertext shortened to invalid size fails
        problem = (
            "Invalid size shortened sync ciphertext allowed."
        )
        for fewer_bytes in range(1, config.BLOCKSIZE):
            with Ignore(ValueError, if_else=violation(problem)):
                cipher.bytes_decrypt(ct[:-fewer_bytes])


async def aciphertext_stream(config, cipher, salt, aad):
    key_bundle = await cipher._KeyAADBundle(cipher._kdfs, aad=aad).async_mode()
    shmac = cipher._StreamHMAC(key_bundle)._for_encryption()
    datastream = abatch(await cipher._padding.apad_plaintext(plaintext_bytes), size=config.BLOCKSIZE)
    cipherstream = cipher._Junction.abytes_encipher(datastream, shmac=shmac)

    first_ciphertext_block = await cipherstream.asend(None)
    yield key_bundle.salt, key_bundle.iv
    yield (
        await shmac.anext_block_id(first_ciphertext_block),
        first_ciphertext_block,
    )
    async for ciphertext_block in cipherstream:
        yield (
            await shmac.anext_block_id(ciphertext_block),
            ciphertext_block,
        )


def ciphertext_stream(config, cipher, salt, aad):
    key_bundle = cipher._KeyAADBundle(cipher._kdfs, aad=aad).sync_mode()
    shmac = enc_hmac = cipher._StreamHMAC(key_bundle)._for_encryption()
    datastream = batch(cipher._padding.pad_plaintext(plaintext_bytes), size=config.BLOCKSIZE)
    cipherstream = cipher._Junction.bytes_encipher(datastream, shmac=shmac)

    first_ciphertext_block = cipherstream.send(None)
    yield key_bundle.salt, key_bundle.iv
    yield (
        shmac.next_block_id(first_ciphertext_block),
        first_ciphertext_block,
    )
    for ciphertext_block in cipherstream:
        yield (
            shmac.next_block_id(ciphertext_block),
            ciphertext_block,
        )


async def test_async_block_ids_during_deciphering():

    for (config, cipher, salt, aad) in all_ciphers:
        cipherstream = aciphertext_stream(config, cipher, salt, aad)
        salt, iv = await cipherstream.asend(None)
        key_bundle = await cipher._KeyAADBundle(cipher._kdfs, salt=salt, aad=aad, iv=iv).async_mode()
        shmac = cipher._StreamHMAC(key_bundle)._for_decryption()

        ciphertext = []
        deciphering = cipher._Junction.abytes_decipher(aunpack(ciphertext), shmac=shmac)

        padded_plaintext = b""
        async for block_id, ciphertext_block in cipherstream:
            await shmac.atest_next_block_id(block_id, ciphertext_block)
            ciphertext.append(ciphertext_block)
            padded_plaintext += await deciphering.asend(None)

            problem = (
                "Block id was modified without notice."
            )
            with Ignore(cipher.InvalidBlockID, if_else=violation(problem)):
                fake_block_id = await axi_mix(block_id + b"\x01", size=config.BLOCK_ID_BYTES)
                await shmac.atest_next_block_id(fake_block_id, ciphertext_block)

            problem = (
                "An insufficient size block ID was allowed."
            )
            with Ignore(PermissionError, if_else=violation(problem)):
                truncated_block_id = block_id[:config.MIN_BLOCK_ID_BYTES - 1]
                await shmac.atest_next_block_id(truncated_block_id, ciphertext_block)

            problem = (
                "An too large block ID was allowed."
            )
            with Ignore(PermissionError, if_else=violation(problem)):
                expanded_block_id = (config.MAX_BLOCK_ID_BYTES + 1) * b"\xff"
                await shmac.atest_next_block_id(expanded_block_id, ciphertext_block)

            problem = (
                "A non-bytes block ID was allowed."
            )
            with Ignore(TypeError, if_else=violation(problem)):
                await shmac.atest_next_block_id(block_id.hex(), ciphertext_block)

            problem = (
                "Block was modified without notice."
            )
            with Ignore(cipher.InvalidBlockID, if_else=violation(problem)):
                fake_block = await axi_mix(ciphertext_block + b"\x01", size=config.BLOCKSIZE)
                await shmac.atest_next_block_id(block_id, fake_block)

        assert plaintext_bytes == await cipher._padding.adepad_plaintext(
            padded_plaintext
        )

        problem = (
            "MAC object accessible after finalization."
        )
        tag = await shmac.afinalize()
        await shmac.atest_shmac(tag)
        with Ignore(AttributeError, if_else=violation(problem)):
            shmac._mac.digest()


def test_sync_block_ids_during_deciphering():

    for (config, cipher, salt, aad) in all_ciphers:
        stream = ciphertext_stream(config, cipher, salt, aad)
        salt, iv = stream.send(None)
        key_bundle = cipher._KeyAADBundle(cipher._kdfs, salt=salt, aad=aad, iv=iv).sync_mode()
        shmac = cipher._StreamHMAC(key_bundle)._for_decryption()

        ciphertext = []
        deciphering = cipher._Junction.bytes_decipher(unpack(ciphertext), shmac=shmac)

        padded_plaintext = b""
        for block_id, ciphertext_block in stream:
            shmac.test_next_block_id(block_id, ciphertext_block)
            ciphertext.append(ciphertext_block)
            padded_plaintext += deciphering.send(None)

            problem = (
                "Block id was modified without notice."
            )
            with Ignore(cipher.InvalidBlockID, if_else=violation(problem)):
                fake_block_id = xi_mix(block_id + b"\x01", size=config.BLOCK_ID_BYTES)
                shmac.test_next_block_id(fake_block_id, ciphertext_block)

            problem = (
                "An insufficient size block ID was allowed."
            )
            with Ignore(PermissionError, if_else=violation(problem)):
                truncated_block_id = block_id[:config.MIN_BLOCK_ID_BYTES - 1]
                shmac.test_next_block_id(truncated_block_id, ciphertext_block)

            problem = (
                "An too large block ID was allowed."
            )
            with Ignore(PermissionError, if_else=violation(problem)):
                expanded_block_id = (config.MAX_BLOCK_ID_BYTES + 1) * b"\xff"
                shmac.test_next_block_id(expanded_block_id, ciphertext_block)

            problem = (
                "A non-bytes block ID was allowed."
            )
            with Ignore(TypeError, if_else=violation(problem)):
                shmac.test_next_block_id(block_id.hex(), ciphertext_block)

            problem = (
                "Block was modified without notice."
            )
            with Ignore(cipher.InvalidBlockID, if_else=violation(problem)):
                fake_block = xi_mix(ciphertext_block + b"\x01", size=config.BLOCKSIZE)
                shmac.test_next_block_id(block_id, fake_block)

        assert plaintext_bytes == cipher._padding.depad_plaintext(padded_plaintext)

        problem = (
            "MAC object accessible after finalization."
        )
        tag = shmac.finalize()
        shmac.test_shmac(tag)
        with Ignore(AttributeError, if_else=violation(problem)):
            shmac._mac.digest()


async def test_calling_aupdate_before_setting_mode_causes_error() -> None:
    for (config, cipher, salt, aad) in all_ciphers:
        key_bundle = await cipher._KeyAADBundle(
            cipher._kdfs, salt=salt, aad=aad
        ).async_mode()

        problem = (
            "An async shmac update was allowed without setting mode."
        )
        with Ignore(PermissionError, if_else=violation(problem)):
            await cipher._StreamHMAC(key_bundle)._aupdate(token_bytes(168))


async def test_calling_update_before_setting_mode_causes_error() -> None:
    for (config, cipher, salt, aad) in all_ciphers:
        key_bundle = cipher._KeyAADBundle(
            cipher._kdfs, salt=salt, aad=aad
        ).sync_mode()

        problem = (
            "A sync shmac update was allowed without setting mode."
        )
        with Ignore(PermissionError, if_else=violation(problem)):
            cipher._StreamHMAC(key_bundle)._update(token_bytes(168))


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

