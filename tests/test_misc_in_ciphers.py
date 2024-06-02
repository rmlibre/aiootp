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

from aiootp._gentools import abatch, batch
from aiootp.ciphers import Ciphertext
from aiootp.ciphers.key_bundle import SaltAADIV


plaintext_bytes = token_bytes(1024)


async def aempty_stream() -> t.AsyncGenerator[None, None]:
    yield


def empty_stream() -> t.Generator[None, None, None]:
    yield


class TestDatastreamLimits:

    async def test_async_datastream_must_emit_in_blocksize_chunks(
        self
    ) -> None:
        for (config, cipher, salt, aad) in dual_output_ciphers:
            BLOCKSIZE = config.BLOCKSIZE
            ainvalid_size_datastream = abatch(plaintext_bytes, size=BLOCKSIZE + 1)
            akey_bundle = await cipher._KeyAADBundle(cipher._kdfs, salt=salt, aad=aad).async_mode()
            shmac = cipher._StreamHMAC(akey_bundle)._for_encryption()

            problem = (
                f"An async datastream block was allowed to exceed {BLOCKSIZE} bytes."
            )
            async with Ignore(OverflowError, if_else=violation(problem)):
                async for chunk in cipher._Junction.abytes_encipher(ainvalid_size_datastream, shmac=shmac):
                    pass

    async def test_sync_datastream_must_emit_in_blocksize_chunks(
        self
    ) -> None:
        for (config, cipher, salt, aad) in dual_output_ciphers:
            BLOCKSIZE = config.BLOCKSIZE
            invalid_size_datastream = batch(plaintext_bytes, size=BLOCKSIZE + 1)
            key_bundle = cipher._KeyAADBundle(cipher._kdfs, salt=salt, aad=aad).sync_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_encryption()

            problem = (
                f"A sync datastream block was allowed to exceed {BLOCKSIZE} bytes."
            )
            with Ignore(OverflowError, if_else=violation(problem)):
                for chunk in cipher._Junction.bytes_encipher(invalid_size_datastream, shmac=shmac):
                    pass

    async def test_async_datastream_must_emit_at_least_one_block(self) -> None:
        for (config, cipher, salt, aad) in dual_output_ciphers:
            BLOCKSIZE = config.BLOCKSIZE
            ainvalid_size_datastream = aempty_stream()
            await ainvalid_size_datastream.asend(None)
            akey_bundle = await cipher._KeyAADBundle(cipher._kdfs, salt=salt, aad=aad).async_mode()
            shmac = cipher._StreamHMAC(akey_bundle)._for_encryption()

            problem = (
                "An empty async datastream was allowed."
            )
            async with Ignore(ValueError, if_else=violation(problem)):
                async for chunk in cipher._Junction.abytes_encipher(ainvalid_size_datastream, shmac=shmac):
                    pass

    async def test_sync_datastream_must_emit_at_least_one_block(self) -> None:
        for (config, cipher, salt, aad) in dual_output_ciphers:
            BLOCKSIZE = config.BLOCKSIZE
            invalid_size_datastream = empty_stream()
            invalid_size_datastream.send(None)
            key_bundle = cipher._KeyAADBundle(cipher._kdfs, salt=salt, aad=aad).sync_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_encryption()

            problem = (
                "An empty sync datastream was allowed."
            )
            with Ignore(ValueError, if_else=violation(problem)):
                for chunk in cipher._Junction.bytes_encipher(invalid_size_datastream, shmac=shmac):
                    pass

    async def test_async_too_large_plaintext_block_overflows_validated_transform(
        self
    ) -> None:
        problem = (
            "An async plaintext block larger than blocksize didn't "
            "overflow."
        )
        for (config, cipher, salt, aad) in dual_output_ciphers:
            BLOCKSIZE = config.BLOCKSIZE
            for mode, kw in (
                ("_for_encryption", dict(salt=salt, aad=aad)),
                ("_for_decryption", dict(salt=salt, aad=aad, iv=token_bytes(config.IV_BYTES))),
            ):
                akey_bundle = await cipher._KeyAADBundle(cipher._kdfs, **kw).async_mode()
                shmac = getattr(cipher._StreamHMAC(akey_bundle), mode)()

                with Ignore(OverflowError, if_else=violation(problem)):
                    await shmac._avalidated_transform(
                        b"\xff" + token_bytes(BLOCKSIZE),
                        token_bytes(BLOCKSIZE),
                    )

    async def test_sync_too_large_plaintext_block_overflows_validated_transform(
        self
    ) -> None:
        problem = (
            "A sync plaintext block larger than blocksize didn't "
            "overflow."
        )
        for (config, cipher, salt, aad) in dual_output_ciphers:
            BLOCKSIZE = config.BLOCKSIZE
            for mode, kw in (
                ("_for_encryption", dict(salt=salt, aad=aad)),
                ("_for_decryption", dict(salt=salt, aad=aad, iv=token_bytes(config.IV_BYTES))),
            ):
                key_bundle = cipher._KeyAADBundle(cipher._kdfs, **kw).sync_mode()
                shmac = getattr(cipher._StreamHMAC(key_bundle), mode)()

                with Ignore(OverflowError, if_else=violation(problem)):
                    shmac._validated_transform(
                        b"\xff" + token_bytes(BLOCKSIZE),
                        token_bytes(BLOCKSIZE),
                    )


class TestCipherInputs:

    async def test_input_container(self) -> None:
        for (config, cipher, salt, aad) in all_ciphers:
            iv = token_bytes(config.IV_BYTES)
            sav = SaltAADIV(salt=salt, aad=aad, iv=iv, config=config)
            container = Namespace({name: sav[name] for name in sav})
            assert container.salt == sav.salt
            assert sav.salt == salt
            assert container.aad == sav.aad
            assert sav.aad == aad
            assert container.iv == sav.iv
            assert sav.iv == iv

    async def test_kdfs_limits(self) -> None:
        class InvalidCipherKDFs:
            pass

        problem = (
            "An invalid cipher KDFs type was allowed."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            kdfs = InvalidCipherKDFs()
            with Ignore(TypeError, if_else=violation(problem)):
                cipher._KeyAADBundle(kdfs)

    async def test_keys_limits(self) -> None:
        for (config, cipher, salt, aad) in all_ciphers:
            problem = (
                "Non-bytes key was allowed."
            )
            with Ignore(TypeError, if_else=violation(problem)):
                cipher.__class__(csprng().hex())

            problem = (
                "A shorter than min length key was allowed."
            )
            with Ignore(ValueError, if_else=violation(problem)):
                cipher.__class__(csprng(MIN_KEY_BYTES - 1))


    async def test_salt_limits(self) -> None:
        for (config, cipher, salt, aad) in all_ciphers:
            problem = (
                "Non-bytes salt was allowed."
            )
            with Ignore(TypeError, if_else=violation(problem)):
                cipher._KeyAADBundle(cipher._kdfs, salt=csprng(config.SALT_BYTES // 2).hex())

            problem = (
                "Invalid length salt was allowed."
            )
            with Ignore(ValueError, if_else=violation(problem)):
                cipher._KeyAADBundle(cipher._kdfs, salt=csprng())


    async def test_aad_limits(self) -> None:
        for (config, cipher, salt, aad) in all_ciphers:
            problem = (
                "Non-bytes aad was allowed."
            )
            with Ignore(TypeError, if_else=violation(problem)):
                cipher._KeyAADBundle(cipher._kdfs, salt=salt, aad=aad.hex())


    async def test_iv_limits(self) -> None:
        for (config, cipher, salt, aad) in all_ciphers:
            problem = (
                "Non-bytes IV was allowed."
            )
            with Ignore(TypeError, if_else=violation(problem)):
                cipher._KeyAADBundle(
                    cipher._kdfs, iv=token_bytes(config.IV_BYTES // 2).hex()
                )

            problem = (
                "Invalid length IV was allowed."
            )
            with Ignore(ValueError, if_else=violation(problem)):
                cipher._KeyAADBundle(
                    cipher._kdfs, iv=token_bytes(config.IV_BYTES + 1)
                )


class TestSaltMisuseReuseResistance:
    number_of_tests: int = 256

    async def test_async_siv_only_resistance(self) -> None:
        for (config, cipher, salt, aad) in all_ciphers:
            iv = token_bytes(config.IV_BYTES)
            kw = dict(kdfs=cipher._kdfs, salt=salt, iv=iv)

            # aggregate the first ciphertext block of a collection of async
            # ciphertexts instantiated with the same key, salt, aad & iv
            aciphertexts = set()
            for _ in range(self.number_of_tests):
                plaintext = await cipher._padding.astart_padding() + (
                    (config.BLOCKSIZE - config.INNER_HEADER_BYTES) * b"\x00"
                )
                key_bundle = await cipher._KeyAADBundle(**kw).async_mode()
                object.__setattr__(key_bundle._bundle, "iv_is_fresh", True)
                ciphertext = await cipher._Junction.abytes_encipher(
                    abatch(plaintext, size=config.BLOCKSIZE),
                    shmac=cipher._StreamHMAC(key_bundle)._for_encryption(),
                ).asend(None)
                aciphertexts.add(ciphertext)

            # the vulnerable first block of async ciphertexts is always
            # unique
            assert len(aciphertexts) == self.number_of_tests

            # the most vulnerable first INNER_HEADER-bytes of async
            # ciphertexts are also always unique
            ainner_headers = {
                aciphertext[config.INNER_HEADER_SLICE]
                for aciphertext in aciphertexts
            }
            assert len(ainner_headers) == self.number_of_tests

    async def test_sync_siv_only_resistance(self) -> None:
        for (config, cipher, salt, aad) in all_ciphers:
            iv = token_bytes(config.IV_BYTES)
            kw = dict(kdfs=cipher._kdfs, salt=salt, iv=iv)

            # aggregate the first ciphertext block of a collection of
            # ciphertexts instantiated with the same key, salt, aad & iv
            ciphertexts = set()
            for _ in range(self.number_of_tests):
                plaintext = cipher._padding.start_padding() + (
                    (config.BLOCKSIZE - config.INNER_HEADER_BYTES) * b"\x00"
                )
                key_bundle = cipher._KeyAADBundle(**kw).sync_mode()
                object.__setattr__(key_bundle._bundle, "iv_is_fresh", True)
                ciphertext = cipher._Junction.bytes_encipher(
                    batch(plaintext, size=config.BLOCKSIZE),
                    shmac=cipher._StreamHMAC(key_bundle)._for_encryption(),
                ).send(None)
                ciphertexts.add(ciphertext)

            # the vulnerable first block of ciphertexts is always unique
            assert len(ciphertexts) == self.number_of_tests

            # the most vulnerable first INNER_HEADER-bytes of ciphertexts
            # are also always unique
            inner_headers = {
                ciphertext[config.INNER_HEADER_SLICE]
                for ciphertext in ciphertexts
            }
            assert len(inner_headers) == self.number_of_tests

    async def test_async_single_component_resistance(self) -> None:
        for (config, cipher, static_salt, static_aad) in all_ciphers:
            static_iv = token_bytes(config.IV_BYTES)
            static_plaintext = config.BLOCKSIZE * b"\x00"
            kw = dict(
                kdfs=cipher._kdfs,
                salt=static_salt,
                iv=static_iv,
                aad=static_aad,
            )
            # aggregate first ciphertext blocks created with all static
            # randomizer components except one.
            for component, size in (
                ("salt", config.SALT_BYTES),
                ("aad", 16),
                ("iv", config.IV_BYTES),
            ):
                aciphertexts = set()

                for _ in range(self.number_of_tests):
                    key_bundle = await cipher._KeyAADBundle(
                        **{**kw, **{component: token_bytes(size)}}
                    ).async_mode()
                    object.__setattr__(key_bundle._bundle, "iv_is_fresh", True)
                    aciphertext = await cipher._Junction.abytes_encipher(
                        abatch(static_plaintext, size=config.BLOCKSIZE),
                        shmac=cipher._StreamHMAC(key_bundle)._for_encryption(),
                    ).asend(None)
                    aciphertexts.add(aciphertext)

                # the vulnerable first block of ciphertexts is always unique
                assert len(aciphertexts) == self.number_of_tests

                # the most vulnerable first INNER_HEADER-bytes of ciphertexts
                # are also always unique
                inner_headers = {
                    aciphertext[config.INNER_HEADER_SLICE]
                    for aciphertext in aciphertexts
                }
                assert len(inner_headers) == self.number_of_tests

    async def test_sync_single_component_resistance(self) -> None:
        for (config, cipher, static_salt, static_aad) in all_ciphers:
            static_iv = token_bytes(config.IV_BYTES)
            static_plaintext = config.BLOCKSIZE * b"\x00"
            kw = dict(
                kdfs=cipher._kdfs,
                salt=static_salt,
                iv=static_iv,
                aad=static_aad,
            )
            # aggregate first ciphertext blocks created with all static
            # randomizer components except one.
            for component, size in (
                ("salt", config.SALT_BYTES),
                ("aad", 16),
                ("iv", config.IV_BYTES),
            ):
                ciphertexts = set()

                for _ in range(self.number_of_tests):
                    key_bundle = cipher._KeyAADBundle(
                        **{**kw, **{component: token_bytes(size)}}
                    ).sync_mode()
                    object.__setattr__(key_bundle._bundle, "iv_is_fresh", True)
                    ciphertext = cipher._Junction.bytes_encipher(
                        batch(static_plaintext, size=config.BLOCKSIZE),
                        shmac=cipher._StreamHMAC(key_bundle)._for_encryption(),
                    ).send(None)
                    ciphertexts.add(ciphertext)

                # the vulnerable first block of ciphertexts is always unique
                assert len(ciphertexts) == self.number_of_tests

                # the most vulnerable first INNER_HEADER-bytes of ciphertexts
                # are also always unique
                inner_headers = {
                    ciphertext[config.INNER_HEADER_SLICE]
                    for ciphertext in ciphertexts
                }
                assert len(inner_headers) == self.number_of_tests


class TestCipherModes:

    async def test_key_bundle_must_be_set_to_either_async_or_sync(
        self
    ) -> None:
        problem = (
            "A cipher ran without a mode set on its key bundle."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            key_bundle = cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad
            )
            with Ignore(RuntimeError, if_else=violation(problem)):
                shmac = cipher._StreamHMAC(key_bundle)

    async def test_async_encryption_must_be_used_with_async_components(
        self
    ) -> None:
        problem = (
            "A cipher ran with mismatched component modes set."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            data = b"test_data..."
            key_bundle = await cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad
            ).async_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_encryption()
            data = batch(
                cipher._padding.pad_plaintext(data), size=config.BLOCKSIZE
            )
            with Ignore(ValueError, if_else=violation(problem)):
                b"".join(cipher._Junction.bytes_encipher(data, shmac=shmac))

    async def test_sync_encryption_must_be_used_with_sync_components(
        self
    ) -> None:
        problem = (
            "A cipher ran with mismatched component modes set."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            data = b"test_data..."
            key_bundle = cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad
            ).sync_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_encryption()
            data = abatch(
                cipher._padding.pad_plaintext(data), size=config.BLOCKSIZE
            )
            with Ignore(ValueError, if_else=violation(problem)):
                [
                    block
                    async for block
                    in cipher._Junction.abytes_encipher(data, shmac=shmac)
                ]

    async def test_async_decryption_must_be_used_with_async_components(
        self
    ) -> None:
        problem = (
            "A cipher ran with mismatched component modes set."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            data = Ciphertext(cipher.bytes_encrypt(b"test_data..."), config=config)
            key_bundle = await cipher._KeyAADBundle(
                cipher._kdfs, salt=data.salt, aad=aad, iv=data.iv
            ).async_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_decryption()
            data = batch(data.ciphertext, size=config.BLOCKSIZE)
            with Ignore(ValueError, if_else=violation(problem)):
                b"".join(cipher._Junction.bytes_decipher(data, shmac=shmac))

    async def test_sync_decryption_must_be_used_with_sync_components(
        self
    ) -> None:
        problem = (
            "A cipher ran with mismatched component modes set."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            data = Ciphertext(cipher.bytes_encrypt(b"test_data..."), config=config)
            key_bundle = cipher._KeyAADBundle(
                cipher._kdfs, salt=data.salt, aad=aad, iv=data.iv
            ).sync_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_decryption()
            data = abatch(data.ciphertext, size=config.BLOCKSIZE)
            with Ignore(ValueError, if_else=violation(problem)):
                [
                    block
                    async for block
                    in cipher._Junction.abytes_decipher(data, shmac=shmac)
                ]

    async def test_async_encryption_components_cant_be_used_for_decryption(
        self
    ) -> None:
        problem = (
            "A cipher ran with mismatched component modes set."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            data = b"test_data..."
            key_bundle = await cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad
            ).async_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_encryption()
            data = abatch(
                cipher._padding.pad_plaintext(data), size=config.BLOCKSIZE
            )
            with Ignore(ValueError, if_else=violation(problem)):
                [
                    block
                    async for block in
                    cipher._Junction.abytes_decipher(data, shmac=shmac)
                ]

    async def test_sync_encryption_components_cant_be_used_for_decryption(
        self
    ) -> None:
        problem = (
            "A cipher ran with mismatched component modes set."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            data = b"test_data..."
            key_bundle = cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad
            ).sync_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_encryption()  # enc
            data = batch(
                cipher._padding.pad_plaintext(data), size=config.BLOCKSIZE
            )
            with Ignore(ValueError, if_else=violation(problem)):
                b"".join(cipher._Junction.bytes_decipher(data, shmac=shmac))

    async def test_async_decryption_components_cant_be_used_for_encryption(
        self
    ) -> None:
        problem = (
            "A cipher ran with mismatched component modes set."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            data = Ciphertext(cipher.bytes_encrypt(b"test_data..."), config=config)
            key_bundle = await cipher._KeyAADBundle(
                cipher._kdfs, salt=data.salt, aad=aad, iv=data.iv
            ).async_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_decryption()
            data = abatch(data.ciphertext, size=config.BLOCKSIZE)
            with Ignore(ValueError, if_else=violation(problem)):
                [
                    block
                    async for block
                    in cipher._Junction.abytes_encipher(data, shmac=shmac)
                ]

    async def test_sync_decryption_components_cant_be_used_for_encryption(
        self
    ) -> None:
        problem = (
            "A cipher ran with mismatched component modes set."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            data = Ciphertext(cipher.bytes_encrypt(b"test_data..."), config=config)
            key_bundle = cipher._KeyAADBundle(
                cipher._kdfs, salt=data.salt, aad=aad, iv=data.iv
            ).sync_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_decryption()
            data = batch(data.ciphertext, size=config.BLOCKSIZE)
            with Ignore(ValueError, if_else=violation(problem)):
                b"".join(cipher._Junction.bytes_encipher(data, shmac=shmac))

    async def test_cant_set_encryption_mode_more_than_once(
        self
    ) -> None:
        problem = (
            "Encryption mode was allowed to be set more than once."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            key_bundle = await cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad
            ).async_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_encryption()
            with Ignore(PermissionError, if_else=violation(problem)):
                shmac._for_encryption()

            key_bundle = cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad
            ).sync_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_encryption()
            with Ignore(PermissionError, if_else=violation(problem)):
                shmac._for_encryption()

    async def test_cant_set_decryption_mode_without_setting_iv(
        self
    ) -> None:
        problem = (
            "Decryption mode was set without also setting IV."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            key_bundle = await cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad
            ).async_mode()
            with Ignore(PermissionError, if_else=violation(problem)):
                cipher._StreamHMAC(key_bundle)._for_decryption()

            key_bundle = cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad
            ).sync_mode()
            with Ignore(PermissionError, if_else=violation(problem)):
                cipher._StreamHMAC(key_bundle)._for_decryption()

    async def test_cant_set_decryption_mode_more_than_once(
        self
    ) -> None:
        problem = (
            "Decryption mode was allowed to be set more than once."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            key_bundle = await cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad, iv=token_bytes(config.IV_BYTES)
            ).async_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_decryption()
            with Ignore(PermissionError, if_else=violation(problem)):
                shmac._for_decryption()

            key_bundle = cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad, iv=token_bytes(config.IV_BYTES)
            ).sync_mode()
            shmac = cipher._StreamHMAC(key_bundle)._for_decryption()
            with Ignore(PermissionError, if_else=violation(problem)):
                shmac._for_decryption()

    async def test_cant_manually_set_iv_and_encryption_mode(
        self
    ) -> None:
        problem = (
            "A manually set IV was allowed in encryption mode."
        )
        for (config, cipher, salt, aad) in all_ciphers:
            key_bundle = await cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad, iv=token_bytes(config.IV_BYTES)
            ).async_mode()
            with Ignore(PermissionError, if_else=violation(problem)):
                cipher._StreamHMAC(key_bundle)._for_encryption()

            key_bundle = cipher._KeyAADBundle(
                cipher._kdfs, salt=salt, aad=aad, iv=token_bytes(config.IV_BYTES)
            ).sync_mode()
            with Ignore(PermissionError, if_else=violation(problem)):
                cipher._StreamHMAC(key_bundle)._for_encryption()


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

