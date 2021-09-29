# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from init_tests import *


__all__ = [
    "test_detection_of_ciphertext_modification",
    "test_current_digest",
    "test_block_ids",
    "__all__",
]


def test_detection_of_ciphertext_modification():

    CT = CIPHERTEXT
    a_hex = lambda: randoms.choice("0123456789abcdef")
    a_number = lambda: randoms.unique_range(1, 1 << 128)
    a_byte = lambda: randoms.unique_range(1, 256)
    token_bytes = lambda size: randoms.token_bytes(size)

    aciphertext = _containers.Ciphertext(run(cipher.abytes_encrypt(plaintext_bytes)))
    act = [CT, aciphertext[CT], aciphertext[HMAC], aciphertext[SALT], aciphertext[SIV]]
    _act = aciphertext[CT]
    _ahmac = aciphertext[HMAC]
    _asalt = aciphertext[SALT]
    _asiv = aciphertext[SIV]

    ciphertext = _containers.Ciphertext(cipher.bytes_encrypt(plaintext_bytes))
    ct = [CT, ciphertext[CT], ciphertext[HMAC], ciphertext[SALT], ciphertext[SIV]]
    _ct = ciphertext[CT]
    _hmac = ciphertext[HMAC]
    _salt = ciphertext[SALT]
    _siv = ciphertext[SIV]

    amodified_ciphertexts = dict(
        amodified_ciphertext_0={
            CT: b"", HMAC: _ahmac, SALT: _asalt, SIV: _asiv
        },
        amodified_ciphertext_1={
            CT: token_bytes(32) + _act[-32:],
            HMAC: _ahmac,
            SALT: _asalt,
            SIV: _asiv,
        },
        amodified_ciphertext_2={
            CT: _act[:-1] + (_act[-1] ^ 0b1).to_bytes(1, "big"),
            HMAC: _ahmac,
            SALT: _asalt,
            SIV: _asiv,
        },
        amodified_ciphertext_3={
            CT: b"\x01" + _act,
            HMAC: _ahmac,
            SALT: _asalt,
            SIV: _asiv,
        },
        amodified_ciphertext_4={
            CT: _act, HMAC: b"", SALT: _asalt, SIV: _asiv
        },
        amodified_ciphertext_5={
            CT: _act,
            HMAC: _ahmac[:6] + bytes([_ahmac[6] ^ a_byte()]) + _ahmac[7:],
            SALT: _asalt,
            SIV: _asiv,
        },
        amodified_ciphertext_6={
            CT: _act,
            HMAC: _ahmac[:-1] + bytes([_ahmac[-1] ^ 0b1]),
            SALT: _asalt,
            SIV: _asiv,
        },
        amodified_ciphertext_7={
            CT: _act, HMAC: _ahmac + _ahmac[:1], SALT: _asalt, SIV: _asiv
        },
        amodified_ciphertext_8={
            CT: _act, HMAC: _ahmac[:-2], SALT: _asalt, SIV: _asiv
        },
        amodified_ciphertext_9={
            CT: _act, HMAC: _ahmac, SALT: b"", SIV: _asiv
        },
        amodified_ciphertext_10={
            CT: _act,
            HMAC: _ahmac,
            SALT: _asalt[:6] + bytes([_asalt[6] ^ a_byte()]) + _asalt[7:],
            SIV: _asiv,
        },
        amodified_ciphertext_11={
            CT: _act,
            HMAC: _ahmac,
            SALT: _asalt[:-1] + bytes([_asalt[-1] ^ 0b1]),
            SIV: _asiv,
        },
        amodified_ciphertext_12={
            CT: _act, HMAC: _ahmac, SALT: _asalt + _asalt[:1], SIV: _asiv
        },
        amodified_ciphertext_13={
            CT: _act, HMAC: _ahmac, SALT: _asalt[:-2], SIV: _asiv
        },
        amodified_ciphertext_14={
            CT: _act, HMAC: _ahmac, SALT: _asalt, SIV: b""
        },
        amodified_ciphertext_15={
            CT: _act,
            HMAC: _ahmac,
            SALT: _asalt,
            SIV: _asiv[:6] + bytes([_asiv[6] ^ 1]) + _asiv[7:],
        },
        amodified_ciphertext_16={
            CT: _act,
            HMAC: _ahmac,
            SALT: _asalt,
            SIV: _asiv[:-1] + bytes([_asiv[-1] ^ 1]),
        },
        amodified_ciphertext_17={
            CT: _act,
            HMAC: _ahmac,
            SALT: _asalt,
            CT: _act, HMAC: _ahmac, SALT: _asalt, SIV: _asiv + _asiv[:1]
        },
        amodified_ciphertext_18={
            CT: _act, HMAC: _ahmac, SALT: _asalt, SIV: _asiv[:-2]
        },
    )

    modified_ciphertexts = dict(
        modified_ciphertext_0={CT: b"", HMAC: _hmac, SALT: _salt, SIV: _siv},
        modified_ciphertext_1={
            CT: token_bytes(32) + _ct[-32:],
            HMAC: _hmac,
            SALT: _salt,
            SIV: _siv,
        },
        modified_ciphertext_2={
            CT: _ct[:-1] + (_ct[-1] ^ 0b1).to_bytes(1, "big"),
            HMAC: _hmac,
            SALT: _salt,
            SIV: _siv,
        },
        modified_ciphertext_3={
            CT: b"\x01" + _ct,
            HMAC: _hmac,
            SALT: _salt,
            SIV: _siv,
        },
        modified_ciphertext_4={CT: _ct, HMAC: b"", SALT: _salt, SIV: _siv},
        modified_ciphertext_5={
            CT: _ct,
            HMAC: _hmac[:6] + bytes([_hmac[6] ^ a_byte()]) + _hmac[7:],
            SALT: _salt,
            SIV: _siv,
        },
        modified_ciphertext_6={
            CT: _ct,
            HMAC: _hmac[:-1] + bytes([_hmac[-1] ^ 0b1]),
            SALT: _salt,
            SIV: _siv,
        },
        modified_ciphertext_7={
            CT: _ct, HMAC: _hmac + _hmac[:1], SALT: _salt, SIV: _siv
        },
        modified_ciphertext_8={
            CT: _ct, HMAC: _hmac[:-2], SALT: _salt, SIV: _siv
        },
        modified_ciphertext_9={CT: _ct, HMAC: _hmac, SALT: b"", SIV: _siv},
        modified_ciphertext_10={
            CT: _ct,
            HMAC: _hmac,
            SALT: _salt[:6] + bytes([_salt[6] ^ a_byte()]) + _salt[7:],
            SIV: _siv,
        },
        modified_ciphertext_11={
            CT: _ct,
            HMAC: _hmac,
            SALT: _salt[:-1] + bytes([_salt[-1] ^ 0b1]),
            SIV: _siv,
        },
        modified_ciphertext_12={
            CT: _ct, HMAC: _hmac, SALT: _salt + _salt[:1], SIV: _siv
        },
        modified_ciphertext_13={
            CT: _ct, HMAC: _hmac, SALT: _salt[:-2], SIV: _siv
        },
        modified_ciphertext_14={CT: _ct, HMAC: _hmac, SALT: _salt, SIV: b""},
        modified_ciphertext_15={
            CT: _ct,
            HMAC: _hmac,
            SALT: _salt,
            SIV: _siv[:6] + bytes([_siv[6] ^ 1]) + _siv[7:],
        },
        modified_ciphertext_16={
            CT: _ct,
            HMAC: _hmac,
            SALT: _salt,
            SIV: _siv[:-1] + bytes([_siv[-1] ^ 1]),
        },
        modified_ciphertext_17={
            CT: _ct, HMAC: _hmac, SALT: _salt, SIV: _siv + _siv[:1]
        },
        modified_ciphertext_18={
            CT: _ct, HMAC: _hmac, SALT: _salt, SIV: _siv[:-2]
        },
    )

    for name, modified_ciphertext in amodified_ciphertexts.items():
        try:
            mct = [name, modified_ciphertext[CT], modified_ciphertext[SALT], modified_ciphertext[HMAC]]
            modified_ciphertext = (
                modified_ciphertext[HMAC]
                + modified_ciphertext[SALT]
                + modified_ciphertext[SIV]
                + modified_ciphertext[CT]
            )
            pt = run(cipher.abytes_decrypt(modified_ciphertext))
        except (ValueError, OverflowError):
            pass
        except Exception as err:
            e = (err, mct, act)
            assert err.__class__ == PermissionError, ("An unexpected error!", e)
        else:
            e = (pt, mct, act)
            raise AssertionError("Modification was not detected!", e)
    for name, modified_ciphertext in modified_ciphertexts.items():
        try:
            mct = [name, modified_ciphertext[CT], modified_ciphertext[SALT], modified_ciphertext[HMAC]]
            modified_ciphertext = (
                modified_ciphertext[HMAC]
                + modified_ciphertext[SALT]
                + modified_ciphertext[SIV]
                + modified_ciphertext[CT]
            )
            pt = cipher.bytes_decrypt(modified_ciphertext)
        except (ValueError, OverflowError):
            pass
        except Exception as err:
            e = (err, mct, ct)
            assert err.__class__ == PermissionError, ("An unexpected error!", e)
        else:
            e = (pt, mct, ct)
            raise AssertionError("Modification was not detected!", e)


def test_current_digest():

    async def acipher_stream():
        key_bundle = await KeyAADBundle(key, aad=aad).async_mode()
        shmac = StreamHMAC(key_bundle).for_encryption()

        datastream = aplaintext_stream(plaintext_bytes, key_bundle)
        cipherstream = datastream.abytes_encipher(key_bundle, validator=shmac)

        first_ciphertext_block = await cipherstream()
        yield key_bundle.salt, shmac.siv
        yield await shmac.acurrent_digest(), first_ciphertext_block
        async for ciphertext_block in cipherstream:
            yield await shmac.acurrent_digest(), ciphertext_block

    def cipher_stream():
        key_bundle = KeyAADBundle(key, aad=aad).sync_mode()
        shmac = StreamHMAC(key_bundle).for_encryption()

        datastream = plaintext_stream(plaintext_bytes, key_bundle)
        cipherstream = datastream.bytes_encipher(key_bundle, validator=shmac)

        first_ciphertext_block = cipherstream()
        yield key_bundle.salt, shmac.siv
        yield shmac.current_digest(), first_ciphertext_block
        for ciphertext_block in cipherstream:
            yield shmac.current_digest(), ciphertext_block

    async def adecipher_and_test():
        cipherstream = acipher_stream()
        salt, siv = await cipherstream.asend(None)
        key_bundle = await KeyAADBundle(key, salt=salt, aad=aad, siv=siv).async_mode()
        shmac = StreamHMAC(key_bundle).for_decryption()

        ciphertext = []
        deciphering = aunpack(ciphertext).abytes_decipher(key_bundle, validator=shmac)

        padded_plaintext = b""
        async for digest, ciphertext_block in cipherstream:
            ciphertext.append(ciphertext_block)
            plaintext_chunk = await deciphering()
            await shmac.atest_current_digest(digest)
            padded_plaintext += plaintext_chunk

            try:
                fake_digest = csprng()[:len(digest)]
                await shmac.atest_current_digest(fake_digest)
            except ValueError:
                pass
            else:
                raise AssertionError("Validators don't detect invalid current digests!")
            try:
                change = (digest[-1] ^ 1).to_bytes(1, "big")
                await shmac.atest_current_digest(digest[:-1] + change)
            except ValueError:
                pass
            else:
                raise AssertionError("Validators don't detect invalid current digests!")

        assert plaintext_bytes == await Padding.adepad_plaintext(
            padded_plaintext, key_bundle
        )

    def decipher_and_test():
        cipherstream = cipher_stream()
        salt, siv = cipherstream.send(None)
        key_bundle = KeyAADBundle(key, salt=salt, aad=aad, siv=siv).sync_mode()
        shmac = StreamHMAC(key_bundle).for_decryption()

        ciphertext = []
        deciphering = unpack(ciphertext).bytes_decipher(key_bundle, validator=shmac)

        padded_plaintext = b""
        for digest, ciphertext_block in cipherstream:
            ciphertext.append(ciphertext_block)
            plaintext_chunk = deciphering()
            shmac.test_current_digest(digest)
            padded_plaintext += plaintext_chunk

            try:
                fake_digest = csprng()[:len(digest)]
                shmac.test_current_digest(fake_digest)
            except ValueError:
                pass
            else:
                raise AssertionError("Validators don't detect invalid current digests!")
            try:
                change = (digest[-1] ^ 1).to_bytes(1, "big")
                shmac.test_current_digest(digest[:-1] + change)
            except ValueError:
                pass
            else:
                raise AssertionError("Validators don't detect invalid current digests!")

        assert plaintext_bytes == Padding.depad_plaintext(
            padded_plaintext, key_bundle
        )

    run(adecipher_and_test())
    decipher_and_test()


def test_block_ids():

    async def aciphertext_stream():
        key_bundle = await KeyAADBundle(key, aad=aad).async_mode()
        shmac = StreamHMAC(key_bundle).for_encryption()
        datastream = aplaintext_stream(plaintext_bytes, key_bundle)
        cipherstream = datastream.abytes_encipher(key_bundle, validator=shmac)

        first_ciphertext_block = await cipherstream()
        yield key_bundle.salt, shmac.siv
        yield (
            await shmac.anext_block_id(first_ciphertext_block),
            first_ciphertext_block,
        )
        async for ciphertext_block in cipherstream:
            yield (
                await shmac.anext_block_id(ciphertext_block),
                ciphertext_block,
            )

    def ciphertext_stream():
        key_bundle = KeyAADBundle(key, aad=aad).sync_mode()
        shmac = enc_hmac = StreamHMAC(key_bundle).for_encryption()
        datastream = plaintext_stream(plaintext_bytes, key_bundle)
        cipherstream = datastream.bytes_encipher(key_bundle, validator=shmac)

        first_ciphertext_block = cipherstream()
        yield key_bundle.salt, shmac.siv
        yield (
            shmac.next_block_id(first_ciphertext_block),
            first_ciphertext_block,
        )
        for ciphertext_block in cipherstream:
            yield (
                shmac.next_block_id(ciphertext_block),
                ciphertext_block,
            )

    async def adecipher_and_test():
        cipherstream = aciphertext_stream()
        salt, siv = await cipherstream.asend(None)
        key_bundle = await KeyAADBundle(key, salt=salt, aad=aad, siv=siv).async_mode()
        shmac = StreamHMAC(key_bundle).for_decryption()

        ciphertext = []
        deciphering = aunpack(ciphertext).abytes_decipher(key_bundle, validator=shmac)

        padded_plaintext = b""
        async for block_id, ciphertext_block in cipherstream:
            await shmac.atest_next_block_id(block_id, ciphertext_block)
            ciphertext.append(ciphertext_block)
            padded_plaintext += await deciphering()

            try:
                truncated_block_id = block_id[:-1] + bytes([block_id[-1] ^ 1])
                await shmac.atest_next_block_id(truncated_block_id, ciphertext_block)
            except ValueError:
                pass
            else:
                raise AssertionError("Block id was modified without notice!")
            try:
                truncated_block_id = block_id[:6]
                await shmac.atest_next_block_id(truncated_block_id, ciphertext_block)
            except PermissionError:
                pass
            else:
                raise AssertionError("An insufficient size block id was allowed!")
            try:
                fake_block_id = csprng()[:len(block_id)]
                await shmac.atest_next_block_id(fake_block_id, ciphertext_block)
            except ValueError:
                pass
            else:
                raise AssertionError("Block was modified without notice!")

        assert plaintext_bytes == await Padding.adepad_plaintext(
            padded_plaintext, key_bundle
        )

    def decipher_and_test():
        stream = ciphertext_stream()
        salt, siv = stream.send(None)
        key_bundle = KeyAADBundle(key, salt=salt, aad=aad, siv=siv).sync_mode()
        shmac = StreamHMAC(key_bundle).for_decryption()

        ciphertext = []
        deciphering = unpack(ciphertext).bytes_decipher(key_bundle, validator=shmac)

        padded_plaintext = b""
        for block_id, ciphertext_block in stream:
            shmac.test_next_block_id(block_id, ciphertext_block)
            ciphertext.append(ciphertext_block)
            padded_plaintext += deciphering()

            try:
                truncated_block_id = block_id[:-1] + bytes([block_id[-1] ^ 1])
                shmac.test_next_block_id(truncated_block_id, ciphertext_block)
            except ValueError:
                pass
            else:
                raise AssertionError("Block id was modified without notice!")
            try:
                truncated_block_id = block_id[:6]
                shmac.test_next_block_id(truncated_block_id, ciphertext_block)
            except PermissionError:
                pass
            else:
                raise AssertionError("An insufficient size block id was allowed!")
            try:
                fake_block_id = csprng()[:len(block_id)]
                shmac.test_next_block_id(fake_block_id, ciphertext_block)
            except ValueError:
                pass
            else:
                raise AssertionError("Block was modified without notice!")

        assert plaintext_bytes == Padding.depad_plaintext(
            padded_plaintext, key_bundle
        )

    run(adecipher_and_test())
    decipher_and_test()

