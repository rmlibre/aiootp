# This file is part of aiootp, an asynchronous crypto and anonymity
# library. Home of the Chunky2048 psuedo one-time pad stream cipher.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


ainvalid_size_datastream = adata(plaintext_bytes, size=BLOCKSIZE + 1)
invalid_size_datastream = data(plaintext_bytes, size=BLOCKSIZE + 1)


async def test_datastream_limits():
    akey_bundle = await KeyAADBundle(key=key, salt=salt, aad=aad, allow_dangerous_determinism=True).async_mode()
    key_bundle = KeyAADBundle(key=key, salt=salt, aad=aad, allow_dangerous_determinism=True).sync_mode()

    # async cipher blocksize limits are respected
    problem = f"A plaintext block was allowed to exceed {BLOCKSIZE} bytes!"
    async with aignore(OverflowError, if_else=aviolation(problem)):
        await ainvalid_size_datastream.areset()
        keystream = abytes_keys(akey_bundle)
        shmac = StreamHMAC(akey_bundle)._for_encryption()
        async for chunk in abytes_encipher(ainvalid_size_datastream, shmac):
            pass

    # sync cipher blocksize limits are respected
    problem = f"A plaintext block was allowed to exceed {BLOCKSIZE} bytes!"
    with ignore(OverflowError, if_else=violation(problem)):
        invalid_size_datastream.reset()
        keystream = bytes_keys(key_bundle)
        shmac = StreamHMAC(key_bundle)._for_encryption()
        for chunk in bytes_encipher(invalid_size_datastream, shmac):
            pass


def test_keys_limits():
    # A falsey key is overwritten
    key_bundle = KeyAADBundle(key=None)
    assert key_bundle.key
    assert len(key_bundle.key) == 64

    problem = "Non-bytes key was allowed"
    with ignore(TypeError, if_else=violation(problem)):
        KeyAADBundle(key=csprng().hex(), allow_dangerous_determinism=True)


def test_salt_limits():
    problem = "Non-bytes salt was allowed"
    with ignore(TypeError, if_else=violation(problem)):
        KeyAADBundle(salt=csprng().hex())

    problem = "Invalid length salt was allowed"
    with ignore(ValueError, if_else=violation(problem)):
        KeyAADBundle(salt=csprng(), allow_dangerous_determinism=True)


async def test_salt_reuse_resistance_given_by_ivs_only():
    number_of_tests = 256
    unpadded_plaintext = BLOCKSIZE * b"\x00"

    # ASYNC
    # aggregate the first ciphertext block of a collection of
    # async ciphertexts instantiated with the same key, salt & aad
    kw = dict(key=key, salt=salt, allow_dangerous_determinism=True)
    aciphertexts = set({
        await abytes_encipher(
            adata.root(unpadded_plaintext),
            shmac=StreamHMAC(await KeyAADBundle(**kw).async_mode())._for_encryption(),
        ).asend(None)
        for _ in range(number_of_tests)
    })
    assert all(len(block) == BLOCKSIZE for block in aciphertexts)

    # the vulnerable first block of async ciphertexts is always
    # unique
    assert len(aciphertexts) == number_of_tests

    # the most vulnerable first INNER_HEADER-bytes of async
    # ciphertexts are also always unique
    ainner_headers = {aciphertext[INNER_HEADER_SLICE] for aciphertext in aciphertexts}
    assert len(ainner_headers) == number_of_tests


    # SYNC
    # aggregate the first ciphertext block of a collection of
    # ciphertexts instantiated with the same key, salt & aad
    kw = dict(key=key, salt=salt, allow_dangerous_determinism=True)
    ciphertexts = set({
        bytes_encipher(
            data.root(unpadded_plaintext),
            shmac=StreamHMAC(KeyAADBundle(**kw).sync_mode())._for_encryption(),
        ).send(None)
        for _ in range(number_of_tests)
    })
    assert all(len(block) == BLOCKSIZE for block in ciphertexts)

    # the vulnerable first block of ciphertexts is always unique
    assert len(ciphertexts) == number_of_tests

    # the most vulnerable first INNER_HEADER-bytes of ciphertexts are
    # also always unique
    inner_headers = {ciphertext[INNER_HEADER_SLICE] for ciphertext in ciphertexts}
    assert len(inner_headers) == number_of_tests


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

