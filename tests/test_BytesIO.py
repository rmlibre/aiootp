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


async def test_json_conversion_functions():

    aciphertext = await cipher.abytes_encrypt(plaintext_bytes)
    ciphertext = cipher.bytes_encrypt(plaintext_bytes)

    assert aciphertext != ciphertext

    aciphertext_json = await BytesIO.aciphertext_to_json(aciphertext)
    ciphertext_json = BytesIO.ciphertext_to_json(ciphertext)

    assert aciphertext_json != ciphertext_json

    assert aciphertext == await BytesIO.ajson_to_ciphertext(aciphertext_json)
    assert ciphertext == BytesIO.json_to_ciphertext(ciphertext_json)


    aad = b"aad"
    key_bundle = KeyAADBundle(key=key, salt=salt, aad=aad, allow_dangerous_determinism=True).sync_mode()
    aaad=b"async_aad"
    akey_bundle = await KeyAADBundle(key=key, salt=salt, aad=aaad, allow_dangerous_determinism=True).async_mode()

    padded_plaintext = apadded_plaintext = await Padding.apad_plaintext(plaintext_bytes)

    shmac = StreamHMAC(key_bundle)._for_encryption()
    ashmac = StreamHMAC(akey_bundle)._for_encryption()

    encipher = bytes_encipher(data(padded_plaintext), shmac)
    aencipher = abytes_encipher(adata(apadded_plaintext), ashmac)

    ciphertext = {
        CIPHERTEXT: [BytesIO.bytes_to_base64(chunk) for chunk in encipher],
        SHMAC: shmac.finalize().hex(),
        SALT: key_bundle.salt.hex(),
        IV: key_bundle.iv.hex(),
    }
    aciphertext = {
        CIPHERTEXT: [BytesIO.bytes_to_base64(chunk) for chunk in await aunpack(aencipher).alist()],
        SHMAC: (await ashmac.afinalize()).hex(),
        SALT: akey_bundle.salt.hex(),
        IV: akey_bundle.iv.hex(),
    }

    # no two ciphertexts are ever the same
    assert ciphertext != aciphertext

    aads = (aad, aaad)
    ciphertexts = (ciphertext, aciphertext)
    for i, (_aad, json_message) in enumerate(zip(aads, ciphertexts)):
        message = BytesIO.json_to_ciphertext(json_message)
        amessage = await BytesIO.ajson_to_ciphertext(json_message)

        # decryption of manually reconstructed ciphertext from json
        # doesn't fail & is sound
        assert plaintext_bytes == cipher.bytes_decrypt(message, aad=_aad)
        assert plaintext_bytes == cipher.bytes_decrypt(amessage, aad=_aad)
        assert plaintext_bytes == await cipher.abytes_decrypt(message, aad=_aad)
        assert plaintext_bytes == await cipher.abytes_decrypt(amessage, aad=_aad)

        # use of wrong aad fails
        problem = "Alteration of aad was not noticed!"
        with ignore(StreamHMAC.InvalidSHMAC, if_else=violation(problem)):
            cipher.bytes_decrypt(message, aad=aads[(i + 1) % 2])

        # async use of wrong aad fails
        problem = "Async alteration of aad was not noticed!"
        async with aignore(StreamHMAC.InvalidSHMAC, if_else=aviolation(problem)):
            await cipher.abytes_decrypt(message, aad=aads[(i + 1) % 2])


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

