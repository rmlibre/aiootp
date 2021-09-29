# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "__all__",
    "test_json_conversion_functions",
]


from init_tests import *


def test_json_conversion_functions():

    aciphertext = run(cipher.abytes_encrypt(plaintext_bytes))
    ciphertext = cipher.bytes_encrypt(plaintext_bytes)

    assert aciphertext != ciphertext

    aciphertext_json = run(BytesIO.abytes_to_json(aciphertext))
    ciphertext_json = BytesIO.bytes_to_json(ciphertext)

    assert aciphertext_json != ciphertext_json

    assert aciphertext == run(BytesIO.ajson_to_bytes(aciphertext_json))
    assert ciphertext == BytesIO.json_to_bytes(ciphertext_json)


    xkey_bundle = KeyAADBundle(key=key, salt=salt, aad=b"wrong", allow_dangerous_determinism=True).sync_mode()
    key_bundle = KeyAADBundle(key=key, salt=salt, aad=aad, allow_dangerous_determinism=True).sync_mode()
    akey_bundle = run(KeyAADBundle(key=key, salt=salt, aad=aad, allow_dangerous_determinism=True).async_mode())

    xpadded_plaintext = Padding.pad_plaintext(plaintext_bytes, xkey_bundle)
    padded_plaintext = Padding.pad_plaintext(plaintext_bytes, key_bundle)
    apadded_plaintext = run(Padding.apad_plaintext(plaintext_bytes, akey_bundle))

    xshmac = StreamHMAC(xkey_bundle).for_encryption()
    shmac = StreamHMAC(key_bundle).for_encryption()
    ashmac = StreamHMAC(akey_bundle).for_encryption()

    xencipher = data(padded_plaintext).bytes_encipher(xkey_bundle, xshmac)
    encipher = data(padded_plaintext).bytes_encipher(key_bundle, shmac)
    aencipher = adata(padded_plaintext).abytes_encipher(akey_bundle, ashmac)

    xciphertext = {
        CIPHERTEXT: xencipher.bytes_to_int().list(),
        HMAC: xshmac.finalize().hex(),
        SALT: xkey_bundle.salt.hex(),
        SIV: xkey_bundle.siv.hex(),
    }
    ciphertext = {
        CIPHERTEXT: encipher.bytes_to_int().list(),
        HMAC: shmac.finalize().hex(),
        SALT: key_bundle.salt.hex(),
        SIV: key_bundle.siv.hex(),
    }
    aciphertext = {
        CIPHERTEXT: run(aencipher.abytes_to_int().alist()),
        HMAC: run(ashmac.afinalize()).hex(),
        SALT: akey_bundle.salt.hex(),
        SIV: akey_bundle.siv.hex(),
    }

    assert ciphertext == aciphertext
    assert ciphertext != xciphertext

    for json_message in [ciphertext, aciphertext]:
        message = BytesIO.json_to_bytes(json_message)
        assert plaintext_bytes == cipher.bytes_decrypt(message, aad=aad)

