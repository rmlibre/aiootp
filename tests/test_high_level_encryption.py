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


async def test_json_functions():
    ciphertext_of_dict = json_encrypt(test_data, key, salt=salt)
    ciphertext_of_string = json_encrypt(plaintext_string, key, salt=salt)

    # plaintext is not trivially detected in ciphertext
    assert json.dumps(test_data).encode() not in ciphertext_of_dict
    assert string_leakage not in ciphertext_of_string

    # no two ciphertexts are ever the same
    assert ciphertext_of_dict != await ajson_encrypt(test_data, key, salt=salt)
    assert ciphertext_of_string != await ajson_encrypt(plaintext_string, key, salt=salt)

    assert ciphertext_of_dict != json_encrypt(test_data, key)
    assert ciphertext_of_string != await ajson_encrypt(plaintext_string, key)

    assert ciphertext_of_dict != json_encrypt(test_data, key, salt=salt, aad=aad)
    assert ciphertext_of_string != await ajson_encrypt(plaintext_string, key, salt=salt, aad=aad)

    # decryption of correct ciphertext & key of json data doesn't fail
    # & is sound
    plaintext_of_dict = json_decrypt(ciphertext_of_dict, key)
    plaintext_of_string = json_decrypt(ciphertext_of_string, key)
    assert test_data == plaintext_of_dict
    assert plaintext_string == plaintext_of_string

    # async decryption with correct ciphertext & key of json data
    # doesn't fail & is sound
    assert plaintext_of_dict == await ajson_decrypt(ciphertext_of_dict, key)
    assert plaintext_of_string == await ajson_decrypt(ciphertext_of_string, key)


async def test_bytes_functions():
    ciphertext_of_bytes = bytes_encrypt(plaintext_bytes, key, salt=salt)
    ciphertext_of_string = bytes_encrypt(plaintext_string.encode(), key, salt=salt)

    # plaintext is not trivially detected in ciphertext
    assert byte_leakage not in ciphertext_of_bytes
    assert string_leakage not in ciphertext_of_string

    # no two ciphertexts are ever the same
    assert ciphertext_of_bytes != await abytes_encrypt(plaintext_bytes, key, salt=salt)
    assert ciphertext_of_string != await abytes_encrypt(plaintext_string.encode(), key, salt=salt)

    assert ciphertext_of_bytes != bytes_encrypt(plaintext_bytes, key)
    assert ciphertext_of_string != await abytes_encrypt(plaintext_string.encode(), key)

    assert ciphertext_of_bytes != bytes_encrypt(plaintext_bytes, key, salt=salt, aad=aad)
    assert ciphertext_of_string != await abytes_encrypt(plaintext_string.encode(), key, salt=salt, aad=aad)

    # decryption of correct ciphertext & key doesn't fail & is sound
    plaintext_of_bytes = bytes_decrypt(ciphertext_of_bytes, key)
    plaintext_of_string = bytes_decrypt(ciphertext_of_string, key)
    assert plaintext_bytes == plaintext_of_bytes
    assert plaintext_string == plaintext_of_string.decode()

    # async decryption with correct ciphertext & key doesn't fail & is sound
    assert plaintext_of_bytes == await abytes_decrypt(ciphertext_of_bytes, key)
    assert plaintext_of_string == await abytes_decrypt(ciphertext_of_string, key)


async def test_token_functions():
    ciphertext_of_bytes = cipher.make_token(plaintext_bytes, aad=aad)

    # no two ciphertexts are ever the same
    assert ciphertext_of_bytes != cipher.make_token(plaintext_bytes, aad=aad)
    assert ciphertext_of_bytes != await cipher.amake_token(plaintext_bytes, aad=aad)
    assert ciphertext_of_bytes != cipher.make_token(plaintext_bytes)
    assert ciphertext_of_bytes != await cipher.amake_token(plaintext_bytes)

    # token decryption of correct ciphertext & key doesn't fail & is sound
    plaintext_of_bytes = cipher.read_token(ciphertext_of_bytes, aad=aad)
    assert plaintext_of_bytes == await cipher.aread_token(ciphertext_of_bytes, aad=aad)
    assert plaintext_bytes == plaintext_of_bytes


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

