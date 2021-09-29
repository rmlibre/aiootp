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
    "test_json_functions",
    "test_bytes_functions",
    "test_token_functions",
    "__all__",
]


def test_json_functions():
    ciphertext_of_dict = json_encrypt(test_data, key, salt=salt)
    ciphertext_of_string = json_encrypt(plaintext_string, key, salt=salt)
    assert ciphertext_of_dict != run(ajson_encrypt(test_data, key, salt=salt))
    assert ciphertext_of_string != run(ajson_encrypt(plaintext_string, key, salt=salt))

    assert ciphertext_of_dict != json_encrypt(test_data, key)
    assert ciphertext_of_string != run(ajson_encrypt(plaintext_string, key))

    assert ciphertext_of_dict != json_encrypt(test_data, key, salt=salt, aad=aad)
    assert ciphertext_of_string != run(ajson_encrypt(plaintext_string, key, salt=salt, aad=aad))

    plaintext_of_dict = json_decrypt(ciphertext_of_dict, key)
    plaintext_of_string = json_decrypt(ciphertext_of_string, key)
    assert plaintext_of_dict == run(ajson_decrypt(ciphertext_of_dict, key))
    assert plaintext_of_string == run(ajson_decrypt(ciphertext_of_string, key))


def test_bytes_functions():
    ciphertext_of_bytes = bytes_encrypt(plaintext_bytes, key, salt=salt)
    ciphertext_of_string = bytes_encrypt(plaintext_string.encode(), key, salt=salt)
    assert ciphertext_of_bytes != run(abytes_encrypt(plaintext_bytes, key, salt=salt))
    assert ciphertext_of_string != run(abytes_encrypt(plaintext_string.encode(), key, salt=salt))

    assert ciphertext_of_bytes != bytes_encrypt(plaintext_bytes, key)
    assert ciphertext_of_string != run(abytes_encrypt(plaintext_string.encode(), key))

    assert ciphertext_of_bytes != bytes_encrypt(plaintext_bytes, key, salt=salt, aad=aad)
    assert ciphertext_of_string != run(abytes_encrypt(plaintext_string.encode(), key, salt=salt, aad=aad))

    plaintext_of_bytes = bytes_decrypt(ciphertext_of_bytes, key)
    plaintext_of_string = bytes_decrypt(ciphertext_of_string, key)
    assert plaintext_of_bytes == run(abytes_decrypt(ciphertext_of_bytes, key))
    assert plaintext_of_string == run(abytes_decrypt(ciphertext_of_string, key))


def test_token_functions():
    ciphertext_of_bytes = cipher.make_token(plaintext_bytes, aad=aad)
    assert ciphertext_of_bytes != cipher.make_token(plaintext_bytes, aad=aad)
    assert ciphertext_of_bytes != run(cipher.amake_token(plaintext_bytes, aad=aad))
    assert ciphertext_of_bytes != cipher.make_token(plaintext_bytes)
    assert ciphertext_of_bytes != run(cipher.amake_token(plaintext_bytes))

    plaintext_of_bytes = cipher.read_token(ciphertext_of_bytes, aad=aad)
    assert plaintext_of_bytes == run(cipher.aread_token(ciphertext_of_bytes, aad=aad))
    assert plaintext_bytes == plaintext_of_bytes

    asynchs.sleep(2)
    try:
        cipher.read_token(ciphertext_of_bytes, aad=aad, ttl=1)
    except TimeoutError:
        pass
    else:
        raise AssertionError("Life-time for tokens is malfunctioning.")
    try:
        run(cipher.aread_token(ciphertext_of_bytes, aad=aad, ttl=1))
    except TimeoutError:
        pass
    else:
        raise AssertionError("Life-time for tokens is malfunctioning.")

