# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
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
    ciphertext_of_dict = json_encrypt(test_data, key, salt=salt, allow_dangerous_determinism=True)
    ciphertext_of_string = json_encrypt(plaintext_string, key, salt=salt, allow_dangerous_determinism=True)
    assert ciphertext_of_dict != run(ajson_encrypt(test_data, key, salt=salt, allow_dangerous_determinism=True))
    assert ciphertext_of_string != run(ajson_encrypt(plaintext_string, key, salt=salt, allow_dangerous_determinism=True))

    assert ciphertext_of_dict != json_encrypt(test_data, key)
    assert ciphertext_of_string != run(ajson_encrypt(plaintext_string, key))

    assert ciphertext_of_dict != json_encrypt(test_data, key, salt=salt, pid=pid, allow_dangerous_determinism=True)
    assert ciphertext_of_string != run(ajson_encrypt(plaintext_string, key, salt=salt, pid=pid, allow_dangerous_determinism=True))

    plaintext_of_dict = json_decrypt(json.dumps(ciphertext_of_dict), key)
    plaintext_of_string = json_decrypt(json.dumps(ciphertext_of_string), key)
    assert plaintext_of_dict == run(ajson_decrypt(json.dumps(ciphertext_of_dict), key))
    assert plaintext_of_string == run(ajson_decrypt(json.dumps(ciphertext_of_string), key))


def test_bytes_functions():
    ciphertext_of_bytes = bytes_encrypt(plaintext_bytes, key, salt=salt, allow_dangerous_determinism=True)
    ciphertext_of_string = bytes_encrypt(plaintext_string.encode(), key, salt=salt, allow_dangerous_determinism=True)
    assert ciphertext_of_bytes != run(abytes_encrypt(plaintext_bytes, key, salt=salt, allow_dangerous_determinism=True))
    assert ciphertext_of_string != run(abytes_encrypt(plaintext_string.encode(), key, salt=salt, allow_dangerous_determinism=True))

    assert ciphertext_of_bytes != bytes_encrypt(plaintext_bytes, key)
    assert ciphertext_of_string != run(abytes_encrypt(plaintext_string.encode(), key))

    assert ciphertext_of_bytes != bytes_encrypt(plaintext_bytes, key, salt=salt, pid=pid, allow_dangerous_determinism=True)
    assert ciphertext_of_string != run(abytes_encrypt(plaintext_string.encode(), key, salt=salt, pid=pid, allow_dangerous_determinism=True))

    plaintext_of_bytes = bytes_decrypt(ciphertext_of_bytes, key)
    plaintext_of_string = bytes_decrypt(ciphertext_of_string, key)
    assert plaintext_of_bytes == run(abytes_decrypt(ciphertext_of_bytes, key))
    assert plaintext_of_string == run(abytes_decrypt(ciphertext_of_string, key))


def test_token_functions():
    ciphertext_of_bytes = pad.make_token(plaintext_bytes, pid=pid)
    assert ciphertext_of_bytes != run(pad.amake_token(plaintext_bytes, pid=pid))
    assert ciphertext_of_bytes != pad.make_token(plaintext_bytes)
    assert ciphertext_of_bytes != run(pad.amake_token(plaintext_bytes))
    assert ciphertext_of_bytes != pad.make_token(plaintext_bytes, key=salt, pid=pid)
    assert ciphertext_of_bytes != run(pad.amake_token(plaintext_bytes, key=salt, pid=pid))

    plaintext_of_bytes = pad.read_token(ciphertext_of_bytes, pid=pid)
    assert plaintext_of_bytes == run(pad.aread_token(ciphertext_of_bytes, pid=pid))

    asynchs.sleep(2)
    try:
        pad.read_token(ciphertext_of_bytes, pid=pid, ttl=1)
    except TimeoutError:
        pass
    else:
        raise AssertionError("Life-time for tokens is malfunctioning.")
    try:
        run(pad.aread_token(ciphertext_of_bytes, pid=pid, ttl=1))
    except TimeoutError:
        pass
    else:
        raise AssertionError("Life-time for tokens is malfunctioning.")

