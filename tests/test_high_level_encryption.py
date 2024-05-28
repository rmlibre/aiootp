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


async def test_json_functions():
    for (config, cipher, salt, aad) in all_ciphers:
        ciphertext_of_dict = cipher.json_encrypt(test_data, salt=salt)
        ciphertext_of_string = cipher.json_encrypt(plaintext_string, salt=salt)

        # plaintext is not trivially detected in ciphertext
        assert json.dumps(test_data).encode() not in ciphertext_of_dict
        assert string_leakage not in ciphertext_of_string

        # no two ciphertexts are ever the same
        assert ciphertext_of_dict != await cipher.ajson_encrypt(test_data, salt=salt)
        assert ciphertext_of_string != await cipher.ajson_encrypt(plaintext_string, salt=salt)

        assert ciphertext_of_dict != cipher.json_encrypt(test_data)
        assert ciphertext_of_string != await cipher.ajson_encrypt(plaintext_string)

        assert ciphertext_of_dict != cipher.json_encrypt(test_data, salt=salt, aad=aad)
        assert ciphertext_of_string != await cipher.ajson_encrypt(plaintext_string, salt=salt, aad=aad)

        # decryption of correct ciphertext & key of json data doesn't fail
        # & is sound
        plaintext_of_dict = cipher.json_decrypt(ciphertext_of_dict)
        plaintext_of_string = cipher.json_decrypt(ciphertext_of_string)
        assert test_data == plaintext_of_dict
        assert plaintext_string == plaintext_of_string

        # async decryption with correct ciphertext & key of json data
        # doesn't fail & is sound
        assert plaintext_of_dict == await cipher.ajson_decrypt(ciphertext_of_dict)
        assert plaintext_of_string == await cipher.ajson_decrypt(ciphertext_of_string)


async def test_bytes_functions():
    for (config, cipher, salt, aad) in all_ciphers:
        ciphertext_of_bytes = cipher.bytes_encrypt(plaintext_bytes, salt=salt)
        ciphertext_of_string = cipher.bytes_encrypt(plaintext_string.encode(), salt=salt)

        # plaintext is not trivially detected in ciphertext
        assert byte_leakage not in ciphertext_of_bytes
        assert string_leakage not in ciphertext_of_string

        # no two ciphertexts are ever the same
        assert ciphertext_of_bytes != await cipher.abytes_encrypt(plaintext_bytes, salt=salt)
        assert ciphertext_of_string != await cipher.abytes_encrypt(plaintext_string.encode(), salt=salt)

        assert ciphertext_of_bytes != cipher.bytes_encrypt(plaintext_bytes)
        assert ciphertext_of_string != await cipher.abytes_encrypt(plaintext_string.encode())

        assert ciphertext_of_bytes != cipher.bytes_encrypt(plaintext_bytes, salt=salt, aad=aad)
        assert ciphertext_of_string != await cipher.abytes_encrypt(plaintext_string.encode(), salt=salt, aad=aad)

        # decryption of correct ciphertext & key doesn't fail & is sound
        plaintext_of_bytes = cipher.bytes_decrypt(ciphertext_of_bytes)
        plaintext_of_string = cipher.bytes_decrypt(ciphertext_of_string)
        assert plaintext_bytes == plaintext_of_bytes
        assert plaintext_string == plaintext_of_string.decode()

        # async decryption with correct ciphertext & key doesn't fail & is sound
        assert plaintext_of_bytes == await cipher.abytes_decrypt(ciphertext_of_bytes)
        assert plaintext_of_string == await cipher.abytes_decrypt(ciphertext_of_string)


async def test_token_functions():
    for (config, cipher, salt, aad) in all_ciphers:
        ciphertext_of_bytes = cipher.make_token(plaintext_bytes, aad=aad)

        # no two ciphertexts are ever the same
        problem = (
            "A non-bytes plaintext was allowed."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            assert await cipher.amake_token("plaintext", aad=aad)
        with Ignore(TypeError, if_else=violation(problem)):
            assert cipher.make_token("plaintext", aad=aad)

        assert ciphertext_of_bytes != cipher.make_token(plaintext_bytes, aad=aad)
        assert ciphertext_of_bytes != await cipher.amake_token(plaintext_bytes, aad=aad)
        assert ciphertext_of_bytes != cipher.make_token(plaintext_bytes)
        assert ciphertext_of_bytes != await cipher.amake_token(plaintext_bytes)

        # token decryption of correct ciphertext & key doesn't fail & is sound
        assert plaintext_bytes == cipher.read_token(ciphertext_of_bytes, aad=aad)
        assert plaintext_bytes == cipher.read_token(ciphertext_of_bytes.decode(), aad=aad)
        assert plaintext_bytes == await cipher.aread_token(ciphertext_of_bytes, aad=aad)
        assert plaintext_bytes == await cipher.aread_token(ciphertext_of_bytes.decode(), aad=aad)


async def test_chunky2048_test_vectors():
    test_vectors = [chunky2048_test_vector_0]

    for test in test_vectors:
        cipher = Chunky2048(test.key)
        assert test.plaintext == cipher.bytes_decrypt(
            test.shmac + test.salt + test.iv + test.ciphertext,
            aad=test.aad,
        )


async def test_slick256_test_vectors():
    test_vectors = [slick256_test_vector_0]

    for test in test_vectors:
        cipher = Slick256(test.key)
        assert test.plaintext == cipher.bytes_decrypt(
            test.shmac + test.salt + test.iv + test.ciphertext,
            aad=test.aad,
        )


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

