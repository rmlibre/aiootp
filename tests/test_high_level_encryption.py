# This file is part of tiny_onion, a small-as-possible solution for p2p
# networking over tor v3 onion services.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from init_tests import *


__all__ = [
    "test_map_generators",
    "test_json_functions",
    "test_bytes_functions",
    "test_ascii_generators",
    "__all__",
]


def test_map_generators():
    names = keys(key, salt=salt, pid=pid).resize(64)[:6].list()
    keystream = keys(key, salt=salt)
    datastream = data(plaintext_string.encode())
    with datastream.map_encipher(names, keystream) as encrypting:
        ciphertext = encrypting.dict()
        assert ciphertext
    with pick(names, ciphertext).map_decipher(keystream.reset()) as decrypting:
        plaintext = decrypting.join(b"")
        assert plaintext
    async_result = run(async_map_functions())
    assert async_result == plaintext


async def async_map_functions():
    names = await akeys(key, salt=salt, pid=pid).aresize(64)[:6].alist()
    keystream = akeys(key, salt=salt)
    datastream = adata(plaintext_string.encode())
    async with datastream.amap_encipher(names, keystream) as encrypting:
        ciphertext = await encrypting.adict()
    async with apick(names, ciphertext).amap_decipher(await keystream.areset()) as decrypting:
        plaintext = await decrypting.ajoin(b"")
    return plaintext


def test_json_functions():
    ciphertext_of_dict = json_encrypt(test_data, key, salt=salt)
    ciphertext_of_string = json_encrypt(plaintext_string, key, salt=salt)
    assert ciphertext_of_dict == run(ajson_encrypt(test_data, key, salt=salt))
    assert ciphertext_of_string == run(ajson_encrypt(plaintext_string, key, salt=salt))

    assert ciphertext_of_dict != json_encrypt(test_data, key)
    assert ciphertext_of_string != run(ajson_encrypt(plaintext_string, key))

    assert ciphertext_of_dict != json_encrypt(test_data, key, salt=salt, pid=pid)
    assert ciphertext_of_string != run(ajson_encrypt(plaintext_string, key, salt=salt, pid=pid))

    plaintext_of_dict = json_decrypt(json.dumps(ciphertext_of_dict), key)
    plaintext_of_string = json_decrypt(json.dumps(ciphertext_of_string), key)
    assert plaintext_of_dict == run(ajson_decrypt(json.dumps(ciphertext_of_dict), key))
    assert plaintext_of_string == run(ajson_decrypt(json.dumps(ciphertext_of_string), key))


def test_bytes_functions():
    ciphertext_of_bytes = bytes_encrypt(plaintext_bytes, key, salt=salt)
    ciphertext_of_string = bytes_encrypt(plaintext_string.encode(), key, salt=salt)
    assert ciphertext_of_bytes == run(abytes_encrypt(plaintext_bytes, key, salt=salt))
    assert ciphertext_of_string == run(abytes_encrypt(plaintext_string.encode(), key, salt=salt))

    assert ciphertext_of_bytes != bytes_encrypt(plaintext_bytes, key)
    assert ciphertext_of_string != run(abytes_encrypt(plaintext_string.encode(), key))

    assert ciphertext_of_bytes != bytes_encrypt(plaintext_bytes, key, salt=salt, pid=pid)
    assert ciphertext_of_string != run(abytes_encrypt(plaintext_string.encode(), key, salt=salt, pid=pid))

    plaintext_of_bytes = bytes_decrypt(ciphertext_of_bytes, key)
    plaintext_of_string = bytes_decrypt(ciphertext_of_string, key)
    assert plaintext_of_bytes == run(abytes_decrypt(ciphertext_of_bytes, key))
    assert plaintext_of_string == run(abytes_decrypt(ciphertext_of_string, key))


async def async_ascii_generators():
    naively_padded_plaintext = 240 * "." + "testing... This." # 16 byte string + 240 == 256
    async with adata(naively_padded_plaintext).aascii_encipher(key, salt=salt) as enciphering:
        ciphertext = await enciphering.alist()
        assert len(ciphertext) == 1
        assert ciphertext[0].bit_length() <= 2048
    with aunpack(ciphertext).aascii_decipher(key, salt=salt) as deciphering:
        deciphered = await deciphering.ajoin()
        assert deciphered == naively_padded_plaintext

    unpadded_plaintext = "testing..." # 10 byte string == 246 null bytes in the deciphered plaintext
    with adata(unpadded_plaintext).aascii_encipher(key, salt=salt) as enciphering:
        ciphertext = await enciphering.alist()
        assert len(ciphertext) == 1
        assert ciphertext[0].bit_length() <= 2048
    with aunpack(ciphertext).aascii_decipher(key, salt=salt) as deciphering:
        deciphered = await deciphering.ajoin()
        assert deciphered != unpadded_plaintext
        assert deciphered[246:] == unpadded_plaintext


def test_ascii_generators():
    # Plaintext is processed in 256 byte blocks. Using these lower level
    # leaves the user having to account for this. This is a very naive
    # way to handle this
    naively_padded_plaintext = 240 * "." + "testing... This." # 16 byte string + 240 == 256
    with data(naively_padded_plaintext).ascii_encipher(key, salt=salt) as enciphering:
        ciphertext = enciphering.list()
        assert len(ciphertext) == 1
        assert ciphertext[0].bit_length() <= 2048
    with unpack(ciphertext).ascii_decipher(key, salt=salt) as deciphering:
        deciphered = deciphering.join()
        assert deciphered == naively_padded_plaintext

    unpadded_plaintext = "testing..." # 10 byte string == 246 null bytes in the deciphered plaintext
    with data(unpadded_plaintext).ascii_encipher(key, salt=salt) as enciphering:
        ciphertext = enciphering.list()
        assert len(ciphertext) == 1
        assert ciphertext[0].bit_length() <= 2048
    with unpack(ciphertext).ascii_decipher(key, salt=salt) as deciphering:
        deciphered = deciphering.join()
        assert deciphered != unpadded_plaintext
        assert deciphered[246:] == unpadded_plaintext

    run(async_ascii_generators())

