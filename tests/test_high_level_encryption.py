# This file is part of tiny_onion, a small-as-possible solution for p2p
# networking over tor v3 onion services.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#          © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from init_tests import *


__all__ = [
    "test_map_functions",
    "test_json_functions",
    "test_bytes_functions",
    "test_generator_functions",
    "__all__",
]


key = csprng()
salt = csprng()
pid = sha_256(key, salt)
plaintext_bytes = 100 * randoms.urandom(128)
plaintext_string = 1280 * "testing..."
plaintext_types = {
    "floats": 10000.243,
    "dicts": {"testing": None},
    "lists": list(range(100)),
    "strings": 100 * "testing...",
}


def test_map_functions():
    names = subkeys(key, salt, pid).resize(64)
    keystream = subkeys(key, salt)
    datastream = data(plaintext_string)
    with datastream.map_encrypt(names, keystream) as encrypting:
        ciphertext = encrypting.dict()
    with pick(names, ciphertext).map_decrypt(keystream) as decrypting:
        plaintext = decrypting.join()
    async_result = run(async_map_functions())
    assert async_result == plaintext


async def async_map_functions():
    names = asubkeys(key, salt, pid).aresize(64)
    keystream = asubkeys(key, salt)
    datastream = adata(plaintext_string)
    async with datastream.amap_encrypt(names, keystream) as encrypting:
        ciphertext = await encrypting.adict()
    async with apick(names, ciphertext).amap_decrypt(keystream) as decrypting:
        plaintext = await decrypting.ajoin()
    return plaintext


def test_json_functions():
    ciphertext_of_dict = json_encrypt(plaintext_types, key, salt)
    ciphertext_of_string = json_encrypt(plaintext_string, key, salt)
    assert ciphertext_of_dict == run(ajson_encrypt(plaintext_types, key, salt))
    assert ciphertext_of_string == run(ajson_encrypt(plaintext_string, key, salt))

    assert ciphertext_of_dict != json_encrypt(plaintext_types, key)
    assert ciphertext_of_string != run(ajson_encrypt(plaintext_string, key))

    assert ciphertext_of_dict != json_encrypt(plaintext_types, key, salt, pid)
    assert ciphertext_of_string != run(ajson_encrypt(plaintext_string, key, salt, pid))

    plaintext_of_dict = json_decrypt(json.dumps(ciphertext_of_dict), key)
    plaintext_of_string = json_decrypt(json.dumps(ciphertext_of_string), key)
    assert plaintext_of_dict == run(ajson_decrypt(json.dumps(ciphertext_of_dict), key))
    assert plaintext_of_string == run(ajson_decrypt(json.dumps(ciphertext_of_string), key))


def test_bytes_functions():
    ciphertext_of_bytes = bytes_encrypt(plaintext_bytes, key, salt)
    ciphertext_of_string = bytes_encrypt(plaintext_string, key, salt)
    assert ciphertext_of_bytes == run(abytes_encrypt(plaintext_bytes, key, salt))
    assert ciphertext_of_string == run(abytes_encrypt(plaintext_string, key, salt))

    assert ciphertext_of_bytes != bytes_encrypt(plaintext_bytes, key)
    assert ciphertext_of_string != run(abytes_encrypt(plaintext_string, key))

    assert ciphertext_of_bytes != bytes_encrypt(plaintext_bytes, key, salt, pid)
    assert ciphertext_of_string != run(abytes_encrypt(plaintext_string, key, salt, pid))

    plaintext_of_bytes = bytes_decrypt(ciphertext_of_bytes, key)
    plaintext_of_string = bytes_decrypt(ciphertext_of_string, key)
    assert plaintext_of_bytes == run(abytes_decrypt(ciphertext_of_bytes, key))
    assert plaintext_of_string == run(abytes_decrypt(ciphertext_of_string, key))


def test_generator_functions():
    encrypting = encrypt(plaintext_string, key)
    decrypting = decrypt(encrypting, key)

    aencrypting = aencrypt(plaintext_string, key)
    adecrypting = adecrypt(aencrypting, key)

    plaintext = decrypting.join()
    async_plaintext = run(adecrypting.ajoin())

    assert plaintext == plaintext_string
    assert plaintext == async_plaintext
