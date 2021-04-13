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
    "test_map_generators",
    "test_json_functions",
    "test_bytes_functions",
    "test_token_functions",
    "test_ascii_generators",
    "__all__",
]


def test_map_generators():
    hmac = StreamHMAC(key, salt=salt, pid=pid).for_encryption()
    names = keys(key, salt=salt, pid=pid).resize(64)[:6].list()
    keystream = keys(key, salt=salt)
    datastream = data(plaintext_string.encode())
    cipher = datastream.map_encipher
    with cipher(names, keystream, validator=hmac) as encrypting:
        ciphertext = encrypting.dict()
        assert ciphertext
        mac = hmac.finalize()
    siv = hmac.siv

    hmac = StreamHMAC(key, salt=salt, pid=pid, siv=siv).for_decryption()
    decipher = pick(names, ciphertext).map_decipher
    with decipher(keystream.reset(), validator=hmac) as decrypting:
        plaintext = decrypting.join(b"")
        assert plaintext
        hmac.finalize()
        hmac.test_hmac(mac)
    async_result = run(async_map_functions())
    assert async_result == plaintext


async def async_map_functions():
    hmac = StreamHMAC(key, salt=salt, pid=pid).for_encryption()
    names = await akeys(key, salt=salt, pid=pid).aresize(64)[:6].alist()
    keystream = akeys(key, salt=salt)
    datastream = adata(plaintext_string.encode())
    cipher = datastream.amap_encipher
    async with cipher(names, keystream, validator=hmac) as encrypting:
        ciphertext = await encrypting.adict()
        mac = await hmac.afinalize()
    siv = hmac.siv

    hmac = StreamHMAC(key, salt=salt, pid=pid, siv=siv).for_decryption()
    decipher = apick(names, ciphertext).amap_decipher
    async with decipher(await keystream.areset(), validator=hmac) as decrypting:
        plaintext = await decrypting.ajoin(b"")
        await hmac.afinalize()
        await hmac.atest_hmac(mac)
    return plaintext


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


async def async_ascii_generators():
    hmac = StreamHMAC(key, salt=salt, pid=pid).for_encryption()
    naively_padded_plaintext = 240 * "." + "testing... This." # 16 byte string + 240 == 256
    cipher = adata(naively_padded_plaintext).aascii_encipher
    async with cipher(key, salt=salt, validator=hmac) as enciphering:
        ciphertext = await enciphering.alist()
        assert len(ciphertext) == 1
        assert ciphertext[0].bit_length() <= 2048
        mac = await hmac.afinalize()
    siv = hmac.siv

    hmac = StreamHMAC(key, salt=salt, pid=pid, siv=siv).for_decryption()
    decipher = aunpack(ciphertext).aascii_decipher
    async with decipher(key, salt=salt, validator=hmac) as deciphering:
        deciphered = await deciphering.ajoin()
        assert deciphered == naively_padded_plaintext
        await hmac.afinalize()
        await hmac.atest_hmac(mac)


    hmac = StreamHMAC(key, salt=salt, pid=pid).for_encryption()
    unpadded_plaintext = "testing..." # 10 byte string == 246 null bytes in the deciphered plaintext
    cipher = adata(unpadded_plaintext).aascii_encipher
    async with cipher(key, salt=salt, validator=hmac) as enciphering:
        ciphertext = await enciphering.alist()
        assert len(ciphertext) == 1
        assert ciphertext[0].bit_length() <= 2048
        mac = await hmac.afinalize()
    siv = hmac.siv

    hmac = StreamHMAC(key, salt=salt, pid=pid, siv=siv).for_decryption()
    decipher = aunpack(ciphertext).aascii_decipher
    async with decipher(key, salt=salt, validator=hmac) as deciphering:
        deciphered = await deciphering.ajoin()
        assert deciphered != unpadded_plaintext
        assert deciphered[246:] == unpadded_plaintext
        await hmac.afinalize()
        await hmac.atest_hmac(mac)


def test_ascii_generators():
    # Plaintext is processed in 256 byte blocks. Using these lower level
    # leaves the user having to account for this. This is a very naive
    # way to handle this
    hmac = StreamHMAC(key, salt=salt, pid=pid).for_encryption()
    naively_padded_plaintext = 240 * "." + "testing... This." # 16 byte string + 240 == 256
    cipher = data(naively_padded_plaintext).ascii_encipher
    with cipher(key, salt=salt, validator=hmac) as enciphering:
        ciphertext = enciphering.list()
        assert len(ciphertext) == 1
        assert ciphertext[0].bit_length() <= 2048
        mac = hmac.finalize()
    siv = hmac.siv

    hmac = StreamHMAC(key, salt=salt, pid=pid, siv=siv).for_decryption()
    decipher = unpack(ciphertext).ascii_decipher
    with decipher(key, salt=salt, validator=hmac) as deciphering:
        deciphered = deciphering.join()
        assert deciphered == naively_padded_plaintext
        hmac.finalize()
        hmac.test_hmac(mac)


    hmac = StreamHMAC(key, salt=salt, pid=pid).for_encryption()
    unpadded_plaintext = "testing..." # 10 byte string == 246 null bytes in the deciphered plaintext
    encipher = data(unpadded_plaintext).ascii_encipher
    with encipher(key, salt=salt, validator=hmac) as enciphering:
        ciphertext = enciphering.list()
        assert len(ciphertext) == 1
        assert ciphertext[0].bit_length() <= 2048
        mac = hmac.finalize()
    siv = hmac.siv

    hmac = StreamHMAC(key, salt=salt, pid=pid, siv=siv).for_decryption()
    decipher = unpack(ciphertext).ascii_decipher
    with decipher(key, salt=salt, validator=hmac) as deciphering:
        deciphered = deciphering.join()
        assert deciphered != unpadded_plaintext
        assert deciphered[246:] == unpadded_plaintext
        hmac.finalize()
        hmac.test_hmac(mac)

    run(async_ascii_generators())

