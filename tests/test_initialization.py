# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


import sys
import hmac
import json
import pytest
import base64
import builtins
from math import ceil
from pathlib import Path
from functools import partial
from collections import deque
from secrets import token_bytes, randbits
from hashlib import sha3_256, sha3_512, shake_128, shake_256


_PACKAGE_PATH = str(Path(__file__).absolute().parent.parent)
sys.path.insert(0, _PACKAGE_PATH)


_original_globals = globals().copy()
_globals = globals()


import aiootp
_globals.update(aiootp.__dict__)
_globals.update(_debuggers.__dict__)
_globals.update(_exceptions.__dict__)
_globals.update(_containers.__dict__)
_globals.update(_paths.__dict__)
_globals.update(_typing.__dict__)
_globals.update(commons.__dict__)
_globals.update(constants.__dict__)
_globals.update(misc.__dict__)
_globals.update(datasets.__dict__)
_globals.update(passcrypt.__dict__)
_globals.update(chunky2048.__dict__)
_globals.update(asynchs.__dict__)
_globals.update(randoms.__dict__)
_globals.update(gentools.__dict__)
_globals.update(generics.__dict__)
_globals.update(ciphers.__dict__)
_globals.update(keygens.__dict__)
_globals.update(_original_globals)
_globals.update(builtins.__dict__)


# Use enable_debugging method to run tests in debug mode. May cause noticable slowdown.
DebugControl.disable_debugging()


# acknowledge private variables
Padding = _Padding
StreamHMAC = _StreamHMAC
SyntheticIV = _SyntheticIV
abytes_decipher = _abytes_decipher
bytes_decipher = _bytes_decipher
abytes_encipher = _abytes_encipher
bytes_encipher = _bytes_encipher
aplaintext_stream = _aplaintext_stream
plaintext_stream = _plaintext_stream
KeyAADBundle = _KeyAADBundle


# create static values for this test session
violation = lambda context: partial(raise_exception, AssertionError(context))
aviolation = lambda context: partial(araise_exception, AssertionError(context))

_entropy = csprng() + token_bytes(32)

key = keygens.generate_key()
salt = randoms.generate_salt()
aad = sha3_256(key + salt).digest()
akey_bundle = run(KeyAADBundle(key=key, salt=salt, aad=aad, allow_dangerous_determinism=True).async_mode())
key_bundle = KeyAADBundle(key=key, salt=salt, aad=aad, allow_dangerous_determinism=True).sync_mode()
cipher = Chunky2048(key)

passphrase_0 = csprng()
passphrase_1 = randoms.token_bytes(32)
passphrases = [passphrase_0, passphrase_1]

salt_0 = csprng()
salt_1 = randoms.token_bytes(32)
salts = [salt_0, salt_1]

passcrypt_settings = OpenNamespace(mb=1, cpu=1, cores=1)

tag = "testing"
atag = "a" + tag
metatag = "clients"
ametatag = "a" + metatag

username = b"test suite"
passphrase = b"terrible low entropy passphrase"
PROFILE = dict(username=username, passphrase=passphrase, salt=salt, aad=aad)
LOW_PASSCRYPT_SETTINGS = OpenNamespace(mb=1, cpu=1, cores=1)
PROFILE_AND_SETTINGS = {**PROFILE, **LOW_PASSCRYPT_SETTINGS}
passcrypt_test_vector_0 = OpenNamespace(
    mb=2,
    cpu=2,
    cores=2,
    tag_size=257,
    salt_size=256,
    aad=b"",
    timestamp=bytes.fromhex("000a59139c603129"),
    passphrase=b"test vector passphrase I",
    salt=bytes.fromhex(
        "b3c100b7670ef0c9e15bf877a80d78342ab1f6039511d8444ef82ee9f185fd"
        "ff3bebf168f4af41c5d735a2a6a19c8aab2d142353e307968d9d65e33c9424"
        "a51e0b70c4415723d5c72267cd992fd51141c2ce6ae94ccff9945d1b222fc0"
        "0be81504032ab3e51d0ed617d51fee6cfd5c5302bbd7ada60e0f3d45d631f6"
        "a7c4dc47517f20659a1c00f0f371d8a2e09bb247d4493502b4460f3826a094"
        "ac50faa39b8473629ae782d7fb3bb6c69dfaf68a52f06bc3f92d5c88d99a1f"
        "064d377dd894ee14993cf4d72cd78a4401d519a78fca5b2d7b4b6557e75507"
        "ab94021f2fcb29a10d87c0deca93607e339c1dd67d2db939ee926028712073"
        "bff2135410a51bb2"
    ),
    tag=bytes.fromhex(
        "3a6ed13d7fa4717777bf1de4ce6a5f17e772f708892e9595dfef5db9556322"
        "c5bd65f29d9430c43997b5206b82d148cb4b4df5e0b255d3e4b9f60e36784a"
        "292096816378ddcf42b014dcc55647c61644747ef146e9f3ecaee403f89f09"
        "1b092cccd57691bac847685730f4ad3d5e13f18420c3aeee07519990c3b0ac"
        "65331c6cd276ba34b76a463ab3e6d8c1a4289913b4c972d6a923612515520e"
        "bb577b4b74664c71e61057c350d1a2d87eda99c1a37b5ba23bc6901355910d"
        "711415dc1b7538e3e2fc9086f6b5cd142b345574c73d262f4fba75eb5a1c18"
        "f32ec8e51ba2eef5f86551b4aad15a32569aaa00b80369cb13e4711e22ce95"
        "aa4010f00bccdd15b6"
    ),
    hash_passphrase_result=bytes.fromhex(
        "000a59139c6031290000010101ffb3c100b7670ef0c9e15bf877a80d78342a"
        "b1f6039511d8444ef82ee9f185fdff3bebf168f4af41c5d735a2a6a19c8aab"
        "2d142353e307968d9d65e33c9424a51e0b70c4415723d5c72267cd992fd511"
        "41c2ce6ae94ccff9945d1b222fc00be81504032ab3e51d0ed617d51fee6cfd"
        "5c5302bbd7ada60e0f3d45d631f6a7c4dc47517f20659a1c00f0f371d8a2e0"
        "9bb247d4493502b4460f3826a094ac50faa39b8473629ae782d7fb3bb6c69d"
        "faf68a52f06bc3f92d5c88d99a1f064d377dd894ee14993cf4d72cd78a4401"
        "d519a78fca5b2d7b4b6557e75507ab94021f2fcb29a10d87c0deca93607e33"
        "9c1dd67d2db939ee926028712073bff2135410a51bb23a6ed13d7fa4717777"
        "bf1de4ce6a5f17e772f708892e9595dfef5db9556322c5bd65f29d9430c439"
        "97b5206b82d148cb4b4df5e0b255d3e4b9f60e36784a292096816378ddcf42"
        "b014dcc55647c61644747ef146e9f3ecaee403f89f091b092cccd57691bac8"
        "47685730f4ad3d5e13f18420c3aeee07519990c3b0ac65331c6cd276ba34b7"
        "6a463ab3e6d8c1a4289913b4c972d6a923612515520ebb577b4b74664c71e6"
        "1057c350d1a2d87eda99c1a37b5ba23bc6901355910d711415dc1b7538e3e2"
        "fc9086f6b5cd142b345574c73d262f4fba75eb5a1c18f32ec8e51ba2eef5f8"
        "6551b4aad15a32569aaa00b80369cb13e4711e22ce95aa4010f00bccdd15b6"
    ),
)

passcrypt_test_vector_1 = OpenNamespace(
    mb=3,
    cpu=3,
    cores=3,
    tag_size=32,
    salt_size=10,
    aad=b"testvector",
    timestamp=bytes.fromhex("000a59328da314c9"),
    passphrase=b"test vector passphrase II",
    salt=bytes.fromhex("ca926bc906fa14b886eb"),
    tag=bytes.fromhex(
        "e93c54b0ab0360a4020b0bb6a3a10bcb45f0359d31f319d43412fbcc801afa"
        "b7"
    ),
    hash_passphrase_result=bytes.fromhex(
        "000a59328da314c9000002020209ca926bc906fa14b886ebe93c54b0ab0360"
        "a4020b0bb6a3a10bcb45f0359d31f319d43412fbcc801afab7"
    ),
)

passcrypt_test_vector_2 = OpenNamespace(
    mb=4,
    cpu=4,
    cores=4,
    tag_size=16,
    salt_size=4,
    aad=b"core_cache_change",
    timestamp=bytes.fromhex("000a59529a517df8"),
    passphrase=b"test vector passphrase III",
    salt=bytes.fromhex("80345361"),
    tag=bytes.fromhex("a677df399db38672de807c9147ec438a"),
    hash_passphrase_result=bytes.fromhex(
        "000a59529a517df800000303030380345361a677df399db38672de807c9147"
        "ec438a"
    ),
)

passcrypt_test_vector_3 = OpenNamespace(
    mb=1,
    cpu=5,
    cores=5,
    tag_size=24,
    salt_size=8,
    aad=bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
        "1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d"
        "3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c"
        "5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b"
        "7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a"
        "9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9"
        "babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8"
        "d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7"
        "f8f9fafbfcfdfeff"
    ),
    timestamp=bytes.fromhex("000a59a53cfe5ecd"),
    passphrase=b"test vector passphrase IIII",
    salt=bytes.fromhex("fbd2ee954afb48c3"),
    tag=bytes.fromhex("8e8850245c2b699993930240c9e89fc052cfe0b9e27febf1"),
    hash_passphrase_result=bytes.fromhex(
        "000a59a53cfe5ecd000000040407fbd2ee954afb48c38e8850245c2b699993"
        "930240c9e89fc052cfe0b9e27febf1"
    ),
)

byte_leakage = 16 * b"\x00"
string_leakage = 16 * "0".encode()
plaintext_bytes = b"\xff" +  BLOCKSIZE * b"\x00"
plaintext_string = "f" + BLOCKSIZE * "0"
test_data = {
    "floats": 10000.243,
    "ints": list(range(-16, 16, 8)),
    "dicts": {"testing": {}},
    "lists": 4 * [[]],
    "strings": "testing...",
    "nul": None,
    "bools": [True, False],
}
atest_data = test_data.copy()


# Creating timestamped values early so later testing has to wait less time
test_json_ciphertext = cipher.json_encrypt(test_data, aad=aad)
atest_json_ciphertext = run(cipher.ajson_encrypt(atest_data, aad=aad))
test_token_ciphertext = cipher.make_token(plaintext_bytes, aad=aad)
atest_token_ciphertext = run(cipher.amake_token(plaintext_bytes, aad=aad))

aexpired_passcrypt_hash = run(Passcrypt.ahash_passphrase(passphrase_0, mb=1, cores=1))
expired_passcrypt_hash = Passcrypt.hash_passphrase(passphrase_0, mb=1, cores=1)

clock = Clock(SECONDS)
time_start = clock.make_timestamp()


@pytest.fixture(scope="session")
def database():
    print("setup".center(15, "-"))

    db = Database(key=key, preload=True)
    db.save_database()
    yield db

    print("teardown".center(18, "-"))
    db.delete_database()


@pytest.fixture(scope="session")
def async_database():
    print("setup".center(15, "-"))

    db = run(AsyncDatabase(key=key, preload=True))
    yield db

    print("teardown".center(18, "-"))
    run(db.adelete_database())


__all__ = [n for n in globals() if not n.startswith("__")]

