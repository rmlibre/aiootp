# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


import sys
import json
import pytest
import builtins
from pathlib import Path


PACKAGE_PATH = str(Path(__file__).absolute().parent.parent)
sys.path.append(PACKAGE_PATH)


import aiootp
from aiootp import *
from commons import *
from asynchs import asleep, run
from aiootp import _containers


g = globals()
builtin_names = dir(builtins)
added_generators = []
for name, value in gentools.items():
    if name in builtin_names:
        continue
    g[name] = value
    added_generators.append(name)


key = csprng()
salt = generate_salt(size=SALT_BYTES)
aad = sha3__256(key, salt, hex=False)
akey_bundle = run(KeyAADBundle(key=key, salt=salt, aad=aad, allow_dangerous_determinism=True).async_mode())
key_bundle = KeyAADBundle(key=key, salt=salt, aad=aad, allow_dangerous_determinism=True).sync_mode()
cipher = Chunky2048(key)

passcrypt_passphrases = []
apasscrypt_passphrases = []

passphrase_0 = csprng()
passphrase_1 = randoms.token_bytes(32)
passphrases = [passphrase_0, passphrase_1]

salt_0 = csprng()
salt_1 = randoms.token_bytes(32)
salts = [salt_0, salt_1]

passcrypt_settings = dict(kb=256, cpu=2, hardness=256)

tag = "testing"
atag = "a" + tag
metatag = "clients"
ametatag = "a" + metatag

depth = 100
username = b"test suite"
passphrase = b"terrible low entropy passphrase"
PROFILE = dict(username=username, passphrase=passphrase, salt=salt)
LOW_PASSCRYPT_SETTINGS = dict(kb=256, cpu=2, hardness=256)
PROFILE_AND_SETTINGS = {**PROFILE, **LOW_PASSCRYPT_SETTINGS}

plaintext_bytes = b"!" + randoms.token_bytes(512)
plaintext_string = 32 * "testing..."
# Testing json encrypt of these dictionaries may fail because the order
# of their elements may change
test_data = {
    "floats": 10000.243,
    "dicts": {"testing": {}},
    "lists": list(range(16)),
    "strings": "testing...",
}
atest_data = {
    "floats": 10000.243,
    "dicts": {"testing": {}},
    "lists": list(range(16)),
    "strings": "testing...",
}


test_json_ciphertext = cipher.json_encrypt(test_data, aad=aad)
atest_json_ciphertext = run(cipher.ajson_encrypt(atest_data, aad=aad))
test_token_ciphertext = cipher.make_token(plaintext_bytes, aad=aad)
atest_token_ciphertext = run(cipher.amake_token(plaintext_bytes, aad=aad))
time_start = asynchs.time()


@pytest.fixture(scope="session")
def database():
    print("setup".center(15, "-"))

    db = Database(key=key, depth=depth, preload=True)
    db.save_database()
    yield db

    print("teardown".center(18, "-"))
    db.delete_database()


@pytest.fixture(scope="session")
def async_database():
    print("setup".center(15, "-"))

    db = run(AsyncDatabase(key=key, depth=depth, preload=True))
    yield db

    print("teardown".center(18, "-"))

    run(db.aload_database(manifest=True, silent=True))
    run(db.adelete_database())


__all__ = [
    "sys",
    "json",
    "pytest",
    "Path",
    "PACKAGE_PATH",
    "aiootp",
    "randoms",
    "_containers",
    "asleep",
    "run",
    *aiootp.__all__,
    *commons.__all__,
    *added_generators,
    *Chunky2048._CONSTANTS.keys(),
    "key",
    "salt",
    "aad",
    "key_bundle",
    "cipher",
    "passcrypt_passphrases",
    "apasscrypt_passphrases",
    "passphrases",
    "salts",
    "passcrypt_settings",
    "tag",
    "atag",
    "metatag",
    "ametatag",
    "depth",
    "username",
    "passphrase",
    "PROFILE",
    "LOW_PASSCRYPT_SETTINGS",
    "PROFILE_AND_SETTINGS",
    "plaintext_bytes",
    "plaintext_string",
    "test_data",
    "atest_data",
    "test_json_ciphertext",
    "atest_json_ciphertext",
    "test_token_ciphertext",
    "atest_token_ciphertext",
    "time_start",
    "database",
    "async_database",
]

