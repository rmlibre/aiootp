# This file is part of tiny_onion, a small-as-possible solution for p2p
# networking over tor v3 onion services.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


import sys
import json
import pytest
from pathlib import Path


PACKAGE_PATH = str(Path(__file__).absolute().parent.parent)
sys.path.append(PACKAGE_PATH)


import aiootp
from aiootp import *


key = csprng()
salt = csprng()[:64]
pid = sha_256(key, salt)
pad = OneTimePad(key)

passcrypt_passwords = []
apasscrypt_passwords = []

password_0 = csprng()
password_1 = randoms.urandom(256)
password_2 = dict(some_data=list(password_1))
passwords = [password_0, password_1, password_2]

salt_0 = csprng()
salt_1 = randoms.urandom(256)
salt_2 = dict(some_data=list(password_1))
salts = [salt_0, salt_1, salt_2]

passcrypt_settings = dict(kb=256, cpu=2, hardness=256)

tag = "testing"
atag = "a" + tag
metatag = "clients"
ametatag = "a" + metatag

depth = 100
username = "test suite"
password = "terrible low entropy password"
PROFILE = dict(username=username, password=password, salt=salt)
LOW_PASSCRYPT_SETTINGS = dict(kb=256, cpu=2, hardness=256)
PROFILE_AND_SETTINGS = {**PROFILE, **LOW_PASSCRYPT_SETTINGS}

plaintext_bytes = 100 * randoms.urandom(128)
plaintext_string = 1280 * "testing..."
test_data = {
    "floats": 10000.243,
    "dicts": {"testing": {}},
    "lists": list(range(100)),
    "strings": 100 * "testing...",
}
atest_data = {
    "floats": 10000.243,
    "dicts": {"testing": {}},
    "lists": list(range(100)),
    "strings": 100 * "testing...",
}


@pytest.fixture(scope="session")
def database():
    print("setup".center(15, "-"))

    db = Database(key=key, password_depth=depth)
    db.save()
    yield db

    print("teardown".center(18, "-"))
    db.delete_database()


@pytest.fixture(scope="session")
def async_database():
    print("setup".center(15, "-"))

    db = run(AsyncDatabase(key=key, password_depth=depth))
    yield db

    print("teardown".center(18, "-"))

    run(db.aload(manifest=True, silent=True))
    run(db.adelete_database())


__all__ = [
    "sys",
    "json",
    "pytest",
    "Path",
    "PACKAGE_PATH",
    "aiootp",
    *aiootp.__all__,
    "key",
    "salt",
    "pid",
    "pad",
    "passcrypt_passwords",
    "apasscrypt_passwords",
    "passwords",
    "salts",
    "passcrypt_settings",
    "tag",
    "atag",
    "metatag",
    "ametatag",
    "depth",
    "username",
    "password",
    "PROFILE",
    "LOW_PASSCRYPT_SETTINGS",
    "PROFILE_AND_SETTINGS",
    "plaintext_bytes",
    "plaintext_string",
    "test_data",
    "atest_data",
    "database",
    "async_database",
]

