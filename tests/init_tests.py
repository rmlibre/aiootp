# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
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
from pathlib import Path


PACKAGE_PATH = str(Path(__file__).absolute().parent.parent)
sys.path.append(PACKAGE_PATH)


import aiootp
from aiootp import *
from commons import *


key = csprng()
salt = generate_salt()
pid = sha_256(key, salt)
pad = Chunky2048(key)

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

plaintext_bytes = randoms.urandom(320)
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
    *commons.__all__,
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

