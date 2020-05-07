# This file is part of tiny_onion, a small-as-possible solution for p2p
# networking over tor v3 onion services.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#          © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


import sys
import pytest
from pathlib import Path


__all__ = [
    "database",
    "async_database",
    "test_Database_instance",
    "test_AsyncDatabase_instance",
    "test_Database_cipher",
    "test_AsyncDatabase_cipher",
    "__all__",
    "aiootp",
    "PACKAGE_PATH",
]


PACKAGE_PATH = str(Path(__file__).absolute().parent.parent)
sys.path.append(PACKAGE_PATH)


import aiootp
from aiootp import *


depth = 100
key = csprng()
tag = "testing"
test_data = {
    "floats": 10000.243,
    "dicts": {"testing": {}},
    "lists": list(range(100)),
    "strings": 100 * "testing...",
}


@pytest.fixture(scope="module")
def database():
    print("setup".center(15, "-"))

    db = Database(key=key, password_depth=depth)
    db.save()
    yield db

    print("teardown".center(18, "-"))
    db.delete_database()


@pytest.fixture(scope="module")
def async_database():
    print("setup".center(15, "-"))

    db = run(AsyncDatabase(key=key, password_depth=depth))
    yield db

    print("teardown".center(18, "-"))
    run(db.asave())
    run(db.adelete_database())


def test_Database_instance(database):
    time_start = asynchs.time()
    db = Database(key=key, password_depth=depth)
    assert asynchs.time() - time_start < 0.02

    assert db.root_key == database.root_key
    assert db.root_hash == database.root_hash
    assert db._Database__root_salt() == database._Database__root_salt()
    assert db.root_seed == database.root_seed
    assert db.root_filename == database.root_filename
    assert db.hmac(tag) == database.hmac(tag)
    assert db.filename(tag) == database.filename(tag)
    assert db.metatag_key(tag) == database.metatag_key(tag)


def test_AsyncDatabase_instance(database):
    time_start = asynchs.time()
    db = run(AsyncDatabase(key=key, password_depth=depth))
    assert asynchs.time() - time_start < 0.02

    assert db.root_key == database.root_key
    assert db.root_hash == database.root_hash
    assert run(db._AsyncDatabase__aroot_salt()) == database._Database__root_salt()
    assert db.root_seed == database.root_seed
    assert db.root_filename == database.root_filename
    assert run(db.ahmac(tag)) == database.hmac(tag)
    assert run(db.afilename(tag)) == database.filename(tag)
    assert run(db.ametatag_key(tag)) == database.metatag_key(tag)


def test_Database_cipher(database):
    db = database
    filename = db.filename(tag)

    encrypted_data = db.encrypt(filename, test_data)

    db[tag] = test_data
    db.save()
    encrypted_file = db.query_ciphertext(filename)

    assert encrypted_file != encrypted_data
    assert encrypted_file["salt"] != encrypted_data["salt"]
    assert db.decrypt(filename, encrypted_file) == test_data
    assert db.decrypt(filename, encrypted_data) == test_data


def test_AsyncDatabase_cipher(database, async_database):
    db = async_database
    filename = run(db.afilename(tag))

    encrypted_data = run(db.aencrypt(filename, test_data))

    db[tag] = test_data
    run(db.asave())
    encrypted_file = run(db.aquery_ciphertext(filename))

    assert encrypted_file != encrypted_data
    assert encrypted_file["salt"] != encrypted_data["salt"]
    assert run(db.adecrypt(filename, encrypted_file)) == test_data
    assert run(db.adecrypt(filename, encrypted_data)) == test_data


