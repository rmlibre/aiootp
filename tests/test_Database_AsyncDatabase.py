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
    "database",
    "async_database",
    "test_tags_metatags",
    "test_Database_instance",
    "test_AsyncDatabase_instance",
    "test_Database_cipher",
    "test_AsyncDatabase_cipher",
    "__all__",
]


tag = "testing"
atag = "a" + tag
metatag = "clients"
ametatag = "a" + metatag
depth = 100
key = csprng()
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
    db = Database(key=key, password_depth=depth)

    assert db.root_key == database.root_key
    assert db.root_hash == database.root_hash
    assert db._Database__root_salt() == database._Database__root_salt()
    assert db.root_seed == database.root_seed
    assert db.root_filename == database.root_filename
    assert db.hmac(tag) == database.hmac(tag)
    assert db.filename(tag) == database.filename(tag)
    assert db.metatag_key(tag) == database.metatag_key(tag)


def test_AsyncDatabase_instance(database):
    db = run(AsyncDatabase(key=key, password_depth=depth))

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


def metatag_isnt_ametatag_but_equal(child, achild, db, adb):
    assert child is db.clients
    assert achild is adb.aclients

    assert child[tag] is db.clients[tag]
    assert achild[atag] is adb.aclients[atag]

    assert db.clients[tag] == adb.aclients[atag]
    assert db.clients[tag] is not adb.aclients[atag]


def databases_save_metatag_files(db, adb, filename, afilename):
    assert not (db.directory / filename).exists()
    assert not (adb.directory / afilename).exists()
    db.save()
    run(adb.asave())
    assert (db.directory / filename).exists()
    assert (adb.directory / afilename).exists()
    assert db.clients[tag] == adb.aclients[atag]
    assert db.clients[tag] is not adb.aclients[atag]


def databases_share_metatags(db, adb, child, achild):
    assert child is db.clients
    assert achild is adb.aclients


def test_tags_metatags():
    database = Database(key * 2, depth)
    async_database = run(AsyncDatabase(key * 2, depth))
    child = database.metatag(metatag)
    achild = run(async_database.ametatag(ametatag))
    databases_share_metatags(database, async_database, child, achild)

    child[tag] = test_data
    achild[atag] = atest_data
    metatag_isnt_ametatag_but_equal(child, achild, database, async_database)

    filename = child.filename(tag)
    afilename = run(achild.afilename(atag))
    databases_save_metatag_files(database, async_database, filename, afilename)

    metatag_key = database.metatag_key(metatag)
    ametatag_key = run(async_database.ametatag_key(ametatag))
    db = Database(metatag_key, metatag=True)
    adb = run(AsyncDatabase(ametatag_key, metatag=True))
    assert db[tag] == adb[atag]
    assert db[tag] == database.clients[tag]
    assert adb[atag] == async_database.aclients[atag]

    database.delete_database()
    run(async_database.adelete_database())
