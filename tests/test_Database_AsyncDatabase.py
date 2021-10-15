# This file is part of aiootp, an asynchronous pseudo one-time pad based
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
    "__all__",
    "database",
    "async_database",
    "test_tags_metatags",
    "test_Database_instance",
    "test_AsyncDatabase_instance",
    "test_database_ciphers",
    "test_user_profiles",
]


def test_Database_instance(database):
    db = Database(key=key, depth=depth, preload=True)

    assert db._root_key == database._root_key
    assert db._root_hash == database._root_hash
    assert db._Database__root_salt == database._Database__root_salt
    assert db._root_seed == database._root_seed
    assert db._root_filename == database._root_filename
    assert db.make_hmac(tag) == database.make_hmac(tag)
    assert db.filename(tag) == database.filename(tag)
    assert db._metatag_key(tag) == database._metatag_key(tag)


def test_AsyncDatabase_instance(database):
    db = run(AsyncDatabase(key=key, depth=depth, preload=True))

    assert db._root_key == database._root_key
    assert db._root_hash == database._root_hash
    assert db._AsyncDatabase__root_salt == database._Database__root_salt
    assert db._root_seed == database._root_seed
    assert db._root_filename == database._root_filename
    assert run(db.amake_hmac(tag)) == database.make_hmac(tag)
    assert run(db.afilename(tag)) == database.filename(tag)
    assert run(db._ametatag_key(tag)) == database._metatag_key(tag)


def database_ciphers(database):
    db = database
    filename = db.filename(tag)

    encrypted_data = db.json_encrypt(test_data, filename=filename, aad=b"aad")

    db[tag] = test_data
    db.save_database()
    encrypted_file = db._query_ciphertext(filename)

    assert encrypted_file != encrypted_data
    assert encrypted_file[SALT_SLICE] != encrypted_data[SALT_SLICE]
    assert db.json_decrypt(encrypted_file, filename=filename, aad=b"aad") == test_data
    assert db.json_decrypt(encrypted_data, filename=filename, aad=b"aad") == test_data


    encrypted_binary_data = db.bytes_encrypt(plaintext_bytes, aad=b"test")
    decrypted_binary_data = db.bytes_decrypt(
        encrypted_binary_data, aad=b"test", ttl=30
    )

    assert decrypted_binary_data == plaintext_bytes


    encrypted_token_data = db.make_token(plaintext_bytes, aad=b"test")
    decrypted_token_data = db.read_token(
        encrypted_token_data, aad=b"test", ttl=3600
    )

    assert decrypted_token_data == plaintext_bytes


async def async_database_ciphers(async_database):
    db = async_database
    filename = await db.afilename(tag)

    encrypted_data = await db.ajson_encrypt(test_data, filename=filename, aad=b"aad")

    db[tag] = test_data
    await db.asave_database()
    encrypted_file = await db._aquery_ciphertext(filename)

    assert encrypted_file != encrypted_data
    assert encrypted_file[SALT_SLICE] != encrypted_data[SALT_SLICE]
    assert await db.ajson_decrypt(encrypted_file, filename=filename, aad=b"aad") == test_data
    assert await db.ajson_decrypt(encrypted_data, filename=filename, aad=b"aad") == test_data


    encrypted_binary_data = await db.abytes_encrypt(
        plaintext_bytes, aad=b"test"
    )
    decrypted_binary_data = await db.abytes_decrypt(
        encrypted_binary_data, aad=b"test", ttl=30
    )

    assert decrypted_binary_data == plaintext_bytes


    encrypted_token_data = await db.amake_token(plaintext_bytes, aad=b"test")
    decrypted_token_data = await db.aread_token(
        encrypted_token_data, aad=b"test", ttl=3600
    )

    assert decrypted_token_data == plaintext_bytes


def test_database_ciphers(database, async_database):
    profile = database_ciphers(database)
    aprofile = run(async_database_ciphers(async_database))


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
    with db:
        pass
    run(adb.__aenter__())
    run(adb.__aexit__())
    assert (db.directory / filename).exists()
    assert (adb.directory / afilename).exists()
    assert db.clients[tag] == adb.aclients[atag]
    assert db.clients[tag] is not adb.aclients[atag]


def databases_share_metatags(db, adb, child, achild):
    assert child is db.clients
    assert achild is adb.aclients


def test_tags_metatags():
    database = Database(key * 2, depth=depth, preload=True)
    async_database = run(AsyncDatabase(key * 2, depth=depth, preload=True))
    child = database.metatag(metatag, preload=True)
    achild = run(async_database.ametatag(ametatag, preload=True))
    databases_share_metatags(database, async_database, child, achild)

    database.set_tag("bytes", plaintext_bytes, cache=False)
    database.query_tag("bytes") == plaintext_bytes
    run(async_database.aset_tag("bytes", plaintext_bytes, cache=False))
    run(async_database.aquery_tag("bytes")) == plaintext_bytes

    child[tag] = test_data
    achild[atag] = atest_data
    metatag_isnt_ametatag_but_equal(child, achild, database, async_database)

    filename = child.filename(tag)
    afilename = run(achild.afilename(atag))
    databases_save_metatag_files(database, async_database, filename, afilename)

    metatag_key = database._metatag_key(metatag)
    ametatag_key = run(async_database._ametatag_key(ametatag))
    db = Database(metatag_key, metatag=True, preload=True)
    adb = run(AsyncDatabase(ametatag_key, metatag=True, preload=True))
    assert db[tag] == adb[atag]
    assert db[tag] == database.clients[tag]
    assert adb[atag] == async_database.aclients[atag]

    database.delete_database()
    run(async_database.adelete_database())


async def async_user_profiles(async_database):
    adb = async_database
    tokens = await adb.agenerate_profile_tokens(**PROFILE_AND_SETTINGS)
    user = await adb.agenerate_profile(tokens)

    async with user:
        user[atag] = atest_data

    user_copy = await adb.aload_profile(tokens, preload=True)
    assert user[atag] == user_copy[atag]
    assert user[atag] is not user_copy[atag]

    await adb.adelete_profile(tokens)
    return user_copy


def user_profiles(database):
    db = database
    tokens = db.generate_profile_tokens(**PROFILE_AND_SETTINGS)
    user = db.generate_profile(tokens)

    with user:
        user[tag] = test_data

    user_copy = db.load_profile(tokens, preload=True)
    assert user[tag] == user_copy[tag]
    assert user[tag] is not user_copy[tag]

    db.delete_profile(tokens)
    return user_copy


def test_user_profiles(database, async_database):
    profile = user_profiles(database)
    aprofile = run(async_user_profiles(async_database))

