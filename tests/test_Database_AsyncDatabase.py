# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


class TestDatabaseCacheSystem:
    async def test_async_clear_cache_clears_metatags_when_instructed(
        self, async_database
    ):
        """
        Setup: 1) a metatag exists AND both the metatag & its parent
        have tags in their caches & saved on the filesystem.

        Test: 2) clearing a database's cache clears its metatags' caches
        when instructed.

        Test: 3) clearing a database's cache doesn't clear its metatags'
        caches when instructed not to.
        """
        # 1
        child = await async_database.ametatag(metatag)
        child[tag] = plaintext_bytes
        async_database[tag] = test_data
        test_data_copy = test_data.copy()
        await async_database.asave_database()

        assert plaintext_bytes
        assert plaintext_bytes.__class__ is bytes
        assert child[tag] == plaintext_bytes
        assert test_data
        assert test_data.__class__ is dict
        assert async_database[tag] == test_data

        # 2
        await async_database.aclear_cache(metatags=True)
        assert plaintext_bytes
        assert plaintext_bytes.__class__ is bytes
        assert child[tag] != plaintext_bytes
        assert child[tag] == None
        assert test_data_copy == test_data
        assert test_data.__class__ is dict
        assert async_database[tag] != test_data
        assert async_database[tag] == None

        # 3
        await async_database.aquery_tag(tag, cache=True)
        assert async_database[tag] == test_data

        await child.aquery_tag(tag, cache=True)
        assert child[tag] == plaintext_bytes

        await async_database.aclear_cache(metatags=False)
        assert plaintext_bytes
        assert plaintext_bytes.__class__ is bytes
        assert child[tag] == plaintext_bytes
        assert test_data_copy == test_data
        assert test_data.__class__ is dict
        assert async_database[tag] != test_data
        assert async_database[tag] == None

    def test_clear_cache_clears_metatags_when_instructed(self, database):
        """
        Setup: 1) a metatag exists AND both the metatag & its parent
        have tags in their caches & saved on the filesystem.

        Test: 2) clearing a database's cache clears its metatags' caches
        when instructed.

        Test: 3) clearing a database's cache doesn't clear its metatags'
        caches when instructed not to.
        """
        # 1
        child = database.metatag(metatag)
        child[tag] = plaintext_bytes
        database[tag] = test_data
        test_data_copy = test_data.copy()
        database.save_database()

        assert plaintext_bytes
        assert plaintext_bytes.__class__ is bytes
        assert child[tag] == plaintext_bytes
        assert test_data
        assert test_data.__class__ is dict
        assert database[tag] == test_data

        # 2
        database.clear_cache(metatags=True)
        assert plaintext_bytes
        assert plaintext_bytes.__class__ is bytes
        assert child[tag] != plaintext_bytes
        assert child[tag] == None
        assert test_data_copy == test_data
        assert test_data.__class__ is dict
        assert database[tag] != test_data
        assert database[tag] == None

        # 3
        database.query_tag(tag, cache=True)
        assert database[tag] == test_data

        child.query_tag(tag, cache=True)
        assert child[tag] == plaintext_bytes

        database.clear_cache(metatags=False)
        assert plaintext_bytes
        assert plaintext_bytes.__class__ is bytes
        assert child[tag] == plaintext_bytes
        assert test_data_copy == test_data
        assert test_data.__class__ is dict
        assert database[tag] != test_data
        assert database[tag] == None


def test_Database_instance(database):
    db = Database(key=key, preload=True)

    # basic database functionalities work the same across reloads
    assert db._Database__root_kdf.sha3_256() == database._Database__root_kdf.sha3_256()
    assert db._Database__kdf.sha3_256() == database._Database__kdf.sha3_256()
    assert db._Database__root_kdf.sha3_256() != database._Database__kdf.sha3_256()
    assert db._Database__root_salt == database._Database__root_salt
    assert db._root_filename == database._root_filename
    assert db._root_salt_filename == database._root_salt_filename
    assert db.make_hmac(atag.encode()) == database.make_hmac(atag.encode())
    assert db.filename(atag) == database.filename(atag)
    assert db._metatag_key(atag) == database._metatag_key(atag)


async def test_AsyncDatabase_instance(database):
    db = await AsyncDatabase(key=key, preload=True)

    # basic async database functionalities work the same across reloads
    assert db._AsyncDatabase__root_kdf.sha3_256() == database._Database__root_kdf.sha3_256()
    assert db._AsyncDatabase__kdf.sha3_256() == database._Database__kdf.sha3_256()
    assert db._AsyncDatabase__root_kdf.sha3_256() != database._Database__kdf.sha3_256()
    assert db._AsyncDatabase__root_salt == database._Database__root_salt
    assert db._root_filename == database._root_filename
    assert db._root_salt_filename == database._root_salt_filename
    assert await db.amake_hmac(tag.encode()) == database.make_hmac(tag.encode())
    assert await db.afilename(tag) == database.filename(tag)
    assert await db._ametatag_key(tag) == database._metatag_key(tag)


def test_Database_user_kdf(database):
    db = Database(key=key, preload=False)

    context = "empty kdf updates were allowed!"
    with ignore(ValueError, if_else=violation(context)):
        db.kdf.update()

    assert db.kdf.sha3_256() == database.kdf.sha3_256()
    assert db.kdf.sha3_512() == database.kdf.sha3_512()
    assert db.kdf.shake_128(32) == database.kdf.shake_128(32)
    assert db.kdf.shake_256(32) == database.kdf.shake_256(32)


async def test_AsyncDatabase_user_kdf(async_database):
    db = await AsyncDatabase(key=key, preload=False)

    context = "empty kdf updates were allowed!"
    with ignore(ValueError, if_else=violation(context)):
        await db.kdf.aupdate()

    assert await db.kdf.asha3_256() == await async_database.kdf.asha3_256()
    assert await db.kdf.asha3_512() == await async_database.kdf.asha3_512()
    assert await db.kdf.ashake_128(32) == await async_database.kdf.ashake_128(32)
    assert await db.kdf.ashake_256(32) == await async_database.kdf.ashake_256(32)


def test_database_ciphers(database):
    # database ciphertexts are unique
    db = database
    filename = db.filename(tag)
    encrypted_data = db.json_encrypt(test_data, filename=filename, aad=DEFAULT_AAD)
    db[tag] = test_data
    db.save_database()
    encrypted_file = db._query_ciphertext(filename)
    assert encrypted_file != encrypted_data
    assert encrypted_file[SHMAC_SLICE] != encrypted_data[SHMAC_SLICE]
    assert encrypted_file[SALT_SLICE] != encrypted_data[SALT_SLICE]
    assert encrypted_file[IV_SLICE] != encrypted_data[IV_SLICE]
    assert encrypted_file[CIPHERTEXT_SLICE] != encrypted_data[CIPHERTEXT_SLICE]

    # database ciphers recover json data correctly
    assert test_data == db.json_decrypt(encrypted_file, filename=filename, aad=DEFAULT_AAD)
    assert test_data == db.json_decrypt(encrypted_data, filename=filename, aad=DEFAULT_AAD)
    assert type(test_data) is dict

    # database ciphers recover bytes data correctly
    encrypted_binary_data = db.bytes_encrypt(plaintext_bytes, aad=b"test")
    decrypted_binary_data = db.bytes_decrypt(
        encrypted_binary_data, aad=b"test", ttl=30
    )
    assert decrypted_binary_data == plaintext_bytes
    assert type(encrypted_binary_data) is bytes
    assert type(decrypted_binary_data) is bytes

    # database ciphers recover token data correctly
    encrypted_token_data = db.make_token(plaintext_bytes, aad=b"test")
    decrypted_token_data = db.read_token(
        encrypted_token_data, aad=b"test", ttl=3600
    )
    assert decrypted_token_data == plaintext_bytes
    assert type(encrypted_token_data) is bytes
    assert type(decrypted_token_data) is bytes
    assert (
        set(Tables.URL_SAFE.encode()).union(encrypted_token_data + b"%")
        == set(Tables.URL_SAFE.encode()).union(b"%")
    )


async def test_async_database_ciphers(async_database):
    # async database ciphertexts are unique
    db = async_database
    filename = await db.afilename(tag)
    encrypted_data = await db.ajson_encrypt(test_data, filename=filename, aad=DEFAULT_AAD)
    db[tag] = test_data
    await db.asave_database()
    encrypted_file = await db._aquery_ciphertext(filename)
    assert encrypted_file != encrypted_data
    assert encrypted_file[SHMAC_SLICE] != encrypted_data[SHMAC_SLICE]
    assert encrypted_file[SALT_SLICE] != encrypted_data[SALT_SLICE]
    assert encrypted_file[IV_SLICE] != encrypted_data[IV_SLICE]

    # async database ciphers recover json data correctly
    assert test_data == await db.ajson_decrypt(encrypted_file, filename=filename, aad=DEFAULT_AAD)
    assert test_data == await db.ajson_decrypt(encrypted_data, filename=filename, aad=DEFAULT_AAD)

    # async database ciphers recover bytes data correctly
    encrypted_binary_data = await db.abytes_encrypt(
        plaintext_bytes, aad=b"test"
    )
    decrypted_binary_data = await db.abytes_decrypt(
        encrypted_binary_data, aad=b"test", ttl=30
    )
    assert decrypted_binary_data == plaintext_bytes
    assert type(encrypted_binary_data) is bytes

    # async database ciphers recover token data correctly
    encrypted_token_data = await db.amake_token(plaintext_bytes, aad=b"test")
    decrypted_token_data = await db.aread_token(
        encrypted_token_data, aad=b"test", ttl=3600
    )
    assert decrypted_token_data == plaintext_bytes
    assert type(encrypted_token_data) is bytes
    assert (
        set(Tables.URL_SAFE.encode()).union(encrypted_token_data + b"%")
        == set(Tables.URL_SAFE.encode()).union(b"%")
    )


async def test_async_tags_metatags():
    async_database = await AsyncDatabase(key * 2, preload=True)
    achild = await async_database.ametatag(ametatag, preload=True)

    # async databases retrieve their stored data uncorrupted
    await async_database.aset_tag("bytes", plaintext_bytes, cache=False)
    assert await async_database.aquery_tag("bytes") == plaintext_bytes

    # metatag references stored as parent attributes are identical to
    # the references returned by their (a)metatag methods
    achild[atag] = atest_data
    assert achild is async_database.aclients
    assert achild[atag] is async_database.aclients[atag]

    # exiting an async database's async context manager saves their
    # childrens' files to disk
    afilename = await achild.afilename(atag)
    assert not (achild.path / afilename).exists()
    async with async_database:
        pass
    assert (achild.path / afilename).exists()

    # metatags of equivalent but not identical database instances
    # contain equivalent but not identical stored data
    adb = await AsyncDatabase(key * 2, preload=True)
    assert async_database.aclients[atag] == adb.aclients[atag]
    assert async_database.aclients[atag] is not adb.aclients[atag]

    # all databases create children from the keys returned by their
    # _ametatag_key methods
    ametatag_key = await async_database._ametatag_key(ametatag)
    achild = await AsyncDatabase(ametatag_key, metatag=True, preload=True)
    assert achild[atag]
    assert achild[atag].__class__ is dict
    assert achild[atag] == async_database.aclients[atag]
    assert achild[atag] is not async_database.aclients[atag]

    await async_database.adelete_database()


def test_sync_tags_metatags():
    database = Database(key * 2, preload=True)
    child = database.metatag(metatag, preload=True)

    # databases retrieve their stored data uncorrupted
    database.set_tag("bytes", plaintext_bytes, cache=False)
    assert database.query_tag("bytes") == plaintext_bytes

    # metatag references stored as parent attributes are identical to
    # the references returned by their (a)metatag methods
    child[tag] = test_data
    assert child is database.clients
    assert child[tag] is database.clients[tag]

    # exiting database's context manager saves their childrens' files to
    # disk
    filename = child.filename(tag)
    assert not (child.path / filename).exists()
    with database:
        pass
    assert (child.path / filename).exists()

    # metatags of equivalent but not identical database instances
    # contain equivalent but not identical stored data
    db = Database(key * 2, preload=True)
    assert database.clients[tag] == db.clients[tag]
    assert database.clients[tag] is not db.clients[tag]

    # all databases create children from the keys returned by their
    # _metatag_key methods
    metatag_key = database._metatag_key(metatag)
    child = Database(metatag_key, metatag=True, preload=True)
    assert child[tag]
    assert child[tag].__class__ is dict
    assert child[tag] == database.clients[tag]
    assert child[tag] is not database.clients[tag]

    database.delete_database()


async def test_async_user_profiles(async_database):
    adb = async_database
    user = await adb.agenerate_profile(**PROFILE_AND_SETTINGS)

    async with user:
        user[atag] = atest_data

    # equivalent async profiles contain their own copies of stored data
    user_copy = await adb.agenerate_profile(**PROFILE_AND_SETTINGS, preload=True)
    assert user[atag] == user_copy[atag]
    assert user.tags == user_copy.tags
    assert user[atag]
    assert user[atag] == atest_data
    assert user[atag].__class__ is dict
    assert user[atag] == user_copy[atag]
    assert user[atag] is not user_copy[atag]

    # async profiles are automatically saved to disk when initialized
    assert user_copy._root_path.is_file()
    assert user_copy._profile_tokens._salt_path.is_file()
    assert (user_copy.path / await user_copy.afilename(atag)).is_file()

    # async & sync profile contructors are equivalent
    sync_user = Database.generate_profile(**PROFILE_AND_SETTINGS, preload=True)
    assert sync_user[atag] == user[atag]
    assert sync_user.tags == user.tags
    assert sync_user[atag]
    assert sync_user[atag] == atest_data
    assert sync_user[atag].__class__ is dict
    assert sync_user[atag] is not user[atag]

    # deleting an async profile removes its files from the filesystem
    await user.adelete_database()
    assert not user_copy._root_path.is_file()
    assert not user_copy._profile_tokens._salt_path.is_file()
    assert not (user_copy.path / await user_copy.afilename(atag)).is_file()


async def test_user_profiles(database):
    db = database
    user = db.generate_profile(**PROFILE_AND_SETTINGS)

    with user:
        user[tag] = test_data

    # equivalent profiles contain their own copies of stored data
    user_copy = db.generate_profile(**PROFILE_AND_SETTINGS, preload=True)
    assert user[tag] == user_copy[tag]
    assert user.tags == user_copy.tags
    assert user[tag]
    assert user[tag] == atest_data
    assert user[tag].__class__ is dict
    assert user[tag] == user_copy[tag]
    assert user[tag] is not user_copy[tag]

    # profiles are automatically saved to disk when initialized
    assert user_copy._root_path.is_file()
    assert user_copy._profile_tokens._salt_path.is_file()
    assert (user_copy.path / user_copy.filename(tag)).is_file()

    # async & sync profile contructors are equivalent
    async_user = await AsyncDatabase.agenerate_profile(**PROFILE_AND_SETTINGS, preload=True)
    assert async_user[tag] == user[tag]
    assert async_user.tags == user.tags
    assert async_user[tag]
    assert async_user[tag] == test_data
    assert async_user[tag].__class__ is dict
    assert async_user[tag] is not user[tag]

    # deleting a profile removes its files from the filesystem
    user.delete_database()
    assert not user_copy._root_path.is_file()
    assert not user_copy._profile_tokens._salt_path.is_file()
    assert not (user_copy.path / user_copy.filename(tag)).is_file()


class TestHMACMethods:
    def test_sync_hmac_methods_are_sound(self, database):
        """
        Sync HMAC methods provide soundness of data validation.
        """
        inputs = token_bytes(32)
        tag = database.make_hmac(inputs)

        # sync validation doesn't fail
        database.test_hmac(tag, inputs)

        # sync hmac tags fail when inputs type is altered
        context = "Data type alteration not caught!"
        with ignore(TypeError, if_else=violation(context)):
            database.test_hmac(tag, str(inputs))

        # sync hmac tags fail when inputs are altered
        iinputs = int.from_bytes(inputs, BIG)
        context = "Data value alteration not caught!"
        for bit in range(iinputs.bit_length()):
            with ignore(database.InvalidHMAC, if_else=violation(context)):
                database.test_hmac(tag, (iinputs ^ (1 << bit)).to_bytes(32, BIG))

        # sync hmac tags fail when they are altered
        itag = int.from_bytes(tag, BIG)
        context = "Tag alteration not caught!"
        for bit in range(itag.bit_length()):
            with ignore(database.InvalidHMAC, if_else=violation(context)):
                altered_tag = (itag ^ (1 << bit)).to_bytes(32, BIG)
                database.test_hmac(altered_tag, inputs)

    async def test_async_hmac_methods_are_sound(self, async_database):
        """
        Async HMAC methods provide soundness of data validation.
        """
        ainputs = token_bytes(32)
        atag = await async_database.amake_hmac(ainputs)

        # async validation doesn't fail
        await async_database.atest_hmac(atag, ainputs)

        # async hmac tags fail when inputs type is altered
        context = "Async data type alteration not caught!"
        async with aignore(TypeError, if_else=aviolation(context)):
            await async_database.atest_hmac(atag, str(ainputs))

        # async hmac tags fail when inputs are altered
        aiinputs = int.from_bytes(ainputs, BIG)
        context = "Async data value alteration not caught!"
        for bit in range(aiinputs.bit_length()):
            async with aignore(async_database.InvalidHMAC, if_else=aviolation(context)):
                await async_database.atest_hmac(atag, (aiinputs ^ (1 << bit)).to_bytes(32, BIG))

        # async hmac tags fail when they are altered
        aitag = int.from_bytes(atag, BIG)
        context = "Async tag alteration not caught!"
        for abit in range(aitag.bit_length()):
            async with aignore(async_database.InvalidHMAC, if_else=aviolation(context)):
                altered_tag = (aitag ^ (1 << abit)).to_bytes(32, BIG)
                await async_database.atest_hmac(altered_tag, ainputs)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

