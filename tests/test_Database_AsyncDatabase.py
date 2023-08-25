# This file is part of aiootp, an asynchronous crypto and anonymity
# library. Home of the Chunky2048 psuedo one-time pad stream cipher.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


class TestDBKDF:
    async def non_of_subkeys_are_the_same(self, kdf):
        assert kdf.aead_key not in {kdf.auth_key, kdf.prf_key}
        assert kdf.auth_key != kdf.prf_key

    async def length_sum_of_all_subkeys_is_declared(self, kdf):
        aead_key = kdf._AEAD_KEY_BYTES * b"a"
        auth_key = kdf._AUTH_KEY_BYTES * b"b"
        prf_key = kdf._PRF_KEY_BYTES * b"c"
        sub_key_control = aead_key + auth_key + prf_key
        assert all([aead_key, auth_key, prf_key])
        assert kdf._KEY_BYTES == (len(aead_key) + len(auth_key) + len(prf_key))
        assert kdf._KEY_BYTES == (
            len(sub_key_control[kdf._AEAD_KEY_SLICE])
            + len(sub_key_control[kdf._AUTH_KEY_SLICE])
            + len(sub_key_control[kdf._PRF_KEY_SLICE])
        )

    async def subkeys_are_non_overlapping(self, kdf):
        aead_key = kdf._AEAD_KEY_BYTES * b"a"
        auth_key = kdf._AUTH_KEY_BYTES * b"b"
        prf_key = kdf._PRF_KEY_BYTES * b"c"
        sub_key_control = aead_key + auth_key + prf_key
        assert all([aead_key, auth_key, prf_key])
        assert aead_key not in {auth_key, prf_key}
        assert auth_key != prf_key
        assert sub_key_control[kdf._AEAD_KEY_SLICE] == aead_key
        assert sub_key_control[kdf._AUTH_KEY_SLICE] == auth_key
        assert sub_key_control[kdf._PRF_KEY_SLICE] == prf_key

    async def test_async_subkeys_are_non_overlapping_correct_size(self, async_database):
        async_kdf = async_database._AsyncDatabase__root_kdf.copy()
        await self.non_of_subkeys_are_the_same(async_kdf)
        await self.length_sum_of_all_subkeys_is_declared(async_kdf)
        await self.subkeys_are_non_overlapping(async_kdf)

    async def test_sync_subkeys_are_non_overlapping_correct_size(self, database):
        kdf = database._Database__root_kdf.copy()
        await self.non_of_subkeys_are_the_same(kdf)
        await self.length_sum_of_all_subkeys_is_declared(kdf)
        await self.subkeys_are_non_overlapping(kdf)


class TestDatabaseCacheSystem:
    async def cached_data_remains_unchanged(self, db, subdb):
        assert plaintext_bytes
        assert plaintext_bytes.__class__ is bytes
        assert subdb[tag] == plaintext_bytes
        assert test_data
        assert test_data.__class__ is dict
        assert db[tag] == test_data

    async def clearing_cache_results_in_null_values(self, db, subdb):
        if issubclass(db.__class__, AsyncDatabase):
            await db.aclear_cache(metatags=True)
        else:
            db.clear_cache(metatags=True)
        assert plaintext_bytes
        assert plaintext_bytes.__class__ is bytes
        assert subdb[tag] == None
        assert test_data.__class__ is dict
        assert db[tag] == None

    async def uncached_loading_from_disk_doesnt_change_data(self, db, subdb):
        if issubclass(db.__class__, AsyncDatabase):
            assert await subdb.aquery_tag(tag, cache=False) == plaintext_bytes
            assert await db.aquery_tag(tag, cache=False) == test_data
        else:
            assert subdb.query_tag(tag, cache=False) == plaintext_bytes
            assert db.query_tag(tag, cache=False) == test_data
        assert subdb[tag] == None
        assert db[tag] == None

    async def cached_loading_from_disk_doesnt_change_data(self, db, subdb):
        if issubclass(db.__class__, AsyncDatabase):
            assert await subdb.aquery_tag(tag, cache=True) == plaintext_bytes
            assert await db.aquery_tag(tag, cache=True) == test_data
        else:
            assert subdb.query_tag(tag, cache=True) == plaintext_bytes
            assert db.query_tag(tag, cache=True) == test_data
        assert subdb[tag] == plaintext_bytes
        assert db[tag] == test_data

    async def clear_cache_clears_metatags_when_instructed(self, db, subdb):
        if issubclass(db.__class__, AsyncDatabase):
            assert await subdb.aquery_tag(tag, cache=True) == plaintext_bytes
            assert subdb[tag] == plaintext_bytes
            await db.aclear_cache(metatags=False)
            assert subdb[tag] == plaintext_bytes
            await db.aclear_cache(metatags=True)
            assert subdb[tag] == None
            assert await subdb.aquery_tag(tag, cache=False) == plaintext_bytes
        else:
            assert subdb.query_tag(tag, cache=True) == plaintext_bytes
            assert subdb[tag] == plaintext_bytes
            db.clear_cache(metatags=False)
            assert subdb[tag] == plaintext_bytes
            db.clear_cache(metatags=True)
            assert subdb[tag] == None
            assert subdb.query_tag(tag, cache=False) == plaintext_bytes

    async def test_async_cache_system(self, async_database):
        subdb = await async_database.ametatag(metatag)
        subdb[tag] = plaintext_bytes
        async_database[tag] = test_data.copy()
        await async_database.asave_database()
        await self.cached_data_remains_unchanged(async_database, subdb)
        await self.clearing_cache_results_in_null_values(async_database, subdb)
        await self.uncached_loading_from_disk_doesnt_change_data(async_database, subdb)
        await self.cached_loading_from_disk_doesnt_change_data(async_database, subdb)
        await self.clear_cache_clears_metatags_when_instructed(async_database, subdb)

    async def test_sync_cache_system(self, database):
        subdb = database.metatag(metatag)
        subdb[tag] = plaintext_bytes
        database[tag] = test_data.copy()
        database.save_database()
        await self.cached_data_remains_unchanged(database, subdb)
        await self.clearing_cache_results_in_null_values(database, subdb)
        await self.uncached_loading_from_disk_doesnt_change_data(database, subdb)
        await self.cached_loading_from_disk_doesnt_change_data(database, subdb)
        await self.clear_cache_clears_metatags_when_instructed(database, subdb)


def test_Database_instance(database):
    db = Database(key=key, preload=True)

    # basic database functionalities work the same across reloads
    assert db._Database__root_kdf.sha3_256() == database._Database__root_kdf.sha3_256()
    assert db._Database__root_kdf.sha3_256() != database._Database__root_kdf.sha3_256(aad=database._Database__root_salt)
    assert db._Database__root_salt == database._Database__root_salt
    assert db._root_filename == database._root_filename
    assert db.make_hmac(atag.encode()) == database.make_hmac(atag.encode())
    assert db.filename(atag) == database.filename(atag)
    assert db._metatag_key(atag) == database._metatag_key(atag)


async def test_AsyncDatabase_instance(database):
    db = await AsyncDatabase(key=key, preload=True)

    # basic async database functionalities work the same across reloads
    assert db._AsyncDatabase__root_kdf.sha3_256() == database._Database__root_kdf.sha3_256()
    assert db._AsyncDatabase__root_kdf.sha3_256() != database._Database__root_kdf.sha3_256(aad=database._Database__root_salt)
    assert db._AsyncDatabase__root_salt == database._Database__root_salt
    assert db._root_filename == database._root_filename
    assert await db.amake_hmac(tag.encode()) == database.make_hmac(tag.encode())
    assert await db.afilename(tag) == database.filename(tag)
    assert await db._ametatag_key(tag) == database._metatag_key(tag)


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
    # new, empty databases are falsey
    async_database = await AsyncDatabase(key * 2, preload=True)
    assert not async_database
    assert not async_database.tags
    assert not async_database.metatags

    # empty databases with metatag sub-databases are truthy
    achild = await async_database.ametatag(ametatag, preload=True)
    assert async_database
    assert not async_database.tags
    assert async_database.metatags
    assert not achild
    assert not achild.tags
    assert not achild.metatags

    # non-empty databases are truthy
    async_database[tag] = plaintext_bytes
    assert async_database
    assert async_database.tags
    assert async_database.metatags
    assert not achild
    assert not achild.tags
    assert not achild.metatags

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

    # metatags are removed from the manifest after calling adelete_metatag
    assert ametatag in async_database.metatags
    await async_database.adelete_metatag(ametatag)
    assert ametatag not in async_database.metatags

    await async_database.adelete_database()


def test_sync_tags_metatags():
    # new, empty databases are falsey
    database = Database(key * 2, preload=True)
    assert not database
    assert not database.tags
    assert not database.metatags

    # empty databases with metatag sub-databases are truthy
    child = database.metatag(metatag, preload=True)
    assert database
    assert not database.tags
    assert database.metatags
    assert not child
    assert not child.tags
    assert not child.metatags

    # non-empty databases are truthy
    database[tag] = plaintext_bytes
    assert database
    assert database.tags
    assert database.metatags
    assert not child
    assert not child.tags
    assert not child.metatags

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

    # metatags are removed from the manifest after calling delete_metatag
    assert metatag in database.metatags
    database.delete_metatag(metatag)
    assert metatag not in database.metatags

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
        problem = "Data type alteration not caught!"
        with ignore(TypeError, if_else=violation(problem)):
            database.test_hmac(tag, str(inputs))

        # sync hmac tags fail when inputs are altered
        iinputs = int.from_bytes(inputs, BIG)
        problem = "Data value alteration not caught!"
        for bit in range(iinputs.bit_length()):
            with ignore(database.InvalidHMAC, if_else=violation(problem)):
                database.test_hmac(tag, (iinputs ^ (1 << bit)).to_bytes(32, BIG))

        # sync hmac tags fail when they are altered
        itag = int.from_bytes(tag, BIG)
        problem = "Tag alteration not caught!"
        for bit in range(itag.bit_length()):
            with ignore(database.InvalidHMAC, if_else=violation(problem)):
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
        problem = "Async data type alteration not caught!"
        async with aignore(TypeError, if_else=aviolation(problem)):
            await async_database.atest_hmac(atag, str(ainputs))

        # async hmac tags fail when inputs are altered
        aiinputs = int.from_bytes(ainputs, BIG)
        problem = "Async data value alteration not caught!"
        for bit in range(aiinputs.bit_length()):
            async with aignore(async_database.InvalidHMAC, if_else=aviolation(problem)):
                await async_database.atest_hmac(atag, (aiinputs ^ (1 << bit)).to_bytes(32, BIG))

        # async hmac tags fail when they are altered
        aitag = int.from_bytes(atag, BIG)
        problem = "Async tag alteration not caught!"
        for abit in range(aitag.bit_length()):
            async with aignore(async_database.InvalidHMAC, if_else=aviolation(problem)):
                altered_tag = (aitag ^ (1 << abit)).to_bytes(32, BIG)
                await async_database.atest_hmac(altered_tag, ainputs)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

