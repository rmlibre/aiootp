# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2024 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


class TestDBKDF:

    async def test_salt_label_makes_state_unique(self, database):
        key = csprng()
        domain = b"testing"
        kdf = DomainKDF(domain, key=key)
        dbkdf = type(database._root_kdf)(domain, key=key)
        for sync_method in ("sha3_256", "sha3_512", "shake_128", "shake_256"):
            if "shake" in sync_method:
                assert getattr(kdf, sync_method)(size=64) != getattr(dbkdf, sync_method)(size=64)
            else:
                assert getattr(kdf, sync_method)() != getattr(dbkdf, sync_method)()


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
        assert subdb[tag] is None
        assert test_data.__class__ is dict
        assert db[tag] is None

    async def uncached_loading_from_disk_doesnt_change_data(self, db, subdb):
        if issubclass(db.__class__, AsyncDatabase):
            assert await subdb.aquery_tag(tag, cache=False) == plaintext_bytes
            assert await db.aquery_tag(tag, cache=False) == test_data
        else:
            assert subdb.query_tag(tag, cache=False) == plaintext_bytes
            assert db.query_tag(tag, cache=False) == test_data
        assert subdb[tag] is None
        assert db[tag] is None

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
            assert subdb[tag] is None
            assert await subdb.aquery_tag(tag, cache=False) == plaintext_bytes
        else:
            assert subdb.query_tag(tag, cache=True) == plaintext_bytes
            assert subdb[tag] == plaintext_bytes
            db.clear_cache(metatags=False)
            assert subdb[tag] == plaintext_bytes
            db.clear_cache(metatags=True)
            assert subdb[tag] is None
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


class TestDatabaseInitialization:

    async def test_async_key_size_limits(self):
        problem = (
            "a key that's too small was allowed."
        )
        token = token_bytes(64)
        for size in (0, 1, 2, 4, 8, 16, 31, MIN_KEY_BYTES - 1):
            key = token[:size]
            async with Ignore(ValueError, if_else=violation(f"{problem} at {len(key)} bytes")):
                db = await AsyncDatabase(key)

    def test_sync_key_size_limits(self):
        problem = (
            "a key that's too small was allowed."
        )
        token = token_bytes(64)
        for size in (0, 1, 2, 4, 8, 16, 31, MIN_KEY_BYTES - 1):
            key = token[:size]
            with Ignore(ValueError, if_else=violation(f"{problem} at {len(key)} bytes")):
                db = Database(key)


class TestDatabases:

    async def test_async_reload_manifest_drops_uncommitted_changes(
        self, async_database: AsyncDatabase
    ) -> None:
        manifest = async_database._manifest
        manifest["change"] = True
        assert "change" in manifest

        await async_database.aload_database(manifest=True)
        assert "change" in manifest
        assert "change" not in async_database._manifest

    async def test_sync_reload_manifest_drops_uncommitted_changes(
        self, database: Database
    ) -> None:
        manifest = database._manifest
        manifest["change"] = True
        assert "change" in manifest

        database.load_database(manifest=True)
        assert "change" in manifest
        assert "change" not in database._manifest

    async def test_async_non_existent_tag_query_doesnt_throw_on_silent(
        self, async_database: AsyncDatabase
    ) -> None:
        tag = "non_existent"
        assert tag not in async_database
        assert None == await async_database.aquery_tag(tag, silent=True)

        problem = (
            "Non-existent tag query doesn't throw when silent flag not set."
        )
        with Ignore(LookupError, if_else=violation(problem)):
            await async_database.aquery_tag(tag)

    async def test_sync_non_existent_tag_query_doesnt_throws_on_silent(
        self, database: Database
    ) -> None:
        tag = "non_existent"
        assert tag not in database
        assert None == database.query_tag(tag, silent=True)

        problem = (
            "Non-existent tag query doesn't throw when silent flag not set."
        )
        with Ignore(LookupError, if_else=violation(problem)):
            database.query_tag(tag)

    async def test_async_pop_doesnt_throw_on_silent(
        self, async_database: AsyncDatabase
    ) -> None:
        tag = "test_tag"
        data = b"test_data..."
        assert tag not in async_database
        assert None == await async_database.apop_tag(tag, silent=True)

        await async_database.aset_tag(tag, data)
        await async_database.asave_database()
        assert data == await async_database.apop_tag(tag)

        problem = (
            "Pop tag doesn't throw when silent flag not set."
        )
        with Ignore(LookupError, if_else=violation(problem)):
            await async_database.apop_tag(tag)

    async def test_sync_pop_doesnt_throw_on_silent(
        self, database: Database
    ) -> None:
        tag = "test_tag"
        data = b"test_data..."
        assert tag not in database
        assert None == database.pop_tag(tag, silent=True)

        database.set_tag(tag, data)
        database.save_database()
        assert data == database.pop_tag(tag)

        problem = (
            "Pop tag doesn't throw when silent flag not set."
        )
        with Ignore(LookupError, if_else=violation(problem)):
            database.pop_tag(tag)

    async def test_async_rollback_returns_previously_committed_state(
        self, async_database: AsyncDatabase
    ) -> None:
        tag = "test_tag"
        data = ["test", "data"]
        await async_database.apop_tag(tag, silent=True)
        async_database[tag] = list(data)
        assert data == async_database[tag]

        async_database[tag].append("mutated")
        assert data + ["mutated"] == async_database[tag]

        await async_database.arollback_tag(tag, cache=True)
        assert None == async_database[tag]

        async_database[tag] = list(data)
        await async_database.asave_database()
        assert data == async_database[tag]

        async_database[tag].append("mutated")
        assert data + ["mutated"] == async_database[tag]

        await async_database.arollback_tag(tag, cache=True)
        assert data == async_database[tag]

    async def test_sync_rollback_returns_previously_committed_state(
        self, database: Database
    ) -> None:
        tag = "test_tag"
        data = ["test", "data"]
        database.pop_tag(tag, silent=True)
        database[tag] = list(data)
        assert data == database[tag]

        database[tag].append("mutated")
        assert data + ["mutated"] == database[tag]

        database.rollback_tag(tag, cache=True)
        assert None == database[tag]

        database[tag] = list(data)
        database.save_database()
        assert data == database[tag]

        database[tag].append("mutated")
        assert data + ["mutated"] == database[tag]

        database.rollback_tag(tag, cache=True)
        assert data == database[tag]

    async def test_async_filenames_shows_all_set_tags(
        self, async_database: AsyncDatabase
    ) -> None:
        data = None
        async with async_database as db:
            tags = [f"tag_{i}" for i in range(32)]
            filenames = [await db.afilename(tag) for tag in tags]
            for tag in tags:
                db[tag] = data
            assert db.filenames.issuperset(filenames)

    async def test_sync_filenames_shows_all_set_tags(
        self, database: Database
    ) -> None:
        data = None
        with database as db:
            tags = [f"tag_{i}" for i in range(32)]
            filenames = [db.filename(tag) for tag in tags]
            for tag in tags:
                db[tag] = data
            assert db.filenames.issuperset(filenames)

    async def test_async_metatag_cant_point_to_non_database_type(
        self, async_database: AsyncDatabase
    ) -> None:
        class NonDatabaseType:
            pass

        problem = (
            "A non-database type metatag was assessed as a metatag."
        )
        metatag = "tested_attribute"
        async_database.tested_attribute = NonDatabaseType()
        with Ignore(NameError, if_else=violation(problem)):
            await async_database.ametatag(metatag)
        del async_database.tested_attribute

    async def test_sync_metatag_cant_point_to_non_database_type(
        self, database: Database
    ) -> None:
        class NonDatabaseType:
            pass

        problem = (
            "A non-database type metatag was assessed as a metatag."
        )
        metatag = "tested_attribute"
        database.tested_attribute = NonDatabaseType()
        with Ignore(NameError, if_else=violation(problem)):
            database.metatag(metatag)
        del database.tested_attribute

    async def test_async_delete_non_existent_metatag_throws_error(
        self, async_database: AsyncDatabase
    ) -> None:
        problem = (
            "A deletion of a non-existent metatag didn't throw an error."
        )
        metatag = "tested_metatag"
        with Ignore(LookupError, if_else=violation(problem)):
            await async_database.adelete_metatag(metatag)

    async def test_sync_delete_non_existent_metatag_throws_error(
        self, database: Database
    ) -> None:
        problem = (
            "A deletion of a non-existent metatag didn't throw an error."
        )
        metatag = "tested_metatag"
        with Ignore(LookupError, if_else=violation(problem)):
            database.delete_metatag(metatag)

    async def test_async_save_non_existent_tag_throws_error(
        self, async_database: AsyncDatabase
    ) -> None:
        problem = (
            "A save of a non-existent tag didn't throw an error."
        )
        tag = "tested_tag"
        await async_database.apop_tag(tag, silent=True)
        with Ignore(LookupError, if_else=violation(problem)):
            await async_database.asave_tag(tag)

    async def test_sync_save_non_existent_tag_throws_error(
        self, database: Database
    ) -> None:
        problem = (
            "A save of a non-existent tag didn't throw an error."
        )
        tag = "tested_tag"
        database.pop_tag(tag, silent=True)
        with Ignore(LookupError, if_else=violation(problem)):
            database.save_tag(tag)

    async def test_async_delitem_removes_tags(
        self, async_database: AsyncDatabase
    ) -> None:
        problem = (
            "A save of a non-existent tag didn't throw an error."
        )
        tag = "tested_tag"
        data = b"tested_data..."
        async_database[tag] = data
        await async_database.asave_database()
        assert data == async_database[tag]
        assert (
            async_database._path / await async_database.afilename(tag)
        ).is_file()

        del async_database[tag]
        assert None == async_database[tag]
        assert not (
            async_database._path / await async_database.afilename(tag)
        ).is_file()

    async def test_sync_delitem_removes_tags(
        self, database: AsyncDatabase
    ) -> None:
        problem = (
            "A save of a non-existent tag didn't throw an error."
        )
        tag = "tested_tag"
        data = b"tested_data..."
        database[tag] = data
        database.save_database()
        assert data == database[tag]
        assert (database._path / database.filename(tag)).is_file()

        del database[tag]
        assert None == database[tag]
        assert not (database._path / database.filename(tag)).is_file()


def test_Database_instance(database):
    db = Database(key=key, preload=True)

    # basic database functionalities work the same across reloads
    assert db._root_kdf.sha3_256() == database._root_kdf.sha3_256()
    assert db._root_kdf.sha3_256() != database._root_kdf.sha3_256(aad=database._root_salt)
    assert db._root_salt == database._root_salt
    assert db._root_filename == database._root_filename
    assert db.filename(atag) == database.filename(atag)
    assert db._metatag_key(atag) == database._metatag_key(atag)


async def test_AsyncDatabase_instance(database):
    db = await AsyncDatabase(key=key, preload=True)

    # basic async database functionalities work the same across reloads
    assert db._root_kdf.sha3_256() == database._root_kdf.sha3_256()
    assert db._root_kdf.sha3_256() != database._root_kdf.sha3_256(aad=database._root_salt)
    assert db._root_salt == database._root_salt
    assert db._root_filename == database._root_filename
    assert await db.afilename(tag) == database.filename(tag)
    assert await db._ametatag_key(tag) == database._metatag_key(tag)


def test_database_ciphers(database):
    # database ciphertexts are unique
    db = database
    cipher = Chunky2048(key)
    c = cipher._config
    filename = db.filename(tag)
    encrypted_data = db.json_encrypt(test_data, filename=filename, aad=b"")
    db[tag] = test_data
    db.save_database()
    encrypted_file = db._query_ciphertext(filename)
    assert encrypted_file != encrypted_data
    assert encrypted_file[c.SHMAC_SLICE] != encrypted_data[c.SHMAC_SLICE]
    assert encrypted_file[c.SALT_SLICE] != encrypted_data[c.SALT_SLICE]
    assert encrypted_file[c.IV_SLICE] != encrypted_data[c.IV_SLICE]
    assert encrypted_file[c.CIPHERTEXT_SLICE] != encrypted_data[c.CIPHERTEXT_SLICE]

    # database ciphers recover json data correctly
    assert test_data == db.json_decrypt(encrypted_file, filename=filename, aad=b"")
    assert test_data == db.json_decrypt(encrypted_data, filename=filename, aad=b"")
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
    cipher = Chunky2048(key)
    c = cipher._config
    filename = await db.afilename(tag)
    encrypted_data = await db.ajson_encrypt(test_data, filename=filename, aad=b"")
    db[tag] = test_data
    await db.asave_database()
    encrypted_file = await db._aquery_ciphertext(filename)
    assert encrypted_file != encrypted_data
    assert encrypted_file[c.SHMAC_SLICE] != encrypted_data[c.SHMAC_SLICE]
    assert encrypted_file[c.SALT_SLICE] != encrypted_data[c.SALT_SLICE]
    assert encrypted_file[c.IV_SLICE] != encrypted_data[c.IV_SLICE]
    assert encrypted_file[c.CIPHERTEXT_SLICE] != encrypted_data[c.CIPHERTEXT_SLICE]

    # async database ciphers recover json data correctly
    assert test_data == await db.ajson_decrypt(encrypted_file, filename=filename, aad=b"")
    assert test_data == await db.ajson_decrypt(encrypted_data, filename=filename, aad=b"")

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


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

