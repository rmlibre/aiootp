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


__all__ = ["AsyncDatabase"]


__doc__ = "Implements an asynchronous transparently encrypted database."


import json

from aiootp._typing import Typing as t
from aiootp._constants import DEFAULT_AAD, DEFAULT_TTL, MIN_KEY_BYTES, BIG
from aiootp._constants import BYTES_FLAG, BYTES_FLAG_SIZE
from aiootp._constants import FILENAME_HASH_BYTES, SHAKE_128_BLOCKSIZE
from aiootp._exceptions import DatabaseIssue, Ignore
from aiootp._paths import adelete_salt_file
from aiootp.asynchs import AsyncInit, asleep, gather, aos
from aiootp.commons import Namespace
from aiootp.randoms import atoken_bytes
from aiootp.keygens.passcrypt.config import passcrypt_spec

from .profile_tokens import AsyncProfileTokens
from .database_properties import DatabaseProperties


class AsyncDatabase(DatabaseProperties, metaclass=AsyncInit):
    """
    This class creates databases which enable the disk persistence of
    any bytes or JSON serializable native python data-types, with fully
    transparent, asynchronous encryption / decryption.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    key = await aiootp.acsprng()
    db = await AsyncDatabase(key)

    # Elements in a database are organized by user-defined tags ->
    db["income"] = 32000

    # Databases can store any JSON serializable data ->
    db["dict"] = {0: 1, 2: 3, 4: 5}-------------------------
    db["lists"] = ["juice", ["nested juice"]]              |
                                                           |
    # As well as raw bytes ->                              |
    db["bytes"] = b"value..."                              |
                                                           |
    # Save changes to disk ->                              |
    await db.asave_database()                              |
                                                           |
    # Clear data (& unsaved changes) from the cache ->     |
    await db.aclear_cache()                                |
                                                           |
    # Retrieve items by their tags ->                      |
    db["dict"]                                             |
    >>> None  # oops, it's not in the cache!               |
                                                           |
    await db.aquery_tag("dict", cache=True)                V
    >>> {"0": 1, "2": 3, "4": 5}  # <----- JSON turns keys into strings

    assert db["dict"] is await db.aquery_tag("dict")

    # Create descendants of databases using what are called metatags ->
    taxes = await db.ametatag("taxes")
    taxes[2020] = {"jan": 130.25, "feb": 163.23, "mar": 149.68}
    assert taxes == db.taxes
    assert taxes[2020] == db.taxes[2020]

    # Delete a descendant database ->
    await db.adelete_metatag("taxes")

    # Purge the filesystem of all database files ->
    await db.adelete_database()
    """

    __slots__ = ()

    _ProfileTokens: type = AsyncProfileTokens

    @classmethod
    async def _aencode_filename(cls, value: bytes) -> str:
        """
        Returns the received bytes-type `value` in base38 encoding.
        """
        return await cls.IO.abytes_to_filename(value)

    @classmethod
    async def agenerate_profile(
        cls,
        # passcrypt credentials
        *credentials: bytes,
        username: bytes,
        passphrase: bytes,
        salt: bytes = b"",
        aad: bytes = DEFAULT_AAD,
        # passcrypt settings
        mb: int = passcrypt_spec.DEFAULT_MB,
        cpu: int = passcrypt_spec.DEFAULT_CPU,
        cores: int = passcrypt_spec.DEFAULT_CORES,
        # database keyword arguments
        path: t.OptionalPathStr = None,
        preload: bool = False,
    ) -> t.Cls:
        """
        Creates & loads a profile database for a user from the `tokens`
        passed in.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        db = await aiootp.AsyncDatabase.agenerate_profile(
            b"server_url",     # Any number of arguments can be passed
            b"email_address",  # here as additional, optional credentials.
            username=b"username",
            passphrase=b"passphrase",
            salt=b"optional salt keyword argument",
            mb=256,   # The passcrypt memory cost in Mebibytes (MiB)
            cpu=2,    # The computational complexity & number of iterations
            cores=8,  # How many parallel processes passcrypt will utilize
        )
        """
        tokens = await cls._ProfileTokens().agenerate(
            *credentials,
            username=username,
            passphrase=passphrase,
            salt=salt,
            aad=aad,
            mb=mb,
            cpu=cpu,
            cores=cores,
            path=path,
        )
        profile_db = await cls(
            key=tokens.login_key, path=path, preload=preload
        )
        if not profile_db._root_path.is_file():
            await profile_db.asave_database()
        profile_db._profile_tokens = tokens
        await tokens.acleanup()
        return profile_db

    async def __init__(
        self,
        key: bytes,
        *,
        preload: bool = False,
        path: t.OptionalPathStr = None,
        metatag: bool = False,
        silent: bool = True,
    ) -> None:
        """
        Sets a database object's basic cryptographic values derived from
        a `key` & opens up the associated administrative files. The
        `generate_profile_tokens` & `generate_profile` methods would be
        a safer choice for opening a database if using a passphrase
        instead of a cryptographic key.

        `preload`:  This boolean value tells the object to -- True --
            load all of the stored database values from the filesystem
            into the cache during initialization, or -- False -- skip
            the loading stage. This can save time up front so users can
            pay the cost of loading data only when that value is needed.

        `path`:  This value is the string or `Pathlib.Path`
            object that points to the filesystem location where the
            database files reside / will be saved. By default, stores
            values in the directory "databases" relative to the package
            source code.

        `metatag`:  This boolean value tells the class whether to
            prepare itself as a sub-database or not, which generally
            means less storage overhead used to secure its cryptographic
            material. Parent databases that are not metatags store a
            random salt value in their `self._root_path` file.

        `silent`:  This boolean value tells the class to surpress
            exceptions when loading files so that errors in the database
            don't prevent a user from logging in.
        """
        self._silent = silent
        self._cache = Namespace()
        self._manifest = Namespace()
        self.path = await self._aformat_path(path)
        self._is_metatag = True if metatag else False
        await self._ainitialize_keys(key)
        await self._aload_manifest()
        await self._ainitialize_metatags()
        await self.aload_database(silent=silent, preload=preload)

    @classmethod
    async def _aformat_path(cls, path: t.PathStr) -> t.Path:
        """
        Returns a `pathlib.Path` object to the user-specified `path`
        if given, else returns a copy of the default database directory
        `Path` object.
        """
        await asleep()
        if path is None:
            return t.Path(cls._path).absolute()
        return t.Path(path).absolute()

    async def _ainitialize_keys(self, key: bytes) -> None:
        """
        Derives the database's cryptographic root key material and the
        filename of the manifest ledger.
        """
        await asleep()
        self._root_kdf = self._DBKDF(self._DBDomains.ROOT_KDF, key=key)

    async def _aopen_manifest(self) -> t.JSONObject:
        """
        Loads an existing manifest file ledger from the filesystem.
        """
        ciphertext = await self.IO.aread(path=self._root_path)
        key = await self._root_kdf.ashake_128(
            aad=self._DBDomains.MANIFEST, size=SHAKE_128_BLOCKSIZE
        )
        return await self._Cipher(key).ajson_decrypt(ciphertext)

    async def _aload_root_salt(self) -> bytes:
        """
        Returns the decoded raw bytes root salt from the manifest.
        """
        return await self.IO.aurlsafe_to_bytes(
            self._manifest[self._ROOT_SALT_LEDGERNAME]
        )

    async def _agenerate_root_salt(self) -> bytes:
        """
        Returns a raw bytes random salt with length metadata appended to
        be used as the instance's root salt.
        """
        return await atoken_bytes(self._ROOT_SALT_BYTES)

    async def _ainstall_root_salt(self, salt: bytes) -> None:
        """
        Stores in the manifest, with a URL-safe base64 encoding, the
        `salt` value as its root salt. This the source of entropy for
        the database which isn't derived from the user's login key.
        """
        self._manifest[self._ROOT_SALT_LEDGERNAME] = (
            (await self.IO.abytes_to_urlsafe(salt)).decode()
        )

    async def _aload_manifest(self) -> t.JSONObject:
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """
        if self._root_path.exists():
            self._manifest = Namespace(await self._aopen_manifest())
            self._root_salt = await self._aload_root_salt()
        else:
            self._manifest = Namespace()
            self._root_salt = await self._agenerate_root_salt()
            await self._ainstall_root_salt(self._root_salt)

    async def _ainitialize_metatags(self) -> None:
        """
        Initializes the values that organize database metatags, which
        are independent offspring of databases that are accessible by
        their parent.
        """
        if not self.metatags:
            self._manifest[self._METATAGS_LEDGERNAME] = []

    async def aload_tags(self, *, silent: bool = False) -> t.Self:
        """
        Specifically loads all of the database's tag values into the
        cache.
        """
        tags = self.tags
        if not tags:
            await asleep()
            return self

        tag_values = (
            self.aquery_tag(tag, silent=silent, cache=True) for tag in tags
        )
        await gather(*tag_values)
        return self

    async def aload_metatags(
        self, *, preload: bool = True, silent: bool = False
    ) -> t.Self:
        """
        Specifically loads all of the database's metatag values into the
        cache. If the `preload` keyword argument is falsey then the
        metatag references are populated in the database's instance
        dictionary, but their internal values are not loaded.
        """
        metatags_set = set(self.metatags)
        if not metatags_set:
            await asleep()
            return self

        metatags = (
            self.ametatag(metatag, preload=preload, silent=silent)
            for metatag in metatags_set
        )
        await gather(*metatags)
        return self

    async def aload_database(
        self,
        *,
        manifest: bool = False,
        silent: bool = False,
        preload: bool = True,
    ) -> t.Self:
        """
        Does initial loading of the database. If `manifest` is `True`,
        then the instance's manifest is reloaded from disk & unsaved
        changes to the manifest are discarded. If `preload` is `True`,
        then the value of all the database's tags, & the value of all of
        its metatag's tags, are cached from the filesystem & unsaved
        changes are discarded. This enables up-to-date bracket lookup of
        tag values without needing to await the `aquery_tag` method,
        but could be quite costly in terms of memory if databases &
        their metatags contain large amounts of data.
        """
        if manifest:
            await self._aload_manifest()
        if preload:
            await self.aload_tags(silent=silent)
        await self.aload_metatags(silent=silent, preload=preload)
        return self

    async def afilename(self, tag: str) -> str:
        """
        Derives the filename hash given a user-defined `tag`.
        """
        filename = await self._root_kdf.ashake_128(
            self._root_salt,
            tag.encode(),
            aad=self._DBDomains.FILENAME,
            size=FILENAME_HASH_BYTES,
        )
        return await self._aencode_filename(filename)

    async def abytes_encrypt(
        self,
        plaintext: bytes,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the `plaintext` bytes with keys specific to the
        `filename` value & returns the ciphertext bytes.
        """
        key = await self._root_kdf.ashake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return await self._Cipher(key).abytes_encrypt(plaintext)

    async def ajson_encrypt(
        self,
        plaintext: t.JSONSerializable,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the JSON serializable `plaintext` object with keys
        specific to the `filename` value & returns the ciphertext
        bytes.
        """
        key = await self._root_kdf.ashake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return await self._Cipher(key).ajson_encrypt(plaintext)

    async def amake_token(
        self,
        plaintext: bytes,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the `plaintext` bytes with keys specific to the
        `filename` value & urlsafe base64 encodes the resulting
        ciphertext bytes.
        """
        key = await self._root_kdf.ashake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return await self._TokenCipher(key).amake_token(plaintext)

    async def abytes_decrypt(
        self,
        ciphertext: bytes,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
    ) -> bytes:
        """
        Decrypts the `ciphertext` bytes with keys specific to the
        `filename` value & returns the plaintext bytes. `ttl` is the
        amount of seconds that dictate the allowable age of the
        decrypted message.
        """
        key = await self._root_kdf.ashake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return await self._Cipher(key).abytes_decrypt(ciphertext, ttl=ttl)

    async def ajson_decrypt(
        self,
        ciphertext: bytes,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
    ) -> t.JSONSerializable:
        """
        Decrypts the `ciphertext` bytes with keys specific to the
        `filename` value & JSON loads the resulting plaintext bytes.
        `ttl` is the amount of seconds that dictate the allowable age
        of the decrypted message.
        """
        key = await self._root_kdf.ashake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return await self._Cipher(key).ajson_decrypt(ciphertext, ttl=ttl)

    async def aread_token(
        self,
        token: t.Base64URLSafe,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
    ) -> bytes:
        """
        Decrypts the urlsafe base64 encoded `token` with keys specific
        to the `filename` value & returns the plaintext bytes. `ttl`
        is the amount of seconds that dictate the allowable age of the
        decrypted message.
        """
        key = await self._root_kdf.ashake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return await self._TokenCipher(key).aread_token(token, ttl=ttl)

    async def _asave_ciphertext(
        self, filename: str, ciphertext: bytes
    ) -> None:
        """
        Saves the encrypted value `ciphertext` in the database file
        called `filename`.
        """
        path = self.path / filename
        await self.IO.awrite(path=path, data=ciphertext)

    async def aset_tag(
        self, tag: str, data: t.JSONSerializable, *, cache: bool = True
    ) -> t.Self:
        """
        Allows users to add the value `data` under the name `tag`
        into the database.
        """
        filename = await self.afilename(tag)
        setattr(self._cache, filename, data)
        setattr(self._manifest, filename, tag)
        if not cache:
            await self.asave_tag(tag, drop_cache=True)
        return self

    async def _aquery_ciphertext(
        self, filename: str, *, silent: bool = False
    ) -> None:
        """
        Retrieves the value stored in the database which has the given
        `filename`.
        """
        try:
            path = self.path / filename
            return await self.IO.aread(path=path)
        except FileNotFoundError as corrupt_database:
            if not silent:
                raise DatabaseIssue.file_not_found(filename)

    async def aquery_tag(
        self, tag: str, *, silent: bool = False, cache: bool = False
    ) -> t.Union[bytes, t.JSONSerializable]:
        """
        Allows users to retrieve the value stored under the name `tag`
        from the database.
        """
        filename = await self.afilename(tag)
        if filename in self._cache:
            return getattr(self._cache, filename)
        ciphertext = await self._aquery_ciphertext(filename, silent=silent)
        if not ciphertext:
            return

        result = await self.abytes_decrypt(ciphertext, filename=filename)
        if result[:BYTES_FLAG_SIZE] == BYTES_FLAG:
            result = result[BYTES_FLAG_SIZE:]  # Remove bytes value flag
        else:
            result = json.loads(result)
        if cache:
            setattr(self._cache, filename, result)
        return result

    async def _adelete_file(self, filename: str, *, silent=False) -> None:
        """
        Deletes a file in the database directory by `filename`.
        """
        try:
            await aos.remove(self.path / filename)
        except FileNotFoundError as error:
            if not silent:
                raise error from None

    async def apop_tag(
        self, tag: str, *, silent: bool = False
    ) -> t.Union[bytes, t.JSONSerializable]:
        """
        Returns a value from the database by it's `tag` & deletes the
        associated file in the database directory.
        """
        failures = []
        track_failure = lambda relay: failures.append(relay.error) or True
        filename = await self.afilename(tag)
        value = await self.aquery_tag(tag, cache=False, silent=True)
        with Ignore(KeyError, AttributeError, if_except=track_failure):
            del self._manifest[filename]
        with Ignore(KeyError, AttributeError, if_except=track_failure):
            del self._cache[filename]
        with Ignore(FileNotFoundError, if_except=track_failure):
            await self._adelete_file(filename)
        if (not silent) and (len(failures) == 3):
            raise DatabaseIssue.tag_file_doesnt_exist(tag)
        return value

    async def arollback_tag(
        self, tag: str, *, cache: bool = False
    ) -> t.Self:
        """
        Clears the new `tag` data from the cache which undoes any
        recent changes. If the `tag` data was never saved to disk,
        then removing it from the cache will prevent it from being
        saved in the database.
        """
        filename = await self.afilename(tag)
        if not (self.path / filename).is_file():
            with Ignore(AttributeError):
                delattr(self._manifest, filename)
        with Ignore(AttributeError):
            delattr(self._cache, filename)
        with Ignore(LookupError):
            await self.aquery_tag(tag, cache=True) if cache else 0
        return self

    async def aclear_cache(self, *, metatags: bool = True) -> t.Self:
        """
        Clears all recent changes in the cache, but this doesn't clear
        a database's metatag caches unless `metatags` is truthy.
        """
        self._cache.__dict__.clear()
        if metatags:
            for metatag in self.metatags:
                await getattr(self, metatag).aclear_cache(metatags=metatags)
        await asleep()
        return self

    async def _ametatag_key(self, tag: str) -> bytes:
        """
        Derives the metatag's database key given a user-defined `tag`.
        """
        return await self._root_kdf.asha3_512(
            self._root_salt, tag.encode(), aad=self._DBDomains.METATAG_KEY
        )

    async def ametatag(
        self, tag: str, *, preload: bool = False, silent: bool = False
    ) -> t.Cls:
        """
        Allows a user to create offspring of a database instance to
        organize data by a name `tag` & domain separate cryptographic
        material. These descendants are accessible by dotted lookup from
        the parent database. Descendants are also synchronized by their
        parents automatically.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        # Create a parent database ->
        key = aiootp.csprng()
        parent = await AsyncDatabase(key)

        # Name the descendant database ->
        tag = "sub_database"
        offspring = await parent.ametatag(tag)

        # It is now accessible from the parent by the tag ->
        assert offspring is parent.sub_database
        """
        if hasattr(self, tag):
            if (
                issubclass(getattr(self, tag).__class__, self.__class__)
                and tag not in self.__class__.__dict__
            ):
                return self.__dict__[tag]
            raise Issue.cant_reassign_attribute(tag)
        self.__dict__[tag] = await self.__class__(
            key=await self._ametatag_key(tag),
            preload=preload,
            path=self.path,
            metatag=True,
            silent=silent,
        )
        if tag not in self.metatags:
            getattr(self._manifest, self._METATAGS_LEDGERNAME).append(tag)
        return self.__dict__[tag]

    async def adelete_metatag(self, tag: str) -> t.Self:
        """
        Removes the descendant database named `tag`.
        """
        if tag not in self.metatags:
            raise DatabaseIssue.no_existing_metatag(tag)
        sub_db = await self.ametatag(tag)
        await sub_db.adelete_database()
        self.__dict__.pop(tag)
        self._manifest[self._METATAGS_LEDGERNAME].remove(tag)
        return self

    async def _anullify(self) -> None:
        """
        Clears the database's memory caches & instance variables of all
        values so a deleted database no longer makes changes to the
        filesystem.
        """
        self._manifest.__dict__.clear()
        self._cache.__dict__.clear()
        self.__dict__.clear()
        for base in self.__class__.__mro__:
            await asleep()
            for attr in getattr(base, "__slots__", ()):
                if hasattr(self, attr):
                    delattr(self, attr)

    async def _adelete_profile_tokens(self) -> None:
        """
        Deletes the salt file that what created if this instance was
        initialized with the `agenerate_profile` classmethod.
        """
        if hasattr(self, "_profile_tokens"):
            salt_path = self._profile_tokens._salt_path
            if salt_path.is_file():
                await adelete_salt_file(salt_path)

    async def adelete_database(self) -> None:
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        for metatag in self.metatags:
            sub_db = await self.ametatag(metatag, preload=False)
            await sub_db.adelete_database()
        for filename in self._manifest.__dict__:
            await self._adelete_file(filename, silent=True)
        await self._adelete_file(self._root_filename, silent=True)
        await self._adelete_profile_tokens()
        await self._anullify()

    async def _aencrypt_manifest(self) -> bytes:
        """
        Takes a `salt` & returns the database's manifest encrypted.
        """
        manifest = self._manifest.__dict__
        key = await self._root_kdf.ashake_128(
            aad=self._DBDomains.MANIFEST, size=SHAKE_128_BLOCKSIZE
        )
        return await self._Cipher(key).ajson_encrypt(manifest)

    async def _asave_manifest(self, ciphertext: bytes) -> None:
        """
        Writes the manifest ledger to disk. It contains all database
        filenames & special cryptographic values for initializing the
        database's key derivation functions.
        """
        await self.IO.awrite(path=self._root_path, data=ciphertext)

    async def _aclose_manifest(self) -> None:
        """
        Prepares for & writes the manifest ledger to disk. The manifest
        contains all database filenames & other metadata used to
        organize databases.
        """
        manifest = await self._aencrypt_manifest()
        await self._asave_manifest(manifest)

    async def _asave_file(
        self, filename: str, *, admin: bool = False
    ) -> None:
        """
        Writes the cached value for a user-specified `filename` to the
        user filesystem.
        """
        value = getattr(self._cache, filename)
        if value.__class__ is bytes:
            value = BYTES_FLAG + value  # Assure not reloaded as JSON
        else:
            value = json.dumps(value).encode()
        ciphertext = await self.abytes_encrypt(value, filename=filename)
        await self._asave_ciphertext(filename, ciphertext)

    async def _asave_tags(self) -> None:
        """
        Writes the database's user-defined tags to disk.
        """
        save = self._asave_file
        filenames = self._cache.__dict__
        saves = (save(filename) for filename in filenames)
        await gather(*saves)

    async def _asave_metatags(self) -> None:
        """
        Writes the database's descendant databases to disk.
        """
        saves = (
            getattr(self, metatag).asave_database()
            for metatag in self.metatags
        )
        await gather(*saves)

    async def asave_tag(
        self, tag: str, *, admin: bool = False, drop_cache: bool = False
    ) -> t.Self:
        """
        Writes the cached value for a user-specified `tag` to the user
        filesystem.
        """
        filename = await self.afilename(tag)
        try:
            await self._asave_file(filename, admin=admin)
        except AttributeError:
            raise DatabaseIssue.tag_file_doesnt_exist(tag)
        finally:
            if drop_cache and hasattr(self._cache, filename):
                delattr(self._cache, filename)
        return self

    async def asave_database(self) -> t.Self:
        """
        Writes the database's values to disk with transparent encryption.
        """
        await self._aclose_manifest()
        await gather(self._asave_metatags(), self._asave_tags())
        return self

    async def __aenter__(self) -> t.Self:
        """
        The context manager automatically writes database changes made
        by a user to disk.
        """
        return self

    async def __aexit__(
        self, exc_type=None, exc_value=None, traceback=None
    ) -> None:
        """
        The context manager automatically writes database changes made
        by a user to disk.
        """
        await self.asave_database()


module_api = dict(
    AsyncDatabase=t.add_type(AsyncDatabase),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

