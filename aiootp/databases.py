# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["AsyncDatabase", "Database"]


__doc__ = (
    "Implements synchronous & asynchronous transparently encrypted data"
    " persistance classes using the package's Chunky2048 cipher."
)


import hmac
import json
import base64
from functools import lru_cache
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from .__dependencies import alru_cache
from .__constants import *
from ._exceptions import *
from ._containers import ProfileTokens
from ._typing import Typing as t
from ._typing import PathStr, OptionalPathStr
from .paths import Path, DatabasePath, SecurePath, AsyncSecurePath
from .paths import deniable_filename, adeniable_filename
from .paths import read_salt_file, aread_salt_file
from .paths import delete_salt_file, adelete_salt_file
from .asynchs import AsyncInit, asleep, gather, aos
from .commons import Namespace
from .commons import make_module
from .gentools import aunpack
from .randoms import generate_salt, agenerate_salt
from .generics import Domains, BytesIO
from .generics import hash_bytes, ahash_bytes
from .generics import int_as_base, aint_as_base
from .generics import canonical_pack, acanonical_pack
from .generics import bytes_are_equal, abytes_are_equal
from .ciphers import Chunky2048
from .ciphers import json_encrypt, ajson_encrypt
from .ciphers import json_decrypt, ajson_decrypt
from .ciphers import bytes_encrypt, abytes_encrypt
from .ciphers import bytes_decrypt, abytes_decrypt
from .keygens import DomainKDF, Passcrypt, KeyAADBundle



class DBDomains:
    """
    A container for database-specific domain constants.
    """

    __slots__ = ()

    _encode: t.Callable = Domains.encode_constant

    ROOT_KDF: bytes = _encode("database_root_kdf", 16)
    ROOT_FILENAME: bytes = _encode("database_root_filename", 16)
    ROOT_SALT: bytes = _encode("database_root_salt", 16)
    ROOT_SALT_FILENAME: bytes = _encode("database_root_salt_filename", 16)
    KDF: bytes = _encode("database_kdf", 16)
    USER_KDF: bytes = _encode("database_user_kdf", 16)
    METATAG: bytes = _encode("database_metatag", 16)
    HMAC: bytes = _encode("database_derive_hmac", 16)
    PROFILE_TOKENS: bytes = _encode("database_profile_tokens", 16)
    MANIFEST: bytes = _encode("database_manifest", 16)
    FILENAME: bytes = _encode("database_filename", 16)
    FILE_KEY: bytes = _encode("database_file_encryption_key", 16)
    METATAG_KEY: bytes = _encode("database_metatag_key", 16)
    DEVICE_SALT: bytes = _encode(b"database_device_salt", 16)


class DBKDF(DomainKDF):
    """
    A specialized KDF type for performing various ``(Async)Database``
    operations.
    """

    __slots__ = ("aead_key", "auth_key", "prf_key")

    _key_size: int = 296
    _key_type: SHAKE_256_TYPE = SHAKE_256_TYPE

    _AEAD_KEY_SLICE: slice = slice(None, 168)
    _AUTH_KEY_SLICE: slice = slice(168, 232)
    _PRF_KEY_SLICE: slice = slice(232, None)

    async def aupdate_key(self, entropy: bytes) -> "self":
        """
        Uses the base class to derive a stretched key which is divided
        up in pieces, each with specific purposes.
        """
        await super().aupdate_key(entropy)
        self.aead_key = self._key[self._AEAD_KEY_SLICE]
        self.auth_key = self._key[self._AUTH_KEY_SLICE]
        self.prf_key = self._key[self._PRF_KEY_SLICE]
        return self

    def update_key(self, entropy: bytes) -> "self":
        """
        Uses the base class to derive a stretched key which is divided
        up in pieces, each with specific purposes.
        """
        super().update_key(entropy)
        self.aead_key = self._key[self._AEAD_KEY_SLICE]
        self.auth_key = self._key[self._AUTH_KEY_SLICE]
        self.prf_key = self._key[self._PRF_KEY_SLICE]
        return self


class AsyncDatabase(metaclass=AsyncInit):
    """
    This class creates databases which enable the disk persistence of
    any bytes or JSON serializable native python data-types, with fully
    transparent, asynchronous encryption / decryption using the
    library's `Chunky2048` cipher.

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

    IO = BytesIO
    InvalidHMAC = InvalidHMAC
    InvalidSHMAC = InvalidSHMAC
    TimestampExpired = TimestampExpired

    path: t.Path = DatabasePath()

    _ROOT_SALT_LEDGERNAME: str = "0"
    _METATAGS_LEDGERNAME: str = "1"

    @classmethod
    async def _aencode_filename(cls, value: bytes) -> str:
        """
        Returns the received bytes-type ``value`` in base38 encoding.
        """
        return await cls.IO.abytes_to_filename(value)

    @classmethod
    def _encode_filename(cls, value: bytes) -> str:
        """
        Returns the received bytes-type ``value`` in base38 encoding.
        """
        return cls.IO.bytes_to_filename(value)

    @classmethod
    async def _asummon_device_salt(cls, path: PathStr = path) -> bytes:
        """
        Generates a salt which is unique for each unique ``path``
        directory that is given to this method. This is a static salt
        which provides an initial form of randomization to cryptographic
        material for all profiles saved under that directory.
        """
        salt_path = await AsyncSecurePath(
            path, key=DBDomains.DEVICE_SALT, _admin=True
        )
        return await aread_salt_file(salt_path)

    @classmethod
    async def _asummon_profile_salt(
        cls, tokens: ProfileTokens, path: PathStr
    ) -> bytes:
        """
        Creates or loads a salt value saved on the user filesystem to
        help add more entropy to their key derivation functions when
        preparing to open a profile database.
        """
        tokens._salt_path = await AsyncSecurePath(path, key=tokens._gist)
        tokens._salt = await aread_salt_file(tokens._salt_path)
        return tokens._salt

    @classmethod
    async def _agenerate_profile_login_key(
        cls,
        tokens: ProfileTokens,
        **passcrypt_settings: t.PasscryptNewSettingsType,
    ) -> bytes:
        """
        Combines the output of the expensive key derivation functions &
        the salt stored on the filesystem gathered in preparation to
        safely open a profile database.
        """
        tokens.login_key = await Passcrypt.anew(
            tokens._tmp_key, tokens._salt, **passcrypt_settings
        )
        tokens._tmp_key = None
        return tokens.login_key

    @classmethod
    async def _agenerate_profile_tokens(
        cls,
        *credentials: t.Iterable[bytes],
        username: bytes,
        passphrase: bytes,
        salt: bytes,
        aad: bytes,
        path: PathStr = path,
        **passcrypt_settings: t.PasscryptNewSettingsType,
    ) -> ProfileTokens:
        """
        Runs a very expensive key derivation function to build keys
        for users to open a database with only access to potentially
        weakly entropic credentials & the filesystem.
        """
        device_salt = await cls._asummon_device_salt(path=path)
        gist = await ahash_bytes(
            DBDomains.PROFILE_TOKENS,
            device_salt,
            salt,
            aad,
            username,
            *credentials,
            key=device_salt,
            hasher=sha3_512,
        )
        tokens = ProfileTokens(
            await ahash_bytes(gist, key=passphrase, hasher=sha3_512),
            gist=gist,
        )
        await cls._asummon_profile_salt(tokens, path=path)
        await cls._agenerate_profile_login_key(tokens, **passcrypt_settings)
        return tokens

    @classmethod
    async def agenerate_profile(
        cls,
        # passcrypt credentials
        *credentials: t.Iterable[bytes],
        username: bytes,
        passphrase: bytes,
        salt: bytes = b"",
        aad: bytes = DEFAULT_AAD,
        # passcrypt settings
        mb: int = passcrypt.DEFAULT_MB,
        cpu: int = passcrypt.DEFAULT_CPU,
        cores: int = passcrypt.DEFAULT_CORES,
        tag_size: int = KEY_BYTES,
        # database keyword arguments
        path: PathStr = path,
        preload: bool = False,
    ) -> "cls":
        """
        Creates & loads a profile database for a user from the ``tokens``
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
            mb=256,   # The passcrypt memory cost in Mibibytes (MiB)
            cpu=2,    # The computational complexity & number of iterations
            cores=8,  # How many parallel processes passcrypt will utilize
        )
        """
        tokens = await cls._agenerate_profile_tokens(
            *credentials,
            username=username,
            passphrase=passphrase,
            salt=salt,
            aad=aad,
            mb=mb,
            cpu=cpu,
            cores=cores,
            tag_size=tag_size,
            path=path,
        )
        profile_db = await cls(
            key=tokens.login_key, path=path, preload=preload, metatag=True
        )
        if not profile_db._root_path.is_file():
            await profile_db.asave_database()
        profile_db._profile_tokens = tokens
        return profile_db

    async def __init__(
        self,
        key: bytes,
        *,
        preload: bool = False,
        path: PathStr = path,
        metatag: bool = False,
        silent: bool = True,
    ) -> "self":
        """
        Sets a database object's basic cryptographic values derived from
        a ``key`` & opens up the associated administrative files. The
        `generate_profile_tokens` & `generate_profile` methods would be
        a safer choice for opening a database if using a passphrase
        instead of a cryptographic key.

        ``preload``:    This boolean value tells the object to -- True --
            load all of the stored database values from the filesystem
            into the cache during initialization, or -- False -- skip
            the loading stage. This can save time up front so users can
            pay the cost of loading data only when that value is needed.

        ``path``:  This value is the string or ``Pathlib.Path``
            object that points to the filesystem location where the
            database files reside / will be saved. By default, stores
            values in the directory "databases" relative to the package
            source code.

        ``metatag``:    This boolean value tells the class whether to
            prepare itself as a sub-database or not, which generally
            means less storage overhead used to secure its cryptographic
            material. Parent databases that are not metatags store a
            random salt value in their ``self._root_path`` file.

        ``silent``:     This boolean value tells the class to surpress
            exceptions when loading files so that errors in the database
            don't prevent a user from logging in.
        """
        self._silent = silent
        self._corrupted_files = {}
        self._cache = Namespace()
        self._manifest = Namespace()
        self.path = await self._aformat_path(path)
        self._is_metatag = True if metatag else False
        await self._ainitialize_keys(key)
        await self._aload_manifest()
        await self._ainitialize_metatags()
        await self.aload_database(silent=silent, preload=preload)

    @classmethod
    async def _aformat_path(cls, path: PathStr) -> Path:
        """
        Returns a `pathlib.Path` object to the user-specified ``path``
        if given, else returns a copy of the default database directory
        `Path` object.
        """
        if path == None:
            return Path(cls.path).absolute()
        return Path(path).absolute()

    async def _ainitialize_keys(self, key: bytes) -> None:
        """
        Derives the database's cryptographic root key material and the
        filename of the manifest ledger.
        """
        self.__root_kdf = kdf = DBKDF(DBDomains.ROOT_KDF, key=key)
        self._root_filename = await self._aencode_filename(
            kdf.shake_128(
                FILENAME_HASH_BYTES, context=DBDomains.ROOT_FILENAME
            )
        )
        self._root_salt_filename = await self._aencode_filename(
            kdf.shake_128(
                FILENAME_HASH_BYTES, context=DBDomains.ROOT_SALT_FILENAME
            )
        )

    @property
    def _root_path(self) -> Path:
        """
        Returns a ``pathlib.Path`` object that points to the file that
        contains the manifest ledger.
        """
        return self.path / self._root_filename

    @property
    def _maintenance_files(self) -> t.Set[str]:
        """
        Returns the filenames of entries in the database that refer to
        administrative values used by objects to track and coordinate
        themselves internally.
        """
        return {self._ROOT_SALT_LEDGERNAME, self._METATAGS_LEDGERNAME}

    @property
    def tags(self) -> t.Set[str]:
        """
        Returns a list of all user-defined names for values stored in
        the database object.
        """
        manifest = self._manifest
        return {
            getattr(manifest, filename)
            for filename in self._maintenance_files.symmetric_difference(
                manifest
            )
        }

    @property
    def filenames(self) -> t.Set[str]:
        """
        Returns a list of all derived filenames of user-defined tags
        stored in the database object.
        """
        return {
            filename
            for filename in self._maintenance_files.symmetric_difference(
                self._manifest.namespace
            )
        }

    @property
    def metatags(self) -> t.Set[str]:
        """
        Returns the list of metatags that a database contains.
        """
        return set(
            self._manifest.namespace.get(self._METATAGS_LEDGERNAME, [])
        )

    @property
    def _root_salt_path(self) -> Path:
        """
        Returns the path of the database's root salt file if the
        instance is not a metatag.
        """
        if not self._is_metatag:
            return self.path / self._root_salt_filename

    async def _aopen_manifest(self) -> t.JSONObject:
        """
        Loads an existing manifest file ledger from the filesystem.
        """
        aad = DBDomains.MANIFEST
        key = self.__root_kdf.aead_key
        return await ajson_decrypt(
            await self.IO.aread(path=self._root_path), key=key, aad=aad
        )

    async def _aload_root_salt(self) -> bytes:
        """
        Pulls the root salt from the filesystem for a database instance,
        or retrieves it from the manifest file if the database is a
        metatag. Returns the result.
        """
        if self._is_metatag:
            await asleep()
            salt = self._manifest[self._ROOT_SALT_LEDGERNAME]
        else:
            encrypted_salt = await self.IO.aread(path=self._root_salt_path)
            aad = DBDomains.ROOT_SALT
            key = self.__root_kdf.aead_key
            salt = await ajson_decrypt(encrypted_salt, key=key, aad=aad)
        return bytes.fromhex(salt)

    async def _agenerate_root_salt(self) -> bytes:
        """
        Returns a 32 byte hex salt for a metatag database, or a 64 byte
        hex salt otherwise.
        """
        if self._is_metatag:
            return await agenerate_salt(size=16)
        else:
            return await agenerate_salt(size=64)

    async def _ainstall_root_salt(self, salt: bytes) -> None:
        """
        Gives the manifest knowledge of the database's root ``salt``.
        This salt is the source of entropy for the database that is not
        derived from the user's key that opens the database. This salt
        is saved in the manifest if the database is a metatag, or the
        salt is saved in its own file if the database is a main parent
        database.
        """
        if self._is_metatag:
            self._manifest[self._ROOT_SALT_LEDGERNAME] = salt.hex()
        else:
            self._manifest[self._ROOT_SALT_LEDGERNAME] = 0

    async def _agenerate_salted_root_kdf(self) -> DBKDF:
        """
        Returns a kkdf that is derived from the database's main key &
        the root salt's entropy.
        """
        kdf = self.__root_kdf.copy()
        await kdf.aupdate_key(self.__root_salt)
        return kdf

    async def _agenerate_salted_user_kdf(self) -> DBKDF:
        """
        Create a KDF object accessible by the user, which is intended to
        safely simplify their work of doing custom cryptographic
        procedures.
        """
        kdf = self.__kdf.copy()
        await kdf.aupdate_key(kdf._key + Domains.USER)
        await kdf.aupdate(kdf._key, Domains.USER)
        return kdf

    async def _aload_manifest(self) -> t.JSONObject:
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """
        if self._root_path.exists():
            self._manifest = Namespace(await self._aopen_manifest())
            self.__root_salt = await self._aload_root_salt()
        else:
            self._manifest = Namespace()
            self.__root_salt = await self._agenerate_root_salt()
            await self._ainstall_root_salt(self.__root_salt)

        self.__kdf = await self._agenerate_salted_root_kdf()
        self.kdf = await self._agenerate_salted_user_kdf()

    async def _ainitialize_metatags(self) -> None:
        """
        Initializes the values that organize database metatags, which
        are independent offspring of databases that are accessible by
        their parent.
        """
        if not self.metatags:
            self._manifest[self._METATAGS_LEDGERNAME] = []

    async def aload_tags(self, *, silent: bool = False) -> "self":
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
        await gather(*tag_values, return_exceptions=True)
        return self

    async def aload_metatags(
        self, *, preload: bool = True, silent: bool = False
    ) -> "self":
        """
        Specifically loads all of the database's metatag values into the
        cache. If the ``preload`` keyword argument is falsey then the
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
        await gather(*metatags, return_exceptions=True)
        return self

    async def aload_database(
        self,
        *,
        manifest: bool = False,
        silent: bool = False,
        preload: bool = True,
    ) -> "self":
        """
        Does initial loading of the database. If ``manifest`` is `True`,
        then the instance's manifest is reloaded from disk & unsaved
        changes to the manifest are discarded. If ``preload`` is `True`,
        then the value of all the database's tags, & the value of all of
        its metatag's tags, are cached from the filesystem & unsaved
        changes are discarded. This enables up-to-date bracket lookup of
        tag values without needing to await the `aquery_tag` method,
        but could be quite costly in terms of memory if databases &
        thier metatags contain large amounts of data.
        """
        if manifest:
            await self._aload_manifest()
        if preload:
            await self.aload_tags(silent=silent)
        await self.aload_metatags(silent=silent, preload=preload)
        return self

    @lru_cache(maxsize=256)
    def _filename(self, tag: str) -> str:
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        key = self.__kdf.prf_key
        context = DBDomains.FILENAME + tag.encode()
        filename = hmac.new(key, context, sha3_256).digest()
        return self._encode_filename(filename[FILENAME_HASH_SLICE])

    @alru_cache(maxsize=256)
    async def afilename(self, tag: str) -> str:
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        await asleep()
        key = self.__kdf.prf_key
        context = DBDomains.FILENAME + tag.encode()
        filename = hmac.new(key, context, sha3_256).digest()
        return self._encode_filename(filename[FILENAME_HASH_SLICE])

    async def amake_hmac(
        self, *data: t.Iterable[bytes], aad: bytes = DEFAULT_AAD
    ) -> bytes:
        """
        Derives an HMAC hash of the supplied ``data`` with a unique
        permutation of the database's keys & a domain-specific kdf key.
        """
        if not data:
            raise Issue.no_value_specified("data")
        key = self.__kdf.auth_key + aad
        context = await acanonical_pack(DBDomains.HMAC, aad, *data)
        return hmac.new(key, context, sha3_256).digest()

    async def atest_hmac(
        self,
        untrusted_hmac: bytes,
        *data: t.Iterable[bytes],
        aad: bytes = DEFAULT_AAD,
    ) -> None:
        """
        Tests if the ``hmac`` of ``data`` is valid using the instance's
        keys & a timing-safe comparison.
        """
        if not untrusted_hmac:
            raise Issue.no_value_specified("untrusted_hmac")
        true_hmac = await self.amake_hmac(*data, aad=aad)
        if not await abytes_are_equal(untrusted_hmac, true_hmac):
            raise DatabaseIssue.invalid_hmac()

    async def abytes_encrypt(
        self,
        plaintext: bytes,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the ``plaintext`` bytes with keys specific to the
        ``filename`` value & returns the ciphertext bytes.
        """
        key = self.__kdf.aead_key
        aad = canonical_pack(DBDomains.FILE_KEY, filename.encode(), aad)
        return await abytes_encrypt(plaintext, key, aad=aad)

    async def ajson_encrypt(
        self,
        plaintext: t.JSONSerializable,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the JSON serializable ``plaintext`` object with keys
        specific to the ``filename`` value & returns the ciphertext
        bytes.
        """
        key = self.__kdf.aead_key
        aad = canonical_pack(DBDomains.FILE_KEY, filename.encode(), aad)
        return await ajson_encrypt(plaintext, key, aad=aad)

    async def amake_token(
        self,
        plaintext: bytes,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the ``plaintext`` bytes with keys specific to the
        ``filename`` value & urlsafe base64 encodes the resulting
        ciphertext bytes.
        """
        key = self.__kdf.aead_key
        aad = canonical_pack(DBDomains.FILE_KEY, filename.encode(), aad)
        return await Chunky2048(key).amake_token(plaintext, aad=aad)

    async def abytes_decrypt(
        self,
        ciphertext: bytes,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
    ) -> bytes:
        """
        Decrypts the ``ciphertext`` bytes with keys specific to the
        ``filename`` value & returns the plaintext bytes. ``ttl`` is the
        amount of seconds that dictate the allowable age of the
        decrypted message.
        """
        key = self.__kdf.aead_key
        aad = canonical_pack(DBDomains.FILE_KEY, filename.encode(), aad)
        return await abytes_decrypt(ciphertext, key, aad=aad, ttl=ttl)

    async def ajson_decrypt(
        self,
        ciphertext: bytes,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
    ) -> t.JSONSerializable:
        """
        Decrypts the ``ciphertext`` bytes with keys specific to the
        ``filename`` value & JSON loads the resulting plaintext bytes.
        ``ttl`` is the amount of seconds that dictate the allowable age
        of the decrypted message.
        """
        key = self.__kdf.aead_key
        aad = canonical_pack(DBDomains.FILE_KEY, filename.encode(), aad)
        return await ajson_decrypt(ciphertext, key, aad=aad, ttl=ttl)

    async def aread_token(
        self,
        token: t.Base64URLSafe,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
    ) -> bytes:
        """
        Decrypts the urlsafe base64 encoded ``token`` with keys specific
        to the ``filename`` value & returns the plaintext bytes. ``ttl``
        is the amount of seconds that dictate the allowable age of the
        decrypted message.
        """
        key = self.__kdf.aead_key
        aad = canonical_pack(DBDomains.FILE_KEY, filename.encode(), aad)
        return await Chunky2048(key).aread_token(token, aad=aad, ttl=ttl)

    async def _asave_ciphertext(
        self, filename: str, ciphertext: bytes
    ) -> None:
        """
        Saves the encrypted value ``ciphertext`` in the database file
        called ``filename``.
        """
        path = self.path / filename
        await self.IO.awrite(path=path, data=ciphertext)

    async def aset_tag(
        self, tag: str, data: t.JSONSerializable, *, cache: bool = True
    ) -> "self":
        """
        Allows users to add the value ``data`` under the name ``tag``
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
        ``filename``.
        """
        try:
            path = self.path / filename
            return await self.IO.aread(path=path)
        except FileNotFoundError as corrupt_database:
            self._corrupted_files[filename] = True
            if not silent:
                raise DatabaseIssue.file_not_found(filename)

    async def aquery_tag(
        self, tag: str, *, silent: bool = False, cache: bool = False
    ) -> t.Union[bytes, t.JSONSerializable]:
        """
        Allows users to retrieve the value stored under the name ``tag``
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
        Deletes a file in the database directory by ``filename``.
        """
        try:
            await aos.remove(self.path / filename)
        except FileNotFoundError as error:
            if not silent:
                raise error from None

    async def apop_tag(
        self, tag: str, *, admin: bool = False, silent: bool = False
    ) -> t.Union[bytes, t.JSONSerializable]:
        """
        Returns a value from the database by it's ``tag`` & deletes the
        associated file in the database directory.
        """
        failures = False
        filename = await self.afilename(tag)
        if filename in self._maintenance_files and not admin:
            raise DatabaseIssue.cant_delete_maintenance_files()
        try:
            value = await self.aquery_tag(tag, cache=False)
        except FileNotFoundError as error:
            value = None
            failures = True
        try:
            del self._manifest[filename]
        except (KeyError, AttributeError):
            failures = True
        try:
            del self._cache[filename]
        except (KeyError, AttributeError):
            pass
        try:
            await self._adelete_file(filename)
        except FileNotFoundError as error:
            pass
        if failures and not silent:
            raise DatabaseIssue.tag_file_doesnt_exist(tag)
        return value

    async def arollback_tag(
        self, tag: str, *, cache: bool = False
    ) -> "self":
        """
        Clears the new ``tag`` data from the cache which undoes any
        recent changes. If the ``tag`` data was never saved to disk,
        then removing it from the cache will prevent it from being
        saved in the database.
        """
        filename = await self.afilename(tag)
        file_exists = (self.path / filename).is_file()
        tag_is_stored = filename in self._manifest
        if tag_is_stored and not file_exists:
            delattr(self._manifest, filename)
        elif not tag_is_stored and not file_exists:
            raise DatabaseIssue.tag_file_doesnt_exist(tag)
        if filename in self._cache:
            delattr(self._cache, filename)
            await self.aquery_tag(tag, cache=True) if cache else 0
        await asleep()
        return self

    async def aclear_cache(self, *, metatags: bool = True) -> "self":
        """
        Clears all recent changes in the cache, but this doesn't clear
        a database's metatag caches unless ``metatags`` is truthy.
        """
        self._cache.namespace.clear()
        if metatags:
            for metatag in self.metatags:
                await getattr(self, metatag).aclear_cache(metatags=metatags)
        await asleep()
        return self

    async def _ametatag_key(self, tag: str) -> bytes:
        """
        Derives the metatag's database key given a user-defined ``tag``.
        """
        context = DBDomains.METATAG_KEY + tag.encode()
        return await self.__kdf.ashake_256(DBKDF._key_size, context=context)

    async def ametatag(
        self, tag: str, *, preload: bool = False, silent: bool = False
    ) -> "cls":
        """
        Allows a user to create offspring of a database instance to
        organize data by a name ``tag`` & domain separate cryptographic
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
        if tag in self.__class__.__dict__:
            raise Issue.cant_overwrite_existing_attribute(tag)
        elif tag in self.__dict__:
            if issubclass(self.__dict__[tag].__class__, self.__class__):
                return self.__dict__[tag]
            else:
                raise Issue.cant_overwrite_existing_attribute(tag)
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

    async def adelete_metatag(self, tag: str) -> "self":
        """
        Removes the descendant database named ``tag``.
        """
        if tag not in self.metatags:
            raise DatabaseIssue.no_existing_metatag(tag)
        sub_db = await self.ametatag(tag)
        await sub_db.adelete_database()
        self.__dict__.pop(tag)
        self.metatags.remove(tag)
        return self

    async def _anullify(self) -> None:
        """
        Clears the database's memory caches & instance variables of all
        values so a deleted database no longer makes changes to the
        filesystem.
        """
        self._manifest.namespace.clear()
        self._cache.namespace.clear()
        self.__dict__.clear()
        await asleep()

    async def adelete_database(self) -> None:
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        for metatag in self.metatags:
            sub_db = await self.ametatag(metatag, preload=False)
            await sub_db.adelete_database()
        for filename in self._manifest.namespace:
            await self._adelete_file(filename, silent=True)
        await self._adelete_file(self._root_salt_filename, silent=True)
        await self._adelete_file(self._root_filename, silent=True)
        if hasattr(self, "_profile_tokens"):
            salt_path = self._profile_tokens._salt_path
            if salt_path.is_file():
                await adelete_salt_file(salt_path)
        await self._anullify()

    async def _aencrypt_manifest(self) -> bytes:
        """
        Takes a ``salt`` & returns the database's manifest encrypted.
        """
        manifest = self._manifest.namespace
        aad = DBDomains.MANIFEST
        key = self.__root_kdf.aead_key
        return await ajson_encrypt(manifest, key=key, aad=aad)

    async def _asave_manifest(
        self, ciphertext: t.DictCiphertext
    ) -> None:
        """
        Writes the manifest ledger to disk. It contains all database
        filenames & special cryptographic values for initializing the
        database's key derivation functions.
        """
        if not ciphertext:
            raise DatabaseIssue.invalid_write_attempt()
        await self.IO.awrite(path=self._root_path, data=ciphertext)

    async def _asave_root_salt(self, salt: bytes) -> None:
        """
        Writes a non-metatag database instance's root salt to disk as a
        separate file.
        """
        aad = DBDomains.ROOT_SALT
        key = self.__root_kdf.aead_key
        await self.IO.awrite(
            path=self._root_salt_path,
            data=await ajson_encrypt(salt.hex(), key=key, aad=aad),
        )

    async def _aclose_manifest(self) -> None:
        """
        Prepares for & writes the manifest ledger to disk. The manifest
        contains all database filenames & other metadata used to
        organize databases.
        """
        if not self._is_metatag:
            await self._asave_root_salt(self.__root_salt)
        manifest = await self._aencrypt_manifest()
        await self._asave_manifest(manifest)

    async def _asave_file(
        self, filename: str, *, admin: bool = False
    ) -> None:
        """
        Writes the cached value for a user-specified ``filename`` to the
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
        filenames = self._cache.namespace
        saves = (save(filename) for filename in filenames)
        await gather(*saves, return_exceptions=True)

    async def _asave_metatags(self) -> None:
        """
        Writes the database's descendant databases to disk.
        """
        saves = (
            getattr(self, metatag).asave_database()
            for metatag in self.metatags
        )
        await gather(*saves, return_exceptions=True)

    async def asave_tag(
        self, tag: str, *, admin: bool = False, drop_cache: bool = False
    ) -> "self":
        """
        Writes the cached value for a user-specified ``tag`` to the user
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

    async def asave_database(self) -> "self":
        """
        Writes the database's values to disk with transparent encryption.
        """
        await self._aclose_manifest()
        await gather(
            self._asave_metatags(),
            self._asave_tags(),
            return_exceptions=True,
        )
        return self

    async def amirror_database(self, database) -> "self":
        """
        Copies over all of the stored & loaded values, tags & metatags
        from the ``database`` object passed into this function.
        """
        async for tag, value in aunpack.root(database):
            await self.aset_tag(tag, value)
        for metatag in database.metatags:
            my_metatag = await self.ametatag(metatag)
            await my_metatag.amirror_database(database.__dict__[metatag])
        return self

    def __contains__(self, tag: str) -> bool:
        """
        Checks the cache & manifest for the filename associated with the
        user-defined ``tag``.
        """
        filename = self._filename(tag)
        return filename in self._manifest or filename in self._cache

    def __bool__(self) -> bool:
        """
        Returns True if the instance dictionary is populated or the
        manifast is saved to the filesystem.
        """
        return bool(self.__dict__)

    async def __aenter__(self) -> "self":
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

    async def __aiter__(self) -> t.AsyncGenerator[
        None, t.Tuple[str, t.Union[bytes, t.JSONSerializable]]
    ]:
        """
        Provides an interface to the names & values stored in databases.
        """
        silent = self._silent
        for tag in self.tags:
            yield (
                tag,
                await self.aquery_tag(tag, silent=silent, cache=False),
            )

    def __setitem__(self, tag: str, data: t.JSONSerializable) -> None:
        """
        Allows users to add the value ``data`` under the name ``tag``
        into the database.
        """
        filename = self._filename(tag)
        setattr(self._cache, filename, data)
        setattr(self._manifest, filename, tag)

    def __getitem__(self, tag: str) -> t.Union[bytes, t.JSONSerializable]:
        """
        Allows users to retrieve the value stored under the name ``tag``
        from the database cache.
        """
        filename = self._filename(tag)
        if filename in self._cache:
            return getattr(self._cache, filename)

    def __delitem__(self, tag: str) -> None:
        """
        Allows users to delete the value stored under the name ``tag``
        from the database.
        """
        filename = self._filename(tag)
        with ignore(KeyError, AttributeError):
            del self._manifest[filename]
        with ignore(KeyError, AttributeError):
            del self._cache[filename]
        with ignore(FileNotFoundError):
            (self.path / filename).unlink()

    __len__ = lambda self: (
        len(self._manifest) - len(self._maintenance_files)
    )


class Database:
    """
    This class creates databases which enable the disk persistence of
    any bytes or JSON serializable native python data-types, with fully
    transparent encryption / decryption using the library's `Chunky2048`
    cipher.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    key = aiootp.generate_key()
    db = Database(key)

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
    db.save_database()                                     |
                                                           |
    # Clear data (& unsaved changes) from the cache ->     |
    db.clear_cache()                                       |
                                                           |
    # Retrieve items by their tags ->                      |
    db["dict"]                                             |
    >>> None  # oops, it's not in the cache!               |
                                                           |
    db.query_tag("dict", cache=True)                       V
    >>> {"0": 1, "2": 3, "4": 5}  # <----- JSON turns keys into strings

    assert db["dict"] is db.query_tag("dict")

    # Create descendant databases using what are called metatags ->
    taxes = db.metatag("taxes")
    taxes[2020] = {"jan": 130.25, "feb": 163.23, "mar": 149.68}
    assert taxes == db.taxes
    assert taxes[2020] == db.taxes[2020]

    # Delete a descendant database ->
    db.delete_metatag("taxes")

    # Purge the filesystem of all parent & descendant files ->
    db.delete_database()
    """

    IO = BytesIO
    InvalidHMAC = InvalidHMAC
    InvalidSHMAC = InvalidSHMAC
    TimestampExpired = TimestampExpired

    path: PathStr = DatabasePath()

    _ROOT_SALT_LEDGERNAME: str = "0"
    _METATAGS_LEDGERNAME: str = "1"

    @classmethod
    def _encode_filename(cls, value: bytes) -> str:
        """
        Returns the received bytes-type ``value`` in base38 encoding.
        """
        return cls.IO.bytes_to_filename(value)

    @classmethod
    def _summon_device_salt(cls, path: PathStr = path) -> bytes:
        """
        Generates a salt which is unique for each unique ``path``
        directory that is given to this method. This is a static salt
        which provides an initial form of randomization to cryptographic
        material for all profiles saved under that directory.
        """
        salt_path = SecurePath(path, key=DBDomains.DEVICE_SALT, _admin=True)
        return read_salt_file(salt_path)

    @classmethod
    def _summon_profile_salt(
        cls, tokens: ProfileTokens, path: PathStr
    ) -> bytes:
        """
        Creates or loads a salt value saved on the user filesystem to
        help add more entropy to their key derivation functions when
        preparing to open a profile database.
        """
        tokens._salt_path = SecurePath(path, key=tokens._gist)
        tokens._salt = read_salt_file(tokens._salt_path)
        return tokens._salt

    @classmethod
    def _generate_profile_login_key(
        cls,
        tokens: ProfileTokens,
        **passcrypt_settings: t.PasscryptNewSettingsType,
    ) -> bytes:
        """
        Combines the output of the expensive key derivation functions &
        the salt stored on the filesystem gathered in preparation to
        safely open a profile database.
        """
        tokens.login_key = Passcrypt.new(
            tokens._tmp_key, tokens._salt, **passcrypt_settings
        )
        tokens._tmp_key = None
        return tokens.login_key

    @classmethod
    def _generate_profile_tokens(
        cls,
        *credentials: t.Iterable[bytes],
        username: bytes,
        passphrase: bytes,
        salt: bytes,
        aad: bytes,
        path: PathStr = path,
        **passcrypt_settings: t.PasscryptNewSettingsType,
    ) -> ProfileTokens:
        """
        Runs a very expensive key derivation function to build keys
        for users to open a database with only access to potentially
        weakly entropic credentials & the filesystem.
        """
        device_salt = cls._summon_device_salt(path=path)
        gist = hash_bytes(
            DBDomains.PROFILE_TOKENS,
            device_salt,
            salt,
            aad,
            username,
            *credentials,
            key=device_salt,
            hasher=sha3_512,
        )
        tokens = ProfileTokens(
            tmp_key=hash_bytes(gist, key=passphrase, hasher=sha3_512),
            gist=gist,
        )
        cls._summon_profile_salt(tokens, path=path)
        cls._generate_profile_login_key(tokens, **passcrypt_settings)
        return tokens

    @classmethod
    def generate_profile(
        cls,
        # passcrypt credentials
        *credentials: t.Iterable[bytes],
        username: bytes,
        passphrase: bytes,
        salt: bytes = b"",
        aad: bytes = DEFAULT_AAD,
        # passcrypt settings
        mb: int = passcrypt.DEFAULT_MB,
        cpu: int = passcrypt.DEFAULT_CPU,
        cores: int = passcrypt.DEFAULT_CORES,
        tag_size: int = KEY_BYTES,
        # database keyword arguments
        path: PathStr = path,
        preload: bool = False,
    ) -> "cls":
        """
        Creates & loads a profile database for a user from the ``tokens``
        passed in.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        db = aiootp.Database.generate_profile(
            b"server_url",     # Any number of arguments can be passed
            b"email_address",  # here as additional, optional credentials.
            username=b"username",
            passphrase=b"passphrase",
            salt=b"optional salt keyword argument",
            mb=256,   # The passcrypt memory cost in Mibibytes (MiB)
            cpu=2,    # The computational complexity & number of iterations
            cores=8,  # How many parallel processes passcrypt will utilize
        )
        """
        tokens = cls._generate_profile_tokens(
            *credentials,
            username=username,
            passphrase=passphrase,
            salt=salt,
            aad=aad,
            mb=mb,
            cpu=cpu,
            cores=cores,
            tag_size=tag_size,
            path=path,
        )
        profile_db = cls(
            key=tokens.login_key, path=path, preload=preload, metatag=True
        )
        if not profile_db._root_path.is_file():
            profile_db.save_database()
        profile_db._profile_tokens = tokens
        return profile_db

    def __init__(
        self,
        key: bytes,
        *,
        preload: bool = False,
        path: PathStr = path,
        metatag: bool = False,
        silent: bool = True,
    ) -> "self":
        """
        Sets a database object's basic cryptographic values derived from
        a ``key`` & opens up the associated administrative files. The
        `generate_profile_tokens` & `generate_profile` methods would be
        a safer choice for opening a database if using a passphrase
        instead of a cryptographic key.

        ``preload``:    This boolean value tells the object to -- True --
            load all of the stored database values from the filesystem
            into the cache during initialization, or -- False -- skip
            the loading stage. This can save time up front so users can
            pay the cost of loading data only when that value is needed.

        ``path``:  This value is the string or ``Pathlib.Path``
            object that points to the filesystem location where the
            database files reside / will be saved. By default, stores
            values in the directory "databases" relative to the package
            source code.

        ``metatag``:    This boolean value tells the class whether to
            prepare itself as a sub-database or not, which generally
            means less storage overhead used to secure its cryptographic
            material. Parent databases that are not metatags store a
            random salt value in their ``self._root_path`` file.

        ``silent``:     This boolean value tells the class to surpress
            exceptions when loading files so that errors in the database
            don't prevent a user from logging in.
        """
        self._silent = silent
        self._corrupted_files = {}
        self._cache = Namespace()
        self._manifest = Namespace()
        self.path = self._format_path(path)
        self._is_metatag = True if metatag else False
        self._initialize_keys(key)
        self._load_manifest()
        self._initialize_metatags()
        self.load_database(silent=silent, preload=preload)

    @classmethod
    def _format_path(cls, path: PathStr) -> Path:
        """
        Returns a `pathlib.Path` object to the user-specified ``path``
        if given, else returns a copy of the default database directory
        `Path` object.
        """
        if path == None:
            return Path(cls.path).absolute()
        return Path(path).absolute()

    def _initialize_keys(self, key: bytes) -> None:
        """
        Derives the database's cryptographic root key material and the
        filename of the manifest ledger.
        """
        self.__root_kdf = kdf = DBKDF(DBDomains.ROOT_KDF, key=key)
        self._root_filename = self._encode_filename(
            kdf.shake_128(
                FILENAME_HASH_BYTES, context=DBDomains.ROOT_FILENAME
            )
        )
        self._root_salt_filename = self._encode_filename(
            kdf.shake_128(
                FILENAME_HASH_BYTES, context=DBDomains.ROOT_SALT_FILENAME
            )
        )

    @property
    def _root_path(self) -> Path:
        """
        Returns a ``pathlib.Path`` object that points to the file that
        contains the manifest ledger.
        """
        return self.path / self._root_filename

    @property
    def _maintenance_files(self) -> t.Set[str]:
        """
        Returns the filenames of entries in the database that refer to
        administrative values used by objects to track and coordinate
        themselves internally.
        """
        return {self._ROOT_SALT_LEDGERNAME, self._METATAGS_LEDGERNAME}

    @property
    def tags(self) -> t.Set[str]:
        """
        Returns a list of all user-defined names for values stored in
        the database object.
        """
        manifest = self._manifest
        return {
            getattr(manifest, filename)
            for filename in self._maintenance_files.symmetric_difference(
                manifest
            )
        }

    @property
    def filenames(self) -> t.Set[str]:
        """
        Returns a list of all derived filenames of user-defined tags
        stored in the database object.
        """
        manifest = self._manifest.namespace
        return {
            filename
            for filename in self._maintenance_files.symmetric_difference(
                manifest
            )
        }

    @property
    def metatags(self) -> t.Set[str]:
        """
        Returns the list of metatags that a database contains.
        """
        return set(
            self._manifest.namespace.get(self._METATAGS_LEDGERNAME, [])
        )

    @property
    def _root_salt_path(self) -> Path:
        """
        Returns the path of the database's root salt file if the
        instance is not a metatag.
        """
        if not self._is_metatag:
            return self.path / self._root_salt_filename

    def _open_manifest(self) -> t.JSONObject:
        """
        Loads an existing manifest file ledger from the filesystem.
        """
        ciphertext = self.IO.read(path=self._root_path)
        aad = DBDomains.MANIFEST
        key = self.__root_kdf.aead_key
        return json_decrypt(ciphertext, key=key, aad=aad)

    def _load_root_salt(self) -> bytes:
        """
        Pulls the root salt from the filesystem for a database instance,
        or retrieves it from the manifest file if the database is a
        metatag. Returns the result.
        """
        if self._is_metatag:
            salt = self._manifest[self._ROOT_SALT_LEDGERNAME]
        else:
            encrypted_salt = self.IO.read(path=self._root_salt_path)
            aad = DBDomains.ROOT_SALT
            key = self.__root_kdf.aead_key
            salt = json_decrypt(encrypted_salt, key=key, aad=aad)
        return bytes.fromhex(salt)

    def _generate_root_salt(self) -> bytes:
        """
        Returns a 32 byte hex salt for a metatag database, or a 64 byte
        hex salt otherwise.
        """
        if self._is_metatag:
            return generate_salt(size=16)
        else:
            return generate_salt(size=64)

    def _install_root_salt(self, salt: bytes) -> None:
        """
        Gives the manifest knowledge of the database's root ``salt``.
        This salt is the source of entropy for the database that is not
        derived from the user's key that opens the database. This salt
        is saved in the manifest if the database is a metatag, or the
        salt is saved in its own file if the database is a main parent
        database.
        """
        if self._is_metatag:
            self._manifest[self._ROOT_SALT_LEDGERNAME] = salt.hex()
        else:
            self._manifest[self._ROOT_SALT_LEDGERNAME] = 0

    def _generate_salted_root_kdf(self) -> DBKDF:
        """
        Returns a key that is derived from the database's main key &
        the root salt's entropy.
        """
        kdf = self.__root_kdf.copy()
        kdf.update_key(self.__root_salt)
        return kdf

    def _generate_salted_user_kdf(self) -> DBKDF:
        """
        Create a KDF object accessible by the user, which is intended to
        safely simplify their work of doing custom cryptographic
        procedures.
        """
        kdf = self.__kdf.copy()
        kdf.update_key(kdf._key + Domains.USER)
        kdf.update(kdf._key, Domains.USER)
        return kdf

    def _load_manifest(self) -> None:
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """
        if self._root_path.exists():
            self._manifest = Namespace(self._open_manifest())
            self.__root_salt = self._load_root_salt()
        else:
            self._manifest = Namespace()
            self.__root_salt = self._generate_root_salt()
            self._install_root_salt(self.__root_salt)

        self.__kdf = self._generate_salted_root_kdf()
        self.kdf = self._generate_salted_user_kdf()

    def _initialize_metatags(self) -> None:
        """
        Initializes the values that organize database metatags, which
        are independent offspring of databases that are accessible by
        their parent.
        """
        if not self.metatags:
            self._manifest[self._METATAGS_LEDGERNAME] = []

    def load_tags(self, *, silent: bool = False) -> "self":
        """
        Specifically loads all of the database's tag values into the
        cache.
        """
        for tag in self.tags:
            self.query_tag(tag, silent=silent, cache=True)
        return self

    def load_metatags(
        self, *, preload: bool = True, silent: bool = False
    ) -> "self":
        """
        Specifically loads all of the database's metatag values into the
        cache. If the ``preload`` keyword argument is falsey then the
        metatag references are populated in the database's instance
        dictionary, but their internal values are not loaded.
        """
        for metatag in set(self.metatags):
            self.metatag(metatag, preload=preload, silent=silent)
        return self

    def load_database(
        self,
        *,
        silent: bool = False,
        manifest: bool = False,
        preload: bool = True,
    ) -> "self":
        """
        Does initial loading of the database. If ``manifest`` is `True`,
        then the instance's manifest is reloaded from disk & unsaved
        changes to the manifest are discarded. If ``preload`` is `True`,
        then the value of all the database's tags, & the value of all of
        its metatag's tags, are cached from the filesystem & unsaved
        changes are discarded. This enables up-to-date bracket lookup of
        tag values without needing to call the `query_tag` method,
        but could be quite costly in terms of memory if databases &
        thier metatags contain large amounts of data.
        """
        if manifest:
            self._load_manifest()
        if preload:
            self.load_tags(silent=silent)
        self.load_metatags(preload=preload, silent=silent)
        return self

    @lru_cache(maxsize=256)
    def filename(self, tag: str) -> str:
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        key = self.__kdf.prf_key
        context = DBDomains.FILENAME + tag.encode()
        filename = hmac.new(key, context, sha3_256).digest()
        return self._encode_filename(filename[FILENAME_HASH_SLICE])

    def make_hmac(
        self, *data: t.Iterable[bytes], aad: bytes = DEFAULT_AAD
    ) -> bytes:
        """
        Derives an HMAC hash of the supplied ``data`` with a unique
        permutation of the database's keys & a domain-specific kdf key.
        """
        if not data:
            raise Issue.no_value_specified("data")
        key = self.__kdf.auth_key + aad
        context = canonical_pack(DBDomains.HMAC, aad, *data)
        return hmac.new(key, context, sha3_256).digest()

    def test_hmac(
        self,
        untrusted_hmac: bytes,
        *data: t.Iterable[bytes],
        aad: bytes = DEFAULT_AAD,
    ) -> None:
        """
        Tests if the ``untrusted_hmac`` of ``data`` is valid using the
        instance's keys & a timing-safe comparison.
        """
        if not untrusted_hmac:
            raise Issue.no_value_specified("untrusted_hmac")
        true_hmac = self.make_hmac(*data, aad=aad)
        if not bytes_are_equal(untrusted_hmac, true_hmac):
            raise DatabaseIssue.invalid_hmac()

    def bytes_encrypt(
        self,
        plaintext: bytes,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the ``plaintext`` bytes with keys specific to the
        ``filename`` value & returns the ciphertext bytes.
        """
        key = self.__kdf.aead_key
        aad = canonical_pack(DBDomains.FILE_KEY, filename.encode(), aad)
        return bytes_encrypt(plaintext, key, aad=aad)

    def json_encrypt(
        self,
        plaintext: t.JSONSerializable,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the JSON serializable ``plaintext`` object with keys
        specific to the ``filename`` value & returns the ciphertext
        bytes.
        """
        key = self.__kdf.aead_key
        aad = canonical_pack(DBDomains.FILE_KEY, filename.encode(), aad)
        return json_encrypt(plaintext, key, aad=aad)

    def make_token(
        self,
        plaintext: bytes,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the ``plaintext`` bytes with keys specific to the
        ``filename`` value & urlsafe base64 encodes the resulting
        ciphertext bytes.
        """
        key = self.__kdf.aead_key
        aad = canonical_pack(DBDomains.FILE_KEY, filename.encode(), aad)
        return Chunky2048(key).make_token(plaintext, aad=aad)

    def bytes_decrypt(
        self,
        ciphertext: bytes,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
    ) -> bytes:
        """
        Decrypts the ``ciphertext`` bytes with keys specific to the
        ``filename`` value & returns the plaintext bytes. ``ttl`` is the
        amount of seconds that dictate the allowable age of the
        decrypted message.
        """
        key = self.__kdf.aead_key
        aad = canonical_pack(DBDomains.FILE_KEY, filename.encode(), aad)
        return bytes_decrypt(ciphertext, key, aad=aad, ttl=ttl)

    def json_decrypt(
        self,
        ciphertext: bytes,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
    ) -> t.Union[bytes, t.JSONSerializable]:
        """
        Decrypts the ``ciphertext`` bytes with keys specific to the
        ``filename`` value & JSON loads the resulting plaintext bytes.
        ``ttl`` is the amount of seconds that dictate the allowable age
        of the decrypted message.
        """
        key = self.__kdf.aead_key
        aad = canonical_pack(DBDomains.FILE_KEY, filename.encode(), aad)
        return json_decrypt(ciphertext, key=key, aad=aad, ttl=ttl)

    def read_token(
        self,
        token: t.Base64URLSafe,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
    ) -> bytes:
        """
        Decrypts the urlsafe base64 encoded ``token`` with keys specific
        to the ``filename`` value & returns the plaintext bytes. ``ttl``
        is the amount of seconds that dictate the allowable age of the
        decrypted message.
        """
        key = self.__kdf.aead_key
        aad = canonical_pack(DBDomains.FILE_KEY, filename.encode(), aad)
        return Chunky2048(key).read_token(token, aad=aad, ttl=ttl)

    def _save_ciphertext(self, filename: str, ciphertext: bytes) -> None:
        """
        Saves the encrypted value ``ciphertext`` in the database file
        called ``filename``.
        """
        path = self.path / filename
        self.IO.write(path=path, data=ciphertext)

    def set_tag(
        self, tag: str, data: t.JSONSerializable, *, cache: bool = True
    ) -> "self":
        """
        Allows users to add the value ``data`` under the name ``tag``
        into the database.
        """
        filename = self.filename(tag)
        setattr(self._cache, filename, data)
        setattr(self._manifest, filename, tag)
        if not cache:
            self.save_tag(tag, drop_cache=True)
        return self

    def _query_ciphertext(
        self, filename: str, *, silent: bool = False
    ) -> None:
        """
        Retrieves the value stored in the database which has the given
        ``filename``.
        """
        try:
            path = self.path / filename
            return self.IO.read(path=path)
        except FileNotFoundError as corrupt_database:
            self._corrupted_files[filename] = True
            if not silent:
                raise DatabaseIssue.file_not_found(filename)

    def query_tag(
        self,
        tag: str,
        *,
        ttl: int = DEFAULT_TTL,
        silent: bool = False,
        cache: bool = False,
    ) -> t.Union[bytes, t.JSONSerializable]:
        """
        Allows users to retrieve the value stored under the name ``tag``
        from the database.
        """
        filename = self.filename(tag)
        if filename in self._cache:
            return getattr(self._cache, filename)
        ciphertext = self._query_ciphertext(filename, silent=silent)
        if not ciphertext:
            return

        result = self.bytes_decrypt(ciphertext, filename=filename, ttl=ttl)
        if result[:BYTES_FLAG_SIZE] == BYTES_FLAG:
            result = result[BYTES_FLAG_SIZE:]  # Remove bytes value flag
        else:
            result = json.loads(result)
        if cache:
            setattr(self._cache, filename, result)
        return result

    def _delete_file(self, filename: str, *, silent=False) -> None:
        """
        Deletes a file in the database directory by ``filename``.
        """
        try:
            (self.path / filename).unlink()
        except FileNotFoundError as error:
            if not silent:
                raise error from None

    def pop_tag(
        self, tag: str, *, admin: bool = False, silent: bool = False
    ) -> t.Union[bytes, t.JSONSerializable]:
        """
        Returns a value from the database by it's ``tag`` & deletes the
        associated file in the database directory.
        """
        failures = False
        filename = self.filename(tag)
        if filename in self._maintenance_files and not admin:
            raise DatabaseIssue.cant_delete_maintenance_files()
        try:
            value = self.query_tag(tag, cache=False)
        except FileNotFoundError as error:
            value = None
            failures = True
        try:
            del self._manifest[filename]
        except (KeyError, AttributeError):
            failures = True
        try:
            del self._cache[filename]
        except (KeyError, AttributeError):
            pass
        try:
            self._delete_file(filename)
        except FileNotFoundError as error:
            pass
        if failures and not silent:
            raise DatabaseIssue.tag_file_doesnt_exist(tag)
        return value

    def rollback_tag(self, tag: str, *, cache: bool = False) -> "self":
        """
        Clears the new ``tag`` data from the cache which undoes any
        recent changes. If the ``tag`` data was never saved to disk,
        then removing it from the cache will prevent it from being
        saved in the database.
        """
        filename = self.filename(tag)
        file_exists = (self.path / filename).is_file()
        tag_is_stored = filename in self._manifest
        if tag_is_stored and not file_exists:
            delattr(self._manifest, filename)
        elif not tag_is_stored and not file_exists:
            raise DatabaseIssue.tag_file_doesnt_exist(tag)
        if filename in self._cache:
            delattr(self._cache, filename)
            self.query_tag(tag, cache=True) if cache else 0
        return self

    def clear_cache(self, *, metatags: bool = True) -> "self":
        """
        Clears all recent changes in the cache. By default ``metatags``
        is truthy, which clears a database's metatag caches.
        """
        self._cache.namespace.clear()
        if metatags:
            for metatag in self.metatags:
                getattr(self, metatag).clear_cache(metatags=metatags)
        return self

    def _metatag_key(self, tag: str) -> bytes:
        """
        Derives the metatag's database key given a user-defined ``tag``.
        """
        context = DBDomains.METATAG_KEY + tag.encode()
        return self.__kdf.shake_256(DBKDF._key_size, context=context)

    def metatag(
        self, tag: str, *, preload: bool = False, silent: bool = False
    ) -> "cls":
        """
        Allows a user to create offspring of a database instance to
        organize data by a name ``tag`` & domain separate cryptographic
        material. These descendants are accessible by dotted lookup from
        the parent database. Descendants are also synchronized by their
        parents automatically.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        # Create a parent database ->
        key = aiootp.csprng()
        parent = Database(key)

        # Name the descendant database ->
        tag = "sub_database"
        offspring = await parent.ametatag(tag)

        # It is now accessible from the parent by the tag ->
        assert offspring == parent.sub_database
        """
        if tag in self.__class__.__dict__:
            raise Issue.cant_overwrite_existing_attribute(tag)
        elif tag in self.__dict__:
            if issubclass(self.__dict__[tag].__class__, self.__class__):
                return self.__dict__[tag]
            else:
                raise Issue.cant_overwrite_existing_attribute(tag)
        self.__dict__[tag] = self.__class__(
            key=self._metatag_key(tag),
            preload=preload,
            path=self.path,
            metatag=True,
            silent=silent,
        )
        if tag not in self.metatags:
            getattr(self._manifest, self._METATAGS_LEDGERNAME).append(tag)
        return self.__dict__[tag]

    def delete_metatag(self, tag: str) -> "self":
        """
        Removes the descendant database named ``tag``.
        """
        if tag not in self.metatags:
            raise DatabaseIssue.no_existing_metatag(tag)
        self.metatag(tag).delete_database()
        self.__dict__.pop(tag)
        self.metatags.remove(tag)
        return self

    def _nullify(self) -> None:
        """
        Clears the database's memory caches & instance variables of all
        values so a deleted database no longer makes changes to the
        filesystem.
        """
        self._manifest.namespace.clear()
        self._cache.namespace.clear()
        self.__dict__.clear()

    def delete_database(self) -> None:
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        for metatag in self.metatags:
            self.metatag(metatag, preload=False).delete_database()
        for filename in self._manifest.namespace:
            self._delete_file(filename, silent=True)
        self._delete_file(self._root_salt_filename, silent=True)
        self._delete_file(self._root_filename, silent=True)
        if getattr(self, "_profile_tokens", None):
            salt_path = self._profile_tokens._salt_path
            if salt_path.is_file():
                delete_salt_file(salt_path)
        self._nullify()

    def _encrypt_manifest(self) -> bytes:
        """
        Takes a ``salt`` & returns the database's manifest encrypted.
        """
        manifest = self._manifest.namespace
        aad = DBDomains.MANIFEST
        key = self.__root_kdf.aead_key
        return json_encrypt(manifest, key=key, aad=aad)

    def _save_manifest(self, ciphertext: bytes) -> None:
        """
        Writes the manifest ledger to disk. It contains all database
        filenames & special cryptographic values for initializing the
        database's key derivation functions.
        """
        if not ciphertext:
            raise DatabaseIssue.invalid_write_attempt()
        self.IO.write(path=self._root_path, data=ciphertext)

    def _save_root_salt(self, salt: bytes) -> None:
        """
        Writes a non-metatag database instance's root salt to disk as a
        separate file.
        """
        aad = DBDomains.ROOT_SALT
        key = self.__root_kdf.aead_key
        self.IO.write(
            path=self._root_salt_path,
            data=json_encrypt(salt.hex(), key=key, aad=aad),
        )

    def _close_manifest(self) -> None:
        """
        Prepares for & writes the manifest ledger to disk. The manifest
        contains all database filenames & other metadata used to
        organize databases.
        """
        if not self._is_metatag:
            self._save_root_salt(self.__root_salt)
        manifest = self._encrypt_manifest()
        self._save_manifest(manifest)

    def _save_file(self, filename: str, *, admin: bool = False) -> None:
        """
        Writes the cached value for a user-specified ``filename`` to the
        user filesystem.
        """
        value = getattr(self._cache, filename)
        if value.__class__ is bytes:
            value = BYTES_FLAG + value  # Assure not reloaded as JSON
        else:
            value = json.dumps(value).encode()
        ciphertext = self.bytes_encrypt(value, filename=filename)
        self._save_ciphertext(filename, ciphertext)

    def _save_tags(self) -> None:
        """
        Writes the database's user-defined tags to disk.
        """
        save = self._save_file
        for filename in self._cache.namespace:
            save(filename)

    def _save_metatags(self) -> None:
        """
        Writes the database's descendant databases to disk.
        """
        for metatag in self.metatags:
            getattr(self, metatag).save_database()

    def save_tag(
        self, tag: str, *, admin: bool = False, drop_cache: bool = False
    ) -> "self":
        """
        Writes the cached value for a user-specified ``tag`` to the user
        filesystem.
        """
        filename = self.filename(tag)
        try:
            self._save_file(filename, admin=admin)
        except AttributeError:
            raise DatabaseIssue.tag_file_doesnt_exist(tag)
        finally:
            if drop_cache and hasattr(self._cache, filename):
                delattr(self._cache, filename)
        return self

    def save_database(self) -> "self":
        """
        Writes the database's values to disk with transparent encryption.
        """
        self._close_manifest()
        self._save_metatags()
        self._save_tags()
        return self

    def mirror_database(self, database) -> "self":
        """
        Copies over all of the stored & loaded values, tags & metatags
        from the ``database`` object passed into this function.
        """
        if issubclass(database.__class__, self.__class__):
            for tag, value in database:
                self.set_tag(tag, value)
        else:
            # Works with async databases, but doesn't load unloaded values
            for tag in database.tags:
                self.set_tag(tag, database[tag])
        for metatag in set(database.metatags):
            my_metatag = self.metatag(metatag)
            my_metatag.mirror_database(database.__dict__[metatag])
        return self

    def __contains__(self, tag: str) -> bool:
        """
        Checks the cache & manifest for the filename associated with the
        user-defined ``tag``.
        """
        filename = self.filename(tag)
        return filename in self._manifest or filename in self._cache

    def __bool__(self) -> bool:
        """
        Returns True if the instance dictionary is populated or the
        manifast is saved to the filesystem.
        """
        return bool(self.__dict__)

    def __enter__(self) -> "self":
        """
        The context manager automatically writes database changes made
        by a user to disk.
        """
        return self

    def __exit__(
        self, exc_type=None, exc_value=None, traceback=None
    ) -> None:
        """
        The context manager automatically writes database changes made
        by a user to disk.
        """
        self.save_database()

    def __iter__(self) -> t.Generator[
        None, t.Tuple[str, t.Union[bytes, t.JSONSerializable]], None
    ]:
        """
        Provides an interface to the names & values stored in databases.
        """
        silent = self._silent
        for tag in self.tags:
            yield tag, self.query_tag(tag, silent=silent, cache=False)

    def __getitem__(self, tag: str) -> t.Union[bytes, t.JSONSerializable]:
        """
        Allows users to retrieve the value stored under the name ``tag``
        from the database cache.
        """
        filename = self.filename(tag)
        if filename in self._cache:
            return getattr(self._cache, filename)

    __delitem__ = pop_tag
    __setitem__ = vars()["set_tag"]
    __len__ = lambda self: (
        len(self._manifest) - len(self._maintenance_files)
    )


extras = dict(
    AsyncDatabase=AsyncDatabase,
    Database=Database,
    __doc__=__doc__,
    __package__=__package__,
)


databases = make_module("databases", mapping=extras)

