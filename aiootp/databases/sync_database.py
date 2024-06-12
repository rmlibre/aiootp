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


__all__ = ["Database"]


__doc__ = "Implements a synchronous transparently encrypted database."


import json

from aiootp._typing import Typing as t
from aiootp._constants import DEFAULT_AAD, DEFAULT_TTL, MIN_KEY_BYTES
from aiootp._constants import BIG, BYTES_FLAG, BYTES_FLAG_SIZE
from aiootp._constants import FILENAME_HASH_BYTES, SHAKE_128_BLOCKSIZE
from aiootp._exceptions import DatabaseIssue, Ignore
from aiootp._paths import delete_salt_file
from aiootp.commons import Namespace
from aiootp.randoms import token_bytes
from aiootp.keygens.passcrypt.config import passcrypt_spec

from .profile_tokens import ProfileTokens
from .database_properties import DatabaseProperties


class Database(DatabaseProperties):
    """
    This class creates databases which enable the disk persistence of
    any bytes or JSON serializable native python data-types, with fully
    transparent encryption / decryption.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    key = aiootp.csprng()
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

    __slots__ = ()

    _ProfileTokens: type = ProfileTokens

    @classmethod
    def generate_profile(
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

        db = aiootp.Database.generate_profile(
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
        tokens = ProfileTokens().generate(
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
        profile_db = cls(key=tokens.login_key, path=path, preload=preload)
        if not profile_db._root_path.is_file():
            profile_db.save_database()
        profile_db._profile_tokens = tokens
        tokens.cleanup()
        return profile_db

    def __init__(
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

        `preload`: This boolean value tells the object to -- True --
            load all of the stored database values from the filesystem
            into the cache during initialization, or -- False -- skip
            the loading stage. This can save time up front so users can
            pay the cost of loading data only when that value is needed.

        `path`: This value is the string or `Pathlib.Path`
            object that points to the filesystem location where the
            database files reside / will be saved. By default, stores
            values in the directory "databases" relative to the package
            source code.

        `metatag`: This boolean value tells the class whether to
            prepare itself as a sub-database or not, which generally
            means less storage overhead used to secure its cryptographic
            material. Parent databases that are not metatags store a
            random salt value in their `self._root_path` file.

        `silent`: This boolean value tells the class to surpress
            exceptions when loading files so that errors in the database
            don't prevent a user from logging in.
        """
        self._silent = silent
        self._cache = Namespace()
        self._manifest = Namespace()
        self.path = self._format_path(path)
        self._is_metatag = True if metatag else False
        self._initialize_keys(key)
        self._load_manifest()
        self._initialize_metatags()
        self.load_database(silent=silent, preload=preload)

    @classmethod
    def _format_path(cls, path: t.PathStr) -> t.Path:
        """
        Returns a `pathlib.Path` object to the user-specified `path`
        if given, else returns a copy of the default database directory
        `Path` object.
        """
        if path is None:
            return t.Path(cls._path).absolute()
        return t.Path(path).absolute()

    def _initialize_keys(self, key: bytes) -> None:
        """
        Derives the database's cryptographic root key material and the
        filename of the manifest ledger.
        """
        self._root_kdf = self._DBKDF(self._DBDomains.ROOT_KDF, key=key)

    def _open_manifest(self) -> t.JSONObject:
        """
        Loads an existing manifest file ledger from the filesystem.
        """
        ciphertext = self.IO.read(path=self._root_path)
        key = self._root_kdf.shake_128(
            aad=self._DBDomains.MANIFEST, size=SHAKE_128_BLOCKSIZE
        )
        return self._Cipher(key).json_decrypt(ciphertext)

    def _load_root_salt(self) -> bytes:
        """
        Returns the decoded raw bytes root salt from the manifest.
        """
        return self.IO.urlsafe_to_bytes(
            self._manifest[self._ROOT_SALT_LEDGERNAME]
        )

    def _generate_root_salt(self) -> bytes:
        """
        Returns a raw bytes random salt with length metadata appended to
        be used as the instance's root salt.
        """
        return token_bytes(self._ROOT_SALT_BYTES)

    def _install_root_salt(self, salt: bytes) -> None:
        """
        Stores in the manifest, with a URL-safe base64 encoding, the
        `salt` value as its root salt. This the source of entropy for
        the database which isn't derived from the user's login key.
        """
        self._manifest[self._ROOT_SALT_LEDGERNAME] = (
            self.IO.bytes_to_urlsafe(salt).decode()
        )

    def _load_manifest(self) -> None:
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """
        if self._root_path.exists():
            self._manifest = Namespace(self._open_manifest())
            self._root_salt = self._load_root_salt()
        else:
            self._manifest = Namespace()
            self._root_salt = self._generate_root_salt()
            self._install_root_salt(self._root_salt)

    def _initialize_metatags(self) -> None:
        """
        Initializes the values that organize database metatags, which
        are independent offspring of databases that are accessible by
        their parent.
        """
        if not self.metatags:
            self._manifest[self._METATAGS_LEDGERNAME] = []

    def load_tags(self, *, silent: bool = False) -> t.Self:
        """
        Specifically loads all of the database's tag values into the
        cache.
        """
        for tag in self.tags:
            self.query_tag(tag, silent=silent, cache=True)
        return self

    def load_metatags(
        self, *, preload: bool = True, silent: bool = False
    ) -> t.Self:
        """
        Specifically loads all of the database's metatag values into the
        cache. If the `preload` keyword argument is falsey then the
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
    ) -> t.Self:
        """
        Does initial loading of the database. If `manifest` is `True`,
        then the instance's manifest is reloaded from disk & unsaved
        changes to the manifest are discarded. If `preload` is `True`,
        then the value of all the database's tags, & the value of all of
        its metatag's tags, are cached from the filesystem & unsaved
        changes are discarded. This enables up-to-date bracket lookup of
        tag values without needing to call the `query_tag` method,
        but could be quite costly in terms of memory if databases &
        their metatags contain large amounts of data.
        """
        if manifest:
            self._load_manifest()
        if preload:
            self.load_tags(silent=silent)
        self.load_metatags(preload=preload, silent=silent)
        return self

    def filename(self, tag: str) -> str:
        """
        Derives the filename hash given a user-defined `tag`.
        """
        filename = self._root_kdf.shake_128(
            self._root_salt,
            tag.encode(),
            aad=self._DBDomains.FILENAME,
            size=FILENAME_HASH_BYTES,
        )
        return self._encode_filename(filename)

    def bytes_encrypt(
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
        key = self._root_kdf.shake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return self._Cipher(key).bytes_encrypt(plaintext)

    def json_encrypt(
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
        key = self._root_kdf.shake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return self._Cipher(key).json_encrypt(plaintext)

    def make_token(
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
        key = self._root_kdf.shake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return self._TokenCipher(key).make_token(plaintext)

    def bytes_decrypt(
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
        key = self._root_kdf.shake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return self._Cipher(key).bytes_decrypt(ciphertext, ttl=ttl)

    def json_decrypt(
        self,
        ciphertext: bytes,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
    ) -> t.Union[bytes, t.JSONSerializable]:
        """
        Decrypts the `ciphertext` bytes with keys specific to the
        `filename` value & JSON loads the resulting plaintext bytes.
        `ttl` is the amount of seconds that dictate the allowable age
        of the decrypted message.
        """
        key = self._root_kdf.shake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return self._Cipher(key).json_decrypt(ciphertext, ttl=ttl)

    def read_token(
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
        key = self._root_kdf.shake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return self._TokenCipher(key).read_token(token, ttl=ttl)

    def _save_ciphertext(self, filename: str, ciphertext: bytes) -> None:
        """
        Saves the encrypted value `ciphertext` in the database file
        called `filename`.
        """
        path = self.path / filename
        self.IO.write(path=path, data=ciphertext)

    def set_tag(
        self, tag: str, data: t.JSONSerializable, *, cache: bool = True
    ) -> t.Self:
        """
        Allows users to add the value `data` under the name `tag`
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
        `filename`.
        """
        try:
            path = self.path / filename
            return self.IO.read(path=path)
        except FileNotFoundError as corrupt_database:
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
        Allows users to retrieve the value stored under the name `tag`
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
        Deletes a file in the database directory by `filename`.
        """
        try:
            (self.path / filename).unlink()
        except FileNotFoundError as error:
            if not silent:
                raise error from None

    def pop_tag(
        self, tag: str, *, silent: bool = False
    ) -> t.Union[bytes, t.JSONSerializable]:
        """
        Returns a value from the database by it's `tag` & deletes the
        associated file in the database directory.
        """
        failures = []
        track_failure = lambda relay: failures.append(relay.error) or True
        filename = self.filename(tag)
        value = self.query_tag(tag, cache=False, silent=True)
        with Ignore(KeyError, AttributeError, if_except=track_failure):
            del self._manifest[filename]
        with Ignore(KeyError, AttributeError, if_except=track_failure):
            del self._cache[filename]
        with Ignore(FileNotFoundError, if_except=track_failure):
            self._delete_file(filename)
        if (not silent) and (len(failures) == 3):
            raise DatabaseIssue.tag_file_doesnt_exist(tag)
        return value

    def rollback_tag(self, tag: str, *, cache: bool = False) -> t.Self:
        """
        Clears the new `tag` data from the cache which undoes any
        recent changes. If the `tag` data was never saved to disk,
        then removing it from the cache will prevent it from being
        saved in the database.
        """
        filename = self.filename(tag)
        if not (self.path / filename).is_file():
            with Ignore(AttributeError):
                delattr(self._manifest, filename)
        with Ignore(AttributeError):
            delattr(self._cache, filename)
        with Ignore(LookupError):
            self.query_tag(tag, cache=True) if cache else 0
        return self

    def clear_cache(self, *, metatags: bool = True) -> t.Self:
        """
        Clears all recent changes in the cache. By default `metatags`
        is truthy, which clears a database's metatag caches.
        """
        self._cache.__dict__.clear()
        if metatags:
            for metatag in self.metatags:
                getattr(self, metatag).clear_cache(metatags=metatags)
        return self

    def _metatag_key(self, tag: str) -> bytes:
        """
        Derives the metatag's database key given a user-defined `tag`.
        """
        return self._root_kdf.sha3_512(
            self._root_salt, tag.encode(), aad=self._DBDomains.METATAG_KEY
        )

    def metatag(
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
        parent = Database(key)

        # Name the descendant database ->
        tag = "sub_database"
        offspring = await parent.ametatag(tag)

        # It is now accessible from the parent by the tag ->
        assert offspring == parent.sub_database
        """
        if hasattr(self, tag):
            if (
                issubclass(getattr(self, tag).__class__, self.__class__)
                and tag not in self.__class__.__dict__
            ):
                return self.__dict__[tag]
            raise Issue.cant_reassign_attribute(tag)
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

    def delete_metatag(self, tag: str) -> t.Self:
        """
        Removes the descendant database named `tag`.
        """
        if tag not in self.metatags:
            raise DatabaseIssue.no_existing_metatag(tag)
        self.metatag(tag).delete_database()
        self.__dict__.pop(tag)
        self._manifest[self._METATAGS_LEDGERNAME].remove(tag)
        return self

    def _nullify(self) -> None:
        """
        Clears the database's memory caches & instance variables of all
        values so a deleted database no longer makes changes to the
        filesystem.
        """
        self._manifest.__dict__.clear()
        self._cache.__dict__.clear()
        self.__dict__.clear()
        for base in self.__class__.__mro__:
            for attr in getattr(base, "__slots__", ()):
                if hasattr(self, attr):
                    delattr(self, attr)

    def _delete_profile_tokens(self) -> None:
        """
        Deletes the salt file that what created if this instance was
        initialized with the `generate_profile` classmethod.
        """
        if getattr(self, "_profile_tokens", None):
            salt_path = self._profile_tokens._salt_path
            if salt_path.is_file():
                delete_salt_file(salt_path)

    def delete_database(self) -> None:
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        for metatag in self.metatags:
            self.metatag(metatag, preload=False).delete_database()
        for filename in self._manifest.__dict__:
            self._delete_file(filename, silent=True)
        self._delete_file(self._root_filename, silent=True)
        self._delete_profile_tokens()
        self._nullify()

    def _encrypt_manifest(self) -> bytes:
        """
        Takes a `salt` & returns the database's manifest encrypted.
        """
        manifest = self._manifest.__dict__
        key = self._root_kdf.shake_128(
            aad=self._DBDomains.MANIFEST, size=SHAKE_128_BLOCKSIZE
        )
        return self._Cipher(key).json_encrypt(manifest)

    def _save_manifest(self, ciphertext: bytes) -> None:
        """
        Writes the manifest ledger to disk. It contains all database
        filenames & special cryptographic values for initializing the
        database's key derivation functions.
        """
        self.IO.write(path=self._root_path, data=ciphertext)

    def _close_manifest(self) -> None:
        """
        Prepares for & writes the manifest ledger to disk. The manifest
        contains all database filenames & other metadata used to
        organize databases.
        """
        manifest = self._encrypt_manifest()
        self._save_manifest(manifest)

    def _save_file(self, filename: str, *, admin: bool = False) -> None:
        """
        Writes the cached value for a user-specified `filename` to the
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
        for filename in self._cache.__dict__:
            save(filename)

    def _save_metatags(self) -> None:
        """
        Writes the database's descendant databases to disk.
        """
        for metatag in self.metatags:
            getattr(self, metatag).save_database()

    def save_tag(
        self, tag: str, *, admin: bool = False, drop_cache: bool = False
    ) -> t.Self:
        """
        Writes the cached value for a user-specified `tag` to the user
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

    def save_database(self) -> t.Self:
        """
        Writes the database's values to disk with transparent encryption.
        """
        self._close_manifest()
        self._save_metatags()
        self._save_tags()
        return self

    def __enter__(self) -> t.Self:
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


module_api = dict(
    Database=t.add_type(Database),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

