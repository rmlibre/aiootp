# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2026 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


"""
Implements a synchronous transparently encrypted database.
"""

__all__ = ["Database"]


import json

from io import BytesIO

from aiootp._typing import Typing as t
from aiootp._constants import DEFAULT_AAD, DEFAULT_TTL
from aiootp._constants import BYTES_FLAG, BYTES_FLAG_SIZE
from aiootp._exceptions import DatabaseIssue, Issue, Ignore
from aiootp._paths import delete_salt_file
from aiootp.commons import Namespace
from aiootp.keygens.passcrypt.config import passcrypt_spec

from .profile_tokens import ProfileTokens
from .db_properties import DatabaseProperties


class Database(DatabaseProperties):
    """
    Creates databases which enable the disk persistence of any bytes or
    JSON serializable native python data-types, with fully transparent
    encryption / decryption.

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

    # Create descendant databases using what are called metatags ->
    taxes = db.metatag("taxes")
    taxes[2020] = {"jan": 130.25, "feb": 163.23, "mar": 149.68}
    assert taxes == db.taxes
    assert taxes[2020] == db.taxes[2020]

    # Delete a descendant database ->
    db.delete_metatag("taxes")

    # Or,

    # Purge the filesystem of all parent & descendant files ->
    db.delete_database()
    """

    __slots__ = ("_profile_tokens",)

    _ProfileTokens: type = ProfileTokens

    slots_types = dict(_profile_tokens=_ProfileTokens)

    @classmethod
    def generate_profile(
        cls,
        /,
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
        path: t.PathStr | None = None,
        preload: bool = False,
    ) -> t.Cls:
        """
        Creates & loads a profile database for a user from the tokens
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
        profile_db._profile_tokens = tokens.cleanup()
        return profile_db

    def __init__(
        self,
        /,
        key: bytes,
        *,
        preload: bool = False,
        path: t.PathStr | None = None,
        metatag: bool = False,
        silent: bool = True,
    ) -> None:
        """
        Sets a database object's basic cryptographic values derived from
        a `key` & opens up the associated administrative files. The
        `generate_profile` method would be a safer choice for opening a
        database if using a passphrase instead of a cryptographic key.

        `preload`: This boolean value tells the object to -- True --
            load all of the stored database values from the filesystem
            into the cache during initialization, or -- False -- skip
            the loading stage. This trades-off between RAM & latency.

        `path`: This value is the string or `Pathlib.Path` object that
            points to the filesystem location where the database files
            reside / will be saved. By default, stores values in the
            directory "db" relative to the package source code.

        `metatag`: This boolean value tells the class whether to
            prepare itself as a sub-database or not. This signals the
            possibility of distinct internal implementation differences.

        `silent`: This boolean value tells the class to surpress
            exceptions when loading files so that errors in the database
            don't prevent a user from logging in.
        """
        self._silent = silent
        self._cache = Namespace()
        self._manifest = Namespace()
        self._is_metatag = bool(metatag)
        self.io = self._IO(path)
        self.crypto = self._Crypto(key=key)
        self._load_manifest()
        self.load_database(silent=silent, preload=preload)

    def _open_manifest(self, /) -> t.JSONObject:
        """
        Loads an existing manifest file ledger from the filesystem.
        """
        ciphertext = self.io.read(path=self._root_path)
        return self.crypto._decrypt_manifest(ciphertext)

    def _load_root_salt(self, /) -> bytes:
        """
        Returns the decoded raw bytes root salt from the manifest.
        """
        return self.io.urlsafe_to_bytes(
            self._manifest[self._ROOT_SALT_LEDGERNAME],
        )

    def _install_root_salt(self, /, salt: bytes) -> None:
        """
        Stores in the manifest, with a URL-safe base64 encoding, the
        `salt` value as its root salt. This the source of entropy for
        the database which isn't derived from the user's login key.
        """
        self._manifest[self._ROOT_SALT_LEDGERNAME] = (
            self.io.bytes_to_urlsafe(salt).decode()
        )

    def _initialize_metatags(self, /) -> None:
        """
        Initializes the values that organize database metatags, which
        are independent offspring of databases that are accessible by
        their parent.
        """
        if self._METATAGS_LEDGERNAME not in self._manifest:
            self._manifest[self._METATAGS_LEDGERNAME] = []

    def _load_manifest(self, /) -> None:
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """
        if self._root_path.exists():
            self._manifest = Namespace(self._open_manifest())
            root_salt = self._load_root_salt()
        else:
            self._manifest = Namespace()
            root_salt = self.crypto._generate_root_salt()
            self._install_root_salt(root_salt)

        self.crypto._set_root_salt(root_salt)
        self._initialize_metatags()

    def load_tags(self, /, *, silent: bool = False) -> t.Self:
        """
        Specifically loads all of the database's tag values into the
        cache.
        """
        for tag in self.tags:
            self.query_tag(tag, silent=silent, cache=True)
        return self

    def load_metatags(
        self,
        /,
        *,
        preload: bool = True,
        silent: bool = False,
    ) -> t.Self:
        """
        Specifically loads all of the database's metatag values into the
        cache. If the `preload` keyword argument is falsey then the
        metatag references are populated in the database's instance
        dictionary, but their internal values are not loaded.
        """
        for metatag in self.metatags:
            self.metatag(metatag, preload=preload, silent=silent)
        return self

    def load_database(
        self,
        /,
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

    def filename(self, /, tag: str) -> str:
        """
        Derives the filename hash given a user-defined `tag`.
        """
        filename_hash = self.crypto._filename_hash(tag)
        return self.io.bytes_to_filename(filename_hash)

    def set_tag(
        self,
        /,
        tag: str,
        data: t.JSONSerializable,
        *,
        cache: bool = True,
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
        self,
        /,
        filename: str,
        *,
        silent: bool = False,
    ) -> bytes | None:
        """
        Retrieves the value stored in the database which has the given
        `filename`.
        """
        try:
            path = self.io.path / filename
            return self.io.read(path=path)
        except FileNotFoundError as error:
            if not silent:
                raise DatabaseIssue.file_not_found(filename) from error

    def query_tag(
        self,
        /,
        tag: str,
        *,
        ttl: int | None = DEFAULT_TTL,
        silent: bool = False,
        cache: bool = False,
    ) -> t.JSONSerializable | bytes:
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

        reader = BytesIO(
            self.crypto.bytes_decrypt(
                ciphertext,
                filename=filename,
                ttl=ttl,
            ),
        )
        if reader.read(BYTES_FLAG_SIZE) == BYTES_FLAG:
            result = reader.read()  # Remove bytes value flag
        else:
            reader.seek(0)
            result = json.loads(reader.read())
        if cache:
            setattr(self._cache, filename, result)
        return result

    def _delete_file(
        self,
        /,
        filename: str,
        *,
        silent: bool = False,
    ) -> None:
        """
        Deletes a file in the database directory by `filename`.
        """
        try:
            (self.io.path / filename).unlink()
        except FileNotFoundError as error:
            if not silent:
                raise error from None

    def pop_tag(
        self,
        /,
        tag: str,
        *,
        silent: bool = False,
    ) -> t.JSONSerializable | bytes:
        """
        Returns a value from the database by it's `tag` & deletes the
        associated file in the database directory.
        """

        def track_failure(relay: Ignore) -> bool:
            return failures.append(relay.error) or True

        failures = []
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

    def rollback_tag(self, /, tag: str, *, cache: bool = False) -> t.Self:
        """
        Clears the new `tag` data from the cache which undoes any
        recent changes. If the `tag` data was never saved to disk,
        then removing it from the cache will prevent it from being
        saved in the database.
        """
        filename = self.filename(tag)
        if not (self.io.path / filename).is_file():
            with Ignore(AttributeError):
                delattr(self._manifest, filename)
        with Ignore(AttributeError):
            delattr(self._cache, filename)
        with Ignore(LookupError):
            cache and self.query_tag(tag, cache=True)
        return self

    def clear_cache(self, /, *, metatags: bool = True) -> t.Self:
        """
        Clears all recent changes in the cache. By default `metatags`
        is truthy, which clears a database's metatag caches.
        """
        self._cache.clear()
        if metatags:
            for metatag in self.metatags:
                getattr(self, metatag).clear_cache(metatags=metatags)
        return self

    def metatag(
        self,
        /,
        tag: str,
        *,
        preload: bool = False,
        silent: bool = False,
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
        cls = self.__class__
        if hasattr(self, tag):
            tag_cls = getattr(self, tag).__class__
            if hasattr(cls, tag) or not issubclass(tag_cls, cls):
                raise Issue.cant_reassign_attribute(tag)  # fixed v0.23.9
        else:
            sub_database = cls(
                key=self.crypto._metatag_key(tag),
                preload=preload,
                path=self.io.path,
                metatag=True,
                silent=silent,
            )
            setattr(self, tag, sub_database)
        if tag not in self.metatags:
            self._manifest[self._METATAGS_LEDGERNAME].append(tag)
        return getattr(self, tag)

    def delete_metatag(self, /, tag: str) -> t.Self:
        """
        Removes the descendant database named `tag`.
        """
        if tag not in self.metatags:
            raise DatabaseIssue.no_existing_metatag(tag)
        self.metatag(tag).delete_database()
        delattr(self, tag)
        self._manifest[self._METATAGS_LEDGERNAME].remove(tag)
        return self

    def _nullify(self, /) -> None:
        """
        Clears the database's memory caches & instance variables of all
        values so a deleted database no longer makes changes to the
        filesystem.
        """
        self._manifest.clear()
        self._cache.clear()
        self.__dict__.clear()
        for base in self.__class__.__mro__:
            for attr in getattr(base, "__slots__", ()):
                if hasattr(self, attr):
                    delattr(self, attr)

    def _delete_profile_tokens(self, /) -> None:
        """
        Deletes the salt file that what created if this instance was
        initialized with the `generate_profile` classmethod.
        """
        if getattr(self, "_profile_tokens", None):
            salt_path = self._profile_tokens._salt_path
            if salt_path.is_file():
                delete_salt_file(salt_path)

    def delete_database(self, /) -> None:
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        for metatag in self.metatags:
            self.metatag(metatag, preload=False).delete_database()
        for filename in self._manifest:
            self._delete_file(filename, silent=True)
        self._delete_file(self._root_filename, silent=True)
        self._delete_profile_tokens()
        self._nullify()

    def _close_manifest(self, /) -> None:
        """
        Prepares for & writes the manifest ledger to disk. The manifest
        contains all database filenames & other metadata used to
        organize databases.
        """
        manifest = self._manifest.__dict__
        ciphertext = self.crypto._encrypt_manifest(manifest)
        self.io.write(path=self._root_path, data=ciphertext)

    def _save_file(self, /, filename: str, *, admin: bool = False) -> None:
        """
        Writes the cached value for a user-specified `filename` to the
        user filesystem.
        """
        file_path = self.io.path / filename
        value = getattr(self._cache, filename)
        if value.__class__ is bytes:
            value = BYTES_FLAG + value  # Assure not reloaded as JSON
        else:
            value = json.dumps(value).encode()

        ciphertext = self.crypto.bytes_encrypt(value, filename=filename)
        self.io.write(path=file_path, data=ciphertext)

    def _save_tags(self, /) -> None:
        """
        Writes the database's user-defined tags to disk.
        """
        save = self._save_file
        for filename in self._cache:
            save(filename)

    def _save_metatags(self, /) -> None:
        """
        Writes the database's descendant databases to disk.
        """
        for metatag in self.metatags:
            getattr(self, metatag).save_database()

    def save_tag(
        self,
        /,
        tag: str,
        *,
        admin: bool = False,
        drop_cache: bool = False,
    ) -> t.Self:
        """
        Writes the cached value for a user-specified `tag` to the user
        filesystem.
        """
        filename = self.filename(tag)
        try:
            self._save_file(filename, admin=admin)
        except AttributeError as error:
            raise DatabaseIssue.tag_file_doesnt_exist(tag) from error
        finally:
            if drop_cache and hasattr(self._cache, filename):
                delattr(self._cache, filename)
        return self

    def save_database(self, /) -> t.Self:
        """
        Writes the database's values to disk with transparent encryption.
        """
        self._close_manifest()
        self._save_metatags()
        self._save_tags()
        return self

    def __enter__(self, /) -> t.Self:
        """
        The context manager automatically writes database changes made
        by a user to disk.
        """
        return self

    def __exit__(
        self,
        /,
        exc_type: type | None = None,
        exc_value: Exception | None = None,
        traceback: t.TracebackType | None = None,
    ) -> bool:
        """
        The context manager automatically writes database changes made
        by a user to disk.
        """
        self.save_database()
        return exc_type is None


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
