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


__all__ = ["DatabaseProperties"]


__doc__ = (
    "A definition of properties shared between `AsyncDatabase` & "
    "`Database`."
)


from aiootp._typing import Typing as t
from aiootp._constants import FILENAME_HASH_BYTES
from aiootp._exceptions import InvalidSHMAC, Ignore, TimestampExpired
from aiootp._paths import DatabasePath
from aiootp.generics import ByteIO
from aiootp.ciphers import Chunky2048, Slick256

from .dbdomains import DBDomains
from .dbkdf import DBKDF


class DatabaseProperties:
    """
    A definition of properties shared between `AsyncDatabase` & `Database`.
    """

    __slots__ = (
        "__dict__",
        "_cache",
        "_is_metatag",
        "_manifest",
        "_profile_tokens",
        "_root_kdf",
        "_root_salt",
        "_silent",
        "path",
    )

    IO = ByteIO
    InvalidSHMAC = InvalidSHMAC
    TimestampExpired = TimestampExpired

    _Cipher: type = Chunky2048
    _DBDomains: type = DBDomains
    _DBKDF: type = DBKDF
    _ProfileTokens: type
    _TokenCipher: type = Slick256

    _ROOT_SALT_BYTES: int = 24
    _ROOT_SALT_LEDGERNAME: str = "0"
    _METATAGS_LEDGERNAME: str = "1"

    _path: t.Path = DatabasePath()

    @classmethod
    def _encode_filename(cls, value: bytes) -> str:
        """
        Returns the received bytes-type `value` in base38 encoding.
        """
        return cls.IO.bytes_to_filename(value)

    @property
    def _root_filename(self) -> str:
        """
        Returns the filename string of database's manifest.
        """
        return self._encode_filename(
            self._root_kdf.shake_128(
                size=FILENAME_HASH_BYTES, aad=self._DBDomains.ROOT_FILENAME
            )
        )

    @property
    def _root_path(self) -> t.Path:
        """
        Returns a `pathlib.Path` object that points to the file that
        contains the manifest ledger.
        """
        return self.path / self._root_filename

    @property
    def _maintenance_records(self) -> t.Set[str]:
        """
        Returns the ledgernames of entries in the manifest that refer to
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
            for filename in self._maintenance_records.symmetric_difference(
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
            for filename in self._maintenance_records.symmetric_difference(
                self._manifest.__dict__
            )
        }

    @property
    def metatags(self) -> t.Set[str]:
        """
        Returns the list of metatags that a database contains.
        """
        return set(
            self._manifest.__dict__.get(self._METATAGS_LEDGERNAME, ())
        )

    def _filename(self, tag: str) -> str:
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

    def __contains__(self, tag: str) -> bool:
        """
        Checks the cache & manifest for the filename associated with the
        user-defined `tag`.
        """
        filename = self._filename(tag)
        return filename in self._manifest or filename in self._cache

    def __bool__(self) -> bool:
        """
        Returns `True` if the instance has any tags or metatags set.
        """
        return bool(
            (len(self) > 0) or self._manifest[self._METATAGS_LEDGERNAME]
        )

    def __setitem__(self, tag: str, data: t.JSONSerializable) -> None:
        """
        Allows users to add the value `data` under the name `tag`
        into the database.
        """
        filename = self._filename(tag)
        setattr(self._cache, filename, data)
        setattr(self._manifest, filename, tag)

    def __getitem__(self, tag: str) -> t.Union[bytes, t.JSONSerializable]:
        """
        Allows users to retrieve the value stored under the name `tag`
        from the database cache.
        """
        filename = self._filename(tag)
        if filename in self._cache:
            return getattr(self._cache, filename)

    def __delitem__(self, tag: str) -> None:
        """
        Allows users to delete the value stored under the name `tag`
        from the database.
        """
        filename = self._filename(tag)
        with Ignore(KeyError, AttributeError):
            del self._manifest[filename]
        with Ignore(KeyError, AttributeError):
            del self._cache[filename]
        with Ignore(FileNotFoundError):
            (self.path / filename).unlink()

    __len__ = lambda self: (
        len(self._manifest) - len(self._maintenance_records)
    )


module_api = dict(
    DatabaseProperties=t.add_type(DatabaseProperties),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

