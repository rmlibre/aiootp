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
A type to manage common cryptographic database operations.
"""

__all__ = ["DatabaseCrypto"]


from hmac import compare_digest

from aiootp._typing import Typing as t
from aiootp._constants import DEFAULT_AAD, DEFAULT_TTL, SHAKE_128_BLOCKSIZE
from aiootp._constants import FILENAME_HASH_BYTES, MIN_KEY_BYTES
from aiootp._exceptions import Issue, InvalidSHMAC, TimestampExpired
from aiootp.commons import FrozenTypedSlots
from aiootp.randoms import atoken_bytes, token_bytes
from aiootp.ciphers import Chunky2048, Slick256

from .db_domains import DBDomains
from .db_kdf import DBKDF


class DatabaseCrypto(FrozenTypedSlots):
    """
    Manages common cryptographic operations for the `AsyncDatabase` &
    `Database` types.
    """

    __slots__ = ("_root_kdf", "_root_salt")

    _FILENAME_HASH_BYTES: int = FILENAME_HASH_BYTES
    _ROOT_SALT_BYTES: int = 24

    _Cipher: type = Chunky2048
    _DBDomains: type = DBDomains
    _DBKDF: type = DBKDF
    _TokenCipher: type = Slick256

    InvalidSHMAC = InvalidSHMAC
    TimestampExpired = TimestampExpired

    slots_types = dict(_root_kdf=_DBKDF, _root_salt=bytes)

    def __init__(self, /, *, key: bytes) -> None:
        """
        Derives the database's cryptographic root KDF from the provided
        initial `key` material.
        """
        self._root_kdf = self._DBKDF(self._DBDomains.ROOT_KDF, key=key)

    def _set_root_salt(self, root_salt: bytes, /) -> None:
        """
        Sets the instance's `root_salt` if it's of a valid length & it
        hasn't already been set. If the length is invalid, raises
        ValueError.

        If the provided value is different from that which has already
        been set, raises PermissionError.

        Otherwise if the value is the same, no-ops to allow the database
        to reload with its existing state.
        """
        correct_length = self._ROOT_SALT_BYTES
        if len(root_salt) != correct_length:
            raise Issue.invalid_length("root_salt", correct_length)
        elif not hasattr(self, "_root_salt"):
            self._root_salt = root_salt
        elif not compare_digest(self._root_salt, root_salt):
            raise Issue.cant_reassign_attribute("root_salt")

    async def _aroot_filename_hash(self, /) -> str:
        """
        Derives the filename hash for the database's manifest file.
        """
        return await self._root_kdf.ashake_128(
            size=self._FILENAME_HASH_BYTES,
            aad=self._DBDomains.ROOT_FILENAME,
        )

    def _root_filename_hash(self, /) -> str:
        """
        Derives the filename hash for the database's manifest file.
        """
        return self._root_kdf.shake_128(
            size=self._FILENAME_HASH_BYTES,
            aad=self._DBDomains.ROOT_FILENAME,
        )

    async def _agenerate_root_salt(self, /) -> bytes:
        """
        Returns a random bytes-type salt of length defined by the class.
        """
        return await atoken_bytes(self._ROOT_SALT_BYTES)

    def _generate_root_salt(self, /) -> bytes:
        """
        Returns a random bytes-type salt of length defined by the class.
        """
        return token_bytes(self._ROOT_SALT_BYTES)

    async def _afilename_hash(self, tag: str, /) -> str:
        """
        Derives the filename hash given a user-defined `tag`.
        """
        return await self._root_kdf.ashake_128(
            self._root_salt,
            tag.encode(),
            aad=self._DBDomains.FILENAME,
            size=FILENAME_HASH_BYTES,
        )

    def _filename_hash(self, tag: str, /) -> str:
        """
        Derives the filename hash given a user-defined `tag`.
        """
        return self._root_kdf.shake_128(
            self._root_salt,
            tag.encode(),
            aad=self._DBDomains.FILENAME,
            size=FILENAME_HASH_BYTES,
        )

    async def _amanifest_key(self, /) -> bytes:
        """
        Derives the key used to open the database's manifest file.
        """
        return await self._root_kdf.ashake_128(
            aad=self._DBDomains.MANIFEST,
            size=SHAKE_128_BLOCKSIZE,
        )

    def _manifest_key(self, /) -> bytes:
        """
        Derives the key used to open the database's manifest file.
        """
        return self._root_kdf.shake_128(
            aad=self._DBDomains.MANIFEST,
            size=SHAKE_128_BLOCKSIZE,
        )

    async def _aencrypt_manifest(
        self,
        manifest: dict[str, t.JSONSerializable],
        /,
    ) -> bytes:
        """
        Returns an encrypted version of the database's `manifest`.
        """
        cipher = self._Cipher(await self._amanifest_key())
        return await cipher.ajson_encrypt(manifest)

    def _encrypt_manifest(
        self,
        manifest: dict[str, t.JSONSerializable],
        /,
    ) -> bytes:
        """
        Returns an encrypted version of the database's `manifest`.
        """
        cipher = self._Cipher(self._manifest_key())
        return cipher.json_encrypt(manifest)

    async def _adecrypt_manifest(
        self,
        ciphertext: bytes,
        /,
    ) -> dict[str, t.JSONSerializable]:
        """
        Returns the database's decrypted manifest.
        """
        cipher = self._Cipher(await self._amanifest_key())
        return await cipher.ajson_decrypt(ciphertext)

    def _decrypt_manifest(
        self,
        ciphertext: bytes,
        /,
    ) -> dict[str, t.JSONSerializable]:
        """
        Returns the database's decrypted manifest.
        """
        cipher = self._Cipher(self._manifest_key())
        return cipher.json_decrypt(ciphertext)

    async def _ametatag_key(self, tag: str, /) -> bytes:
        """
        Derives the metatag's database key given a user-defined `tag`.
        """
        return await self._root_kdf.asha3_512(
            self._root_salt,
            tag.encode(),
            aad=self._DBDomains.METATAG_KEY,
        )

    def _metatag_key(self, tag: str, /) -> bytes:
        """
        Derives the metatag's database key given a user-defined `tag`.
        """
        return self._root_kdf.sha3_512(
            self._root_salt,
            tag.encode(),
            aad=self._DBDomains.METATAG_KEY,
        )

    async def abytes_encrypt(
        self,
        plaintext: bytes,
        /,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the `plaintext` bytes with a key specific to the
        `filename` & returns the ciphertext bytes.
        """
        key = await self._root_kdf.ashake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return await self._Cipher(key).abytes_encrypt(plaintext)

    def bytes_encrypt(
        self,
        plaintext: bytes,
        /,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the `plaintext` bytes with a key specific to the
        `filename` & returns the ciphertext bytes.
        """
        key = self._root_kdf.shake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return self._Cipher(key).bytes_encrypt(plaintext)

    async def ajson_encrypt(
        self,
        plaintext: t.JSONSerializable,
        /,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the JSON serializable `plaintext` object with a key
        specific to the `filename` & returns the ciphertext bytes.
        """
        key = await self._root_kdf.ashake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return await self._Cipher(key).ajson_encrypt(plaintext)

    def json_encrypt(
        self,
        plaintext: t.JSONSerializable,
        /,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the JSON serializable `plaintext` object with a key
        specific to the `filename` & returns the ciphertext bytes.
        """
        key = self._root_kdf.shake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return self._Cipher(key).json_encrypt(plaintext)

    async def amake_token(
        self,
        plaintext: bytes,
        /,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the `plaintext` bytes with a key specific to the
        `filename` & urlsafe base64 encodes the resulting ciphertext
        bytes.
        """
        key = await self._root_kdf.ashake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return await self._TokenCipher(key).amake_token(plaintext)

    def make_token(
        self,
        plaintext: bytes,
        /,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Encrypts the `plaintext` bytes with a key specific to the
        `filename` & urlsafe base64 encodes the resulting ciphertext
        bytes.
        """
        key = self._root_kdf.shake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return self._TokenCipher(key).make_token(plaintext)

    async def abytes_decrypt(
        self,
        ciphertext: bytes,
        /,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int | None = DEFAULT_TTL,
    ) -> bytes:
        """
        Decrypts the `ciphertext` bytes with a key specific to the
        `filename` & returns the plaintext bytes. `ttl` is the amount of
        seconds that dictate the allowable age of the decrypted message.
        """
        key = await self._root_kdf.ashake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return await self._Cipher(key).abytes_decrypt(ciphertext, ttl=ttl)

    def bytes_decrypt(
        self,
        ciphertext: bytes,
        /,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int | None = DEFAULT_TTL,
    ) -> bytes:
        """
        Decrypts the `ciphertext` bytes with a key specific to the
        `filename` & returns the plaintext bytes. `ttl` is the amount of
        seconds that dictate the allowable age of the decrypted message.
        """
        key = self._root_kdf.shake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return self._Cipher(key).bytes_decrypt(ciphertext, ttl=ttl)

    async def ajson_decrypt(
        self,
        ciphertext: bytes,
        /,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int | None = DEFAULT_TTL,
    ) -> t.JSONSerializable:
        """
        Decrypts the `ciphertext` bytes with a key specific to the
        `filename` & JSON loads the resulting plaintext bytes. `ttl` is
        the amount of seconds that dictate the allowable age of the
        decrypted message.
        """
        key = await self._root_kdf.ashake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return await self._Cipher(key).ajson_decrypt(ciphertext, ttl=ttl)

    def json_decrypt(
        self,
        ciphertext: bytes,
        /,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int | None = DEFAULT_TTL,
    ) -> t.JSONSerializable | bytes:
        """
        Decrypts the `ciphertext` bytes with a key specific to the
        `filename` & JSON loads the resulting plaintext bytes. `ttl` is
        the amount of seconds that dictate the allowable age of the
        decrypted message.
        """
        key = self._root_kdf.shake_128(
            self._DBDomains.CIPHER,
            self._root_salt,
            filename.encode(),
            aad=aad,
            size=MIN_KEY_BYTES,
        )
        return self._Cipher(key).json_decrypt(ciphertext, ttl=ttl)

    async def aread_token(
        self,
        token: t.Base64URLSafe,
        /,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int | None = DEFAULT_TTL,
    ) -> bytes:
        """
        Decrypts the urlsafe base64 encoded `token` with a key specific
        to the `filename` & returns the plaintext bytes. `ttl` is the
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
        return await self._TokenCipher(key).aread_token(token, ttl=ttl)

    def read_token(
        self,
        token: t.Base64URLSafe,
        /,
        *,
        filename: str = "",
        aad: bytes = DEFAULT_AAD,
        ttl: int | None = DEFAULT_TTL,
    ) -> bytes:
        """
        Decrypts the urlsafe base64 encoded `token` with a key specific
        to the `filename` & returns the plaintext bytes. `ttl` is the
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
        return self._TokenCipher(key).read_token(token, ttl=ttl)


module_api = dict(
    DatabaseCrypto=t.add_type(DatabaseCrypto),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
