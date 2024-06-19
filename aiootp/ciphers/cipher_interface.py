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


__all__ = ["CipherInterface"]


__doc__ = (
    "An interface for the package's online, salt misuse-reuse resistant, "
    "fully context commiting, tweakable, AEAD ciphers ."
)


import json

from aiootp._typing import Typing as t
from aiootp._constants.misc import DEFAULT_AAD, DEFAULT_TTL
from aiootp._exceptions import Issue, TimestampExpired
from aiootp._exceptions import InvalidBlockID, InvalidSHMAC
from aiootp._gentools import abatch, batch
from aiootp.commons import FrozenInstance, Config
from aiootp.generics import ByteIO

from .ciphertext_formatting import Ciphertext
from .padding import Padding
from .key_bundle import KeyAADBundle
from .stream_hmac import StreamHMAC
from .cipher_streams import AsyncCipherStream, CipherStream
from .decipher_streams import AsyncDecipherStream, DecipherStream


class CipherInterface(FrozenInstance):
    """
    A general definition for a high-level cipher interface.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    import aiootp

    key = aiootp.csprng()
    cipher = aiootp.CipherInterfaceSubclass(key)

    plaintext = b"Hello, Bob!"
    ciphertext = cipher.bytes_encrypt(plaintext)
    assert plaintext == cipher.bytes_decrypt(ciphertext)

    json_plaintext = ["any", {"JSON": "serializable object"}]
    ciphertext = cipher.json_encrypt(json_plaintext)
    assert json_plaintext == cipher.json_decrypt(ciphertext)

    token_plaintext = b"user_id|session_secret"
    token = cipher.make_token(token_plaintext)
    assert token_plaintext == cipher.read_token(token, ttl=3600)

     _____________________________________
    |                                     |
    |     Format Diagram: Ciphertext      |
    |_____________________________________|
     __________________________________________________________________
    |                       |                                          |
    |         Header        |                Ciphertext                |
    |---------|------|------|------|-------|-----------|---------|-----|
    |  shmac  | salt |  iv  | inner-header | plaintext | padding | len |
    |         |      |      |------|-------|           |         |     |
    |         |      |      | time | ikey  |           |         |     |
    |_________|______|______|______|_______|___________|_________|_____|

    """

    __slots__ = ("_kdfs",)

    InvalidBlockID: type = InvalidBlockID
    InvalidSHMAC: type = InvalidSHMAC
    TimestampExpired: type = TimestampExpired

    _KDFs: type
    _KeyAADBundle: type
    _StreamHMAC: type
    _Junction: type
    _AsyncCipherStream: type = AsyncCipherStream
    _CipherStream: type = CipherStream
    _AsyncDecipherStream: type = AsyncDecipherStream
    _DecipherStream: type = DecipherStream
    _Ciphertext: type = Ciphertext

    _config: t.ConfigType
    _padding: t.PaddingType

    def __init_subclass__(cls, *a, **kw) -> None:
        """
        Populates class specific configuration during class definition
        to reduce instance initialization costs.
        """
        cls._padding = Padding(config=cls._config)
        super().__init_subclass__(*a, **kw)

    def __init__(self, key: bytes) -> None:
        """
        Manages an encryption `key` within the state of a set of SHA3
        hashing objects defined by the cipher. This allows for efficient
        use of arbitrary sized keys, amortizing initialization time &
        memory costs.
        """
        self._kdfs = self._KDFs(key, config=self._config)

    async def abytes_encrypt(
        self,
        data: bytes,
        *,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Returns the ciphertext of any bytes type `data` containing the
        SHMAC authentication tag, the salt, & the IV.

        `salt`: A [pseudo]random salt that may be supplied by the user.
                By default it's sent in the clear attached to the
                ciphertext. Thus it may simplify implementing efficient
                features, such as search or routing, though care must still
                be taken when considering how leaking such metadata may be
                harmful. Keeping this value constant is strongly discouraged,
                though the salt misuse-reuse resistance of the cipher
                extends up to ~256**(len(iv)/2 + len(siv_key)/2)
                encryptions/second.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.
        """
        key_bundle = await self._KeyAADBundle(
            self._kdfs, salt=salt, aad=aad
        ).async_mode()
        shmac = self._StreamHMAC(key_bundle)._for_encryption()
        data = abatch(
            await self._padding.apad_plaintext(data),
            size=self._config.BLOCKSIZE,
        )
        ciphering = self._Junction.abytes_encipher(data, shmac=shmac)
        ciphertext = (
            b"".join([block async for block in ciphering]),
            key_bundle.iv,
            key_bundle.salt,
            await shmac.afinalize(),
        )
        return b"".join(ciphertext[::-1])

    def bytes_encrypt(
        self,
        data: bytes,
        *,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Returns the ciphertext of any bytes type `data` containing the
        SHMAC authentication tag, the salt, & the IV.

        `salt`: Returns a [pseudo]random salt that may be supplied by the
                user. By default it's sent in the clear attached to the
                ciphertext. Thus it may simplify implementing efficient
                features, such as search or routing, though care must still
                be taken when considering how leaking such metadata may be
                harmful. Keeping this value constant is strongly discouraged,
                though the salt misuse-reuse resistance of the cipher
                extends up to ~256**(len(iv)/2 + len(siv_key)/2)
                encryptions/second.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.
        """
        key_bundle = self._KeyAADBundle(
            self._kdfs, salt=salt, aad=aad
        ).sync_mode()
        shmac = self._StreamHMAC(key_bundle)._for_encryption()
        data = batch(
            self._padding.pad_plaintext(data), size=self._config.BLOCKSIZE
        )
        ciphertext = (
            b"".join(self._Junction.bytes_encipher(data, shmac=shmac)),
            key_bundle.iv,
            key_bundle.salt,
            shmac.finalize(),
        )
        return b"".join(ciphertext[::-1])

    async def abytes_decrypt(
        self, data: bytes, *, aad: bytes = DEFAULT_AAD, ttl: int = 0
    ) -> bytes:
        """
        Returns the plaintext bytes from the bytes ciphertext `data`. The
        `data` bytes contain the SHMAC authentication tag, the salt, &
        the IV.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.

        `ttl`: An amount of seconds that dictate the allowable age of
                the decrypted message.
        """
        data = self._Ciphertext(data, config=self._config)
        key_bundle = await self._KeyAADBundle(
            self._kdfs, salt=data.salt, aad=aad, iv=data.iv
        ).async_mode()
        shmac = self._StreamHMAC(key_bundle)._for_decryption()
        ciphertext = abatch(data.ciphertext, size=self._config.BLOCKSIZE)
        deciphering = self._Junction.abytes_decipher(ciphertext, shmac=shmac)
        plaintext = b"".join([block async for block in deciphering])
        await shmac.afinalize()
        await shmac.atest_shmac(data.shmac)
        return await self._padding.adepad_plaintext(plaintext, ttl=ttl)

    def bytes_decrypt(
        self, data: bytes, *, aad: bytes = DEFAULT_AAD, ttl: int = 0
    ) -> bytes:
        """
        Returns the plaintext bytes from the bytes ciphertext `data`. The
        `data` bytes contain the SHMAC authentication tag, the salt, &
        the IV.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.

        `ttl`: An amount of seconds that dictate the allowable age of
                the decrypted message.
        """
        data = self._Ciphertext(data, config=self._config)
        key_bundle = self._KeyAADBundle(
            self._kdfs, salt=data.salt, aad=aad, iv=data.iv
        ).sync_mode()
        shmac = self._StreamHMAC(key_bundle)._for_decryption()
        ciphertext = batch(data.ciphertext, size=self._config.BLOCKSIZE)
        plaintext = b"".join(
            self._Junction.bytes_decipher(ciphertext, shmac=shmac)
        )
        shmac.finalize()
        shmac.test_shmac(data.shmac)
        return self._padding.depad_plaintext(plaintext, ttl=ttl)

    async def ajson_encrypt(
        self,
        data: t.JSONSerializable,
        *,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Returns the ciphertext of any JSON serializable `data` containing
        the SHMAC authentication tag, the salt, & the IV.

        `salt`: Returns a [pseudo]random salt that may be supplied by the
                user. By default it's sent in the clear attached to the
                ciphertext. Thus it may simplify implementing efficient
                features, such as search or routing, though care must still
                be taken when considering how leaking such metadata may be
                harmful. Keeping this value constant is strongly discouraged,
                though the salt misuse-reuse resistance of the cipher
                extends up to ~256**(len(iv)/2 + len(siv_key)/2)
                encryptions/second.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.
        """
        return await self.abytes_encrypt(
            json.dumps(data).encode(), salt=salt, aad=aad
        )

    def json_encrypt(
        self,
        data: t.JSONSerializable,
        *,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Returns the ciphertext of any JSON serializable `data` containing
        the SHMAC authentication tag, the salt, & the IV.

        `salt`: Returns a [pseudo]random salt that may be supplied by the
                user. By default it's sent in the clear attached to the
                ciphertext. Thus it may simplify implementing efficient
                features, such as search or routing, though care must still
                be taken when considering how leaking such metadata may be
                harmful. Keeping this value constant is strongly discouraged,
                though the salt misuse-reuse resistance of the cipher
                extends up to ~256**(len(iv)/2 + len(siv_key)/2)
                encryptions/second.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.
        """
        return self.bytes_encrypt(
            json.dumps(data).encode(), salt=salt, aad=aad
        )

    async def ajson_decrypt(
        self, data: bytes, *, aad: bytes = DEFAULT_AAD, ttl: int = 0
    ) -> t.JSONSerializable:
        """
        Decrypts the bytes ciphertext `data` & returns the loaded JSON
        plaintext. The `data` bytes contain the SHMAC authentication tag,
        the salt, & the IV.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.

        `ttl`: An amount of seconds that dictate the allowable age of
                the decrypted message.
        """
        return json.loads(await self.abytes_decrypt(data, aad=aad, ttl=ttl))

    def json_decrypt(
        self, data: bytes, *, aad: bytes = DEFAULT_AAD, ttl: int = 0
    ) -> t.JSONSerializable:
        """
        Decrypts the bytes ciphertext `data` & returns the loaded JSON
        plaintext. The `data` bytes contain the SHMAC authentication tag,
        the salt, & the IV.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.

        `ttl`: An amount of seconds that dictate the allowable age of
                the decrypted message.
        """
        return json.loads(self.bytes_decrypt(data, aad=aad, ttl=ttl))

    async def amake_token(
        self, data: bytes, *, aad: bytes = DEFAULT_AAD
    ) -> bytes:
        """
        Encrypts the bytes `data` & returns a urlsafe encoded ciphertext
        token. The `token` contains the SHMAC authentication tag, the
        salt, & the IV.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.
        """
        if data.__class__ is not bytes:
            raise Issue.value_must_be_type("token data", bytes)
        ciphertext = await self.abytes_encrypt(data, aad=aad)
        return await ByteIO.abytes_to_urlsafe(ciphertext)

    def make_token(self, data: bytes, *, aad: bytes = DEFAULT_AAD) -> bytes:
        """
        Encrypts the bytes `data` & returns a urlsafe encoded ciphertext
        token. The `token` contains the SHMAC authentication tag, the
        salt, & the IV.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.
        """
        if data.__class__ is not bytes:
            raise Issue.value_must_be_type("token data", bytes)
        ciphertext = self.bytes_encrypt(data, aad=aad)
        return ByteIO.bytes_to_urlsafe(ciphertext)

    async def aread_token(
        self,
        token: t.Base64URLSafe,
        *,
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
    ) -> bytes:
        """
        Decodes a ciphertext `token` & returns the decrypted token
        data. The `token` bytes contain the SHMAC authentication tag,
        the salt, & the IV.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.

        `ttl`: An amount of seconds that dictate the allowable age of
                the decrypted message.
        """
        if token.__class__ is not bytes:
            token = token.encode()
        ciphertext = await ByteIO.aurlsafe_to_bytes(token)
        return await self.abytes_decrypt(ciphertext, aad=aad, ttl=ttl)

    def read_token(
        self,
        token: t.Base64URLSafe,
        *,
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
    ) -> bytes:
        """
        Decodes a ciphertext `token` & returns the decrypted token
        data. The `token` bytes contain the SHMAC authentication tag,
        the salt, & the IV.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.

        `ttl`: An amount of seconds that dictate the allowable age of
                the decrypted message.
        """
        if token.__class__ is not bytes:
            token = token.encode()
        ciphertext = ByteIO.urlsafe_to_bytes(token)
        return self.bytes_decrypt(ciphertext, aad=aad, ttl=ttl)

    async def astream_encrypt(
        self, *, salt: t.Optional[bytes] = None, aad: bytes = DEFAULT_AAD
    ) -> AsyncCipherStream:
        """
        Returns an object to manage encrypting a stream of plaintext.

        `salt`: A [pseudo]random salt that may be supplied by the user.
                By default it's sent in the clear attached to the
                ciphertext. Thus it may simplify implementing efficient
                features, such as search or routing, though care must still
                be taken when considering how leaking such metadata may be
                harmful. Keeping this value constant is strongly discouraged,
                though the salt misuse-reuse resistance of the cipher
                extends up to ~256**(len(iv)/2 + len(siv_key)/2)
                encryptions/second.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.
        """
        return await self._AsyncCipherStream(self, salt=salt, aad=aad)

    def stream_encrypt(
        self, *, salt: t.Optional[bytes] = None, aad: bytes = DEFAULT_AAD
    ) -> CipherStream:
        """
        Returns an object to manage encrypting a stream of plaintext.

        `salt`: A [pseudo]random salt that may be supplied by the user.
                By default it's sent in the clear attached to the
                ciphertext. Thus it may simplify implementing efficient
                features, such as search or routing, though care must still
                be taken when considering how leaking such metadata may be
                harmful. Keeping this value constant is strongly discouraged,
                though the salt misuse-reuse resistance of the cipher
                extends up to ~256**(len(iv)/2 + len(siv_key)/2)
                encryptions/second.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.
        """
        return self._CipherStream(self, salt=salt, aad=aad)

    async def astream_decrypt(
        self,
        *,
        salt: bytes,
        aad: bytes = DEFAULT_AAD,
        iv: bytes,
        ttl: int = DEFAULT_TTL,
    ) -> AsyncDecipherStream:
        """
        Returns an object to manage decrypting a stream of ciphertext.

        `salt`: A [pseudo]random salt that may be supplied by the user.
                By default it's sent in the clear attached to the
                ciphertext. Thus it may simplify implementing efficient
                features, such as search or routing, though care must still
                be taken when considering how leaking such metadata may be
                harmful. Keeping this value constant is strongly discouraged,
                though the salt misuse-reuse resistance of the cipher
                extends up to ~256**(len(iv)/2 + len(siv_key)/2)
                encryptions/second.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.

        `iv`: An ephemeral, uniform, random value that's generated by
                the encryption algorithm. Ensures salt misue / reuse
                security even if the `key`, `salt`, & `aad` are the same
                for ~256**(len(iv)/2 + len(siv_key)/2) encryptions/second.

        `ttl`: An amount of seconds that dictate the allowable age of
                the decrypted message.
        """
        return await self._AsyncDecipherStream(
            self, salt=salt, aad=aad, iv=iv, ttl=ttl
        )

    def stream_decrypt(
        self,
        *,
        salt: bytes,
        aad: bytes = DEFAULT_AAD,
        iv: bytes,
        ttl: int = DEFAULT_TTL,
    ) -> DecipherStream:
        """
        Returns an object to manage decrypting a stream of ciphertext.

        `salt`: A [pseudo]random salt that may be supplied by the user.
                By default it's sent in the clear attached to the
                ciphertext. Thus it may simplify implementing efficient
                features, such as search or routing, though care must still
                be taken when considering how leaking such metadata may be
                harmful. Keeping this value constant is strongly discouraged,
                though the salt misuse-reuse resistance of the cipher
                extends up to ~256**(len(iv)/2 + len(siv_key)/2)
                encryptions/second.

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.

        `iv`: An ephemeral, uniform, random value that's generated by
                the encryption algorithm. Ensures salt misue / reuse
                security even if the `key`, `salt`, & `aad` are the same
                for ~256**(len(iv)/2 + len(siv_key)/2) encryptions/second.

        `ttl`: An amount of seconds that dictate the allowable age of
                the decrypted message.
        """
        return self._DecipherStream(
            self, salt=salt, aad=aad, iv=iv, ttl=ttl
        )


module_api = dict(
    CipherInterface=t.add_type(CipherInterface),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

