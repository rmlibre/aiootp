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


__all__ = [
    "ShakePermuteKDFs",
    "ShakePermuteSessionKDFs",
    "ShakePermuteKeyAADBundle",
    "ShakePermuteStreamHMAC",
    "ShakePermuteStreamJunction",
]


__doc__ = (
    "Definitions for compossible types to run the SHAKE permute cipher "
    "mode of operation."
)


from aiootp._typing import Typing as t
from aiootp._constants.misc import BIG, ENCRYPTION
from aiootp._exceptions import Issue
from aiootp.asynchs import asleep
from aiootp.commons import FrozenInstance

from .cipher_kdfs import CipherKDFs
from .key_bundle import KeyAADBundle
from .stream_hmac import StreamHMAC
from .stream_junction import StreamJunction
from .cipher_interface import CipherInterface
from .slick_256_config import SHMAC_KDF


class ShakePermuteKDFs(CipherKDFs):
    """
    A type responsible for initializing the key-derivation & mac objects
    for SHAKE permute mode ciphers.
    """

    __slots__ = ("keyed_shmac_kdf",)

    def __init__(self, key: bytes, *, config: t.ConfigType) -> None:
        """
        Keys the KDFs for handling by `KeyAADBundle`.
        """
        self.config = config
        self.test_key_validity(key)
        self.keyed_shmac_kdf = self.key_base_kdf(SHMAC_KDF, key=key)

    def new_session(
        self, summary: bytes
    ) -> t.Generator[t.Tuple[str, t.XOFType], None, None]:
        """
        Yields copies of the instance's KDFs that have been given the
        fresh randomness & context of a session's `summary`.
        """
        yield SHMAC_KDF, self.keyed_shmac_kdf.new_session_copy(summary)


class ShakePermuteSessionKDFs(FrozenInstance):
    """
    Efficiently stores & gives access to keyed & session-randomized /
    contextualized functions.
    """

    __slots__ = ("shmac_kdf",)

    def __init__(self) -> None:
        pass


class ShakePermuteKeyAADBundle(KeyAADBundle):
    """
    A low-level interface for managing a key, salt, iv & authenticated
    associated data bundle which is to be used for ONLY ONE encryption.
    """

    __slots__ = ()

    _Session: type = ShakePermuteSessionKDFs

    async def async_mode(self) -> t.Self:
        """
        Sets the instance to run async SHAKE permute mode key derivation.
        """
        await asleep()
        self._mode.set_async_mode()
        return self

    def sync_mode(self) -> t.Self:
        """
        Sets the instance to run sync SHAKE permute mode key derivation.
        """
        self._mode.set_sync_mode()
        return self


class ShakePermuteStreamHMAC(StreamHMAC):
    """
    This class is used as an inline validator for ciphertext streams as
    they are being created & decrypted. It's designed for full context
    commitment, salt misuse-reuse resistance, & RUP security.
    """

    __slots__ = ()

    async def _aencipher_then_hash(
        self,
        plaintext: bytes,
        *,
        _from_bytes: t.Callable[[bytes, str], int] = int.from_bytes,
    ) -> bytes:
        """
        This method is inserted as the instance's `_avalidated_transform`
        method after the encryption mode is set.
        """
        c = self.config
        try:
            digest = self._current_digest[c.PERMUTATION_DIGEST_SLICE]
            in_key = _from_bytes(self._current_digest[c.IN_KEY_SLICE], BIG)
            out_key = _from_bytes(self._current_digest[c.OUT_KEY_SLICE], BIG)
            ciphertext = (
                out_key ^ await self._permutation.auncapped_permute(
                    in_key ^ _from_bytes(plaintext, BIG)
                )
            ).to_bytes(c.BLOCKSIZE, BIG)
            await self._aupdate(plaintext + ciphertext + digest)  # 168 bytes
            return ciphertext
        except OverflowError:  # pragma: no cover
            raise Issue.exceeded_blocksize(c.BLOCKSIZE)  # pragma: no cover

    def _encipher_then_hash(
        self,
        plaintext: bytes,
        *,
        _from_bytes: t.Callable[[bytes, str], int] = int.from_bytes,
    ) -> bytes:
        """
        This method is inserted as the instance's `_validated_transform`
        method after the encryption mode is set.
        """
        c = self.config
        try:
            digest = self._current_digest[c.PERMUTATION_DIGEST_SLICE]
            in_key = _from_bytes(self._current_digest[c.IN_KEY_SLICE], BIG)
            out_key = _from_bytes(self._current_digest[c.OUT_KEY_SLICE], BIG)
            ciphertext = (
                out_key ^ self._permutation.uncapped_permute(
                    in_key ^ _from_bytes(plaintext, BIG)
                )
            ).to_bytes(c.BLOCKSIZE, BIG)
            self._update(plaintext + ciphertext + digest)  # 168 bytes
            return ciphertext
        except OverflowError:  # pragma: no cover
            raise Issue.exceeded_blocksize(c.BLOCKSIZE)  # pragma: no cover

    async def _ahash_then_decipher(
        self,
        ciphertext: bytes,
        *,
        _from_bytes: t.Callable[[bytes, str], int] = int.from_bytes,
    ) -> bytes:
        """
        This method is inserted as the instance's `_avalidated_transform`
        method after the decryption mode is set.
        """
        c = self.config
        try:
            digest = self._current_digest[c.PERMUTATION_DIGEST_SLICE]
            in_key = _from_bytes(self._current_digest[c.IN_KEY_SLICE], BIG)
            out_key = _from_bytes(self._current_digest[c.OUT_KEY_SLICE], BIG)
            plaintext = (
                in_key ^ await self._permutation.auncapped_invert(
                    out_key ^ _from_bytes(ciphertext, BIG)
                )
            ).to_bytes(c.BLOCKSIZE, BIG)
            await self._aupdate(plaintext + ciphertext + digest)  # 168 bytes
            return plaintext
        except OverflowError:  # pragma: no cover
            raise Issue.exceeded_blocksize(c.BLOCKSIZE)  # pragma: no cover

    def _hash_then_decipher(
        self,
        ciphertext: bytes,
        *,
        _from_bytes: t.Callable[[bytes, str], int] = int.from_bytes,
    ) -> bytes:
        """
        This method is inserted as the instance's `_avalidated_transform`
        method after the decryption mode is set.
        """
        c = self.config
        try:
            digest = self._current_digest[c.PERMUTATION_DIGEST_SLICE]
            in_key = _from_bytes(self._current_digest[c.IN_KEY_SLICE], BIG)
            out_key = _from_bytes(self._current_digest[c.OUT_KEY_SLICE], BIG)
            plaintext = (
                in_key ^ self._permutation.uncapped_invert(
                    out_key ^ _from_bytes(ciphertext, BIG)
                )
            ).to_bytes(c.BLOCKSIZE, BIG)
            self._update(plaintext + ciphertext + digest)  # 168 bytes
            return plaintext
        except OverflowError:  # pragma: no cover
            raise Issue.exceeded_blocksize(c.BLOCKSIZE)  # pragma: no cover


class ShakePermuteStreamJunction(StreamJunction):
    """
    A definition for how the key & data streams are combined for the
    SHAKE permute cipher mode.
    """

    @classmethod
    async def acombine_streams(
        cls, data: t.AsyncDatastream, *, shmac: StreamHMAC
    ) -> t.AsyncGenerator[bytes, None]:
        """
        XORs each ciphertext or plaintext block with a SHAKE round key,
        then passes the sum through a keyed permutation before XORing
        with another SHAKE round key, & feeding the values to the `shmac`
        for validation & distinct altering of the keystream.
        """
        datastream, validated_transform = (data, shmac._avalidated_transform)
        async for block in datastream:
            yield await validated_transform(block)

    @classmethod
    def combine_streams(
        cls, data: t.Datastream, *, shmac: StreamHMAC
    ) -> t.Generator[bytes, None, None]:
        """
        XORs each ciphertext or plaintext block with a SHAKE round key,
        then passes the sum through a keyed permutation before XORing
        with another SHAKE round key, & feeding the values to the `shmac`
        for validation & distinct altering of the keystream.
        """
        datastream, validated_transform = (data, shmac._validated_transform)
        for block in datastream:
            yield validated_transform(block)


module_api = dict(
    ShakePermuteKDFs=t.add_type(ShakePermuteKDFs),
    ShakePermuteSessionKDFs=t.add_type(ShakePermuteSessionKDFs),
    ShakePermuteKeyAADBundle=t.add_type(ShakePermuteKeyAADBundle),
    ShakePermuteStreamHMAC=t.add_type(ShakePermuteStreamHMAC),
    ShakePermuteStreamJunction=t.add_type(ShakePermuteStreamJunction),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

