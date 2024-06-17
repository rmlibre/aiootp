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
    "DualOutputKDFs",
    "DualOutputSessionKDFs",
    "DualOutputKeyAADBundle",
    "DualOutputStreamHMAC",
    "DualOutputSyntheticIV",
    "DualOutputStreamJunction",
]


__doc__ = (
    "Definitions for compossible types to run the dual-output cipher "
    "mode of operation."
)


from aiootp._typing import Typing as t
from aiootp._constants.misc import ENCRYPTION, BIG
from aiootp._exceptions import Issue
from aiootp.asynchs import asleep
from aiootp.commons import FrozenInstance

from .cipher_kdfs import CipherKDFs
from .key_bundle import KeyAADBundle
from .stream_hmac import StreamHMAC
from .synthetic_iv import SyntheticIV
from .stream_junction import StreamJunction
from .cipher_interface import CipherInterface
from .chunky_2048_config import SHMAC_KDF, LEFT_KDF, RIGHT_KDF


class DualOutputKDFs(CipherKDFs):
    """
    A type responsible for initializing the key-derivation & mac objects
    for dual-output mode ciphers.
    """

    __slots__ = (
        "keyed_shmac_kdf",
        "keyed_left_kdf",
        "keyed_right_kdf",
    )

    def __init__(self, key: bytes, *, config: t.ConfigType) -> None:
        """
        Keys the KDFs for handling by `KeyAADBundle`.
        """
        self.config = config
        self.test_key_validity(key)
        self.keyed_shmac_kdf = self.key_base_kdf(SHMAC_KDF, key=key)
        self.keyed_left_kdf = self.key_base_kdf(LEFT_KDF, key=key)
        self.keyed_right_kdf = self.key_base_kdf(RIGHT_KDF, key=key)

    def new_session(self, summary: bytes) -> t.Iterable[t.XOFType]:
        """
        Yields copies of the instance's KDFs that have been given the
        fresh randomness & context of a session's `summary`.
        """
        yield SHMAC_KDF, self.keyed_shmac_kdf.new_session_copy(summary)
        yield LEFT_KDF, self.keyed_left_kdf.new_session_copy(summary)
        yield RIGHT_KDF, self.keyed_right_kdf.new_session_copy(summary)


class DualOutputSessionKDFs(FrozenInstance):
    """
    Efficiently stores & gives access to keyed & session-randomized /
    contextualized functions.
    """

    __slots__ = (
        "keystream",
        "shmac_kdf",
        "left_kdf",
        "right_kdf",
    )

    def __init__(self) -> None:
        pass

    def __iter__(self) -> t.Generator[t.XOFType, None, None]:
        """
        An api for retrieving the instance's keystream kdfs.
        """
        yield self.left_kdf
        yield self.right_kdf


class DualOutputKeyAADBundle(KeyAADBundle):
    """
    A low-level interface for managing a key, salt, iv & authenticated
    associated data bundle which is to be used for ONLY ONE encryption.
    """

    __slots__ = ()

    _Session: type = DualOutputSessionKDFs

    def _keystream_ratchets(
        self
    ) -> t.Tuple[
        t.Callable[[bytes], None],
        t.Callable[[int], bytes],
        t.Callable[[bytes], None],
        t.Callable[[int], bytes],
    ]:
        """
        Returns the method pointers to the `hashlib.shake_128` objects
        that have been primed in different ways with cipher-specific
        static values, as well as the `key`, `salt`, `aad` & `iv`.

        The pointers are used to construct a key ratchet algorithm.
        """
        left_kdf, right_kdf = self._session
        return (
            left_kdf.update,
            left_kdf.digest,
            right_kdf.update,
            right_kdf.digest,
        )

    async def _anew_keystream(self) -> t.AsyncGenerator[bytes, bytes]:
        """
        An efficient async coroutine producing an unending, non-repeating
        stream of bytes key material which incorporates new key material
        in the stream derivation on each iteration.
        """
        c = self.config
        (
            l_update,
            l_digest,
            r_update,
            r_digest,
        ) = self._keystream_ratchets()
        (
            LEFT_RATCHET_KEY_SLICE,
            RIGHT_RATCHET_KEY_SLICE,
            SHMAC_BLOCKSIZE,
        ) = c.LEFT_RATCHET_KEY_SLICE, c.RIGHT_RATCHET_KEY_SLICE, c.SHMAC_BLOCKSIZE
        ratchet_key = yield
        while True:
            l_update(ratchet_key[LEFT_RATCHET_KEY_SLICE])   # update with 168 even index bytes
            r_update(ratchet_key[RIGHT_RATCHET_KEY_SLICE])  # update with 168 odd index bytes
            ratchet_key = yield l_digest(SHMAC_BLOCKSIZE) + r_digest(SHMAC_BLOCKSIZE)
            await asleep()

    def _new_keystream(self) -> t.Generator[bytes, bytes, None]:
        """
        An efficient sync coroutine producing an unending, non-repeating
        stream of bytes key material which incorporates new key material
        in the stream derivation on each iteration.
        """
        c = self.config
        (
            l_update,
            l_digest,
            r_update,
            r_digest,
        ) = self._keystream_ratchets()
        (
            LEFT_RATCHET_KEY_SLICE,
            RIGHT_RATCHET_KEY_SLICE,
            SHMAC_BLOCKSIZE,
        ) = c.LEFT_RATCHET_KEY_SLICE, c.RIGHT_RATCHET_KEY_SLICE, c.SHMAC_BLOCKSIZE
        ratchet_key = yield
        while True:
            l_update(ratchet_key[LEFT_RATCHET_KEY_SLICE])   # update with 168 even index bytes
            r_update(ratchet_key[RIGHT_RATCHET_KEY_SLICE])  # update with 168 odd index bytes
            ratchet_key = yield l_digest(SHMAC_BLOCKSIZE) + r_digest(SHMAC_BLOCKSIZE)

    async def async_mode(self) -> t.Self:
        """
        Sets the instance to run async dual-output mode key derivation.
        """
        self._session.keystream = keystream = self._anew_keystream()
        await keystream.asend(None)
        self._mode.set_async_mode()
        return self

    def sync_mode(self) -> t.Self:
        """
        Sets the instance to run sync dual-output mode key derivation.
        """
        self._session.keystream = keystream = self._new_keystream()
        keystream.send(None)
        self._mode.set_sync_mode()
        return self

    @property
    def _keystream(
        self
    ) -> t.Union[
        t.Generator[bytes, bytes, None], t.AsyncGenerator[bytes, bytes]
    ]:
        """
        Returns the private keystream coroutine used in the `DualOutput`
        cipher to encrypt / decrypt data. The coroutine can be either
        async or sync depending on what mode the instance is set to.
        """
        return self._session.keystream


class DualOutputStreamHMAC(StreamHMAC):
    """
    This class is used as an inline validator for ciphertext streams as
    they are being created & decrypted. It's designed for full context
    commitment, salt misuse-reuse resistance, & RUP security.
    """

    __slots__ = ()

    @property
    def _ratchet_key(self) -> bytes:
        """
        Combines the current & previous cached state to efficiently
        incorporate fresh entropy from the message into keystream
        generation, as well as prior & current context as commitment.
        This also acts to mitigate adversarial attempts to control the
        internal state of the cipher by spreading/dividing out message
        influence over serveral blocks/outputs of the XOF objects.
        """
        return self._current_digest + self._previous_digest

    async def _aencipher_then_hash(
        self,
        plaintext_block: bytes,
        key: bytes,
        *,
        _from_bytes: t.Callable[..., int] = int.from_bytes,
    ) -> bytes:
        """
        This method is inserted as the instance's `_avalidated_transform`
        method after the encryption mode is set.
        """
        config = self.config
        try:
            ciphertext_block = (
                _from_bytes(plaintext_block, BIG)
                ^ _from_bytes(key[config.EMBEDDED_CIPHERTEXT_SLICE], BIG)
            ).to_bytes(config.BLOCKSIZE, BIG)
            await self._aupdate(
                key[config.EMBEDDED_LEFT_CAPACITY_SLICE]
                + ciphertext_block
                + key[config.EMBEDDED_RIGHT_CAPACITY_SLICE]
            )
            return ciphertext_block
        except OverflowError:
            raise Issue.exceeded_blocksize(config.BLOCKSIZE)

    def _encipher_then_hash(
        self,
        plaintext_block: bytes,
        key: bytes,
        *,
        _from_bytes: t.Callable[..., int] = int.from_bytes,
    ) -> bytes:
        """
        This method is inserted as the instance's `_validated_transform`
        method after the encryption mode is set.
        """
        config = self.config
        try:
            ciphertext_block = (
                _from_bytes(plaintext_block, BIG)
                ^ _from_bytes(key[config.EMBEDDED_CIPHERTEXT_SLICE], BIG)
            ).to_bytes(config.BLOCKSIZE, BIG)
            self._update(
                key[config.EMBEDDED_LEFT_CAPACITY_SLICE]
                + ciphertext_block
                + key[config.EMBEDDED_RIGHT_CAPACITY_SLICE]
            )
            return ciphertext_block
        except OverflowError:
            raise Issue.exceeded_blocksize(config.BLOCKSIZE)

    async def _ahash_then_decipher(
        self,
        ciphertext_block: bytes,
        key: bytes,
        *,
        _from_bytes: t.Callable[..., int] = int.from_bytes,
    ) -> bytes:
        """
        This method is inserted as the instance's `_avalidated_transform`
        method after the decryption mode is set.
        """
        config = self.config
        try:
            await self._aupdate(
                key[config.EMBEDDED_LEFT_CAPACITY_SLICE]
                + ciphertext_block
                + key[config.EMBEDDED_RIGHT_CAPACITY_SLICE]
            )
            return (
                _from_bytes(ciphertext_block, BIG)
                ^ _from_bytes(key[config.EMBEDDED_CIPHERTEXT_SLICE], BIG)
            ).to_bytes(config.BLOCKSIZE, BIG)
        except OverflowError:
            raise Issue.exceeded_blocksize(config.BLOCKSIZE)

    def _hash_then_decipher(
        self,
        ciphertext_block: bytes,
        key: bytes,
        *,
        _from_bytes: t.Callable[..., int] = int.from_bytes,
    ) -> bytes:
        """
        This method is inserted as the instance's `_validated_transform`
        method after the decryption mode is set.
        """
        config = self.config
        try:
            self._update(
                key[config.EMBEDDED_LEFT_CAPACITY_SLICE]
                + ciphertext_block
                + key[config.EMBEDDED_RIGHT_CAPACITY_SLICE]
            )
            return (
                _from_bytes(ciphertext_block, BIG)
                ^ _from_bytes(key[config.EMBEDDED_CIPHERTEXT_SLICE], BIG)
            ).to_bytes(config.BLOCKSIZE, BIG)
        except OverflowError:
            raise Issue.exceeded_blocksize(config.BLOCKSIZE)


class DualOutputSyntheticIV(SyntheticIV):
    """
    Manages the application of synthetic IVs which improve the salt
    misuse-reuse resistance of dual-output mode ciphers, since if either
    the 4-byte timestamp or ephemeral SIV-key are unique, then the
    entire stream of key material will be unique. The required plaintext
    padding is handled within the `Padding` class.

     _____________________________________
    |                                     |
    |    Algorithm Diagram: Encryption    |
    |_____________________________________|

     ------------------------------------------------------------------
    |    H = inner-header     |      P = first block of plaintext      |
    |                         |                                        |
    |         I-bytes         |                D-bytes                 |
    |-------------------------|----------------------------------------|
    |  timestamp |  siv-key   |                                        |
     ------------------------------------------------------------------

    |---------------------------- B-bytes -----------------------------|
    |----------- H -----------|------------------- P ------------------|
                 |                                 |
                 v                                 |
     shmac.perm( H )                               |
         |                                         |
         v                                         |
    M = masked-inner-header                        |
    J = (336 + I - B) / 2                          |
    L = (336 - B) / 2                              |
    siv = H + M + shmac.digest(168 - len(H + M))   |
    shmac.update(siv)                              |
    key = keystream(shmac.digest(336))             |
                                                   |
    key[J:-J] -------------------------------------⊕----> C
                                                   |
    shmac.update(key[:L] + M + C + key[-L:])       |
                                                   |
                                                   v
     ------------------------------------------------------------------
    | M = masked-inner-header |     C = first block of ciphertext      |
     ------------------------------------------------------------------

     _____________________________________
    |                                     |
    |    Algorithm Diagram: Decryption    |
    |_____________________________________|

     ------------------------------------------------------------------
    | M = masked-inner-header |     C = first block of ciphertext      |
     ------------------------------------------------------------------

    |---------------------------- B-bytes -----------------------------|
    |----------- M -----------|------------------- C ------------------|
                 |                                 |
                 v                                 |
     shmac.perm( M )                               |
         |                                         |
         v                                         |
    H = inner-header                               |
    siv = H + M + shmac.digest(168 - len(H + M))   |
    shmac.update(siv)                              |
    key = keystream(shmac.digest(336))             |
                                                   |
    key[J:-J] -------------------------------------⊕----> P
                                                   |
    shmac.update(key[:L] + M + C + key[-L:])       |
                                                   |
                                                   v
     ------------------------------------------------------------------
    |    H = inner-header     |      P = first block of plaintext      |
    |                         |                                        |
    |         I-bytes         |                D-bytes                 |
    |-------------------------|----------------------------------------|
    |  timestamp |  siv-key   |                                        |
     ------------------------------------------------------------------
    """

    __slots__ = ()

    @classmethod
    async def _aunique_cipher(
        cls,
        block: bytes,
        keystream: t.Callable[[bytes], t.Awaitable[bytes]],
        shmac: t.StreamHMACType,
    ) -> bytes:
        """
        Uses a masking & encryption algorithm to pull secret ephemeral
        data from the plaintext header to protect the payload of the
        ciphertext with more salt misuse-reuse resistance.
        """
        config = shmac.config
        header = block[config.INNER_HEADER_SLICE]
        masked_header = (
            await shmac._permutation.apermute(int.from_bytes(header, BIG))
        ).to_bytes(config.INNER_HEADER_BYTES, BIG)
        shmac._mac.update(
            header
            + masked_header
            + shmac._current_digest[config.SIV_DIGEST_SLICE]
        )
        key = await keystream(
            shmac._mac.digest(config.SHMAC_DOUBLE_BLOCKSIZE)
        )
        l_capacity = key[config.EMBEDDED_LEFT_CAPACITY_SLICE]
        r_capacity = key[config.EMBEDDED_RIGHT_CAPACITY_SLICE]
        ciphertext = masked_header + (
            int.from_bytes(key[config.FIRST_KEY_SLICE], BIG)
            ^ int.from_bytes(block[config.FIRST_CONTENT_SLICE], BIG)
        ).to_bytes(config.FIRST_CONTENT_BYTES, BIG)
        await shmac._aupdate(l_capacity + ciphertext + r_capacity)
        return ciphertext

    @classmethod
    def _unique_cipher(
        cls,
        block: bytes,
        keystream: t.Callable[[bytes], bytes],
        shmac: t.StreamHMACType,
    ) -> bytes:
        """
        Uses a masking & encryption algorithm to pull secret ephemeral
        data from the plaintext header to protect the payload of the
        ciphertext with more salt misuse-reuse resistance.
        """
        config = shmac.config
        header = block[config.INNER_HEADER_SLICE]
        masked_header = shmac._permutation.permute(
            int.from_bytes(header, BIG)
        ).to_bytes(config.INNER_HEADER_BYTES, BIG)
        shmac._mac.update(
            header
            + masked_header
            + shmac._current_digest[config.SIV_DIGEST_SLICE]
        )
        key = keystream(shmac._mac.digest(config.SHMAC_DOUBLE_BLOCKSIZE))
        l_capacity = key[config.EMBEDDED_LEFT_CAPACITY_SLICE]
        r_capacity = key[config.EMBEDDED_RIGHT_CAPACITY_SLICE]
        ciphertext = masked_header + (
            int.from_bytes(key[config.FIRST_KEY_SLICE], BIG)
            ^ int.from_bytes(block[config.FIRST_CONTENT_SLICE], BIG)
        ).to_bytes(config.FIRST_CONTENT_BYTES, BIG)
        shmac._update(l_capacity + ciphertext + r_capacity)
        return ciphertext

    @classmethod
    async def _aunique_decipher(
        cls,
        block: bytes,
        keystream: t.Callable[[bytes], t.Awaitable[bytes]],
        shmac: t.StreamHMACType,
    ) -> bytes:
        """
        Uses an unmasking & decryption algorithm to pull secret
        ephemeral data from the plaintext header to protect the payload
        of the ciphertext with more salt misuse-reuse resistance.
        """
        config = shmac.config
        masked_header = block[config.INNER_HEADER_SLICE]
        header = (
            await shmac._permutation.ainvert(
                int.from_bytes(masked_header, BIG)
            )
        ).to_bytes(config.INNER_HEADER_BYTES, BIG)
        shmac._mac.update(
            header
            + masked_header
            + shmac._current_digest[config.SIV_DIGEST_SLICE]
        )
        key = await keystream(
            shmac._mac.digest(config.SHMAC_DOUBLE_BLOCKSIZE)
        )
        l_capacity = key[config.EMBEDDED_LEFT_CAPACITY_SLICE]
        r_capacity = key[config.EMBEDDED_RIGHT_CAPACITY_SLICE]
        plaintext = header + (
            int.from_bytes(key[config.FIRST_KEY_SLICE], BIG)
            ^ int.from_bytes(block[config.FIRST_CONTENT_SLICE], BIG)
        ).to_bytes(config.FIRST_CONTENT_BYTES, BIG)
        await shmac._aupdate(l_capacity + block + r_capacity)
        return plaintext

    @classmethod
    def _unique_decipher(
        cls,
        block: bytes,
        keystream: t.Callable[[bytes], bytes],
        shmac: t.StreamHMACType,
    ) -> bytes:
        """
        Uses an unmasking & decryption algorithm to pull secret
        ephemeral data from the plaintext header to protect the payload
        of the ciphertext with more salt misuse-reuse resistance.
        """
        config = shmac.config
        masked_header = block[config.INNER_HEADER_SLICE]
        header = shmac._permutation.invert(
            int.from_bytes(masked_header, BIG)
        ).to_bytes(config.INNER_HEADER_BYTES, BIG)
        shmac._mac.update(
            header
            + masked_header
            + shmac._current_digest[config.SIV_DIGEST_SLICE]
        )
        key = keystream(shmac._mac.digest(config.SHMAC_DOUBLE_BLOCKSIZE))
        l_capacity = key[config.EMBEDDED_LEFT_CAPACITY_SLICE]
        r_capacity = key[config.EMBEDDED_RIGHT_CAPACITY_SLICE]
        plaintext = header + (
            int.from_bytes(key[config.FIRST_KEY_SLICE], BIG)
            ^ int.from_bytes(block[config.FIRST_CONTENT_SLICE], BIG)
        ).to_bytes(config.FIRST_CONTENT_BYTES, BIG)
        shmac._update(l_capacity + block + r_capacity)
        return plaintext


class DualOutputStreamJunction(StreamJunction):
    """
    A definition for how the key & data streams are combined for the
    dual-output cipher modes.
    """

    __slots__ = ()

    @classmethod
    async def acombine_streams(
        cls, data: t.AsyncDatastream, *, shmac: t.StreamHMACType
    ) -> t.AsyncGenerator[bytes, None]:
        """
        Bitwise XORs a ciphertext or plaintext datastream with a keystream
        then feeds ciphertext into the `shmac` for validation & distinct
        altering of the keystream.
        """
        datastream, keystream, validated_transform = (
            data,
            shmac._key_bundle._keystream.asend,
            shmac._avalidated_transform,
        )
        yield await DualOutputSyntheticIV.avalidated_transform(
            datastream, keystream, shmac
        )
        async for block in datastream:
            yield await validated_transform(
                block, await keystream(shmac._ratchet_key)
            )

    @classmethod
    def combine_streams(
        cls, data: t.Datastream, *, shmac: t.StreamHMACType
    ) -> t.Generator[bytes, None, None]:
        """
        Bitwise XORs a ciphertext or plaintext datastream with a keystream
        then feeds ciphertext into the `shmac` for validation & distinct
        altering of the keystream.
        """
        datastream, keystream, validated_transform = (
            data,
            shmac._key_bundle._keystream.send,
            shmac._validated_transform,
        )
        yield DualOutputSyntheticIV.validated_transform(
            datastream, keystream, shmac
        )
        for block in datastream:
            yield validated_transform(block, keystream(shmac._ratchet_key))


module_api = dict(
    DualOutputKDFs=t.add_type(DualOutputKDFs),
    DualOutputSessionKDFs=t.add_type(DualOutputSessionKDFs),
    DualOutputKeyAADBundle=t.add_type(DualOutputKeyAADBundle),
    DualOutputStreamHMAC=t.add_type(DualOutputStreamHMAC),
    DualOutputSyntheticIV=t.add_type(DualOutputSyntheticIV),
    DualOutputStreamJunction=t.add_type(DualOutputStreamJunction),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

