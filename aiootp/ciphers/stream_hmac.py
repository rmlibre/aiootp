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


__all__ = ["StreamHMAC"]


__doc__ = "General definition for the StreamHMAC interface."


from aiootp._typing import Typing as t
from aiootp._constants import DEFAULT_AAD, SHAKE_128_BLOCKSIZE, BIG
from aiootp._constants import ENCRYPTION, DECRYPTION
from aiootp._exceptions import Issue, SHMACIssue
from aiootp._exceptions import InvalidBlockID, InvalidSHMAC
from aiootp.asynchs import asleep
from aiootp.generics import Domains, bytes_are_equal

from .key_bundle import KeyAADBundle


class StreamHMAC:
    """
    This class is used as an inline validator for ciphertext streams as
    they are being created & decrypted. It's designed for full context
    commitment, salt misuse-reuse resistance, & RUP security.
    """

    __slots__ = (
        "_aupdate",
        "_avalidated_transform",
        "_current_digest",
        "_is_finalized",
        "_key_bundle",
        "_previous_digest",
        "_mac",
        "_permutation",
        "_mode",
        "_result",
        "_result_is_ready",
        "_update",
        "_validated_transform",
        "config",
    )

    InvalidBlockID = InvalidBlockID
    InvalidSHMAC = InvalidSHMAC

    def __init__(self, key_bundle: KeyAADBundle) -> None:
        """
        Begins a stateful hash object that's used to calculate a keyed-
        message authentication code referred to as a shmac, as well as
        block IDs to validate ciphertext streams that have not yet been
        completed.
        """
        if not issubclass(key_bundle.__class__, KeyAADBundle):
            raise Issue.value_must_be_type("key_bundle", KeyAADBundle)
        self._mode = None
        self._is_finalized = False
        self._result_is_ready = False
        self._register_key_bundle(key_bundle)
        self._initialize_session_state()
        self._update = self._placeholder_update    # Don't allow updates
        self._aupdate = self._aplaceholder_update  # unless mode is set

    def _register_key_bundle(self, key_bundle: KeyAADBundle) -> None:
        """
        Registers the `KeyAADBundle` object & necessary values, which
        will be tied to the instance for a single run of the cipher.
        Reusing the same instance or `key_bundle` for multiple cipher
        calls is NOT SAFE, & is disallowed by this registration.
        """
        key_bundle._mode.validate()
        self._key_bundle = key_bundle
        self.config = key_bundle.config
        self._mac = key_bundle._shmac_kdf

    def _initialize_session_state(self) -> None:
        """
        Prepares the state for the current call session.
        """
        config = self.config
        primer_key = self._mac.digest(config.PRIMER_KEY_BYTES)
        self._previous_digest = self._current_digest = primer_key[
            config.FIRST_DIGEST_SLICE
        ]
        self._permutation = config.Permutation(
            key=primer_key[config.PERMUTATION_KEY_SLICE],
            config_id=config.PERMUTATION_CONFIG_ID,
        )

    @property
    def mode(self) -> str:
        """
        Returns the mode which the instance was instructed to be in
        after `_for_encryption` or `_for_decryption` are called.
        """
        return self._mode

    @property
    def result(self) -> bytes:
        """
        Returns the instance's final authentication tag result. Raises
        `PermissionError` if the instance hasn't been finalized.
        """
        if not self._result_is_ready:
            raise SHMACIssue.validation_incomplete()
        return self._result

    def _for_encryption(self) -> t.Self:
        """
        Instructs the SHMAC instance to prepare itself for validating
        ciphertext while encrypting.
        """
        if self._mode:
            raise Issue.value_already_set("shmac", self._mode)
        elif self._key_bundle._iv_given_by_user:
            raise SHMACIssue.invalid_iv_usage()
        self._mode = ENCRYPTION
        self._update = self._update_mac
        self._aupdate = self._aupdate_mac
        self._validated_transform = self._encipher_then_hash
        self._avalidated_transform = self._aencipher_then_hash
        return self

    def _for_decryption(self) -> t.Self:
        """
        Instructs the SHMAC instance to prepare itself for validating
        ciphertext while decrypting.
        """
        if self._mode:
            raise Issue.value_already_set("shmac", self._mode)
        elif not self._key_bundle._iv_given_by_user:
            raise SHMACIssue.invalid_iv_usage()
        self._mode = DECRYPTION
        self._update = self._update_mac
        self._aupdate = self._aupdate_mac
        self._validated_transform = self._hash_then_decipher
        self._avalidated_transform = self._ahash_then_decipher
        return self

    async def _aplaceholder_update(self, *a, **kw) -> None:
        """
        This method is overwritten with the propper functionality when a
        cipher mode is declared with either the `_for_encryption` or
        `_for_decryption` methods. This interface helps ensure correct
        usage of the object.
        """
        raise SHMACIssue.no_cipher_mode_declared()

    def _placeholder_update(self, *a, **kw) -> None:
        """
        This method is overwritten with the propper functionality when a
        cipher mode is declared with either the `_for_encryption` or
        `_for_decryption` methods. This interface helps ensure correct
        usage of the object.
        """
        raise SHMACIssue.no_cipher_mode_declared()

    async def _aupdate_mac(self, ciphertext_block: bytes) -> t.Self:
        """
        This method is called automatically when an instance is passed
        into the low-level `(a)bytes_encipher` / `(a)bytes_decipher`
        generators.
        """
        await asleep()
        mac = self._mac
        self._previous_digest = self._current_digest
        mac.update(ciphertext_block)
        self._current_digest = mac.digest(self.config.SHMAC_BLOCKSIZE)
        return self

    def _update_mac(self, ciphertext_block: bytes) -> t.Self:
        """
        This method is called automatically when an instance is passed
        into the low-level `(a)bytes_encipher` / `(a)bytes_decipher`
        generators.
        """
        mac = self._mac
        self._previous_digest = self._current_digest
        mac.update(ciphertext_block)
        self._current_digest = mac.digest(self.config.SHMAC_BLOCKSIZE)
        return self

    def _test_block_id_size(self, size: int) -> None:
        """
        Raises errors if the requested `block_id` `size` is not within
        the allowed bounds.
        """
        if size < self.config.MIN_BLOCK_ID_BYTES:
            raise SHMACIssue.block_id_is_too_small(
                size, self.config.MIN_BLOCK_ID_BYTES
            )
        elif size > self.config.MAX_BLOCK_ID_BYTES:
            raise SHMACIssue.block_id_is_too_big(
                size, self.config.MAX_BLOCK_ID_BYTES
            )

    def _get_block_id_mac(self) -> None:
        """
        Returns a correct mac digest considering that during encryption
        the ciphertext is generated before the block id is generated, &
        it must be checked by an instance during decryption before it's
        decrypted.
        """
        if self._mode == ENCRYPTION:
            return self._previous_digest
        else:
            return self._current_digest

    async def anext_block_id(
        self,
        next_block: bytes,
        *,
        size: t.Optional[int] = None,
        aad: bytes = DEFAULT_AAD,
        _join: t.Callable[..., bytes] = b"".join
    ) -> bytes:
        """
        Returns a `size`-byte block id derived from the current state
        & the supplied `next_block` chunk of ciphertext. These block
        ids can be used to detect out-of-order messages, as well as
        ciphertext forgeries, without altering the internal state. This
        allows for robust decryption of ciphertext streams, mitigates
        adversarial attempts to crash communication channels, & allows
        release of plaintexts without waiting for the stream to end.

        Additional `aad` for each block may be specified if desired,
        however the `aad` passed into this method DO NOT alter the
        keystream. It's only used to create block ids that authenticate
        the associated data.
        """
        await asleep()
        size = size if size else self.config.BLOCK_ID_BYTES
        self._test_block_id_size(size)
        mac = self.config.BLOCK_ID_KDF_CONFIG.factory()
        payload = (
            self._get_block_id_mac(),
            size.to_bytes(1, BIG),
            len(aad).to_bytes(8, BIG),
            aad,
            len(next_block).to_bytes(8, BIG),
            next_block,
        )
        mac.update(_join(payload))
        return mac.digest(size)

    def next_block_id(
        self,
        next_block: bytes,
        *,
        size: t.Optional[int] = None,
        aad: bytes = DEFAULT_AAD,
        _join: t.Callable[..., bytes] = b"".join
    ) -> bytes:
        """
        Returns a `size`-byte block id derived from the current state
        & the supplied `next_block` chunk of ciphertext. These block
        ids can be used to detect out-of-order messages, as well as
        ciphertext forgeries, without altering the internal state. This
        allows for robust decryption of ciphertext streams & mitigates
        adversarial attempts to crash communication channels, & allows
        release of plaintexts without waiting for the stream to end.

        Additional `aad` for each block may be specified if desired,
        however the `aad` passed into this method DO NOT alter the
        keystream. It's only used to create block ids that authenticate
        the associated data.
        """
        size = size if size else self.config.BLOCK_ID_BYTES
        self._test_block_id_size(size)
        mac = self.config.BLOCK_ID_KDF_CONFIG.factory()
        payload = (
            self._get_block_id_mac(),
            size.to_bytes(1, BIG),
            len(aad).to_bytes(8, BIG),
            aad,
            len(next_block).to_bytes(8, BIG),
            next_block,
        )
        mac.update(_join(payload))
        return mac.digest(size)

    async def _aset_final_result(self) -> None:
        """
        Sets the instance's final result with a SHMAC of its state. This
        signals the end of a stream of data that can be validated with
        the current instance.
        """
        await asleep()
        self._result = self._mac.digest(
            self.config.SHMAC_DOUBLE_BLOCKSIZE
        )[self.config.SHMAC_RESULT_SLICE]

    def _set_final_result(self) -> None:
        """
        Sets the instance's final result with a SHMAC of its state. This
        signals the end of a stream of data that can be validated with
        the current instance.
        """
        self._result = self._mac.digest(
            self.config.SHMAC_DOUBLE_BLOCKSIZE
        )[self.config.SHMAC_RESULT_SLICE]

    async def afinalize(self) -> bytes:
        """
        Sets the instance's final result with a SHMAC of its state. This
        signals the end of a stream of data that can be validated with
        the current instance. Returns the authentication tag.
        """
        if self._is_finalized:
            raise SHMACIssue.already_finalized()
        self._is_finalized = True
        await self._aset_final_result()
        self._result_is_ready = True
        del self._mac
        del self._previous_digest
        del self._current_digest
        return self._result

    def finalize(self) -> bytes:
        """
        Sets the instance's final result with a SHMAC of its state. This
        signals the end of a stream of data that can be validated with
        the current instance. Returns the authentication tag.
        """
        if self._is_finalized:
            raise SHMACIssue.already_finalized()
        self._is_finalized = True
        self._set_final_result()
        self._result_is_ready = True
        del self._mac
        del self._previous_digest
        del self._current_digest
        return self._result

    async def atest_next_block_id(
        self,
        untrusted_block_id: bytes,
        next_block: bytes,
        aad: bytes = DEFAULT_AAD,
    ) -> None:
        """
        Does a timing-safe comparison of a supplied `untrusted_block_id`
        with a derived block id of the supplied `next_block` chunk of
        ciphertext. Raises `InvalidBlockID` if the untrusted block ID is
        invalid. These block id checks can detect out of order messages,
        or ciphertext forgeries, without altering the internal state.
        This allows for robust decryption of ciphertext streams,
        mitigates adversarial attempts to crash a communication channel,
        & allows release of plaintexts without waiting for the stream to
        end.

        The `aad` for each block may be specified to authenticate the
        associated data with the block.
        """
        if untrusted_block_id.__class__ is not bytes:
            raise Issue.value_must_be_type("untrusted_block_id", bytes)
        size = len(untrusted_block_id)
        block_id = await self.anext_block_id(next_block, size=size, aad=aad)
        if not bytes_are_equal(untrusted_block_id, block_id):
            raise SHMACIssue.invalid_block_id()

    def test_next_block_id(
        self,
        untrusted_block_id: bytes,
        next_block: bytes,
        aad: bytes = DEFAULT_AAD,
    ) -> None:
        """
        Does a timing-safe comparison of a supplied `untrusted_block_id`
        with a derived block id of the supplied `next_block` chunk of
        ciphertext. Raises `InvalidBlockID` if the untrusted block ID is
        invalid. These block id checks can detect out of order messages,
        or ciphertext forgeries, without altering the internal state.
        This allows for robust decryption of ciphertext streams,
        mitigates adversarial attempts to crash a communication channel,
        & allows release of plaintexts without waiting for the stream to
        end.

        The `aad` for each block may be specified to authenticate the
        associated data with the block.
        """
        if untrusted_block_id.__class__ is not bytes:
            raise Issue.value_must_be_type("untrusted_block_id", bytes)
        size = len(untrusted_block_id)
        block_id = self.next_block_id(next_block, size=size, aad=aad)
        if not bytes_are_equal(untrusted_block_id, block_id):
            raise SHMACIssue.invalid_block_id()

    async def atest_shmac(self, untrusted_shmac: bytes) -> None:
        """
        Does a time-safe comparison of a supplied `untrusted_shmac`
        with the instance's final result shmac. Raises `InvalidSHMAC` if
        the shmac doesn't match.
        """
        if untrusted_shmac.__class__ is not bytes:
            raise Issue.value_must_be_type("untrusted_shmac", bytes)
        elif not bytes_are_equal(untrusted_shmac, self.result):
            raise SHMACIssue.invalid_shmac()

    def test_shmac(self, untrusted_shmac: bytes) -> None:
        """
        Does a time-safe comparison of a supplied `untrusted_shmac`
        with the instance's final result shmac. Raises `InvalidSHMAC` if
        the shmac doesn't match.
        """
        if untrusted_shmac.__class__ is not bytes:
            raise Issue.value_must_be_type("untrusted_shmac", bytes)
        elif not bytes_are_equal(untrusted_shmac, self.result):
            raise SHMACIssue.invalid_shmac()


module_api = dict(
    StreamHMAC=t.add_type(StreamHMAC),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

