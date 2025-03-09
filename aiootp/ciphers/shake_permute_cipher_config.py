# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2025 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


"""
A generic configuration type for the SHAKE permute cipher mode of
operation.
"""

__all__ = ["ShakePermuteCipherConfig"]


from math import ceil
from hashlib import shake_128

from aiootp._typing import Typing as t
from aiootp._constants import NamespaceMapping, BIG
from aiootp._exceptions import UndefinedRequiredAttributes
from aiootp.asynchs import Clock
from aiootp.commons import Config
from aiootp.generics import canonical_pack

from .cipher_kdfs import ShakeConfig


class ShakePermuteCipherConfig(Config):
    """
    Configuration framework for SHAKE-permute type ciphers.
    """

    __slots__ = (
        "BLOCKSIZE",
        "BLOCK_ID_BYTES",
        "BLOCK_ID_KDF",
        "BLOCK_ID_KDF_CONFIG",
        "BLOCK_ID_SLICE",
        "CIPHERTEXT_SLICE",
        "EPOCH_NS",
        "FIRST_DIGEST_SLICE",
        "HEADER_BYTES",
        "HEADER_SLICE",
        "INNER_BODY_SLICE",
        "INNER_HEADER_BYTES",
        "INNER_HEADER_SLICE",
        "IN_KEY_SLICE",
        "IV_BYTES",
        "IV_SLICE",
        "KDF_CONFIGS",
        "MAX_BLOCK_ID_BYTES",
        "MIN_BLOCK_ID_BYTES",
        "MIN_PADDING_BLOCKS",
        "MIN_STREAM_QUEUE",
        "NAME",
        "OUT_KEY_SLICE",
        "PACKED_METADATA",
        "PACKETSIZE",
        "PADDING_FRAME",
        "PERMUTATION_CONFIG_ID",
        "PERMUTATION_DIGEST_SLICE",
        "PERMUTATION_KEY_BYTES",
        "PERMUTATION_KEY_SLICE",
        "PERMUTATION_TEST_VECTOR",
        "PRIMER_KEY_BYTES",
        "Permutation",
        "SALT_BYTES",
        "SALT_SLICE",
        "SENTINEL_BYTES",
        "SENTINEL_SLICE",
        "SHMAC_BLOCKSIZE",
        "SHMAC_BYTES",
        "SHMAC_DOUBLE_BLOCKSIZE",
        "SHMAC_KDF",
        "SHMAC_KDF_CONFIG",
        "SHMAC_RESULT_SLICE",
        "SHMAC_SLICE",
        "SIV_KEY_BYTES",
        "SIV_KEY_SLICE",
        "TIMESTAMP_BYTES",
        "TIMESTAMP_SLICE",
        "TIME_UNIT",
        "clock",
    )

    slots_types: t.Mapping[str, type] = dict(
        BLOCKSIZE=int,
        BLOCK_ID_BYTES=int,
        BLOCK_ID_KDF=str,
        BLOCK_ID_KDF_CONFIG=ShakeConfig,
        BLOCK_ID_SLICE=slice,
        CIPHERTEXT_SLICE=slice,
        CONFIG_ID=bytes,
        EPOCH_NS=int,
        FIRST_DIGEST_SLICE=slice,
        HEADER_BYTES=int,
        HEADER_SLICE=slice,
        INNER_BODY_SLICE=slice,
        INNER_HEADER_BYTES=int,
        INNER_HEADER_SLICE=slice,
        IN_KEY_SLICE=slice,
        IV_BYTES=int,
        IV_SLICE=slice,
        KDF_CONFIGS=NamespaceMapping,
        MAX_BLOCK_ID_BYTES=int,
        MIN_BLOCK_ID_BYTES=int,
        MIN_PADDING_BLOCKS=int,
        MIN_STREAM_QUEUE=int,
        NAME=str,
        OUT_KEY_SLICE=slice,
        PACKED_METADATA=bytes,
        PACKETSIZE=int,
        PADDING_FRAME=int,
        PERMUTATION_CONFIG_ID=t.Hashable,
        PERMUTATION_DIGEST_SLICE=slice,
        PERMUTATION_KEY_BYTES=int,
        PERMUTATION_KEY_SLICE=slice,
        PERMUTATION_TEST_VECTOR=bytes,
        PRIMER_KEY_BYTES=int,
        Permutation=t.PermutationType,
        SALT_BYTES=int,
        SALT_SLICE=slice,
        SENTINEL_BYTES=int,
        SENTINEL_SLICE=slice,
        SHMAC_BLOCKSIZE=int,
        SHMAC_BYTES=int,
        SHMAC_DOUBLE_BLOCKSIZE=int,
        SHMAC_KDF=str,
        SHMAC_KDF_CONFIG=ShakeConfig,
        SHMAC_RESULT_SLICE=slice,
        SHMAC_SLICE=slice,
        SIV_KEY_BYTES=int,
        SIV_KEY_SLICE=slice,
        TIMESTAMP_BYTES=int,
        TIMESTAMP_SLICE=slice,
        TIME_UNIT=str,
        clock=t.ClockType,
    )

    def __init__(
        self,
        *,
        name: str,
        config_id: bytes,
        blocksize: int,
        min_padding_blocks: int,
        epoch_ns: int,
        time_unit: str,
        timestamp_bytes: int,
        siv_key_bytes: int,
        shmac_bytes: int,
        block_id_bytes: int,
        max_block_id_bytes: int,
        min_block_id_bytes: int,
        salt_bytes: int,
        iv_bytes: int,
        block_id_kdf: str,
        block_id_kdf_config: ShakeConfig,
        shmac_kdf: str,
        shmac_kdf_config: ShakeConfig,
        permutation_type: t.PermutationType,
    ) -> None:
        self.NAME = name
        self.CONFIG_ID = config_id
        self.BLOCKSIZE = blocksize
        self.MIN_PADDING_BLOCKS = min_padding_blocks
        self.EPOCH_NS = epoch_ns
        self.TIME_UNIT = time_unit
        self.TIMESTAMP_BYTES = timestamp_bytes
        self.SIV_KEY_BYTES = siv_key_bytes
        self.SHMAC_BYTES = shmac_bytes
        self.BLOCK_ID_BYTES = block_id_bytes
        self.MAX_BLOCK_ID_BYTES = max_block_id_bytes
        self.MIN_BLOCK_ID_BYTES = min_block_id_bytes
        self.SALT_BYTES = salt_bytes
        self.IV_BYTES = iv_bytes
        self.BLOCK_ID_KDF = block_id_kdf
        self.BLOCK_ID_KDF_CONFIG = block_id_kdf_config
        self.SHMAC_KDF = shmac_kdf
        self.SHMAC_KDF_CONFIG = shmac_kdf_config
        self.Permutation = permutation_type
        self._perform_dynamic_configuration_from_constants()
        self._perform_correctness_checks()
        self._ensure_all_attributes_have_been_defined()

    def _alias_primitives_values(self) -> None:
        """
        Maps configuration values of cipher primitives.
        """
        # fmt: off
        self.KDF_CONFIGS = NamespaceMapping(**{
            self.SHMAC_KDF: self.SHMAC_KDF_CONFIG,
        })
        # fmt: on
        self.SHMAC_BLOCKSIZE = self.SHMAC_KDF_CONFIG.blocksize
        self.SHMAC_DOUBLE_BLOCKSIZE = self.SHMAC_KDF_CONFIG.double_blocksize
        self.SHMAC_RESULT_SLICE = slice(-self.SHMAC_BYTES, None, 1)
        self.PERMUTATION_CONFIG_ID = self.BLOCKSIZE
        self.PERMUTATION_KEY_BYTES = self.Permutation.key_size(
            self.PERMUTATION_CONFIG_ID
        )

    def _compute_inner_header_measurements(self) -> None:
        """
        Use the provided configuration constants to determine the values
        of dependent inner header constants.
        """
        self.clock = Clock(self.TIME_UNIT, epoch=self.EPOCH_NS)
        self.INNER_HEADER_BYTES = self.TIMESTAMP_BYTES + self.SIV_KEY_BYTES
        self.INNER_HEADER_SLICE = slice(0, self.INNER_HEADER_BYTES, 1)
        self.INNER_BODY_SLICE = slice(self.INNER_HEADER_BYTES, None, 1)
        self.TIMESTAMP_SLICE = slice(0, self.TIMESTAMP_BYTES, 1)
        self.SIV_KEY_SLICE = slice(
            self.TIMESTAMP_BYTES, self.INNER_HEADER_BYTES, 1
        )

    def _compute_header_measurements(self) -> None:
        """
        Dynamic initialization of header constants from configuration.
        """
        self.HEADER_BYTES = (
            self.SHMAC_BYTES + self.SALT_BYTES + self.IV_BYTES
        )
        self.HEADER_SLICE = slice(0, self.HEADER_BYTES, 1)
        self.BLOCK_ID_SLICE = slice(0, self.BLOCK_ID_BYTES, 1)
        self.SHMAC_SLICE = slice(0, self.SHMAC_BYTES, 1)
        self.SALT_SLICE = slice(
            self.SHMAC_BYTES, self.SHMAC_BYTES + self.SALT_BYTES, 1
        )
        self.IV_SLICE = slice(
            self.SHMAC_BYTES + self.SALT_BYTES, self.HEADER_BYTES, 1
        )

    def _compute_permutation_integration_measurements(self) -> None:
        """
        Dynamic initialization of constants for the cipher's permutation.
        """
        self.FIRST_DIGEST_SLICE = slice(0, self.SHMAC_BLOCKSIZE, 1)
        self.PERMUTATION_DIGEST_SLICE = slice(
            2 * self.BLOCKSIZE, self.SHMAC_BLOCKSIZE, 1
        )
        self.IN_KEY_SLICE = slice(0, self.BLOCKSIZE, 1)
        self.OUT_KEY_SLICE = slice(self.BLOCKSIZE, 2 * self.BLOCKSIZE, 1)
        self.PERMUTATION_KEY_SLICE = slice(
            -self.PERMUTATION_KEY_BYTES, None, 1
        )
        self.PRIMER_KEY_BYTES = self.SHMAC_BLOCKSIZE * ceil(
            1 + self.PERMUTATION_KEY_BYTES / self.SHMAC_BLOCKSIZE
        )
        # fmt: off
        self.PERMUTATION_TEST_VECTOR = self.Permutation(
            key=shake_128(self.CONFIG_ID).digest(self.PERMUTATION_KEY_BYTES),
            config_id=self.PERMUTATION_CONFIG_ID,
        ).permute(0).to_bytes(self.BLOCKSIZE, BIG)
        # fmt: on

    def _compute_ciphertext_measurements(self) -> None:
        """
        Initialization of remaining ciphertext formatting constants.
        """
        self.PACKETSIZE = self.BLOCK_ID_BYTES + self.BLOCKSIZE
        self.CIPHERTEXT_SLICE = slice(self.HEADER_BYTES, None, 1)
        self.MIN_STREAM_QUEUE = self.MIN_PADDING_BLOCKS + 1
        self.PADDING_FRAME = self.BLOCKSIZE * self.MIN_STREAM_QUEUE
        self.SENTINEL_BYTES = ceil(self.PADDING_FRAME / 256)
        self.SENTINEL_SLICE = slice(-self.SENTINEL_BYTES, None, 1)

    def _construct_metadata_constant(self) -> None:
        """
        Causes ciphertexts & plaintexts to be distinct & scrambled for
        distinct configurations.

        IMPORTANT FOR SECURITY.
        See:
        https://eprint.iacr.org/2016/292.pdf
        https://csrc.nist.gov/csrc/media/Events/2023/third-workshop-on-
            block-cipher-modes-of-operation/documents/accepted-papers/
            Flexible%20Authenticated%20Encryption.pdf

        DO NOT OVERRIDE TO PROVIDE ITER-OP.
        """
        self.PACKED_METADATA = canonical_pack(
            self.NAME.encode(),
            self.CONFIG_ID,
            self.EPOCH_NS.to_bytes(16, BIG),
            self.BLOCKSIZE.to_bytes(2, BIG),
            self.MIN_PADDING_BLOCKS.to_bytes(2, BIG),
            str(self.SHMAC_SLICE).encode(),
            str(self.BLOCK_ID_SLICE).encode(),
            str(self.SALT_SLICE).encode(),
            str(self.IV_SLICE).encode(),
            str(self.TIMESTAMP_SLICE).encode(),
            str(self.SIV_KEY_SLICE).encode(),
            str(self.SENTINEL_SLICE).encode(),
            self.PRIMER_KEY_BYTES.to_bytes(2, BIG),
            str(self.FIRST_DIGEST_SLICE).encode(),
            self.PERMUTATION_TEST_VECTOR,
            str(self.PERMUTATION_CONFIG_ID).encode(),
            str(self.PERMUTATION_KEY_SLICE).encode(),
            str(self.PERMUTATION_DIGEST_SLICE).encode(),
            str(self.IN_KEY_SLICE).encode(),
            str(self.OUT_KEY_SLICE).encode(),
            str(self.SHMAC_RESULT_SLICE).encode(),
            self.BLOCK_ID_KDF_CONFIG.pad,
            self.BLOCK_ID_KDF_CONFIG.hasher().name.encode(),
            str(self.BLOCK_ID_KDF_CONFIG.key_slice).encode(),
            self.SHMAC_KDF_CONFIG.pad,
            self.SHMAC_KDF_CONFIG.hasher().name.encode(),
            str(self.SHMAC_KDF_CONFIG.key_slice).encode(),
            int_bytes=1,
        )

    def _prepare_kdf_factories(self) -> None:
        """
        Each object part of the authentication & keystream generator
        defined for the cipher is initialized & updated with the
        serialized metadata of this configuration.
        """
        config_id = self.CONFIG_ID
        packed_metadata = self.PACKED_METADATA
        self.BLOCK_ID_KDF_CONFIG.prepare_factory(config_id, packed_metadata)
        for kdf in self.KDF_CONFIGS.values():
            kdf.prepare_factory(config_id, packed_metadata)

    def _perform_dynamic_configuration_from_constants(self) -> None:
        """
        Perform an ordered dynamic setup based on the provided values.
        """
        self._alias_primitives_values()
        self._compute_inner_header_measurements()
        self._compute_header_measurements()
        self._compute_ciphertext_measurements()
        self._compute_permutation_integration_measurements()
        self._construct_metadata_constant()
        self._prepare_kdf_factories()

    def _ensure_blocksize_is_positive(self) -> None:
        """
        A negative or zero blocksize cannot make sense.
        """
        if self.BLOCKSIZE <= 0:
            raise ValueError("BLOCKSIZE *cannot* be 0 or negative!")

    def _ensure_extracted_entropy_less_than_kdf_blocksize(self) -> None:
        """
        The blocksize of the output KDFs is intimately connected with the
        arguments of secuirty for the cipher. Particularly, exposing an
        amount of bytes larger than their internal blocksize, to XOR with
        plaintext, can only have negative impacts on security.
        """
        entropy_window = self.SHMAC_BLOCKSIZE
        if self.BLOCKSIZE > entropy_window:
            raise ValueError("BLOCKSIZE *must* be <= the stream KDF!")

    def _ensure_min_block_id_size_isnt_larger_than_max(self) -> None:
        """
        Sanity check.
        """
        if self.MIN_BLOCK_ID_BYTES > self.MAX_BLOCK_ID_BYTES:
            raise ValueError(
                "The MIN_BLOCK_ID_BYTES mustn't be larger than the "
                "MAX_BLOCK_ID_BYTES."
            )

    def _ensure_max_information_of_block_smaller_than_state(self) -> None:
        """
        Allow for enough space for the plaintext block, ciphertext block,
        & a key-sized portion of the current digest to be fed back into
        the SHMAC object.
        """
        if self.SHMAC_BLOCKSIZE < 2 * self.BLOCKSIZE + 32:
            raise ValueError(
                "The BLOCKSIZE can't be greater than half the block "
                "size of the SHAKE object + 32 bytes."
            )

    def _ensure_inner_header_leaves_adequate_space(self) -> None:
        """
        The inner-header must fit in the first block, therefore the
        blocksize of the cipher cannot be smaller than it. But, the
        available space for the first portion of plaintext must be at
        least 16-bytes. This ensures the possibility space of possible
        plaintexts for even single-block messages is sufficiently large.
        """
        remainder = (
            self.BLOCKSIZE - self.INNER_HEADER_BYTES - self.SENTINEL_BYTES
        ) % self.BLOCKSIZE
        if remainder < 16 and remainder >= 0:
            raise ValueError(
                "BLOCKSIZE - INNER_HEADER - SENTINEL_BYTES *must* leave "
                "at least 16-bytes for the plaintext!",
                remainder,
            )

    def _perform_correctness_checks(self) -> None:
        """
        Perform validity checks for the provided values & subsequent
        dynamic setup.
        """
        self._ensure_blocksize_is_positive()
        self._ensure_extracted_entropy_less_than_kdf_blocksize()
        self._ensure_min_block_id_size_isnt_larger_than_max()
        self._ensure_max_information_of_block_smaller_than_state()
        self._ensure_inner_header_leaves_adequate_space()

    def _ensure_all_attributes_have_been_defined(self) -> None:
        """
        Raise an error if a defined attribute failed to be initialized.
        """
        undefined_attributes = [
            name for name in self.__slots__ if not hasattr(self, name)
        ]
        if undefined_attributes:
            raise UndefinedRequiredAttributes(*undefined_attributes)


module_api = dict(
    ShakePermuteCipherConfig=t.add_type(ShakePermuteCipherConfig),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
