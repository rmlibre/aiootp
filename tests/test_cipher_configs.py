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


from test_initialization import *

from aiootp.ciphers.cipher_kdfs import ShakeConfig


BLOCK_ID_KDF = "block_id_kdf"
SHMAC_KDF = "shmac_kdf"
LEFT_KDF = "left_kdf"
RIGHT_KDF = "right_kdf"


def new_dual_output_config_copy(
    _config: t.ConfigType,
    *,
    name: str = "DualOutputCipher",
    config_id: bytes = b"DualOutputCipher",
    blocksize: int = 256,
    min_padding_blocks: int = 0,
    epoch_ns: int = EPOCH_NS,
    time_unit: str = SECONDS,
    timestamp_bytes: int = 4,
    siv_key_bytes: int = 16,
    shmac_bytes: int = 32,
    block_id_bytes: int = 24,
    max_block_id_bytes: int = 32,
    min_block_id_bytes: int = 16,
    salt_bytes: int = 8,
    iv_bytes: int = 8,
    permutation_type: type = FastAffineXORChain,
) -> t.ConfigType:
    config = _config.__new__(_config.__class__)
    config.__init__(
        name=name,
        config_id=config_id,
        blocksize=blocksize,
        min_padding_blocks=min_padding_blocks,
        epoch_ns=epoch_ns,
        time_unit=time_unit,
        timestamp_bytes=timestamp_bytes,
        siv_key_bytes=siv_key_bytes,
        shmac_bytes=shmac_bytes,
        block_id_bytes=block_id_bytes,
        max_block_id_bytes=max_block_id_bytes,
        min_block_id_bytes=min_block_id_bytes,
        salt_bytes=salt_bytes,
        iv_bytes=iv_bytes,
        block_id_kdf=BLOCK_ID_KDF,
        block_id_kdf_config=ShakeConfig(
            name=BLOCK_ID_KDF,
            pad=b"\xac",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(None),
        ),
        shmac_kdf=SHMAC_KDF,
        shmac_kdf_config=ShakeConfig(
            name=SHMAC_KDF,
            pad=b"\x9a",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(None),
        ),
        left_kdf=LEFT_KDF,
        left_kdf_config=ShakeConfig(
            name=LEFT_KDF,
            pad=b"\x5c",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(0, None, 2),  # Even index bytes
        ),
        right_kdf=RIGHT_KDF,
        right_kdf_config=ShakeConfig(
            name=RIGHT_KDF,
            pad=b"\x36",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(1, None, 2),  # Odd index bytes
        ),
        permutation_type=permutation_type,
    )
    return config


def new_shake_permute_config_copy(
    _config: t.ConfigType,
    *,
    name: str = "ShakePermuteCipher",
    config_id: bytes = b"ShakePermuteCipher",
    blocksize: int = 32,
    min_padding_blocks: int = 0,
    epoch_ns: int = EPOCH_NS,
    time_unit: str = SECONDS,
    timestamp_bytes: int = 4,
    siv_key_bytes: int = 8,
    shmac_bytes: int = 24,
    block_id_bytes: int = 16,
    max_block_id_bytes: int = 32,
    min_block_id_bytes: int = 16,
    salt_bytes: int = 8,
    iv_bytes: int = 8,
    permutation_type: type = FastAffineXORChain,
) -> t.ConfigType:
    config = _config.__new__(_config.__class__)
    config.__init__(
        name=name,
        config_id=config_id,
        blocksize=blocksize,
        min_padding_blocks=min_padding_blocks,
        epoch_ns=epoch_ns,
        time_unit=time_unit,
        timestamp_bytes=timestamp_bytes,
        siv_key_bytes=siv_key_bytes,
        shmac_bytes=shmac_bytes,
        block_id_bytes=block_id_bytes,
        max_block_id_bytes=max_block_id_bytes,
        min_block_id_bytes=min_block_id_bytes,
        salt_bytes=salt_bytes,
        iv_bytes=iv_bytes,
        block_id_kdf=BLOCK_ID_KDF,
        block_id_kdf_config=ShakeConfig(
            name=BLOCK_ID_KDF,
            pad=b"\x9a",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(None),
        ),
        shmac_kdf=SHMAC_KDF,
        shmac_kdf_config=ShakeConfig(
            name=SHMAC_KDF,
            pad=b"\xac",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(None),
        ),
        permutation_type=permutation_type,
    )
    return config


def new_config_copy(_config: t.ConfigType, **kw) -> t.ConfigType:
    if _config.NAME in dual_output_cipher_names:
        return new_dual_output_config_copy(_config, **kw)
    elif _config.NAME in shake_permute_cipher_names:
        return new_shake_permute_config_copy(_config, **kw)


class TestCipherConfigs:

    async def test_blocksize_must_be_positive(self) -> None:
        problem = (
            "A nonsensical blocksize was allowed."
        )
        for (_config, cipher, salt, aad) in all_ciphers:
            config = _config.__new__(_config.__class__)
            config.BLOCKSIZE = -1
            with Ignore(ValueError, if_else=violation(problem)):
                config._ensure_blocksize_is_positive()

    async def test_extracted_round_entopy_not_larger_than_blocksize(
        self
    ) -> None:
        problem = (
            "More information in plaintext than is passed between KDFs "
            "each round was allowed to be configured."
        )
        for (_config, cipher, salt, aad) in shake_permute_ciphers:
            config = new_config_copy(_config)
            object.__setattr__(config, "BLOCKSIZE", config.SHMAC_BLOCKSIZE + 1)
            with Ignore(ValueError, if_else=violation(problem)):
                config._ensure_extracted_entropy_less_than_kdf_blocksize()

        for (_config, cipher, salt, aad) in dual_output_ciphers:
            config = new_config_copy(_config)
            object.__setattr__(config, "BLOCKSIZE", 2 * config.SHMAC_BLOCKSIZE + 1)
            with Ignore(ValueError, if_else=violation(problem)):
                config._ensure_extracted_entropy_less_than_kdf_blocksize()

    async def test_min_block_id_not_larger_than_max(self) -> None:
        problem = (
            "The minimum block ID was allowed to be larger that the "
            "max."
        )
        for (_config, cipher, salt, aad) in all_ciphers:
            with Ignore(ValueError, if_else=violation(problem)):
                new_config_copy(
                    _config,
                    min_block_id_bytes=24,
                    max_block_id_bytes=23,
                )

    async def test_blocksize_doesnt_overflow_allottable_space_in_shmac_object(
        self
    ) -> None:
        problem = (
            "The blocksize was allowed to take up the space allotted "
            "to other values within a SHMAC object update."
        )
        for (_config, cipher, salt, aad) in shake_permute_ciphers:
            with Ignore(ValueError, if_else=violation(problem)):
                new_shake_permute_config_copy(_config, blocksize=128)

    async def test_inner_header_doesnt_cause_inadequate_space_for_plaintext(
        self
    ) -> None:
        problem = (
            "At least 16 bytes weren't left for plaintext after accounting "
            "for obligatory padding."
        )
        for (_config, cipher, salt, aad) in all_ciphers:
            config = new_config_copy(_config)
            timestamp_bytes = 4
            sentinel_bytes = config.SENTINEL_BYTES
            siv_key_bytes = config.BLOCKSIZE - timestamp_bytes - 16 + sentinel_bytes
            header_bytes = timestamp_bytes + siv_key_bytes
            object.__setattr__(config, "TIMESTAMP_BYTES", timestamp_bytes)
            object.__setattr__(config, "SIV_KEY_BYTES", siv_key_bytes)
            object.__setattr__(config, "INNER_HEADER_BYTES", header_bytes)
            with Ignore(ValueError, if_else=violation(problem)):
                config._ensure_inner_header_leaves_adequate_space()

    async def test_all_attributes_must_be_set(self) -> None:
        problem = (
            "The attribute existence checker didn't proc when an "
            "attribute was missing."
        )
        for (_config, cipher, salt, aad) in all_ciphers:
            config = new_config_copy(_config)
            object.__delattr__(config, await achoice(config.__slots__))
            with Ignore(UndefinedRequiredAttributes, if_else=violation(problem)):
                config._ensure_all_attributes_have_been_defined()


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

