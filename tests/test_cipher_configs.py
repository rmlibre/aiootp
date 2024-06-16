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
    block_id_kdf_config: t.Optional[t.ShakeConfig] = None,
    shmac_kdf_config: t.Optional[t.ShakeConfig] = None,
    left_kdf_config: t.Optional[t.ShakeConfig] = None,
    right_kdf_config: t.Optional[t.ShakeConfig] = None,
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
        ) if block_id_kdf_config is None else block_id_kdf_config,
        shmac_kdf=SHMAC_KDF,
        shmac_kdf_config=ShakeConfig(
            name=SHMAC_KDF,
            pad=b"\x9a",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(None),
        ) if shmac_kdf_config is None else shmac_kdf_config,
        left_kdf=LEFT_KDF,
        left_kdf_config=ShakeConfig(
            name=LEFT_KDF,
            pad=b"\x5c",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(0, None, 2),  # Even index bytes
        ) if left_kdf_config is None else left_kdf_config,
        right_kdf=RIGHT_KDF,
        right_kdf_config=ShakeConfig(
            name=RIGHT_KDF,
            pad=b"\x36",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(1, None, 2),  # Odd index bytes
        ) if right_kdf_config is None else right_kdf_config,
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
    block_id_kdf_config: t.Optional[t.ShakeConfig] = None,
    shmac_kdf_config: t.Optional[t.ShakeConfig] = None,
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
        ) if block_id_kdf_config is None else block_id_kdf_config,
        shmac_kdf=SHMAC_KDF,
        shmac_kdf_config=ShakeConfig(
            name=SHMAC_KDF,
            pad=b"\xac",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(None),
        ) if shmac_kdf_config is None else shmac_kdf_config,
        permutation_type=permutation_type,
    )
    return config


def new_config_copy(_config: t.ConfigType, **kw) -> t.ConfigType:
    if _config.NAME in dual_output_cipher_names:
        return new_dual_output_config_copy(_config, **kw)
    elif _config.NAME in shake_permute_cipher_names:
        return new_shake_permute_config_copy(_config, **kw)


class TestCipherConfigs:

    async def test_inner_header_size_must_be_even(self) -> None:
        problem = (
            "An odd sized inner-header was allowed to be configured."
        )
        for (_config, *_) in dual_output_ciphers:
            with Ignore(ValueError, if_else=violation(problem)):
                new_dual_output_config_copy(
                    _config, timestamp_bytes=4, siv_key_bytes=11
                )

    async def test_blocksize_size_must_be_even(self) -> None:
        problem = (
            "An odd blocksize was allowed to be configured."
        )
        for (_config, *_) in dual_output_ciphers:
            with Ignore(ValueError, if_else=violation(problem)):
                new_dual_output_config_copy(_config, blocksize=255)

    async def test_blocksize_must_be_positive(self) -> None:
        problem = (
            "A nonsensical blocksize was allowed."
        )
        for (_config, *_) in all_ciphers:
            config = _config.__new__(_config.__class__)
            config.BLOCKSIZE = -1
            with Ignore(ValueError, if_else=violation(problem)):
                config._ensure_blocksize_is_positive()

    async def test_left_right_kdf_blocksizes_are_equal(self) -> None:
        problem = (
            "Non-equal left & right KDF blocksizes were allowed to be "
            "configured."
        )
        for (_config, *_) in dual_output_ciphers:
            with Ignore(ValueError, if_else=violation(problem)):
                new_dual_output_config_copy(
                    _config,
                    left_kdf_config=ShakeConfig(
                        name=LEFT_KDF,
                        pad=b"\x5c",
                        offset_amount=0,
                        hasher=shake_256,
                        key_slice=slice(0, None, 2),
                    ),
                    right_kdf_config=ShakeConfig(
                        name=RIGHT_KDF,
                        pad=b"\x36",
                        offset_amount=0,
                        hasher=shake_128,
                        key_slice=slice(1, None, 2),
                    ),
                )

    async def test_extracted_round_entopy_not_larger_than_blocksize(
        self
    ) -> None:
        problem = (
            "More information in plaintext than is passed between KDFs "
            "each round was allowed to be configured."
        )
        for (_config, *_) in shake_permute_ciphers:
            config = new_config_copy(_config)
            object.__setattr__(config, "BLOCKSIZE", config.SHMAC_BLOCKSIZE + 1)
            with Ignore(ValueError, if_else=violation(problem)):
                config._ensure_extracted_entropy_less_than_kdf_blocksize()

        for (_config, *_) in dual_output_ciphers:
            config = new_config_copy(_config)
            object.__setattr__(config, "BLOCKSIZE", 2 * config.SHMAC_BLOCKSIZE + 1)
            with Ignore(ValueError, if_else=violation(problem)):
                config._ensure_extracted_entropy_less_than_kdf_blocksize()

    async def test_min_block_id_not_larger_than_max(self) -> None:
        problem = (
            "The minimum block ID was allowed to be larger that the "
            "max."
        )
        for (_config, *_) in all_ciphers:
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
        for (_config, *_) in shake_permute_ciphers:
            with Ignore(ValueError, if_else=violation(problem)):
                new_shake_permute_config_copy(_config, blocksize=128)

    async def test_inner_header_doesnt_cause_inadequate_space_for_plaintext(
        self
    ) -> None:
        problem = (
            "At least 16 bytes weren't left for plaintext after accounting "
            "for obligatory padding."
        )
        for (_config, *_) in all_ciphers:
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
        for (_config, *_) in all_ciphers:
            config = new_config_copy(_config)
            object.__delattr__(config, await achoice(config.__slots__))
            with Ignore(UndefinedRequiredAttributes, if_else=violation(problem)):
                config._ensure_all_attributes_have_been_defined()

    async def test_min_padding_blocks_alters_min_ciphertext_size(self) -> None:
        extra_padding = token_bits(3) or 1
        for (control_config, control_cipher, *_) in all_ciphers:
            config = new_config_copy(control_config, min_padding_blocks=extra_padding)

            class ExtraPaddingCipher(control_cipher.__class__):
                __slots__ = ()
                _config: t.ConfigType = config

            cipher = ExtraPaddingCipher(key)
            plaintext = b"padding test"
            assert len(plaintext) < (
                control_config.BLOCKSIZE
                - control_config.INNER_HEADER_BYTES
                - control_config.SENTINEL_BYTES
            )
            assert len(plaintext) < (
                config.BLOCKSIZE
                - config.INNER_HEADER_BYTES
                - config.SENTINEL_BYTES
            )

            control_ciphertext = control_cipher.bytes_encrypt(plaintext)
            assert len(control_ciphertext) == control_config.HEADER_BYTES + control_config.BLOCKSIZE

            ciphertext = cipher.bytes_encrypt(plaintext)
            assert len(ciphertext) == config.HEADER_BYTES + (extra_padding + 1) * config.BLOCKSIZE
            assert plaintext == cipher.bytes_decrypt(ciphertext)

    async def test_altered_config_alters_initial_kdf_states(self) -> None:
        problem = (
            "Differently configured ciphers allowed to interop."
        )
        for (control_config, control_cipher, salt, aad) in all_ciphers:
            config = new_config_copy(control_config, name="AlteredCipher")
            assert config.PACKED_METADATA != control_config.PACKED_METADATA
            assert config.SHMAC_KDF_CONFIG.factory().digest(32) != control_config.SHMAC_KDF_CONFIG.factory().digest(32)

            class AlteredCipher(control_cipher.__class__):
                __slots__ = ()
                _config: t.ConfigType = config

            cipher = AlteredCipher(key)
            plaintext = b"kdf test"
            ciphertext = cipher.bytes_encrypt(plaintext, salt=salt, aad=aad)
            with Ignore(cipher.InvalidSHMAC, if_else=violation(problem)):
                control_cipher.bytes_decrypt(ciphertext, aad=aad)

    async def test_large_siv_key_is_supported(self) -> None:
        control_config, control_cipher, salt, aad = MemoizedCipher(Slick256)
        config = new_config_copy(control_config, siv_key_bytes=28)

        class LargeSIVKeyCipher(control_cipher.__class__):
            __slots__ = ()
            _config: t.ConfigType = config

        cipher = LargeSIVKeyCipher(key)

        plaintext = b"siv key test"
        ciphertext = cipher.bytes_encrypt(plaintext, salt=salt, aad=aad)
        assert plaintext == cipher.bytes_decrypt(ciphertext, aad=aad)

        enc_stream = await cipher.astream_encrypt(salt=salt, aad=aad)
        ciphertext = b"".join([b"".join(id_ct) async for id_ct in await enc_stream.abuffer(plaintext)])
        ciphertext += b"".join([b"".join(id_ct) async for id_ct in enc_stream.afinalize()])
        dec_stream = await cipher.astream_decrypt(salt=salt, aad=aad, iv=enc_stream.iv)
        result = b"".join([block async for block in await dec_stream.abuffer(ciphertext)])
        result += b"".join([block async for block in dec_stream.afinalize()])
        await dec_stream.shmac.atest_shmac(enc_stream.shmac.result)
        assert plaintext == result

        enc_stream = cipher.stream_encrypt(salt=salt, aad=aad)
        ciphertext = b"".join(b"".join(id_ct) for id_ct in enc_stream.buffer(plaintext))
        ciphertext += b"".join(b"".join(id_ct) for id_ct in enc_stream.finalize())
        dec_stream = cipher.stream_decrypt(salt=salt, aad=aad, iv=enc_stream.iv)
        result = b"".join(dec_stream.buffer(ciphertext))
        result += b"".join(dec_stream.finalize())
        dec_stream.shmac.test_shmac(enc_stream.shmac.result)
        assert plaintext == result


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

