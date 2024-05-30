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


def test_when_new_padding_blocks_are_created():
    for cipher in [Chunky2048(key), Slick256(key)]:
        config = cipher._config
        Pad = Padding(config)
        FIRST_BLOCKSIZE = (
            config.BLOCKSIZE
            - config.INNER_HEADER_BYTES
            - config.SENTINEL_BYTES
        )

        start = config.INNER_HEADER_BYTES
        for n in range(FIRST_BLOCKSIZE + config.BLOCKSIZE):
            pt = n * b"0"
            padded_pt = Pad.pad_plaintext(pt)
            sentinel = int.from_bytes(padded_pt[config.SENTINEL_SLICE], BIG)
            end = -(sentinel if sentinel else config.BLOCKSIZE)

            # The data is prepended with a constant size inner-header &
            # appended with extra padding that is measured by the value of
            # the final byte of padded plaintext modulo the blocksize.
            assert padded_pt[start:end] == pt, f"n={n} : {sentinel=} : {start=} : {end=}"


def test_chunky2048_min_padding_blocks_option():
    from aiootp.ciphers.cipher_kdfs import ShakeConfig
    from aiootp.ciphers.dual_output_shake_cipher_config import DualOutputShakeCipherConfig

    BLOCK_ID_KDF: str = "block_id_kdf"
    SHMAC_KDF: str = "shmac_kdf"
    LEFT_KDF: str = "left_kdf"
    RIGHT_KDF: str = "right_kdf"
    extra_padding: int = token_bits(3) or 1

    config = chunky2048_extra_padding_spec = DualOutputShakeCipherConfig(
        name="Chunky2048ExtraPadding",
        config_id=b"Chunky2048ExtraPadding",
        blocksize=256,
        min_padding_blocks=extra_padding,  # extra padding control
        epoch_ns=EPOCH_NS,
        time_unit=SECONDS,
        timestamp_bytes=4,
        siv_key_bytes=16,
        shmac_bytes=32,
        block_id_bytes=24,
        max_block_id_bytes=32,
        min_block_id_bytes=16,
        salt_bytes=8,
        iv_bytes=8,
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
            key_slice=slice(0, None, 2),
        ),
        right_kdf=RIGHT_KDF,
        right_kdf_config=ShakeConfig(
            name=RIGHT_KDF,
            pad=b"\x36",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(1, None, 2),
        ),
        permutation_type=FastAffineXORChain,
    )

    class Chunky2048ExtraPadding(Chunky2048):
        _config: t.ConfigType = config

    cipher = Chunky2048ExtraPadding(key)
    plaintext = b"padding test"
    ciphertext = cipher.bytes_encrypt(plaintext)

    assert len(plaintext) < config.BLOCKSIZE // 2
    assert plaintext == cipher.bytes_decrypt(ciphertext)
    assert len(ciphertext) == config.HEADER_BYTES + (extra_padding + 1) * config.BLOCKSIZE

    problem = (
        "Differently configured ciphers allowed to interop."
    )
    with Ignore(cipher.InvalidSHMAC, if_else=violation(problem)):
        control_cipher = Chunky2048(key)
        control_config = control_cipher._config
        assert config.PACKED_METADATA != control_config.PACKED_METADATA
        assert config.SHMAC_KDF_CONFIG.factory().digest(32) != control_config.SHMAC_KDF_CONFIG.factory().digest(32)
        control_cipher.bytes_decrypt(ciphertext)


def test_slick256_min_padding_blocks_option():
    from aiootp.ciphers.cipher_kdfs import ShakeConfig
    from aiootp.ciphers.shake_permute_cipher_config import ShakePermuteCipherConfig

    SHMAC_KDF: str = "shmac_kdf"
    BLOCK_ID_KDF: str = "block_id_kdf"
    extra_padding: int = token_bits(3) or 1

    config = slick256_extra_padding_spec = ShakePermuteCipherConfig(
        name="Slick256ExtraPadding",
        config_id=b"Slick256ExtraPadding",
        blocksize=32,
        min_padding_blocks=extra_padding,  # extra padding control
        epoch_ns=EPOCH_NS,
        time_unit=SECONDS,
        timestamp_bytes=4,
        siv_key_bytes=4,
        shmac_bytes=24,
        block_id_bytes=16,
        max_block_id_bytes=32,
        min_block_id_bytes=16,
        salt_bytes=8,
        iv_bytes=8,
        shmac_kdf=SHMAC_KDF,
        shmac_kdf_config=ShakeConfig(
            name=SHMAC_KDF,
            pad=b"\xac",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(None),
        ),
        block_id_kdf=BLOCK_ID_KDF,
        block_id_kdf_config=ShakeConfig(
            name=BLOCK_ID_KDF,
            pad=b"\x9a",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(None),
        ),
        permutation_type=FastAffineXORChain,
    )

    class Slick256ExtraPadding(Slick256):
        _config: t.ConfigType = config

    cipher = Slick256ExtraPadding(key)
    plaintext = b"padding test"
    ciphertext = cipher.bytes_encrypt(plaintext)

    assert len(plaintext) < config.BLOCKSIZE // 2
    assert plaintext == cipher.bytes_decrypt(ciphertext)
    assert len(ciphertext) == config.HEADER_BYTES + (extra_padding + 1) * config.BLOCKSIZE

    problem = (
        "Differently configured ciphers allowed to interop."
    )
    with Ignore(cipher.InvalidSHMAC, if_else=violation(problem)):
        control_cipher = Slick256(key)
        control_config = control_cipher._config
        assert config.PACKED_METADATA != control_config.PACKED_METADATA
        assert config.SHMAC_KDF_CONFIG.factory().digest(32) != control_config.SHMAC_KDF_CONFIG.factory().digest(32)
        control_cipher.bytes_decrypt(ciphertext)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

