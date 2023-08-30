# This file is part of aiootp, an asynchronous crypto and anonymity
# library. Home of the Chunky2048 psuedo one-time pad stream cipher.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__doc__  =  "Aggregated Slick256 constants."


from math import ceil
from hashlib import shake_128

from . import SimpleNamespace, EPOCH_NS


# Config Constants:
KEY = "key"
KEY_BYTES = 168
MIN_KEY_BYTES = 64

AAD = "aad"
DEFAULT_AAD = b""


INNER_HEADER = "inner_header"

TIMESTAMP = "timestamp"
TIMESTAMP_BYTES = 4  # measures seconds

SIV_KEY = "siv_key"
SIV_KEY_BYTES = 11


HEADER = "header"

SHMAC = "shmac"
SHMAC_BYTES = 16

BLOCK_ID = "block_id"
BLOCK_ID_BYTES = 16
MAX_BLOCK_ID_BYTES = 32
MIN_BLOCK_ID_BYTES = 8
BLOCK_ID_PAD = b"\xb8"

SALT = "salt"
SALT_BYTES = 8

IV = "iv"
IV_BYTES = 8


FRONT_KDF = "front_seed_kdf"
FRONT_KDF_TYPE = type(shake_128())
FRONT_PAD = b"\x5c"
FRONT_KDF_OFFSET = 0
FRONT_KDF_HASHER = shake_128

BACK_KDF = "back_seed_kdf"
BACK_KDF_TYPE = type(shake_128())
BACK_PAD = b"\x36"
BACK_KDF_OFFSET = 0
BACK_KDF_HASHER = shake_128

SHMAC_MAC = "shmac_mac"
SHMAC_TYPE = type(shake_128())
SHMAC_PAD = b"\x9a"
SHMAC_MAC_OFFSET = 0
SHMAC_MAC_HASHER = shake_128


SLICK_256 = "Slick256"
DECRYPTION = "decryption"
ENCRYPTION = "encryption"
PLAINTEXT = "plaintext"
CIPHERTEXT = "ciphertext"
BLOCKSIZE = 32
MIN_PADDING_BLOCKS = 0


# Dynamically Generated:
KEY_NIBBLES = 2 * KEY_BYTES
MIN_KEY_NIBBLES = 2 * MIN_KEY_BYTES


INNER_BODY_SLICE = slice(TIMESTAMP_BYTES + SIV_KEY_BYTES, None)
INNER_HEADER_BYTES = TIMESTAMP_BYTES + SIV_KEY_BYTES
INNER_HEADER_NIBBLES = 2 * INNER_HEADER_BYTES
INNER_HEADER_SLICE = slice(None, INNER_HEADER_BYTES)

TIMESTAMP_NIBBLES = 2 * TIMESTAMP_BYTES
TIMESTAMP_SLICE = slice(TIMESTAMP_BYTES)

SIV_KEY_NIBBLES = 2 * SIV_KEY_BYTES
SIV_KEY_SLICE = slice(TIMESTAMP_BYTES, INNER_HEADER_BYTES)


HEADER_BYTES = SHMAC_BYTES + SALT_BYTES + IV_BYTES
HEADER_NIBBLES = 2 * HEADER_BYTES
HEADER_SLICE = slice(None, HEADER_BYTES)

SHMAC_NIBBLES = 2 * SHMAC_BYTES
SHMAC_SLICE = slice(SHMAC_BYTES)

BLOCK_ID_NIBBLES = 2 * BLOCK_ID_BYTES
BLOCK_ID_SLICE = slice(None, BLOCK_ID_BYTES)
MAX_BLOCK_ID_NIBBLES = 2 * MAX_BLOCK_ID_BYTES
MIN_BLOCK_ID_NIBBLES = 2 * MIN_BLOCK_ID_BYTES

SALT_NIBBLES = 2 * SALT_BYTES
SALT_SLICE = slice(SHMAC_BYTES, SHMAC_BYTES + SALT_BYTES)

IV_NIBBLES = 2 * IV_BYTES
IV_SLICE = slice(SHMAC_BYTES + SALT_BYTES, HEADER_BYTES)


FRONT_KDF_BLOCKSIZE = FRONT_KDF_HASHER().block_size

BACK_KDF_BLOCKSIZE = BACK_KDF_HASHER().block_size

SHMAC_BLOCKSIZE = SHMAC_MAC_HASHER().block_size
SHMAC_DOUBLE_BLOCKSIZE = 2 * SHMAC_BLOCKSIZE


KDF_SETTINGS = SimpleNamespace(**{
    FRONT_KDF: SimpleNamespace(
        pad=FRONT_PAD,
        offset=FRONT_PAD * FRONT_KDF_OFFSET,
        blocksize=FRONT_KDF_BLOCKSIZE,
        hasher=FRONT_KDF_HASHER,
    ),
    BACK_KDF: SimpleNamespace(
        pad=BACK_PAD,
        offset=BACK_PAD * BACK_KDF_OFFSET,
        blocksize=BACK_KDF_BLOCKSIZE,
        hasher=BACK_KDF_HASHER,
    ),
    SHMAC_MAC: SimpleNamespace(
        pad=SHMAC_PAD,
        offset=SHMAC_PAD * SHMAC_MAC_OFFSET,
        blocksize=SHMAC_BLOCKSIZE,
        hasher=SHMAC_MAC_HASHER,
    ),
})


CIPHERTEXT_SLICE = slice(HEADER_BYTES, None)
HALF_BLOCKSIZE = BLOCKSIZE // 2
PACKETSIZE = BLOCK_ID_BYTES + BLOCKSIZE
SENTINEL_BYTES_PER_BLOCKSIZE = ceil(BLOCKSIZE / 256)
PADDING_SENTINEL_BYTES = MIN_PADDING_BLOCKS + SENTINEL_BYTES_PER_BLOCKSIZE
MIN_STREAM_QUEUE = MIN_PADDING_BLOCKS + 1


if BLOCKSIZE <= 0:
    # A negative or zero blocksize cannot make sense.
    raise ValueError("BLOCKSIZE *cannot* be 0 or negative!")
elif BLOCKSIZE > FRONT_KDF_BLOCKSIZE:
    # The blocksize of the output KDFs is intimately connected with the
    # arguments of secuirty of the cipher. Particularly, exposing an
    # amount of bytes larger than their internal blocksize, to XOR with
    # plaintext, can only have negative impacts on security.
    raise ValueError(
        "The output BLOCKSIZE of the cipher *must* be <= the internal "
        "KDF blocksizes!"
    )
elif (
    (SHMAC_BLOCKSIZE != FRONT_KDF_BLOCKSIZE)
    or (FRONT_KDF_BLOCKSIZE != BACK_KDF_BLOCKSIZE)
):
    raise ValueError("cipher KDF blocksizes *must* be equal!")
elif (BLOCKSIZE - INNER_HEADER_BYTES) < 16:
    # The inner-header must fit in the first block, therefore the
    # blocksize of the cipher cannot be smaller than it. But, the
    # available space for the first portion of plaintext must be at
    # least 16-bytes. This ensures the possibility space of possible
    # plaintexts for even single-block messages is sufficiently large.
    raise ValueError(
        "BLOCKSIZE - INNER_HEADER *must* leave at least 16-bytes for "
        "the first block of plaintext!"
    )


# Create a binding to the module's name for UI
slick256 = {n: v for n, v in globals().items() if n[0].isupper()}
slick256["__all__"] = [*slick256]

