# This file is part of aiootp, an asynchronous crypto and anonymity
# library. Home of the Chunky2048 psuedo one-time pad stream cipher.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__doc__  =  "Aggregated Chunky2048 constants."


from math import ceil
from hashlib import sha3_256, sha3_512, shake_128, shake_256


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
SIV_KEY_BYTES = 16


HEADER = "header"

SHMAC = "shmac"
SHMAC_BYTES = 32

BLOCK_ID = "block_id"
BLOCK_ID_BYTES = 24
MAX_BLOCK_ID_BYTES = 32
MIN_BLOCK_ID_BYTES = 16
BLOCK_ID_PAD = b"\xb8"

SALT = "salt"
SALT_BYTES = 16

IV = "iv"
IV_BYTES = 16


SEED_KDF = "seed_kdf"
SEED_KDF_TYPE = type(shake_128())
SEED_PAD = b"\xac"

LEFT_KDF = "left_kdf"
LEFT_KDF_TYPE = type(shake_128())
LEFT_PAD = b"\x5c"

RIGHT_KDF = "right_kdf"
RIGHT_KDF_TYPE = type(shake_128())
RIGHT_PAD = b"\x36"

SHMAC_TYPE = type(shake_128())
SHMAC_PAD = b"\x9a"


CHUNKY_2048 = "Chunky2048"
DECRYPTION = "decryption"
ENCRYPTION = "encryption"
PLAINTEXT = "plaintext"
CIPHERTEXT = "ciphertext"
BLOCKSIZE = 256
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


SEED_KDF_BLOCKSIZE = shake_128().block_size
SEED_KDF_DOUBLE_BLOCKSIZE = 2 * SEED_KDF_BLOCKSIZE
SEED_KDF_OFFSET = (SEED_KDF_BLOCKSIZE // 2) * SEED_PAD
SEED_RATCHET_KEY_SLICE = slice(SEED_KDF_BLOCKSIZE, None)

LEFT_KDF_BLOCKSIZE = shake_128().block_size
LEFT_RATCHET_KEY_SLICE = slice(0, None, 2)  # Even index bytes

RIGHT_KDF_BLOCKSIZE = shake_128().block_size
RIGHT_RATCHET_KEY_SLICE = slice(1, None, 2)  # Odd index bytes

SHMAC_BLOCKSIZE = shake_128().block_size
SHMAC_DOUBLE_BLOCKSIZE = 2 * SHMAC_BLOCKSIZE


CIPHERTEXT_SLICE = slice(HEADER_BYTES, None)
HALF_BLOCKSIZE = BLOCKSIZE // 2
PACKETSIZE = BLOCK_ID_BYTES + BLOCKSIZE
SENTINEL_BYTES_PER_BLOCKSIZE = ceil(BLOCKSIZE / 256)
PADDING_SENTINEL_BYTES = MIN_PADDING_BLOCKS + SENTINEL_BYTES_PER_BLOCKSIZE
MIN_STREAM_QUEUE = MIN_PADDING_BLOCKS + 1


if INNER_HEADER_BYTES % 2:
    # `SyntheticIV` calculations require the len(inner_header) to be
    # even, otherwise plaintext bytes could be leaked when salt reuse
    # / misuse resistance fails.
    raise ValueError("INNER_HEADER_BYTES *cannot* be an odd number!")
elif BLOCKSIZE % 2:
    # The keystream consists of a left & right KDF which produce equal
    # length keys equal to half the blocksize. An odd number blocksize
    # could leak plaintext as the keys may not sum to the blocksize.
    # It also introduces an unnecessary bias.
    raise ValueError("BLOCKSIZE *cannot* be an odd number!")
elif BLOCKSIZE <= 0:
    # A negative or zero blocksize can not make sense.
    raise ValueError("BLOCKSIZE *cannot* be 0 or negative!")
elif LEFT_KDF_BLOCKSIZE != RIGHT_KDF_BLOCKSIZE:
    # The output KDFs have to produce equal digest outputs.
    raise ValueError("left & right blocksizes *must* be equal!")
elif BLOCKSIZE > (LEFT_KDF_BLOCKSIZE + RIGHT_KDF_BLOCKSIZE):
    # The blocksize of the output KDFs is intimately connected with the
    # arguments of secuirty of the cipher. Particularly, exposing an
    # amount of bytes larger than their internal blocksize, to XOR with
    # plaintext, can only have negative impacts on security.
    raise ValueError(
        "BLOCKSIZE *must* sum to <= the left + right blocksizes!"
    )
elif BLOCKSIZE < INNER_HEADER_BYTES:
    # The inner-header must fit in the first block, therefore the
    # blocksize of the cipher cannot be smaller than it.
    raise ValueError(
        "BLOCKSIZE *must* be at least the size of the INNER_HEADER!"
    )
elif BLOCKSIZE < MIN_KEY_BYTES:
    # The cipher produces a stream of keys which are the length of the
    # blocksize, therefore it cannot be smaller than the minimum allowed
    # size for a key.
    raise ValueError(
        "BLOCKSIZE *must* be at least the size of the MIN_KEY_BYTES!"
    )


# Create a binding to the module's name for UI
chunky2048 = {n: v for n, v in globals().items() if n[0].isupper()}
chunky2048["__all__"] = [*chunky2048]

