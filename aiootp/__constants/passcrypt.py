# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__doc__ = "Aggregated passcrypt constants."


# Config Constants:
PASSPHRASE = "passphrase"
MIN_PASSPHRASE_BYTES = 12

AAD = "aad"
DEFAULT_AAD = b""

SCHEMA = "schema"

TIMESTAMP = "timestamp"
TIMESTAMP_BYTES = 8  # measures nanoseconds
NS_TO_S_RATIO = 1_000_000_000

MB = "mb"
B_TO_MB_RATIO = 1024 * 1024
DEFAULT_MB = 64
MIN_MB = 1
MAX_MB = 256**3
MB_BYTES = 3

CPU = "cpu"
CPU_TO_DIGEST_PAIRS_PER_ROW_RATIO = 2
DEFAULT_CPU = 1
MIN_CPU = 1
MAX_CPU = 256
CPU_BYTES = 1

CORES = "cores"
DEFAULT_CORES = 4
MIN_CORES = 1
MAX_CORES = 256
CORES_BYTES = 1

SALT = "salt"
SALT_SIZE = "salt_size"
DEFAULT_SCHEMA_SALT_SIZE = 8
DEFAULT_SALT_SIZE = 16
MIN_SALT_SIZE = 4
MAX_SALT_SIZE = 256
SALT_SIZE_BYTES = 1

TAG = "tag"
TAG_SIZE = "tag_size"
DEFAULT_SCHEMA_TAG_SIZE = 16
DEFAULT_TAG_SIZE = 64
MIN_TAG_SIZE = 16

PASSCRYPT_PAD = b"\xf2"


# Dynamically Generated:
HEADER_BYTES = (
    TIMESTAMP_BYTES
    + MB_BYTES
    + CPU_BYTES
    + CORES_BYTES
    + SALT_SIZE_BYTES
)
HEADER_NIBBLES = 2 * HEADER_BYTES
HEADER_SLICE = slice(HEADER_BYTES)

TIMESTAMP_NIBBLES = 2 * TIMESTAMP_BYTES
TIMESTAMP_SLICE = slice(TIMESTAMP_BYTES)

MB_NIBBLES = 2 * MB_BYTES
MB_SLICE = slice(TIMESTAMP_BYTES, TIMESTAMP_BYTES + MB_BYTES)
MB_RESOURCE_SAFETY_RANGE = range(MIN_MB, 512)

CPU_NIBBLES = 2 * CPU_BYTES
CPU_SLICE = slice(
    TIMESTAMP_BYTES + MB_BYTES, TIMESTAMP_BYTES + MB_BYTES + CPU_BYTES
)
CPU_RESOURCE_SAFETY_RANGE = range(MIN_CPU, 33)

CORES_NIBBLES = 2 * CORES_BYTES
CORES_SLICE = slice(
    TIMESTAMP_BYTES + MB_BYTES + CPU_BYTES,
    TIMESTAMP_BYTES + MB_BYTES + CPU_BYTES + CORES_BYTES,
)
CORES_RESOURCE_SAFETY_RANGE = range(MIN_CORES, 9)

SALT_SIZE_NIBBLES = 2 * SALT_SIZE_BYTES
SALT_SIZE_SLICE = slice(
    TIMESTAMP_BYTES + MB_BYTES + CPU_BYTES + CORES_BYTES,
    HEADER_BYTES,
)

MIN_SCHEMA_BYTES = HEADER_BYTES + MIN_SALT_SIZE + MIN_TAG_SIZE


# Create a binding to the module's name for UI
passcrypt = {n: v for n, v in globals().items() if n[0].isupper()}
passcrypt["__all__"] = [*passcrypt]

