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


__doc__ = (
    "A collection constants & precomputed values to standardize, speed "
    "up, & clean up their usage in the package."
)


import hashlib
from hashlib import sha3_256, sha3_512, shake_128, shake_256

from aiootp._typing import Typing as t

from . import NamespaceMapping, collect_non_private_constants


INT_BYTES: int = 8
B_TO_MB_RATIO: int = 1024 * 1024

BYTES_FLAG: bytes = b"\x01\x02"
BYTES_FLAG_SIZE: int = 2

FILENAME_HASH_BYTES: int = 24

EPOCH: int = 1672531200  # Sun, 01 Jan 2023 00:00:00 UTC
SAFE_TIMESTAMP_BYTES: int = 8
DEFAULT_TTL: int = 0
DEFAULT_TIMEOUT: int = 0
NS_TO_S_RATIO: int = 1_000_000_000


OMITTED: str = "<omitted>"

TB_PORT: int = 9150
TOR_PORT: int = 9050

_algorithms_available: t.Set[str] = set(hashlib.algorithms_available)
HASHER_TYPES: NamespaceMapping = NamespaceMapping(**{
    str(name): NamespaceMapping(
        factory=factory,
        digest_size=factory().digest_size,
        block_size=factory().block_size,
    )
    for name, factory in hashlib.__dict__.items()
    if name in _algorithms_available
})
SHA3_STATE_SIZE: int = 200
SHA3_256_BLOCKSIZE: int = sha3_256().block_size
SHA3_512_BLOCKSIZE: int = sha3_512().block_size
SHAKE_128_BLOCKSIZE: int = shake_128().block_size
SHAKE_256_BLOCKSIZE: int = shake_256().block_size

MIN_KEY_BYTES: int = 64
DEFAULT_AAD: bytes = b""


# String Names:
ACTIVE: str = "active_connection"
ADDRESS: str = "address"
ADMIN: str = "admin"
AAD: str = "aad"
AGE: str = "age_of_connection"
AIOOTP: str = "aiootp"
ASYNC: str = "asynchronous"
AUTHENTICATED_ASSOCIATED_DATA: str = "authenticated_associated_data"
AUTHENTICATION: str = "authentication"
AUTHENTICATION_KEY: str = "authentication_key"
BIG: str = "big"
BLOCK_ID: str = "block_id"
CHANNEL: str = "channel"
CHANNELS: str = "channels"
CHECKSUM: str = "checksum"
CHECKSUMS: str = "checksums"
CHUNKY_2048: str = "Chunky2048"
CIPHERTEXT: str = "ciphertext"
CLIENT: str = "client"
CLIENT_ADDRESS: str = "client_address"
CLIENT_ID: str = "client_id"
CLIENT_INDEX: str = "client_database_index"
CLIENT_KEY: str = "client_key"
CLIENT_MESSAGE_KEY: str = "client_message_key"
CONFIG: str = "config"
CONFIG_ID: str = "CONFIG_ID"
CONFIG_TYPE: str = "CONFIG_TYPE"
CONTROL_BITS: str = "control_bits"
CONVERSATION: str = "conversation"
CORES: str = "cores"
CORRUPT: str = "corrupt"
CPU: str = "cpu"
CSPRNG: str = "cryptographically_secure_prng"
DATABASE: str = "database"
DAY: str = "day"
DAYS: str = "days"
DECRYPT: str = "decrypt"
DECRYPTION: str = "decryption"
DH2: str = "diffie_hellman_2x"
DH3: str = "diffie_hellman_3x"
DIFFIE_HELLMAN: str = "diffie_hellman"
DIRECTORY: str = "directory"
ECDHE: str = "elliptic_curve_diffie_hellman"
EMAIL_ADDRESS: str = "email_address"
ENCRYPT: str = "encrypt"
ENCRYPTION: str = "encryption"
ENCRYPTION_KEY: str = "encryption_key"
ENTROPY: str = "entropy"
EPHEMERAL_KEY: str = "ephemeral_key"
EQUALITY: str = "equality"
EXTENDED_DH_EXCHANGE: str = "extended_diffie_hellman_exchange"
FAILED: str = "failed"
FILE_KEY: str = "file_key"
FILENAME: str = "filename"
GUEST: str = "guest"
GUID_CLOCK_MASK: str = "guid_clock_mask"
GUID_SALT: str = "guid_salt"
HEADER: str = "header"
HMAC: str = "hmac"
HOUR: str = "hour"
HOURS: str = "hours"
HTTP: str = "http"
HTTPS: str = "https"
ID: str = "contact_id"
IDENTITY_KEY: str = "identity_key"
INACTIVE: str = "terminated_connection"
INNER_HEADER: str = "inner_header"
IV: str = "iv"
KEY: str = "key"
KDF: str = "key_derivation_function"
KEEP_ALIVE: str = "keep_alive"
KEY_ID: str = "key_id"
KEYSTREAM: str = "keystream"
LISTENING: str = "listening"
LITTLE: str = "little"
MAINTAINING: str = "maintaining"
MANIFEST: str = "manifest"
MANUAL: str = "manual_mode"
MAX_INACTIVITY: str = "max_inactivity"
MB: str = "mb"
MESSAGE_ID: str = "message_id"
MESSAGE_KEY: str = "message_key"
MESSAGE_NUMBER: str = "message_number"
MESSAGE: str = "message"
MESSAGES: str = "messages"
METADATA: str = "metadata"
METATAG: str = "metatag"
METATAG_KEY: str = "metatag_key"
MICROSECOND: str = "microsecond"
MICROSECONDS: str = "microseconds"
MILLISECOND: str = "millisecond"
MILLISECONDS: str = "milliseconds"
MINUTE: str = "minute"
MINUTES: str = "minutes"
MNEMONIC: str = "mnemonic"
MONTH: str = "month"
MONTHS: str = "months"
NANOSECOND: str = "nanosecond"
NANOSECONDS: str = "nanoseconds"
NEW_CONTACT: str = "new_contact"
OLD_KEY: str = "last_shared_key"
ONION: str = "onion"
PACKAGE_SIGNER: str = "PackageSigner"
PASSCRYPT: str = "passcrypt"
PASSPHRASE: str = "passphrase"
PAYLOAD: str = "payload"
PERIOD_KEY: str = "period_key"
PERIOD_KEYS: str = "period_keys"
PERMUTATION: str = "permutation"
PERMUTATION_KEY: str = "permutation_key"
PHASE: str = "phase"
PHONE_NUMBER: str = "phone_number"
PLAINTEXT: str = "plaintext"
PRNG: str = "pseudo_random_number_generator"
PUBLIC_CREDENTIALS: str = "public_credentials"
PUBLIC_KEY: str = "public_key"
RACHET: str = "rachet_shared_key"
RECEIVING: str = "receiving"
RECEIVING_COUNT: str = "receiving_count"
RECEIVING_KEYS: str = "receiving_keys"
RECEIVING_STREAM: str = "receiving_stream"
REGISTRATION: str = "registration"
RETRY: str = "retry"
SALT: str = "salt"
SALT_SIZE: str = "salt_size"
SCHEMA: str = "schema"
SCOPE: str = "scope"
SECOND: str = "second"
SECONDS: str = "seconds"
SECRET: str = "secret"
SECRET_CREDENTIALS: str = "secret_credentials"
SECRET_KEY: str = "secret_key"
SECURE_CHANNEL: str = "secure_channel"
SEED: str = "seed"
SENDER: str = "sender"
SENDING: str = "sending"
SENDING_COUNT: str = "sending_count"
SENDING_KEYS: str = "sending_keys"
SENDING_STREAM: str = "sending_stream"
SERVER: str = "server"
SERVER_ADDRESS: str = "server_address"
SERVER_ID: str = "server_id"
SERVER_INDEX: str = "server_database_index"
SERVER_KEY: str = "server_key"
SERVER_MESSAGE_KEY: str = "server_message_key"
SESSION_ID: str = "session_id"
SESSION_KEY: str = "session_key"
SESSION_TOKEN: str = "session_tracking_token"
SHARED_KEY: str = "shared_key"
SHARED_KEYS: str = "shared_keys"
SHARED_SECRET: str = "shared_secret"
SHARED_SEED: str = "shared_seed"
SHMAC: str = "shmac"
SIGNAL: str = "signal"
SIGNALS: str = "signals"
SIGNATURE: str = "signature"
SIGNING_KEY: str = "signing_key"
SIV: str = "synthetic_iv"
SIV_KEY: str = "siv_key"
SLICK_256: str = "Slick256"
STATE: str = "state"
STATUS: str = "status"
SUCCESS: str = "success"
SYNC: str = "synchronous"
TAG: str = "tag"
TAG_SIZE: str = "tag_size"
THREAD_SAFE_ENTROPY: str = "thread_safe_entropy"
TIMEOUT: str = "timeout"
TIMESTAMP: str = "timestamp"
TOKEN: str = "token"
TTL: str = "ttl"
UNSENT_MESSAGES: str = "unsent_messages"
URL: str = "url"
USER: str = "user"
USERNAME: str = "username"
UUID: str = "unique_user_id"
VERIFICATION: str = "verification"
VERSIONS: str = "versions"
YEAR: str = "year"
YEARS: str = "years"


# Dynamically Generated:
FILENAME_HASH_SLICE: slice = slice(None, FILENAME_HASH_BYTES)

EPOCH_NS: int = 1_000_000_000 * EPOCH


# Create a binding to the module's definitions for UI
definitions = collect_non_private_constants(globals())


__all__ = [*definitions]


module_api = dict(
    **definitions,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

