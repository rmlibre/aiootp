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

from . import NamespaceMapping, collect_non_private_constants


INT_BYTES = 8
B_TO_MB_RATIO = 1024 * 1024

BYTES_FLAG = b"\x01\x02"
BYTES_FLAG_SIZE = 2

FILENAME_HASH_BYTES = 24

EPOCH = 1672531200  # Sun, 01 Jan 2023 00:00:00 UTC
SAFE_TIMESTAMP_BYTES: int = 8
DEFAULT_TTL: int = 0
DEFAULT_TIMEOUT: int = 0
NS_TO_S_RATIO: int = 1_000_000_000


OMITTED = "<omitted>"

TB_PORT = 9150
TOR_PORT = 9050

_algorithms_available = set(hashlib.algorithms_available)
HASHER_TYPES = NamespaceMapping(**{
    str(name): NamespaceMapping(
        factory=factory,
        cls=factory().__class__,
        digest_size=factory().digest_size,
        block_size=factory().block_size,
    )
    for name, factory in hashlib.__dict__.items()
    if name in _algorithms_available
})
SHA3_STATE_SIZE = 200
SHA3_256_BLOCKSIZE = sha3_256().block_size
SHA3_256_TYPE = type(sha3_256())
SHA3_512_BLOCKSIZE = sha3_512().block_size
SHA3_512_TYPE = type(sha3_512())
SHAKE_128_BLOCKSIZE = shake_128().block_size
SHAKE_128_TYPE = type(shake_128())
SHAKE_256_BLOCKSIZE = shake_256().block_size
SHAKE_256_TYPE = type(shake_256())

MIN_KEY_BYTES = 64
DEFAULT_AAD = b""


# String Names:
ACTIVE = "active_connection"
ADDRESS = "address"
ADMIN = "admin"
AAD = "aad"
AGE = "age_of_connection"
AIOOTP = "aiootp"
ASYNC = "asynchronous"
AUTHENTICATED_ASSOCIATED_DATA = "authenticated_associated_data"
AUTHENTICATION = "authentication"
BIG = "big"
BLOCK_ID = "block_id"
CHANNEL = "channel"
CHANNELS = "channels"
CHECKSUM = "checksum"
CHECKSUMS = "checksums"
CHUNKY_2048 = "Chunky2048"
CIPHERTEXT = "ciphertext"
CLIENT = "client"
CLIENT_ADDRESS = "client_address"
CLIENT_ID = "client_id"
CLIENT_INDEX = "client_database_index"
CLIENT_KEY = "client_key"
CLIENT_MESSAGE_KEY = "client_message_key"
CONFIG = "config"
CONFIG_ID = "CONFIG_ID"
CONFIG_TYPE = "CONFIG_TYPE"
CONTROL_BITS = "control_bits"
CONVERSATION = "conversation"
CORES = "cores"
CORRUPT = "corrupt"
CPU = "cpu"
CSPRNG = "cryptographically_secure_prng"
DATABASE = "database"
DAY = "day"
DAYS = "days"
DECRYPT = "decrypt"
DECRYPTION = "decryption"
DH2 = "diffie_hellman_2x"
DH3 = "diffie_hellman_3x"
DIFFIE_HELLMAN = "diffie_hellman"
DIRECTORY = "directory"
ECDHE = "elliptic_curve_diffie_hellman"
EMAIL_ADDRESS = "email_address"
ENCRYPT = "encrypt"
ENCRYPTION = "encryption"
ENTROPY = "entropy"
EPHEMERAL_KEY = "ephemeral_key"
EQUALITY = "equality"
EXTENDED_DH_EXCHANGE = "extended_diffie_hellman_exchange"
FAILED = "failed"
FILE_KEY = "file_key"
FILENAME = "filename"
GUEST = "guest"
GUID_CLOCK_MASK = "guid_clock_mask"
GUID_SALT = "guid_salt"
HEADER = "header"
HMAC = "hmac"
HOUR = "hour"
HOURS = "hours"
HTTP = "http"
HTTPS = "https"
ID = "contact_id"
IDENTITY_KEY = "identity_key"
INACTIVE = "terminated_connection"
INNER_HEADER = "inner_header"
IV = "iv"
KEY = "key"
KDF = "key_derivation_function"
KEEP_ALIVE = "keep_alive"
KEY_ID = "key_id"
KEYSTREAM = "keystream"
LISTENING = "listening"
LITTLE = "little"
MAINTAINING = "maintaining"
MANIFEST = "manifest"
MANUAL = "manual_mode"
MAX_INACTIVITY = "max_inactivity"
MB = "mb"
MESSAGE_ID = "message_id"
MESSAGE_KEY = "message_key"
MESSAGE_NUMBER = "message_number"
MESSAGE = "message"
MESSAGES = "messages"
METADATA = "metadata"
METATAG = "metatag"
METATAG_KEY = "metatag_key"
MICROSECOND = "microsecond"
MICROSECONDS = "microseconds"
MILLISECOND = "millisecond"
MILLISECONDS = "milliseconds"
MINUTE = "minute"
MINUTES = "minutes"
MNEMONIC = "mnemonic"
MONTH = "month"
MONTHS = "months"
NANOSECOND = "nanosecond"
NANOSECONDS = "nanoseconds"
NEW_CONTACT = "new_contact"
OLD_KEY = "last_shared_key"
ONION = "onion"
PACKAGE_SIGNER = "PackageSigner"
PASSCRYPT = "passcrypt"
PASSPHRASE = "passphrase"
PAYLOAD = "payload"
PERIOD_KEY = "period_key"
PERIOD_KEYS = "period_keys"
PERMUTATION = "permutation"
PERMUTATION_KEY = "permutation_key"
PHASE = "phase"
PHONE_NUMBER = "phone_number"
PLAINTEXT = "plaintext"
PRNG = "pseudo_random_number_generator"
PUBLIC_CREDENTIALS = "public_credentials"
PUBLIC_KEY = "public_key"
RACHET = "rachet_shared_key"
RECEIVING = "receiving"
RECEIVING_COUNT = "receiving_count"
RECEIVING_KEYS = "receiving_keys"
RECEIVING_STREAM = "receiving_stream"
REGISTRATION = "registration"
RETRY = "retry"
SALT = "salt"
SALT_SIZE = "salt_size"
SCHEMA = "schema"
SCOPE = "scope"
SECOND = "second"
SECONDS = "seconds"
SECRET = "secret"
SECRET_CREDENTIALS = "secret_credentials"
SECRET_KEY = "secret_key"
SECURE_CHANNEL = "secure_channel"
SEED = "seed"
SENDER = "sender"
SENDING = "sending"
SENDING_COUNT = "sending_count"
SENDING_KEYS = "sending_keys"
SENDING_STREAM = "sending_stream"
SERVER = "server"
SERVER_ADDRESS = "server_address"
SERVER_ID = "server_id"
SERVER_INDEX = "server_database_index"
SERVER_KEY = "server_key"
SERVER_MESSAGE_KEY = "server_message_key"
SESSION_ID = "session_id"
SESSION_KEY = "session_key"
SESSION_TOKEN = "session_tracking_token"
SHARED_KEY = "shared_key"
SHARED_KEYS = "shared_keys"
SHARED_SECRET = "shared_secret"
SHARED_SEED = "shared_seed"
SHMAC = "shmac"
SIGNAL = "signal"
SIGNALS = "signals"
SIGNATURE = "signature"
SIGNING_KEY = "signing_key"
SIV = "synthetic_iv"
SIV_KEY = "siv_key"
SLICK_256 = "Slick256"
STATE = "state"
STATUS = "status"
SUCCESS = "success"
SYNC = "synchronous"
TAG = "tag"
TAG_SIZE = "tag_size"
THREAD_SAFE_ENTROPY = "thread_safe_entropy"
TIMEOUT = "timeout"
TIMESTAMP = "timestamp"
TOKEN = "token"
TTL = "ttl"
UNSENT_MESSAGES = "unsent_messages"
URL = "url"
USER = "user"
USERNAME = "username"
UUID = "unique_user_id"
VERIFICATION = "verification"
VERSIONS = "versions"
YEAR = "year"
YEARS = "years"


# Dynamically Generated:
EPOCH_NS = 1_000_000_000 * EPOCH
EPOCH_TIMESTAMP = EPOCH.to_bytes(8, BIG)
EPOCH_NS_TIMESTAMP = EPOCH_NS.to_bytes(8, BIG)

FILENAME_HASH_SLICE = slice(None, FILENAME_HASH_BYTES)


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

