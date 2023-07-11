# This file is part of aiootp, an asynchronous crypto and anonymity
# library. Home of the Chunky2048 psuedo one-time pad stream cipher.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__doc__ = (
    "A collection constants & precomputed values to standardize, speed"
    "up, & clean up their usage in the package."
)


import hashlib
from hashlib import sha3_256, sha3_512, shake_128, shake_256


# Config Constants:
BYTE_ORDER = "big"
BIG = "big"
LITTLE = "little"

INT_BYTES = 8

BYTES_FLAG = b"\x01\x02"
BYTES_FLAG_SIZE = 2

EPOCH = 1672531200  # Sun, 01 Jan 2023 00:00:00 UTC
SAFE_TIMESTAMP_BYTES = 8

FILENAME = "filename"
FILENAME_HASH_BYTES = 24

GUID_BYTES = 16
MIN_GUID_BYTES = 12
MAX_GUID_BYTES = 64
MIN_RAW_GUID_BYTES = 10
NODE_NUMBER_BYTES = 1

JSON_DESERIALIZABLE_TYPES = {str, bytes, bytearray}

MESSAGE_ID = "message_id"
MESSAGE_ID_BYTES = 32
MESSAGE_ID_NIBBLES = 64

OMITTED = "<omitted-value>"

PACK_PAD_INDEX = 32

PORT = 8081
TB_PORT = 9150
TOR_PORT = 9050

_algorithms_available = set(hashlib.algorithms_available)
HASHER_TYPES = {
    str(name): value
    for name, value
    in hashlib.__dict__.items()
    if str(name) in _algorithms_available
}
SHA3_256_BLOCKSIZE = sha3_256().block_size
SHA3_256_TYPE = type(sha3_256())
SHA3_512_BLOCKSIZE = sha3_512().block_size
SHA3_512_TYPE = type(sha3_512())
SHAKE_128_BLOCKSIZE = shake_128().block_size
SHAKE_128_TYPE = type(shake_128())
SHAKE_256_BLOCKSIZE = shake_256().block_size
SHAKE_256_TYPE = type(shake_256())

TTL = "ttl"
DEFAULT_TTL = 0
TIMEOUT = "timeout"
DEFAULT_TIMEOUT = 0


# String Names:
ACTIVE = "active_connection"
ADDRESS = "address"
ADMIN = "admin"
AGE = "age_of_connection"
AIOOTP = "aiootp"
ASYNC = "asynchronous"
AUTHENTICATED_ASSOCIATED_DATA = "authenticated_associated_data"
AUTHENTICATION = "authentication"
CHANNEL = "channel"
CHANNELS = "channels"
CHECKSUM = "checksum"
CHECKSUMS = "checksums"
CLIENT = "client"
CLIENT_ADDRESS = "client_address"
CLIENT_ID = "client_id"
CLIENT_INDEX = "client_database_index"
CLIENT_KEY = "client_key"
CLIENT_MESSAGE_KEY = "client_message_key"
CONTROL_BITS = "control_bits"
CONVERSATION = "conversation"
CORRUPT = "corrupt"
CSPRNG = "cryptographically_secure_prng"
DATABASE = "database"
DAY = "day"
DAYS = "days"
DECRYPT = "decrypt"
DH2 = "diffie_hellman_2x"
DH3 = "diffie_hellman_3x"
DIFFIE_HELLMAN = "diffie_hellman"
DIRECTORY = "directory"
ECDHE = "elliptic_curve_diffie_hellman"
EMAIL_ADDRESS = "email_address"
ENCRYPT = "encrypt"
ENTROPY = "entropy"
EPHEMERAL_KEY = "ephemeral_key"
EQUALITY = "equality"
EXTENDED_DH_EXCHANGE = "extended_diffie_hellman_exchange"
FAILED = "failed"
FILE_KEY = "file_key"
GUEST = "guest"
GUID_CLOCK_MASK = "guid_clock_mask"
GUID_SALT = "guid_salt"
HMAC = "hmac"
HOUR = "hour"
HOURS = "hours"
HTTP = "http"
HTTPS = "https"
ID = "contact_id"
IDENTITY_KEY = "identity_key"
INACTIVE = "terminated_connection"
KDF = "key_derivation_function"
KEEP_ALIVE = "keep_alive"
KEY_ID = "key_id"
KEYSTREAM = "keystream"
LISTENING = "listening"
MAINTAINING = "maintaining"
MANIFEST = "manifest"
MANUAL = "manual_mode"
MAX_INACTIVITY = "max_inactivity"
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
PHASE = "phase"
PHONE_NUMBER = "phone_number"
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
SIGNAL = "signal"
SIGNALS = "signals"
SIGNATURE = "signature"
SIGNING_KEY = "signing_key"
STATE = "state"
STATUS = "status"
SUCCESS = "success"
SYNC = "synchronous"
TOKEN = "token"
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


# Create a binding to the module's name for UI
misc = {n: v for n, v in globals().items() if n[0].isupper()}
misc["__all__"] = [*misc]

