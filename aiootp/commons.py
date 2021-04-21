# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "commons",
    "bits",
    "primes",
    "Namespace",
    "WORD_LIST",
    "ASCII_TABLE",
    "BYTES_TABLE",
    "BASE_36_TABLE",
    "BASE_38_TABLE",
    "BASE_64_TABLE",
    "URL_SAFE_TABLE",
    "ASCII_TABLE_128",
    "ONION_CHAR_TABLE",
    "ASCII_ALPHANUMERIC",
]


__doc__ = (
    "A module used to aggregate commonly used constants & arbitrary "
    "utilities."
)


import sys
import copy
import types
import asyncio
from os import linesep
from .__datasets import *
from . import DebugControl


async def aimport_namespace(
    dictionary=None, *, mapping=None, deepcopy=False
):
    """
    Takes a ``dictionary``, such as ``globals()``, and copies the
    key-value pairs from the ``mapping`` kwarg into it.
    """
    if deepcopy == True:
        dictionary.update(copy.deepcopy(mapping))
    else:
        dictionary.update(dict(mapping))
    await asyncio.sleep(0)


def import_namespace(dictionary=None, *, mapping=None, deepcopy=False):
    """
    Takes a ``dictionary``, such as ``globals()``, and copies the
    key-value pairs from the ``mapping`` kwarg into it.
    """
    if deepcopy == True:
        dictionary.update(copy.deepcopy(mapping))
    else:
        dictionary.update(dict(mapping))


async def acreate_namespace(mapping=None, **kwargs):
    """
    Takes in a mapping of key-value pairs and returns a Namespace object
    that allows dotted lookup & assignment on the mapping. The
    mappings are mutated when the user mutates Namespace object values.
    """
    return Namespace(mapping, **kwargs)


def create_namespace(mapping=None, **kwargs):
    """
    Takes in a mapping of key-value pairs and returns a Namespace object
    that allows dotted lookup & assignment on the mapping. The
    mappings are mutated when the user mutates Namespace object values.
    """
    return Namespace(mapping, **kwargs)


async def amake_module(name=None, *, mapping=None, deepcopy=False):
    """
    Turns a mapping into a module object version of a Namespace which is
    importable using normal python syntax.
    """
    module = types.ModuleType(name)
    await aimport_namespace(
        module.__dict__, mapping=mapping, deepcopy=deepcopy
    )
    sys.modules[name] = module
    return Namespace(module.__dict__)


def make_module(name=None, *, mapping=None, deepcopy=False):
    """
    Turns a mapping into a module object version of a Namespace which is
    importable using normal python syntax.
    """
    module = types.ModuleType(name)
    import_namespace(module.__dict__, mapping=mapping, deepcopy=deepcopy)
    sys.modules[name] = module
    return Namespace(module.__dict__)


class Namespace():
    """
    A simple wrapper for turning mappings into Namespace objects that
    allow dotted lookup and assignment on those mappings. Also, provides
    utilities for copying mappings into other containers, & turning
    mappings into stand-alone, first-class modules.
    """

    amake_module = staticmethod(amake_module)
    make_module = staticmethod(make_module)
    acreate_namespace = staticmethod(acreate_namespace)
    create_namespace = staticmethod(create_namespace)
    aimport_namespace = staticmethod(aimport_namespace)
    import_namespace = staticmethod(import_namespace)

    def __init__(self, mapping={}, **kwargs):
        """
        Maps the user-defined mapping & kwargs to the Namespace's
        instance dictionary.
        """
        self.__dict__.update({**mapping, **kwargs})

    @property
    def __all__(self):
        """
        Allows users that have turned their Namespace into a Module
        object to do a ``from namespace import *`` on the contents of
        the namespace's mapping. This method excludes exporting dunder
        methods.
        """
        exports = {
            var: val for var, val in self.__dict__.items()
            if not (var.startswith("__") and var.endswith("__"))
        }
        return exports

    def __len__(self):
        """
        Returns the number of elements in the Namespace's mapping.
        """
        return len(self.__dict__)

    def __bool__(self):
        """
        If the namespace is empty then return False, otherwise True.
        """
        return bool(self.__dict__)

    def __str__(self, *, tab=4 * " "):
        """
        Pretty displays the Namespace's mapping.
        """
        result = self.__class__.__qualname__
        result += f"({linesep}" + "    mapping={"
        ending = f"{linesep}" + "    }" + f"{linesep})"
        spacer = f"{linesep + 2 * tab}"
        if DebugControl.is_debugging():
            for variable, value in self:
                result += spacer + f"{variable}:\t{repr(value)},"
        else:
            for variable, value in self:
                exists = (bool(value) and "is <truthy>") or "is <falsey>"
                omitted_value = f"{OMITTED} of {type(value)} {exists}"
                result += spacer + f"{variable}:\t{omitted_value},"
        return result + ending

    def __repr__(self):
        """
        Pretty displays the Namespace's mapping.
        """
        return str(self)

    def __dir__(self):
        """
        Returns the list of names in the Namespace's mapping.
        """
        return list(self.__dict__.keys())

    def __setitem__(self, variable, value):
        """
        Transforms bracket item assignment into dotted assignment on the
        Namespace's mapping.
        """
        self.__dict__[variable] = value

    def __getitem__(self, variable):
        """
        Transforms bracket lookup into dotted access on the Namespace's
        mapping.
        """
        try:
            return self.__dict__[variable]
        except KeyError:
            return getattr(self, variable)

    def __iter__(self):
        """
        Allows Namespace's to be unpacked with tools like ``dict`` &
        ``list``.
        """
        for variable, value in dict(self.__dict__).items():
            yield variable, value

    async def __aiter__(self):
        """
        Allows Namespace's to be unpacked with with async iteration.
        """
        for variable, value in dict(self.__dict__).items():
            await asyncio.sleep(0)
            yield variable, value

    def __contains__(self, variable=None):
        """
        Returns a bool of ``variable``'s membership in the instance
        dictionary.
        """
        return variable in self.__dict__

    def __delitem__(self, variable=None):
        """
        Deletes the item ``variable`` from the instance dictionary.
        """
        del self.__dict__[variable]

    @property
    def namespace(self):
        """
        Cleaner name for users to access the instance's dictionary.
        """
        return self.__dict__

    def keys(self):
        """
        Yields the names of all items in the namespace.
        """
        yield from (name for name, value in self)

    def values(self):
        """
        Yields the values of all items in the namespace.
        """
        yield from (value for name, value in self)

    def items(self):
        """
        Yields the name, value pairs of all items in the namespace.
        """
        yield from self


__extras = {
    # A domain-specific support namespace for networking, communications
    # & cryptographic data processing.
    "ACTIVE": "active_connection",
    "ADDRESS": "address",
    "ADMIN": "admin",
    "AGE": "age_of_connection",
    "ALL_BLOCKS": "all_blocks",
    "ASCII_ALPHANUMERIC": ASCII_ALPHANUMERIC,
    "ASCII_TABLE": ASCII_TABLE,
    "ASCII_TABLE_128": ASCII_TABLE_128,
    "AUTHENTICATION": "authentication",
    "BASE_36_TABLE": BASE_36_TABLE,
    "BASE_38_TABLE": BASE_38_TABLE,
    "BASE_64_TABLE": BASE_64_TABLE,
    "BLOCKSIZE": 256,
    "BLOCK_ID": "block_id",
    "BYTES_TABLE": BYTES_TABLE,
    "CHANNEL": "channel",
    "CHANNELS": "channels",
    "CHUNKY_2048": "Chunky2048",
    "CIPHERED_SALT": "ciphered_salt",
    "CIPHERTEXT": "ciphertext",
    "CIPHERTEXT_IS_NOT_BYTES": "Ciphertext is not in bytes format.",
    "CLIENT": "client",
    "CLIENT_ID": "client_identifier",
    "CLIENT_INDEX": "client_database_index",
    "CLIENT_KEY": "client_key",
    "CLIENT_MESSAGE_KEY": "client_message_key",
    "CLIENT_URL": "client_contact_address",
    "CORRUPT": "corrupt_connection",
    "DECRYPT": "decrypt",
    "DECRYPTION": "decryption",
    "DH2": "diffie_hellman_2x",
    "DH3": "diffie_hellman_3x",
    "DIGEST": "message_digest",
    "DIRECTORY": "directory",
    "ENCRYPT": "encrypt",
    "ENCRYPTION": "encryption",
    "ENTROPY": "entropy",
    "EQUALITY": "equality",
    "EXCEEDED_BLOCKSIZE": "Data MUST NOT exceed 256 bytes.",
    "FAILED": "failed",
    "STREAM_IS_EMPTY": "An emtpy stream is invalid.",
    "FILENAME": "filename",
    "FILE_KEY": "file_key",
    "GUEST": "guest",
    "HEADER": "header",
    "HEADER_BYTES": 80,
    "HEADER_NIBBLES": 160,
    "HMAC": "hmac",
    "HMAC_BYTES": 32,
    "HMAC_NIBBLES": 64,
    "HTTP": "http",
    "HTTPS": "https",
    "ID": "contact_identifier",
    "INACTIVE": "terminated_connection",
    "INNER_HEADER": "inner_header",
    "INNER_HEADER_BYTES": 24,
    "INNER_HEADER_NIBBLES": 48,
    "INVALID_BLOCKSIZE": "The block of data isn't 256 bytes.",
    "INVALID_CIPHERTEXT_LENGTH": "The length of ciphertext is invalid.",
    "INVALID_DECRYPTION_VALIDATOR": (
        "Must set `validator` for decryption or preemptive validation."
    ),
    "INVALID_DIGEST": "Current digest of the data stream isn't valid.",
    "INVALID_BLOCK_ID": "Next block id of the data stream isn't valid.",
    "INVALID_ENCRYPTION_VALIDATOR": "Must set `validator` for encryption.",
    "UNSAFE_DETERMINISM": (
        "Must enable dangerous determinism to use a custom salt."
    ),
    "INVALID_HMAC": "HMAC of the data stream isn't valid.",
    "KDF": "key_derivation_function",
    "KEEP_ALIVE": "keep_alive",
    "KEY": "key",
    "KEY_ID": "key_id",
    "KEYSTREAM": "keystream",
    "KEYED_PASSWORD": "keyed_password",
    "LEFT_PAD": b"\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c",
    "LIST_ENCODING": "listed_ciphertext",
    "LISTENING": "listening",
    "MAINTAINING": "maintaining",
    "MANIFEST": "manifest",
    "MANUAL": "manual_mode",
    "MAP_ENCODING": "mapped_ciphertext",
    "MAX_INACTIVITY": "max_inactivity",
    "MESSAGE_ID": "message_id",
    "MESSAGE_KEY": "message_key",
    "MESSAGE_NUMBER": "message_number",
    "MESSAGES": "message_archive",
    "METADATA": "metadata",
    "METATAG": "metatag",
    "METATAG_KEY": "metatag_key",
    "MISSING_HMAC": "The ``hmac`` keyword argument was not given.",
    "NEW_CONTACT": "new_contact",
    "NEXT_KEYED_PASSWORD": "next_keyed_password",
    "NEXT_PASSWORD_SALT": "next_password_salt",
    "NO_PROFILE_OR_CORRUPT": "Profile doesn't exist or is corrupt.",
    "OLD_KEY": "last_shared_key",
    "OLD_VERIFID": "last_verification_code",
    "OMITTED": "<omitted-data>",
    "ONION": "onion",
    "ONION_CHAR_TABLE": ONION_CHAR_TABLE,
    "PADDING_KEY": "padding_key",
    "PASSWORD": "password",
    "PASSWORD_SALT": "password_salt",
    "PHASE": "phase",
    "PLAINTEXT": "plaintext",
    "PLAINTEXT_ISNT_BYTES": "The provided ``data`` must be bytes type.",
    "PUB": "pub",
    "PORT": 8081,
    "PREEMPTIVE": "preemptive_mode",
    "RACHET": "rachet_shared_key",
    "RECEIVING": "receiving",
    "REGISTRATION": "registration",
    "RETRY": "retry",
    "RIGHT_PAD": b"\x36\x36\x36\x36\x36\x36\x36\x36",
    "ROPAKE_TIMEOUT": 0,
    "SALT": "salt",
    "SALT_BYTES": 32,
    "SALT_NIBBLES": 64,
    "SECRET": "secret",
    "SEED": "seed",
    "SENDER": "sender",
    "SENDING": "sending",
    "SERVER": "server",
    "SERVER_ID": "server_identifier",
    "SERVER_INDEX": "server_database_index",
    "SERVER_KEY": "server_key",
    "SERVER_MESSAGE_KEY": "server_message_key",
    "SERVER_URL": "server_contact_address",
    "SESSION_ID": "session_identifier",
    "SESSION_KEY": "session_key",
    "SESSION_SALT": "session_salt",
    "SESSION_TOKEN": "session_tracking_token",
    "SHARED_KEY": "shared_key",
    "SHARED_SECRET": "shared_secret",
    "SHARED_SEED": "shared_seed",
    "SHMAC": "stream_hmac",
    "SIV": "synthetic_iv",
    "SIV_BYTES": 16,
    "SIV_NIBBLES": 32,
    "SIV_KEY": "synthetic_iv_key",
    "SIV_KEY_BYTES": 16,
    "SIV_KEY_NIBBLES": 32,
    "SMALL_MESSAGE_ISNT_PADDED": (
        "The first block is too small & was not flagged as also the final "
        "block."
    ),
    "STATUS": "status",
    "SUCCESS": "success",
    "TB_PORT": 9150,
    "TIMEOUT": "timeout",
    "TIMESTAMP": "timestamp",
    "TIMESTAMP_BYTES": 8,
    "TIMESTAMP_NIBBLES": 16,
    "TOR_PORT": 9050,
    "UniformPrimes": UniformPrimes,
    "UNSAFE_KEY_REUSE": "Providing both a `key` & `salt` risks key reuse.",
    "UNSENT_MESSAGES": "unsent_message_archive",
    "URL": "url",
    "URL_SAFE_TABLE": URL_SAFE_TABLE,
    "UUID": "unique_user_id",
    "VERIFICATION": "verification",
    "VERIFID": "verification_code",
    "WORD_LIST": WORD_LIST,
    "Namespace": Namespace,
    "BasePrimeGroups": BasePrimeGroups,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "acreate_namespace": acreate_namespace,
    "create_namespace": create_namespace,
    "aimport_namespace": aimport_namespace,
    "import_namespace": import_namespace,
    "amake_module": amake_module,
    "make_module": make_module,
    "bits": bits,
    "primes": primes,
}


commons = make_module("commons", mapping=__extras, deepcopy=True)


import_namespace(globals(), mapping=__extras)

