# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "commons", "Tables", "WORD_LIST", "Namespace", "OpenNamespace"
]


__doc__ = (
    "A module used to aggregate commonly used constants & arbitrary uti"
    "lities."
)


import sys
import copy
import json
import types
import asyncio
from os import linesep as sep
from functools import lru_cache
from .__datasets import *
from ._exceptions import *
from ._typing import Typing


class AsyncInit(type):
    """
    A metaclass which allows classes to use asynchronous ``__init__``
    methods. Inspired by David Beazley.
    """

    async def __call__(cls, *args, **kwargs):
        self = cls.__new__(cls, *args, **kwargs)
        await self.__init__(*args, **kwargs)
        return self


class DeletedAttribute:
    """
    Creates objects which raise the result of a callback function if the
    object is queried for attributes.
    """

    __slots__ = ("_callback",)

    def __init__(self, callback: Typing.Callable):
        self._callback = callback

    def __getattr__(self, name: str):
        raise self._callback()


async def aimport_namespace(
    dictionary: dict, *, mapping: dict, deepcopy: bool = False
):
    """
    Takes a ``dictionary``, such as ``globals()``, and copies the
    key-value pairs from the ``mapping`` kwarg into it.
    """
    if deepcopy == True:
        dictionary.update(copy.deepcopy(mapping))
    else:
        dictionary.update(mapping)
    await asyncio.sleep(0)


def import_namespace(
    dictionary: dict, *, mapping: dict, deepcopy: bool = False
):
    """
    Takes a ``dictionary``, such as ``globals()``, and copies the
    key-value pairs from the ``mapping`` kwarg into it.
    """
    if deepcopy == True:
        dictionary.update(copy.deepcopy(mapping))
    else:
        dictionary.update(mapping)


async def amake_module(name: str, *, mapping: dict, deepcopy: bool = False):
    """
    Turns a mapping into a module object version of a Namespace which is
    importable using normal python syntax.
    """
    module = types.ModuleType(name)
    await aimport_namespace(
        module.__dict__, mapping=mapping, deepcopy=deepcopy
    )
    sys.modules[name] = module
    return OpenNamespace(module.__dict__)


def make_module(name: str, *, mapping: dict, deepcopy: bool = False):
    """
    Turns a mapping into a module object version of a Namespace which is
    importable using normal python syntax.
    """
    module = types.ModuleType(name)
    import_namespace(module.__dict__, mapping=mapping, deepcopy=deepcopy)
    sys.modules[name] = module
    return OpenNamespace(module.__dict__)


class Slots:
    """
    A base class which allow subclasses to create very efficient
    instances, with explicitly declared attributes in their `__slots__`.
    """

    __slots__ = ()

    def __init__(self, **kwargs):
        """
        Maps the user-defined kwargs to the instance attributes. If a
        subclass defines a `__slots__` list, then only variables with
        names in the list can be admitted to the instance. Defining
        classes with __slots__ can greatly increase memory efficiency if
        a system instantiates many objects of the class.
        """
        for name, value in kwargs.items():
            setattr(self, name, value)

    def __bool__(self):
        """
        If the instance is empty then return False, otherwise True.
        """
        return any(self)

    def __len__(self):
        """
        Returns the number of elements in the instance.
        """
        return len([*self.keys()])

    def __dir__(self):
        """
        Returns the list of names in the instance.
        """
        return [*self.keys()]

    def __contains__(self, variable=None):
        """
        Returns a bool of ``variable``'s membership in the instance.
        """
        return hasattr(self, variable)

    def __setitem__(self, variable, value):
        """
        Transforms bracket item assignment into dotted assignment on the
        instance.
        """
        setattr(self, variable, value)

    def __getitem__(self, variable):
        """
        Transforms bracket lookup into dotted access on the instance.
        """
        return getattr(self, variable)

    def __delitem__(self, variable=None):
        """
        Deletes the item ``variable`` from the instance.
        """
        delattr(self, variable)

    @staticmethod
    def _repr(items: Typing.Iterable[Typing.Tuple[Typing.Any, Typing.Any]]):
        """
        Individually wraps the produced ``items`` values in a visible
        string for an instance's repr.
        """
        for name, value in items:
            yield f"{name}={repr(value)}"

    @staticmethod
    def _omitted_repr(
        items: Typing.Iterable[Typing.Tuple[Typing.Any, Typing.Any]]
    ):
        """
        Individually wraps the produced ``items`` values in a masked
        string for an instance's repr.
        """
        for name, value in items:
            exists = (value and "is <truthy>") or "is <falsey>"
            omitted_value = f"{OMITTED} of {type(value)} {exists}"
            yield f"{name}={omitted_value}"

    def __repr__(self, *, new_line=sep + 4 * " ", mask: bool = True):
        """
        Pretty displays the instance & its attributes.
        """
        from .debuggers import DebugControl

        cls = f"{self.__class__.__qualname__}("
        spacer = f",{new_line}"
        if not mask or DebugControl.is_debugging():
            items = spacer.join(self._repr(self.items()))
        else:
            items = spacer.join(self._omitted_repr(self.items()))
        return f"{cls}{f'{new_line}{items},{sep}' if items else ''})"

    async def __aiter__(self):
        """
        Allows an instance to be unpacked with with async iteration.
        """
        for variable in self.__slots__:
            if hasattr(self, variable):
                await asyncio.sleep(0)
                yield variable

    def __iter__(self):
        """
        Allows an instance to be unpacked with tools like ``dict`` &
        ``list``.
        """
        for variable in self.__slots__:
            if hasattr(self, variable):
                yield variable

    def keys(self):
        """
        Yields the names of all items in the instance.
        """
        yield from (
            name
            for name in self.__slots__
            if hasattr(self, name)
        )

    def values(self):
        """
        Yields the values of all items in the instance.
        """
        yield from (
            getattr(self, name)
            for name in self.__slots__
            if hasattr(self, name)
        )

    def items(self):
        """
        Yields the name, value pairs of all items in the instance.
        """
        yield from (
            (name, getattr(self, name))
            for name in self.__slots__
            if hasattr(self, name)
        )


class Namespace(Slots):
    """
    A simple wrapper for turning mappings into Namespace objects that
    allow dotted lookup and assignment on those mappings. Also, provides
    utilities for copying mappings into other containers, & turning
    mappings into stand-alone, first-class modules.
    """

    __slots__ = ("__dict__",)

    def __init__(self, mapping={}, **kwargs):
        """
        Maps the user-defined mapping & kwargs to the Namespace's
        instance dictionary.
        """
        if mapping.__class__ in {str, bytes, bytearray}:
            mapping = json.loads(mapping)
        self.__dict__.update(mapping)
        self.__dict__.update(kwargs)

    @property
    def __all__(self):
        """
        Allows users that have turned their Namespace into a Module
        object to do a ``from namespace import *`` on the contents of
        the namespace's mapping. This method excludes exporting private
        methods & attributes.
        """
        exports = {
            var: val
            for var, val in self.__dict__.items() if var[0] != "_"
        }
        return exports

    @property
    def namespace(self):
        """
        Cleaner name for users to access the instance's dictionary.
        """
        return self.__dict__

    def __bool__(self):
        """
        If the namespace is empty then return False, otherwise True.
        """
        return bool(self.__dict__)

    def __len__(self):
        """
        Returns the number of elements in the Namespace's mapping.
        """
        return len(self.__dict__)

    def __dir__(self):
        """
        Returns the list of names in the Namespace's mapping.
        """
        return [*self.__dict__]

    def __contains__(self, variable=None):
        """
        Returns a bool of ``variable``'s membership in the instance
        dictionary.
        """
        return variable in self.__dict__

    def __setitem__(self, variable, value):
        """
        Transforms bracket item assignment into dotted assignment on the
        Namespace's mapping.
        """
        setattr(self, variable, value)

    def __getitem__(self, variable):
        """
        Transforms bracket lookup into dotted access on the Namespace's
        mapping.
        """
        try:
            return self.__dict__[variable]
        except KeyError:
            return getattr(self, variable)

    def __delitem__(self, variable=None):
        """
        Deletes the item ``variable`` from the instance dictionary.
        """
        del self.__dict__[variable]

    def __repr__(self, *, new_line=sep + 4 * " ", mask: bool = True):
        """
        Pretty displays the instance & its attributes.
        """
        from .debuggers import DebugControl

        cls = f"{self.__class__.__qualname__}("
        spacer = f",{new_line}"
        items = (
            (name, value) for name, value in self.items()
            if str(name)[0] != "_"
        )
        if not mask or DebugControl.is_debugging():
            items = spacer.join(self._repr(items))
        else:
            items = spacer.join(self._omitted_repr(items))
        return f"{cls}{f'{new_line}{items},{sep}' if items else ''})"

    async def __aiter__(self):
        """
        Allows Namespace's to be unpacked with with async iteration.
        """
        for variable in self.__dict__:
            await asyncio.sleep(0)
            yield variable

    def __iter__(self):
        """
        Allows Namespace's to be unpacked with tools like ``dict`` &
        ``list``.
        """
        yield from self.__dict__

    def keys(self):
        """
        Yields the names of all items in the instance.
        """
        yield from self.__dict__

    def values(self):
        """
        Yields the values of all items in the instance.
        """
        yield from self.__dict__.values()

    def items(self):
        """
        Yields the name, value pairs of all items in the instance.
        """
        yield from self.__dict__.items()


class OpenNamespace(Namespace):
    """
    A version of the `Namespace` class which doesn't omit instance
    repr's by default.
    """

    def __repr__(self):
        """
        Pretty displays the instance & its attributes.
        """
        return super().__repr__(mask=False)


chunky2048_constants = OpenNamespace(
    #  These constants control the structure of the Chunky2048 cipher
    AAD="aad",
    BLOCK_ID="block_id",
    BLOCK_ID_BYTES=16,
    BLOCKSIZE=256,
    CHUNKY_2048="Chunky2048",
    CIPHERTEXT="ciphertext",
    DECRYPTION="decryption",
    DIGEST="digest",
    DIGEST_BYTES=32,
    ENCRYPTION="encryption",
    HEADER="header",
    HEADER_BYTES=80,  # HMAC_BYTES + SALT_BYTES + SIV_BYTES
    HMAC="hmac",
    HMAC_BYTES=32,
    INNER_HEADER="inner_header",
    INNER_HEADER_BYTES=24,  # TIMESTAMP_BYTES + SIV_KEY_BYTES
    KEY="key",
    KEY_BYTES=64,
    LEFT_PAD=8 * b"\x5c",
    MAX_BLOCK_ID_BYTES=32,
    MINIMUM_BLOCK_ID_BYTES=16,
    MINIMUM_KEY_BYTES=64,
    PADDING_KEY="padding_key",
    PADDING_KEY_BYTES=32,
    PLAINTEXT="plaintext",
    RIGHT_PAD=8 * b"\x36",
    SALT="salt",
    SALT_BYTES=24,
    SEED_PAD=16 * b"\xa1",
    SHMAC="stream_hmac",
    SIV="synthetic_iv",
    SIV_BYTES=24,
    SIV_KEY="synthetic_iv_key",
    SIV_KEY_BYTES=16,
    TIMESTAMP="timestamp",
    TIMESTAMP_BYTES=8,
)


globals().update(chunky2048_constants.namespace)


chunky2048_constants.namespace.update(
    dict(
        BLOCK_ID_NIBBLES=2 * BLOCK_ID_BYTES,
        BLOCKSIZE_BITS=8 * BLOCKSIZE,
        CIPHERTEXT_SLICE=slice(HEADER_BYTES, None),
        DIGEST_NIBBLES=2 * DIGEST_BYTES,
        HEADER_NIBBLES=2 * HEADER_BYTES,
        HEADER_SLICE=slice(None, HEADER_BYTES),
        HMAC_NIBBLES=2 * HMAC_BYTES,
        HMAC_SLICE=slice(HMAC_BYTES),
        INNER_HEADER_NIBBLES=2 * INNER_HEADER_BYTES,
        INNER_HEADER_SLICE=slice(None, INNER_HEADER_BYTES),
        KEY_NIBBLES=2 * KEY_BYTES,
        MAX_BLOCK_ID_NIBBLES=2 * MAX_BLOCK_ID_BYTES,
        MINIMUM_BLOCK_ID_NIBBLES=2 * MINIMUM_BLOCK_ID_BYTES,
        MINIMUM_KEY_NIBBLES=2 * MINIMUM_KEY_BYTES,
        PADDING_KEY_NIBBLES=2 * PADDING_KEY_BYTES,
        SALT_NIBBLES=2 * SALT_BYTES,
        SALT_SLICE=slice(HMAC_BYTES, HMAC_BYTES + SALT_BYTES),
        SIV_NIBBLES=2 * SIV_BYTES,
        SIV_SLICE=slice(HMAC_BYTES + SALT_BYTES, HEADER_BYTES),
        SIV_KEY_NIBBLES=2 * SIV_KEY_BYTES,
        SIV_KEY_SLICE=slice(TIMESTAMP_BYTES, INNER_HEADER_BYTES),
        TIMESTAMP_NIBBLES=2 * TIMESTAMP_BYTES,
        TIMESTAMP_SLICE=slice(TIMESTAMP_BYTES),
    )
)


misc_constants = OpenNamespace(
    ACTIVE="active_connection",
    ADDRESS="address",
    ADMIN="admin",
    AGE="age_of_connection",
    ASYNC="asynchronous",
    AUTHENTICATED_ASSOCIATED_DATA="authenticated_associated_data",
    AUTHENTICATION="authentication",
    BYTES_FLAG=b"\x01\x02",
    BYTES_FLAG_SIZE=2,
    CHANNEL="channel",
    CHANNELS="channels",
    CHECKSUM="checksum",
    CHECKSUMS="checksums",
    CLIENT="client",
    CLIENT_ID="client_identifier",
    CLIENT_INDEX="client_database_index",
    CLIENT_KEY="client_key",
    CLIENT_MESSAGE_KEY="client_message_key",
    CLIENT_URL="client_contact_address",
    CONTROL_BITS="control_bits",
    CORRUPT="corrupt_connection",
    DECRYPT="decrypt",
    DEFAULT_TIMEOUT=0,
    DH2="diffie_hellman_2x",
    DH3="diffie_hellman_3x",
    DIFFIE_HELLMAN="diffie_hellman",
    DIRECTORY="directory",
    ENCRYPT="encrypt",
    ENTROPY="entropy",
    EPHEMERAL_KEY="ephemeral_key",
    EQUALITY="equality",
    EXTENDED_DH_EXCHANGE="extended_diffie_hellman_exchange",
    FAILED="failed",
    FILENAME="filename",
    FILE_KEY="file_key",
    GUEST="guest",
    HTTP="http",
    HTTPS="https",
    ID="contact_identifier",
    IDENTITY_KEY="identity_key",
    INACTIVE="terminated_connection",
    JSON_DESERIALIZABLE_TYPES={str, bytes, bytearray},
    KDF="key_derivation_function",
    KEEP_ALIVE="keep_alive",
    KEY_ID="key_id",
    KEYSTREAM="keystream",
    LISTENING="listening",
    MAINTAINING="maintaining",
    MANIFEST="manifest",
    MANUAL="manual_mode",
    MASKING_KEY="masking_key",
    MASKING_KEY_BYTES=32,
    MASKING_KEY_NIBBLES=64,
    MAX_INACTIVITY="max_inactivity",
    MESSAGE_ID="message_id",
    MESSAGE_ID_BYTES=32,
    MESSAGE_ID_NIBBLES=64,
    MESSAGE_KEY="message_key",
    MESSAGE_NUMBER="message_number",
    MESSAGES="message_archive",
    METADATA="metadata",
    METATAG="metatag",
    METATAG_KEY="metatag_key",
    NEW_CONTACT="new_contact",
    OLD_KEY="last_shared_key",
    OMITTED="<omitted-value>",
    ONION="onion",
    PASSCRYPT="passcrypt",
    PASSPHRASE="passphrase",
    PAYLOAD="payload",
    PHASE="phase",
    PORT=8081,
    PREEMPTIVE="preemptive_mode",
    PUBLIC_CREDENTIALS = "public_credentials",
    RACHET="rachet_shared_key",
    RECEIVING="receiving",
    RECEIVING_COUNT="receiving_count",
    RECEIVING_KEYS="receiving_keys",
    RECEIVING_STREAM="receiving_stream",
    REGISTRATION="registration",
    RETRY="retry",
    SCOPE="scope",
    SECRET="secret",
    SECRET_CREDENTIALS = "secret_credentials",
    SECURE_CHANNEL="secure_channel",
    SEED="seed",
    SENDER="sender",
    SENDING="sending",
    SENDING_COUNT="sending_count",
    SENDING_KEYS="sending_keys",
    SENDING_STREAM="sending_stream",
    SERVER="server",
    SERVER_ID="server_identifier",
    SERVER_INDEX="server_database_index",
    SERVER_KEY="server_key",
    SERVER_MESSAGE_KEY="server_message_key",
    SERVER_URL="server_contact_address",
    SESSION_ID="session_identifier",
    SESSION_KEY="session_key",
    SESSION_TOKEN="session_tracking_token",
    SHARED_KEY="shared_key",
    SHARED_SECRET="shared_secret",
    SHARED_SEED="shared_seed",
    SIGNATURE="signature",
    SIGNING_KEY="signing_key",
    STATUS="status",
    SUCCESS="success",
    SYNC="synchronous",
    TB_PORT=9150,
    TIMEOUT="timeout",
    TOKEN="token",
    TOKEN_BYTES=48,
    TOKEN_NIBBLES=96,
    TOR_PORT=9050,
    UNSENT_MESSAGES="unsent_message_archive",
    URL="url",
    UUID="unique_user_id",
    VERIFICATION="verification",
    VERSIONS="versions",
)


passcrypt_constants = OpenNamespace(
    DEFAULT_KB=1024,
    DEFAULT_CPU=3,
    DEFAULT_HARDNESS=1024,
    KB="kb",
    KB_BYTES=4,
    KB_NIBBLES=8,
    KB_SLICE=slice(4),
    CPU="cpu",
    CPU_BYTES=2,
    CPU_NIBBLES=4,
    CPU_SLICE=slice(4, 6),
    HARDNESS="hardness",
    HARDNESS_BYTES=4,
    HARDNESS_NIBBLES=8,
    HARDNESS_SLICE=slice(6, 10),
    SALT="salt",
    SALT_BYTES=32,
    SALT_NIBBLES=64,
    SALT_SLICE=slice(10, 42),
    PASSPHRASE_HASH="passphrase_hash",
    PASSPHRASE_HASH_BYTES=64,
    PASSPHRASE_HASH_NIBBLES=128,
    PASSPHRASE_HASH_SLICE=slice(42, 106),
    PASSCRYPT_SCHEMA="passcrypt_schema",
    PASSCRYPT_SCHEMA_BYTES=106,
    PASSCRYPT_SCHEMA_NIBBLES=212,
)


ropake_constants = OpenNamespace(
    AUTHENTICATION="authentication",
    CIPHERTEXT="ciphertext",
    DEFAULT_TIMEOUT=0,
    KEY="key",
    KEY_ID="key_id",
    KEYED_PASSPHRASE="keyed_passphrase",
    NEXT_KEYED_PASSPHRASE="next_keyed_passphrase",
    NEXT_PASSPHRASE_SALT="next_passphrase_salt",
    PASSPHRASE_SALT="passphrase_salt",
    PUBLIC_KEY="public_key",
    REGISTRATION="registration",
    SALT="salt",
    SESSION_KEY="session_key",
    SESSION_SALT="session_salt",
)


extras = dict(
    WORD_LIST=WORD_LIST,
    AsyncInit=AsyncInit,
    DeletedAttribute=DeletedAttribute,
    Namespace=Namespace,
    OpenNamespace=OpenNamespace,
    Slots=Slots,
    Tables=Tables,
    Typing=Typing,
    UniformPrimes=UniformPrimes,
    __doc__=__doc__,
    __main_exports__=__all__,
    __package__=__package__,
    aimport_namespace=aimport_namespace,
    amake_module=amake_module,
    import_namespace=import_namespace,
    make_module=make_module,
    passcrypt_constants=passcrypt_constants,
    primes=primes,
    ropake_constants=ropake_constants,
    **chunky2048_constants,
    **misc_constants,
)


commons = make_module("commons", mapping=extras, deepcopy=True)


import_namespace(globals(), mapping=extras)

