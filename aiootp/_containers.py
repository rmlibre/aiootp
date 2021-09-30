# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["_containers"]


__main_exports__ = [
    "Chunky2048Keys",
    "Ciphertext",
    "JSONCiphertext",
    "KeyAADBundleRegisters",
    "KeyAADMode",
    "KeySaltAAD",
    "NoRegisters",
    "PackageSignerFiles",
    "PackageSignerScope",
    "PasscryptHash",
    "PlaintextMeasurements",
    "ProfileTokens",
]


__doc__ = (
    "A collection of types which allow efficient & purpose-specific sto"
    "rage, retrieval & usage of values."
)


import json
from hashlib import sha3_256, sha3_512
from ._typing import Typing
from ._exceptions import *
from .asynchs import asleep
from .commons import *
from commons import *
from .paths import Path


class KeySaltAAD(Slots):
    """
    Creates efficient containers for key, salt & aad value bundles.
    """

    __slots__ = [KEY, SALT, AAD]

    def __init__(self, key: bytes, salt: bytes, aad: bytes):
        self.key = key
        self.salt = salt
        self.aad = aad


class NoRegisters(Slots):
    """
    Copies the api for an object with a `register` method, but which
    doesn't do anything on that call.
    """

    __slots__ = []

    def __init__(self):
        pass

    def register(self, name: str, value: Typing.Any):
        pass


class KeyAADBundleRegisters(Slots):
    """
    Efficiently stores objects which help to enforce the limited usage
    of a `KeyAADBundle` object for a single encryption / decryption
    round.
    """

    __slots__ = ["keystream", "validator"]

    def __init__(self):
        pass

    def register(self, name: str, value: Typing.Any):
        setattr(self, name, value)


class KeyAADMode(Slots):
    """
    Helps guide users towards correct usage of `KeyAADBundle` objects in
    the `Chunky2048` cipher by enforcing that they are set to async or
    sync key derivation modes when using them in those contexts.
    """

    __slots__ = ["_mode"]

    def __repr__(self):
        """
        Returns a repr string without the instance's values being masked.
        """
        return super().__repr__(mask=False)

    def __eq__(self, mode: str):
        """
        The object can directly be compared to the string ``mode`` from
        within the runtime of an async & sync contexts. Procs an error
        if the mode has not been set.
        """
        return self.mode == mode

    def validate(self):
        """
        Procs an error if the mode has not been set, else returns `True`.
        """
        return self.mode and True

    @property
    def mode(self):
        """
        Procs an error if the mode has not been set.
        """
        try:
            return self._mode
        except AttributeError as error:
            raise KeyAADIssue.no_kdf_mode_declared() from error

    async def aset_async_mode(self):
        """
        Sets the object's mode to signal async key derivation is needed.
        """
        await asleep()
        self._mode = ASYNC

    def set_sync_mode(self):
        """
        Sets the object's mode to signal sync key derivation is needed.
        """
        self._mode = SYNC


class Chunky2048Keys(Slots):
    """
    Efficiently stores & gives acces to `KeyAADBundle` keys & KDFs.
    """

    __slots__ = [
        "kdf",
        "seed_0",
        "seed_1",
        "keystream",
        "seed_kdf",
        "left_kdf",
        "right_kdf",
        "primer_key",
        "shmac_mac",
        "shmac_key",
        "padding_key",
    ]

    def __init__(self):
        pass

    def __repr__(self):
        """
        Blocks the viewing of instance values.
        """
        return f"{self.__class__.__qualname__}()"

    def __iter__(self):
        """
        An api for retrieving the instance & its key seeds.
        """
        yield self
        yield self.seed_0
        yield self.seed_1

    def add_keystream_kdfs(
        self, seed_kdf: sha3_512, left_kdf: sha3_512, right_kdf: sha3_512
    ):
        """
        Stores the main internal KDFs of the `Chunky2048` cipher's
        keystream.
        """
        self.seed_kdf = seed_kdf
        self.left_kdf = left_kdf
        self.right_kdf = right_kdf


class Ciphertext(Slots):
    """
    Efficiently stores bytes type ciphertext organized by instance
    attributes.
    """

    __slots__ = [HMAC, SALT, SIV, CIPHERTEXT]

    HMAC_SLICE = HMAC_SLICE
    SALT_SLICE = SALT_SLICE
    SIV_SLICE = SIV_SLICE
    CIPHERTEXT_SLICE = CIPHERTEXT_SLICE

    def __init__(self, data: bytes):
        size = len(data) - HEADER_BYTES
        if size <= 0 or size % BLOCKSIZE:
            raise CiphertextIssue.invalid_ciphertext_length(len(data))
        self.hmac = data[HMAC_SLICE]
        self.salt = data[SALT_SLICE]
        self.synthetic_iv = data[SIV_SLICE]
        self.ciphertext = data[CIPHERTEXT_SLICE]

    def __repr__(self):
        """
        Returns a repr string without the instance's values being masked.
        """
        return super().__repr__(mask=False)


class JSONCiphertext(Slots):
    """
    Efficiently stores JSON / dict type ciphertext organized by instance
    attributes.
    """

    __slots__ = [HMAC, SALT, SIV, CIPHERTEXT]

    def __init__(self, data: Typing.JSONCiphertext):
        if data.__class__ in JSON_DESERIALIZABLE_TYPES:
            data = json.loads(data)
        self.hmac = data[HMAC]
        self.salt = data[SALT]
        self.synthetic_iv = data[SIV]
        self.ciphertext = data[CIPHERTEXT]

    def __repr__(self):
        """
        Returns a repr string without the instance's values being masked.
        """
        return super().__repr__(mask=False)


class PlaintextMeasurements(Slots):
    """
    Efficiently stores plaintext measurements in instance attributes
    which are used to determine the padding that's needed.
    """

    __slots__ = [
        "length",
        "remainder",
        "padding_size",
        "no_padding_required",
        "padding_sentinel_fits_in_block",
    ]

    def __init__(
        self,
        length: int,
        remainder: int,
        padding_size: int,
        no_padding_required: bool,
        padding_sentinel_fits_in_block: bool,
    ):
        self.length = length
        self.remainder = remainder
        self.padding_size = padding_size
        self.no_padding_required = no_padding_required
        self.padding_sentinel_fits_in_block = padding_sentinel_fits_in_block


class PasscryptHash(Slots):
    """
    Efficiently stores & formats the bytes type passcrypt hash that has
    attached metadata & organizes its values by instance attributes.
    """

    __slots__ = ["kb", "cpu", "hardness", "salt", "passphrase_hash"]

    KB_SLICE = passcrypt_constants.KB_SLICE
    CPU_SLICE = passcrypt_constants.CPU_SLICE
    HARDNESS_SLICE = passcrypt_constants.HARDNESS_SLICE
    SALT_SLICE = passcrypt_constants.SALT_SLICE
    PASSPHRASE_HASH_SLICE = passcrypt_constants.PASSPHRASE_HASH_SLICE

    def __init__(self, passcrypt_hash: bytes):
        _int = int.from_bytes
        self.kb = _int(passcrypt_hash[self.KB_SLICE], "big")
        self.cpu = _int(passcrypt_hash[self.CPU_SLICE], "big")
        self.hardness = _int(passcrypt_hash[self.HARDNESS_SLICE], "big")
        self.salt = passcrypt_hash[self.SALT_SLICE]
        self.passphrase_hash = passcrypt_hash[self.PASSPHRASE_HASH_SLICE]


class ProfileTokens(Slots):
    """
    Efficiently stores AsyncDatabase & Database profile token values
    which are used to more safely construct databases from potentially
    low entropy passphrases.
    """

    __slots__ = [
        "_bytes_key",
        "_salt",
        "_salt_path",
        "_uuid",
        "login_key",
        "profile",
    ]

    def __init__(self, bytes_key: bytes, uuid: bytes):
        self._bytes_key = bytes_key
        self._uuid = uuid


class PackageSignerScope(OpenNamespace):
    """
    Stores user-defined scope values of a package signing session.
    """

    def __init__(
        self,
        *,
        package: str,
        version: str,
        date: int,
        **extras: Typing.Dict[str, Typing.JSONSerializable],
    ):
        self.__dict__.update(extras)
        self.package = package
        self.version = version
        self.date = date


class PackageSignerFiles(OpenNamespace):
    """
    Stores the filename, hashing object key-value pairs of a package
    signing session.
    """


extras = OpenNamespace(
    Chunky2048Keys=Chunky2048Keys,
    Ciphertext=Ciphertext,
    JSONCiphertext=JSONCiphertext,
    KeyAADBundleRegisters=KeyAADBundleRegisters,
    KeyAADMode=KeyAADMode,
    KeySaltAAD=KeySaltAAD,
    NoRegisters=NoRegisters,
    PackageSignerFiles=PackageSignerFiles,
    PackageSignerScope=PackageSignerScope,
    PasscryptHash=PasscryptHash,
    PlaintextMeasurements=PlaintextMeasurements,
    ProfileTokens=ProfileTokens,
    __all__=__main_exports__,
    __doc__=__doc__,
    __package__=__package__,
)


_containers = commons.make_module("_containers", mapping=extras)

