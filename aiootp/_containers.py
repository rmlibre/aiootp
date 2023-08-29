# This file is part of aiootp:
# an application agnostic — async-compatible — anonymity & cryptography
# library, providing access to high-level Pythonic utilities to simplify
# the tasks of secure data processing, communication & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "AuthFail",
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
    "PasscryptResources",
    "PasscryptSettings",
    "PlaintextMeasurements",
    "ProfileTokens",
    "UnmaskedGUID",
]


__doc__ = (
    "A collection of types which allow efficient & purpose-specific sto"
    "rage, retrieval & usage of values."
)


import json
import math
from io import BytesIO
from hashlib import sha3_256, sha3_512
from .__constants import *
from ._exceptions import *
from ._typing import Typing as t
from .asynchs import asleep
from .commons import Slots, OpenNamespace
from .commons import make_module
from .paths import Path


class AuthFail(Slots):
    """
    Creates efficient containers for data lost in a buffer during
    authentication failure of a block ID in (Async)DecipherStream
    objects.
    """

    __slots__ = ("block_id", "block", "buffer")

    def __init__(
        self, block_id: bytes, block: bytes, buffer: t.Callable
    ) -> None:
        self.block_id = block_id
        self.block = block
        self.buffer = buffer

    def __repr__(self) -> str:
        """
        Returns a repr string without the instance's values being masked.
        """
        return super().__repr__(mask=False)


class KeySaltAAD(Slots):
    """
    Creates efficient containers for key, salt & aad value bundles.
    """

    __slots__ = (KEY, SALT, AAD)

    def __init__(self, key: bytes, salt: bytes, aad: bytes) -> None:
        self.key = key
        self.salt = salt
        self.aad = aad


class NoRegisters(Slots):
    """
    Copies the api for an object with a `register` method, but which
    doesn't do anything on that call.
    """

    __slots__ = ()

    def register(self, name: str, value: t.Any) -> None:
        pass


class KeyAADBundleRegisters(Slots):
    """
    Efficiently stores objects which help to enforce the limited usage
    of a `KeyAADBundle` object for a single encryption / decryption
    round.
    """

    __slots__ = (KEYSTREAM, SHMAC)

    def register(self, name: str, value: t.Any) -> None:
        setattr(self, name, value)


class KeyAADMode(Slots):
    """
    Helps guide users towards correct usage of `KeyAADBundle` objects in
    the `Chunky2048` cipher by enforcing that they are set to async or
    sync key derivation modes when using them in those contexts.
    """

    __slots__ = ("_mode",)

    def __repr__(self) -> str:
        """
        Returns a repr string without the instance's values being masked.
        """
        return super().__repr__(mask=False)

    def __eq__(self, mode: str) -> bool:
        """
        The object can directly be compared to the string ``mode`` from
        within the runtime of an async & sync contexts. Procs an error
        if the mode has not been set.
        """
        return self.mode == mode

    @property
    def mode(self) -> str:
        """
        Procs an error if the mode has not been set.
        """
        try:
            return self._mode
        except AttributeError as error:
            raise KeyAADIssue.no_kdf_mode_declared() from error

    def set_async_mode(self) -> None:
        """
        Sets the object's mode to signal async key derivation is needed.
        """
        self._mode = ASYNC

    def set_sync_mode(self) -> None:
        """
        Sets the object's mode to signal sync key derivation is needed.
        """
        self._mode = SYNC

    def validate(self) -> None:
        """
        Procs an error if the mode has not been set, else returns `None`.
        """
        return self.mode and None


class Chunky2048Keys(Slots):
    """
    Efficiently stores & gives access to `KeyAADBundle` keys & KDFs.
    """

    __slots__ = (
        "keystream",
        "seed_kdf",
        "left_kdf",
        "right_kdf",
        "primer_key",
        "shmac_mac",
    )

    def __repr__(self) -> str:
        """
        Blocks the viewing of instance values.
        """
        return f"{self.__class__.__qualname__}()"

    def __iter__(self) -> SHAKE_128_TYPE:
        """
        An api for retrieving the instance's keystream kdfs.
        """
        yield self.seed_kdf
        yield self.left_kdf
        yield self.right_kdf


class Ciphertext(Slots):
    """
    Efficiently stores bytes type ciphertext organized by instance
    attributes.
    """

    __slots__ = (SHMAC, SALT, IV, CIPHERTEXT)

    def __init__(self, data: bytes) -> None:
        """
        Decomposes a blob of ciphertext ``data`` bytes into an organized
        instance where the `shmac` auth tag, `salt` & `iv` randomizers &
        the body of `ciphertext` are queriable through dotted attribute
        lookup.
        """
        size = len(data) - HEADER_BYTES
        if size <= 0 or size % BLOCKSIZE:
            raise CiphertextIssue.invalid_ciphertext_size(len(data))
        self.shmac = data[SHMAC_SLICE]
        self.salt = data[SALT_SLICE]
        self.iv = data[IV_SLICE]
        self.ciphertext = data[CIPHERTEXT_SLICE]

    def __repr__(self) -> str:
        """
        Returns a repr string without the instance's values being masked.
        """
        return super().__repr__(mask=False)


class JSONCiphertext(Slots):
    """
    Efficiently stores JSON / dict type ciphertext organized by instance
    attributes.
    """

    __slots__ = (SHMAC, SALT, IV, CIPHERTEXT)

    def __init__(self, data: t.JSONCiphertext) -> None:
        """
        Efficiently stores JSON / dict type ciphertext organized by
        instance attributes.
        """
        if data.__class__ in JSON_DESERIALIZABLE_TYPES:
            data = json.loads(data)
        self.shmac = data[SHMAC]
        self.salt = data[SALT]
        self.iv = data[IV]
        self.ciphertext = data[CIPHERTEXT]

    def __repr__(self) -> str:
        """
        Returns a repr string without the instance's values being masked.
        """
        return super().__repr__(mask=False)


class PlaintextMeasurements(Slots):
    """
    Efficiently stores plaintext measurements in instance attributes
    which are used to determine the padding that's needed.
    """

    __slots__ = ("padding_size", "pad_sentinel")

    def __init__(self, padding_size: int, pad_sentinel: bytes) -> None:
        self.padding_size = padding_size
        self.pad_sentinel = pad_sentinel


class UnmaskedGUID(Slots):
    """
    Efficiently stores the de-obfuscated values used to generate a guid.
    """

    __slots__ = ("timestamp", "entropy", "node_number", "counter")

    def __init__(self, guid: bytes, node_number_bytes: int) -> None:
        read = BytesIO(guid).read
        self.timestamp = read(SAFE_TIMESTAMP_BYTES)
        self.entropy = read(len(guid) - SAFE_TIMESTAMP_BYTES - node_number_bytes - 1)
        self.node_number = read(node_number_bytes)
        self.counter = read()

    def __repr__(self) -> str:
        """
        Allows the instance state to be viewed.
        """
        return super().__repr__(mask=False)

    def __hash__(self) -> int:
        return int.from_bytes(self.sort_key, BIG)

    def __eq__(self, other: "cls") -> bool:
        return self.sort_key == other.sort_key

    def __gt__(self, other: "cls") -> bool:
        return self.sort_key > other.sort_key

    def __lt__(self, other: "cls") -> bool:
        return self.sort_key < other.sort_key

    @property
    def sort_key(self) -> bytes:
        return (
            self.timestamp + self.node_number + self.counter + self.entropy
        )


class PasscryptResources(Slots):
    """
    Efficiently stores the resource values located in the header of a
    `Passcrypt` hash.
    """

    __slots__ = ("mb", "cpu", "cores")

    def __init__(self, mb: int, cpu: int, cores: int) -> None:
        self.mb = mb
        self.cpu = cpu
        self.cores = cores

    def __repr__(self) -> str:
        """
        Allows instance state to be viewed.
        """
        return super().__repr__(mask=False)


class PasscryptSettings(Slots):
    """
    Efficiently stores the resource values located in the header of a
    `Passcrypt` hash.
    """

    __slots__ = ("mb", "cpu", "cores", "tag_size", "salt_size")

    def __init__(
        self, mb: int, cpu: int, cores: int, tag_size: int, salt_size: int
    ) -> "self" :
        self.mb = mb
        self.cpu = cpu
        self.cores = cores
        self.tag_size = tag_size
        self.salt_size = salt_size

    def __repr__(self) -> str:
        """
        Allows instance state to be viewed.
        """
        return super().__repr__(mask=False)


class PasscryptHash(Slots):
    """
    Efficiently stores `Passcrypt` session values to be encoded into &
    decoded from formatted `Passcrypt` hashes. Does NOT check that
    provided values follow the specification.
    """

    __slots__ = ("timestamp", "mb", "cpu", "cores", "salt", "tag")

    vars().update({var: passcrypt[var] for var in passcrypt.__all__})

    def __init__(
        self,
        *,
        timestamp: t.Optional[bytes] = None,
        mb: t.Optional[int] = None,
        cpu: t.Optional[int] = None,
        cores: t.Optional[int] = None,
        salt: t.Optional[bytes] = None,
        tag: t.Optional[bytes] = None,
    ) -> None:
        """
        Populates the instance state from the provided session values
        which are composable into a `Passcrypt` hash.
        """
        self.timestamp = timestamp
        self.mb = mb
        self.cpu = cpu
        self.cores = cores
        self.salt = salt
        self.tag = tag

    @property
    def salt_size(self) -> t.Optional[int]:
        """
        Returns the length of the `salt` value stored in the instance
        state. If the `salt` has not been set, returns `None`.
        """
        salt = getattr(self, "salt", None)
        return len(salt) if salt else None

    @property
    def tag_size(self) -> t.Optional[int]:
        """
        Returns the length of the `tag` value stored in the instance
        state. If the `tag` has not been set, returns `None`.
        """
        tag = getattr(self, "tag", None)
        return len(tag) if tag else None

    def import_hash(self, passcrypt_hash: bytes) -> "self":
        """
        Populates the instance state from the decoded values represented
        in the bytes-type ``passcrypt_hash``. These hashes contain the
        inputs & parameters of a `Passcrypt` session. Does NOT check
        that decoded values follow the specification.
        """
        to_int = int.from_bytes
        read = BytesIO(passcrypt_hash).read

        self.timestamp = read(self.TIMESTAMP_BYTES)
        self.mb = to_int(read(self.MB_BYTES), BIG) + 1
        self.cpu = to_int(read(self.CPU_BYTES), BIG) + 1
        self.cores = to_int(read(self.CORES_BYTES), BIG) + 1
        salt_size = to_int(read(self.SALT_SIZE_BYTES), BIG) + 1
        self.salt = read(salt_size)
        self.tag = read()
        if not all(self.values()):
            raise PasscryptIssue.decoding_failed("premature termination")
        return self

    def export_hash(self) -> bytes:
        """
        Returns the composed `Passcrypt` hash from the instance state.
        Does NOT check that the instance state values follow the
        specification.
        """
        passcrypt_hash = (
            self.timestamp,
            (self.mb - 1).to_bytes(self.MB_BYTES, BIG),
            (self.cpu - 1).to_bytes(self.CPU_BYTES, BIG),
            (self.cores - 1).to_bytes(self.CORES_BYTES, BIG),
            (self.salt_size - 1).to_bytes(self.SALT_SIZE_BYTES, BIG),
            self.salt,
            self.tag,
        )
        return b"".join(passcrypt_hash)

    def in_allowed_ranges(
        self, mb_allowed: range, cpu_allowed: range, cores_allowed: range
    ) -> bool:
        """
        Procs a `ResourceWarning` exception if any of the range objects
        passed into the method do not contain the value which is set for
        its specified difficulty setting.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import Passcrypt

        allowed_resource_consumption = dict(
            mb_allowed=range(16, 256),  # Less than 256 MiB allowed
            cpu_allowed=range(2, 8),    # Less than 8 complexity allowed
            cores_allowed=range(1, 5),  # Less than 5 processes allowed
        )

        try:
            Passcrypt.verify(hashed_pw, pw, **allowed_resource_consumption)
        except ResourceWarning as danger:
            admin.log(danger)
            hard_limits_exceeded = (
                danger.requested_resources.mb > 512
                or danger.requested_resources.cpu > 11
                or danger.requested_resources.cores > 8
            )
            below_security_guidelines = (
                danger.requested_resources.mb < 16
                or danger.requested_resources.cpu < 2
            )
            if hard_limits_exceeded:
                raise danger
            elif below_security_guidelines:
                raise PermissionError("Minimum hash difficulty unmet.")
            Passcrypt.verify(hashed_pw, pw)
        """
        proc = raise_exception
        exc = PasscryptIssue.untrusted_resource_consumption
        header = PasscryptResources(self.mb, self.cpu, self.cores)
        self.mb in mb_allowed or proc(exc(self.MB, header))
        self.cpu in cpu_allowed or proc(exc(self.CPU, header))
        self.cores in cores_allowed or proc(exc(self.CORES, header))
        return True


class ProfileTokens(Slots):
    """
    Efficiently stores AsyncDatabase & Database profile token values
    which are used to more safely construct databases from potentially
    low entropy passphrases.
    """

    __slots__ = (
        "_gist",
        "_salt",
        "_salt_path",
        "_tmp_key",
        "login_key",
        "profile",
    )

    def __init__(self, tmp_key: bytes, gist: bytes) -> None:
        self._tmp_key = tmp_key
        self._gist = gist


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
        **extras: t.Dict[str, t.JSONSerializable],
    ) -> None:
        self.__dict__.update(extras)
        self.package = package
        self.version = version
        self.date = date


class PackageSignerFiles(OpenNamespace):
    """
    Stores the filename, hashing object key-value pairs of a package
    signing session.
    """


extras = dict(
    AuthFail=AuthFail,
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
    PasscryptResources=PasscryptResources,
    PasscryptSettings=PasscryptSettings,
    PlaintextMeasurements=PlaintextMeasurements,
    ProfileTokens=ProfileTokens,
    UnmaskedGUID=UnmaskedGUID,
    __doc__=__doc__,
    __package__=__package__,
)


_containers = make_module("_containers", mapping=extras)

