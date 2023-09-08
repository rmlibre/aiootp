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
    "DomainKDF",
    "Ed25519",
    "PackageSigner",
    "PackageVerifier",
    "Passcrypt",
    "X25519",
    "agenerate_key",
    "amnemonic",
    "generate_key",
    "mnemonic",
]


__doc__ = (
    "A collection of high-level tools for creating & managing symmetric"
    " & 25519 elliptic curve asymmetric keys."
)


import json
import math
import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey,
    X25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
    Ed25519PrivateKey,
)
from pathlib import Path
from secrets import token_bytes
from functools import wraps, partial
from hashlib import sha384, sha3_256, sha3_512, shake_128, shake_256
from ._constants import *
from ._exceptions import *
from ._typing import Typing as t
from ._containers import PasscryptHash, PasscryptSettings
from ._containers import PackageSignerFiles, PackageSignerScope
from .asynchs import sleep, asleep, Processes
from .commons import Slots, OpenNamespace, FrozenInstance
from .commons import make_module
from .gentools import Comprende, comprehension
from .gentools import data, adata
from .gentools import bytes_range, abytes_range
from .generics import Domains, Clock
from .generics import xi_mix, axi_mix
from .generics import encode_key, aencode_key
from .generics import hash_bytes, ahash_bytes
from .generics import int_as_bytes, bytes_as_int
from .generics import canonical_pack, acanonical_pack
from .generics import bytes_are_equal, abytes_are_equal
from .randoms import csprng, acsprng
from .randoms import generate_key, agenerate_key
from .randoms import generate_salt, agenerate_salt
from .ciphers import KeyAADBundle
from .ciphers import bytes_keys, abytes_keys


ns_clock = Clock(NANOSECONDS)
day_clock = Clock(DAYS, epoch=0)


class KDF(FrozenInstance):
    """
    A base type for passing KDF-related class attributes to subclasses
    in a consistent manner.
    """

    __slots__ = ()

    def __init_subclass__(cls, *, salt_label: t.AnyStr) -> None:
        """
        Ensures subclasses can define custom key & base type hasher
        algorithms within their class bodies & have the blocksizes of
        those objects be recorded by the class correctly during
        definition time.
        """
        cls._TYPE_BLOCKSIZE: int = cls._type().block_size
        cls._new_payload: callable = cls._type(
            Domains.encode_constant(salt_label, size=cls._TYPE_BLOCKSIZE)
        ).copy


class DomainKDF(KDF, salt_label=b"domain_kdf_salt"):
    """
    Creates objects able to derive domain & payload-specific keyed
    hashes. Payload updates are automatically canonicalized.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp import DomainKDF


    kdf = DomainKDF(b"ecdhe", session.transcript, key=session.key)

    auth_key = kdf.sha3_512(aad=b"auth-key")
    encryption_key = kdf.sha3_512(aad=b"encryption-key")

    """

    __slots__ = ("_domain", "_payload")

    _type: callable = shake_256

    def _initialize_payload(
        self, payload: t.Iterable[bytes], *, key: bytes
    ) -> None:
        """
        Canonically encodes the key & first batch of input data to
        prepare a hashing object which will process all additional
        payload.
        """
        kw = dict(blocksize=self._TYPE_BLOCKSIZE)
        payload = (
            canonical_pack(self._domain, *payload, **kw) if payload else b""
        )
        self._payload.update(key + payload)

    def _process_key(self, key: bytes) -> bytes:
        """
        Transforms an input key into a uniform value the size of the
        payload hashing object's blocksize.
        """
        return hash_bytes(
            Domains.KDF,
            self._domain,
            key=key,
            size=self._TYPE_BLOCKSIZE,
            hasher=self._type,
        )

    def __init__(
        self, domain: bytes, *payload: t.Iterable[bytes], key: bytes
    ) -> None:
        """
        Initializes a ``domain``-specific key & a keyed-mac object to
        incorporate an arbitrary amount of ``payload`` data, which is
        canonically encoded by the class, in key derivation.
        """
        self._domain = domain
        self._payload = self._new_payload()
        self._initialize_payload(payload, key=self._process_key(key))

    def copy(self) -> "cls":
        """
        Copies the instance state into a new object which can be updated
        separately in differing contexts.
        """
        kdf = self.__class__.__new__(self.__class__)
        kdf._domain = self._domain
        kdf._payload = self._payload.copy()
        return kdf

    async def aupdate(self, *payload: t.Iterable[bytes]) -> "self":
        """
        Canonically updates the payload object with additional values.
        This facilitates safe incorporation of arbitrary amounts of data
        for key derivation. Update calls, input data & the order of both,
        must match exactly to create matching KDF states in distinct
        instances.
        """
        if not payload:
            raise Issue.value_must("update payload", "not be empty")
        self._payload.update(
            await acanonical_pack(*payload, blocksize=self._TYPE_BLOCKSIZE)
        )
        return self

    def update(self, *payload: t.Iterable[bytes]) -> "self":
        """
        Canonically updates the payload object with additional values.
        This facilitates safe incorporation of arbitrary amounts of data
        for key derivation. Update calls, input data & the order of both,
        must match exactly to create matching KDF states in distinct
        instances.
        """
        if not payload:
            raise Issue.value_must("update payload", "not be empty")
        self._payload.update(
            canonical_pack(*payload, blocksize=self._TYPE_BLOCKSIZE)
        )
        return self

    async def asha3_256(
        self, *data: t.Iterable[bytes], aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed sha3_256 hash of the instance's state.
        """
        return await ahash_bytes(
            self._domain,
            aad,
            *data,
            key=self._payload.digest(SHA3_256_BLOCKSIZE) + aad,
            hasher=sha3_256,
        )

    def sha3_256(
        self, *data: t.Iterable[bytes], aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed sha3_256 hash of the instance's state.
        """
        return hash_bytes(
            self._domain,
            aad,
            *data,
            key=self._payload.digest(SHA3_256_BLOCKSIZE) + aad,
            hasher=sha3_256,
        )

    async def asha3_512(
        self, *data: t.Iterable[bytes], aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed sha3_512 hash of the instance's state.
        """
        return await ahash_bytes(
            self._domain,
            aad,
            *data,
            key=self._payload.digest(SHA3_512_BLOCKSIZE) + aad,
            hasher=sha3_512,
        )

    def sha3_512(
        self, *data: t.Iterable[bytes], aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed sha3_512 hash of the instance's state.
        """
        return hash_bytes(
            self._domain,
            aad,
            *data,
            key=self._payload.digest(SHA3_512_BLOCKSIZE) + aad,
            hasher=sha3_512,
        )

    async def ashake_128(
        self, *data: t.Iterable[bytes], size: int, aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed shake_128 hash of the instance's state.
        """
        return await ahash_bytes(
            self._domain,
            aad,
            *data,
            size=size,
            key=self._payload.digest(SHAKE_128_BLOCKSIZE) + aad,
            hasher=shake_128,
        )

    def shake_128(
        self, *data: t.Iterable[bytes], size: int, aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed shake_128 hash of the instance's state.
        """
        return hash_bytes(
            self._domain,
            aad,
            *data,
            size=size,
            key=self._payload.digest(SHAKE_128_BLOCKSIZE) + aad,
            hasher=shake_128,
        )

    async def ashake_256(
        self, *data: t.Iterable[bytes], size: int, aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed shake_256 hash of the instance's state.
        """
        return await ahash_bytes(
            self._domain,
            aad,
            *data,
            size=size,
            key=self._payload.digest(SHAKE_256_BLOCKSIZE) + aad,
            hasher=shake_256,
        )

    def shake_256(
        self, *data: t.Iterable[bytes], size: int, aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed shake_256 hash of the instance's state.
        """
        return hash_bytes(
            self._domain,
            aad,
            *data,
            size=size,
            key=self._payload.digest(SHAKE_256_BLOCKSIZE) + aad,
            hasher=shake_256,
        )


async def akeyed_choices(
    choices: t.Sequence[t.Any],
    selection_size: int,
    *,
    domain: bytes = b"",
    key: bytes,
) -> t.AsyncGenerator[None, t.Any]:
    """
    Makes ``selection_size`` number of selections from an indexable
    sequence of ``choices`` using subkeys derived from a provided
    ``domain`` & ``key``. Yields each selection one at a time.
    """
    total_choices = len(choices)
    key = await DomainKDF(
        domain,
        int_as_bytes(total_choices),
        int_as_bytes(selection_size),
        key=key,
    ).ashake_256(size=16 * selection_size, aad=Domains.PRNG)
    async for index in adata.root(key, size=16):
        yield choices[bytes_as_int(index) % total_choices]


def keyed_choices(
    choices: t.Sequence[t.Any],
    selection_size: int,
    *,
    domain: bytes = b"",
    key: bytes,
) -> t.Generator[None, t.Any, None]:
    """
    Makes ``selection_size`` number of selections from an indexable
    sequence of ``choices`` using subkeys derived from a provided
    ``domain`` & ``key``. Yields each selection one at a time.
    """
    total_choices = len(choices)
    key = DomainKDF(
        domain,
        int_as_bytes(total_choices),
        int_as_bytes(selection_size),
        key=key,
    ).shake_256(size=16 * selection_size, aad=Domains.PRNG)
    for index in data.root(key, size=16):
        yield choices[bytes_as_int(index) % total_choices]


async def amnemonic(
    passphrase: bytes = b"",
    size: int = 8,
    *,
    salt: t.Optional[bytes] = b"",
    words: t.Optional[t.Sequence[t.Any]] = None,
    **passcrypt_settings: t.PasscryptKWsNew,
) -> t.List[bytes]:
    """
    Creates list of ``size`` number of words for a mnemonic key from a
    user ``passphrase`` & an optional ``salt``. If no ``passphrase`` is
    supplied, then a random value is used to derive a unique mnemonic.
    The ``words`` used for the mnemonic can be passed, but by default
    are a word-list of 2048 unique, all lowercase english words.
    """
    domain = Domains.MNEMONIC
    words = words if words else WORD_LIST
    salt = (salt + domain) if salt else domain
    if passphrase:
        key = await Passcrypt.anew(passphrase, salt, **passcrypt_settings)
    elif passcrypt_settings:
        raise Issue.unused_parameters(
            "passcrypt_settings", "generating a random mnemonic key"
        )
    else:
        key = await acsprng()
    return [
        word
        async for word in akeyed_choices(
            words, size, domain=domain, key=key
        )
    ]


def mnemonic(
    passphrase: bytes = b"",
    size: int = 8,
    *,
    salt: t.Optional[bytes] = b"",
    words: t.Optional[t.Sequence[t.Any]] = None,
    **passcrypt_settings: t.PasscryptKWsNew,
) -> t.List[bytes]:
    """
    Creates list of ``size`` number of words for a mnemonic key from a
    user ``passphrase`` & an optional ``salt``. If no ``passphrase`` is
    supplied, then a random value is used to derive a unique mnemonic.
    The ``words`` used for the mnemonic can be passed, but by default
    are a word-list of 2048 unique, all lowercase english words.
    """
    domain = Domains.MNEMONIC
    words = words if words else WORD_LIST
    salt = (salt + domain) if salt else domain
    if passphrase:
        key = Passcrypt.new(passphrase, salt, **passcrypt_settings)
    elif passcrypt_settings:
        raise Issue.unused_parameters(
            "passcrypt_settings", "generating a random mnemonic key"
        )
    else:
        key = csprng()
    return [*keyed_choices(words, size, domain=domain, key=key)]


class PasscryptSession(FrozenInstance):
    """
    Hanldes the initialization of running the `Passcrypt` hashing
    algorithm with sets of given user parameters.
    """

    __slots__ = (
        "passphrase",
        "salt",
        "aad",
        "mb",
        "cpu",
        "cores",
        "tag_size",
        "row_size",
        "rows",
        "total_size",
        "ram",
        "proof",
    )

    vars().update({var: val for var, val in passcrypt.__dict__.items()})

    _PASSCRYPT_KDF_SALT: bytes = Domains.encode_constant(
        b"passcrypt_kdf_salt", size=SHAKE_128_BLOCKSIZE
    )

    _new_passcrypt_proof_kdf: callable = shake_128(_PASSCRYPT_KDF_SALT).copy

    specification: OpenNamespace = OpenNamespace(
        is_passphrase=lambda passphrase: (
            len(passphrase) >= passcrypt.MIN_PASSPHRASE_BYTES
            and passphrase.__class__ is bytes
        ),
        is_salt=lambda salt: (
            len(salt)
            in range(passcrypt.MIN_SALT_SIZE, passcrypt.MAX_SALT_SIZE + 1)
            and salt.__class__ is bytes
        ),
        is_aad=lambda aad: aad.__class__ is bytes,
        is_mb=lambda mb: (
            mb in range(passcrypt.MIN_MB, passcrypt.MAX_MB + 1)
            and mb.__class__ is int
        ),
        is_cpu=lambda cpu: (
            cpu in range(passcrypt.MIN_CPU, passcrypt.MAX_CPU + 1)
            and cpu.__class__ is int
        ),
        is_cores=lambda cores: (
            cores in range(passcrypt.MIN_CORES, passcrypt.MAX_CORES + 1)
            and cores.__class__ is int
        ),
        is_tag_size=lambda tag_size: (
            tag_size >= passcrypt.MIN_TAG_SIZE and tag_size.__class__ is int
        ),
        is_salt_size=lambda salt_size: (
            salt_size
            in range(passcrypt.MIN_SALT_SIZE, passcrypt.MAX_SALT_SIZE + 1)
            and salt_size.__class__ is int
        ),
    )

    @classmethod
    def _validate_inputs(
        cls, passphrase: bytes, salt: bytes, aad: bytes
    ) -> None:
        """
        Makes sure ``passphrase``, ``salt`` & ``aad`` are to the
        ``Passcrypt`` specification. Throws `ValueError` or `TypeError`
        accordingly.
        """
        if not cls.specification.is_passphrase(passphrase):
            raise PasscryptIssue.improper_passphrase(Metadata(passphrase))
        elif not cls.specification.is_salt(salt):
            raise PasscryptIssue.improper_salt(Metadata(salt))
        elif not cls.specification.is_aad(aad):
            raise PasscryptIssue.improper_aad()

    @classmethod
    def _validate_settings(
        cls,
        mb: int,
        cpu: int,
        cores: int,
        tag_size: int,
        salt_size: int = passcrypt.MIN_SALT_SIZE,
    ) -> None:
        """
        Ensures the values ``mb``, ``cpu``, ``cores`` & ``tag_size``
        passed into this package's Argon2i-like, passphrase-based key
        derivation function are within acceptable bounds & types. The
        ``salt_size`` can be validated as well. Since it's not used in
        all interfaces, it's optional here.
        """
        if not cls.specification.is_mb(mb):
            raise PasscryptIssue.invalid_mb(mb)
        elif not cls.specification.is_cpu(cpu):
            raise PasscryptIssue.invalid_cpu(cpu)
        elif not cls.specification.is_cores(cores):
            raise PasscryptIssue.invalid_cores(cores)
        elif not cls.specification.is_tag_size(tag_size):
            raise PasscryptIssue.invalid_tag_size(tag_size)
        elif not cls.specification.is_salt_size(salt_size):
            raise PasscryptIssue.invalid_salt_size(salt_size)

    def __init__(
        self,
        passphrase: bytes,
        salt: bytes,
        *,
        aad: bytes,
        mb: int,
        cpu: int,
        cores: int,
        tag_size: int,
    ) -> None:
        """
        Efficiently stores user parameters.
        """
        self._validate_inputs(passphrase, salt, aad=aad)
        self._validate_settings(mb, cpu, cores, tag_size)
        self.passphrase = passphrase
        self.salt = salt
        self.aad = aad
        self.mb = mb
        self.cpu = cpu
        self.cores = cores
        self.tag_size = tag_size

    def __iter__(
        self,
    ) -> t.Generator[None, t.Union[bytearray, t.Callable, int], None]:
        """
        Dumps the set of relevant parameters & function pointers for the
        `Passcrypt` worker. Gives the session a cleaner interface.
        """
        yield from (
            self.ram,
            self.proof.update,
            self.proof.digest,
            self.row_size,
            self.total_size,
        )

    def _hash_session_parameters(self) -> bytes:
        """
        Returns a 336-byte hash of the session's canonically encoded
        parameters.
        """
        return hash_bytes(
            Domains.PASSCRYPT,
            self.salt,
            self.aad,
            int_as_bytes(self.mb),
            int_as_bytes(self.cpu),
            int_as_bytes(self.cores),
            int_as_bytes(self.tag_size),
            key=self.passphrase + self.salt + self.aad,
            hasher=shake_128,
            size=336,
            pad=self.PASSCRYPT_PAD,
        )

    def prepare_session(self) -> "self":
        """
        Canonically hash the parameters to the function & calculate the
        dimensionality of the cache from the given settings.
        """
        rounds = max(
            (1, self.cpu // self.CPU_TO_DIGEST_PAIRS_PER_ROW_RATIO)
        )
        self.rows = math.ceil((B_TO_MB_RATIO * self.mb) / (336 * rounds))
        self.row_size = 336 * rounds
        self.total_size = self.row_size * self.rows
        parameters = self._hash_session_parameters()
        self.proof = self._new_passcrypt_proof_kdf()
        self.proof.update(parameters)
        return self

    def allocate_ram(self) -> "self":
        """
        Builds a virtual 2d memory cache out of a 1d bytearray to do
        efficient & in-place memory overwrites of segments of the cache
        with new proofs-of-work as the `Passcrypt` algorithm runs to
        completion.

        The bytearray is traversed to simulate the dimensionality of a
        columns=2*rounds, rows=ceil((1024*1024*mb) / (2*168*rounds)),
        2d array, where the unit measure for the width of one column is
        168-bytes (one digest from the `shake_128` `proof` object), &
        rounds=max([1, cpu // 2]).

        This procedure is designed to build the initial cache as fast as
        possible using the C implementation of `hashlib.shake_128` to
        better equalize the execution time between users & their
        adversaries. Quickly building the initial cache to the full size
        of the desired `mb` memory cost is also intended to reduce the
        inefficiencies of doing any resizing of the cache once the
        algorithm begins. This too is the main motivating factor for the
        size of each row being an equal multiple of 336, as it allows
        cache traversal & insertions without needing to plan separately
        for how to treat insertions once the end of a row is reached.
        """
        self.ram = bytearray()
        size = self.total_size
        max_size = (B_TO_MB_RATIO * 512) - 1  # 512MiB, max digest size
        while size > max_size:                # of shake_128 in python
            self.ram.extend(self.proof.digest(max_size))
            self.proof.update(self.ram[-168:])
            size -= max_size
        if size:
            self.ram.extend(self.proof.digest(size))
            self.proof.update(self.ram[-168:])
        return self


class Passcrypt:
    """
    This class is used to implement an Argon2i-like passphrase-based
    key derivation function that's designed to be resistant to cache-
    timing side-channel attacks & time-memory trade-offs.

    It uses a passphrase-keyed scanning function which sequentially
    passes over unique memory caches requiring a tunable amount of
    difficulty, which is designed here to be very intuitive.

    This scheme is secret independent with regard to how it chooses to
    pass over memory. Through proofs of work & memory, it ensures an
    attacker attempting to crack a passphrase hash cannot complete the
    algorithm substantially faster by storing more memory than what's
    already necessary, or with substantially less memory, by dropping
    cache entries, without drastically increasing the computational
    cost.

    The algorithm initializes all of the columns for the cache using a
    single `shake_128` object after being fed the passphrase, salt, aad
    & all of the parameters. The number of columns is computed
    dynamically to reach the specified memory cost considering that each
    row will hold 2 * max([1, cpu // 2]) digests of 168-bytes. This
    allows the cache to be efficiently allocated up front, benefiting
    further by not needing to resize the memory cache throughout the
    running of the algorithm.

    The sequential passes involve a current row index, the index of the
    row which is the reflection of the first across the cache, & a
    current offset into a row which are multiples of 336 (two digests).
    The index & reflection pointers interleave each other, hashing rows
    with the same object as they scan, & overwriting the 168-byte digest
    / piece of cache at the offset they're pointing to after each hash.

     _____________________________________
    |                                     |
    |    Algorithm Diagram: Side-View     |
    |_____________________________________|

           ___________________ # of rows ___________________
          |                                                 |
          |              initial memory cache               |
          |  row  # of columns == 2 * max([1, cpu // 2])    |
          |   |   # of rows == ⌈1024*1024*mb/168*columns⌉   |
          v   v                                             v
    column|---'-----------------------------------------'---| the initial cache
    column|---'-----------------------------------------'---| of size ~`mb` is
    column|---'-----------------------------------------'---| built very quickly
    column|---'-----------------------------------------'---| using SHAKE-128.
    column|---'-----------------------------------------'---| each (row, column)
    column|---'-----------------------------------------'---| coordinate holds
    column|---'-----------------------------------------'---| one element of
    column|---'-----------------------------------------'---| 168-bytes.
                                                        ^
                                                        |
                           reflection                  row
                          <-   |
          |--------------------'-------'--------------------| each row is
          |--------------------'-------'--------------------| hashed then has
          |--------------------'-------'--------------------| a new 168-byte
          |--------------------'-------'--------------------| digest overwrite
          |--------------------'-------'--------------------| the current pointer
          |--------------------'-------'--------------------| in an alternating
          |--------------------Xxxxxxxx'xxxxxxxxxxxxxxxxxxxx| sequence, first at
          |oooooooooooooooooooo'oooooooO--------------------| the index, then at
                                       |   ->                 its reflection.
                                     index


          |--'-------------------------------------------'--| this continues
          |--'-------------------------------------------'--| until the entire
          |--'-------------------------------------------Xxx| cache has been
          |ooO-------------------------------------------'--| overwritten.
          |xx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'xx| a single `shake_128`
          |oo'ooooooooooooooooooooooooooooooooooooooooooo'oo| object (H) is used
          |xx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'xx| to do all of the
          |oo'ooooooooooooooooooooooooooooooooooooooooooo'oo| hashing.
             |   ->                                 <-   |
           index                                     reflection


          |xxxxxxxxxxx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx| finally, the whole
          |ooooooooooo'ooooooooooooooooooooooooooooooooooooo| cache is quickly
          |xxxxxxxxxxx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx| hashed `cpu` + 2
          |ooooooooooo'ooooooooooooooooooooooooooooooooooooo| number of times.
          |Fxxxxxxxxxx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx| after each pass an
          |foooooooooo'ooooooooooooooooooooooooooooooooooooo| 84-byte digest (F)
          |fxxxxxxxxxx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx| is inserted into the
          |foooooooooo'ooooooooooooooooooooooooooooooooooooo| cache, ruling out
                      |   ->                                  hashing state cycles.
                      | hash cpu + 2 # of times               Then a `tag_size`-
                      v                                       byte tag is output.
           H.update(cache)

          tag = H.digest(tag_size)

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp import Passcrypt, Domains
    from getpass import getpass


    Passcrypt.PEPPER = bytes.fromhex(app.application_pepper)

    # registration ->

    un = getpass("username: ").encode() + Domains.USERNAME
    pw = getpass("passphrase: ").encode() + Domains.PASSPHRASE

    pw_hash = Passcrypt.hash_passphrase(pw, aad=un, mb=128)


    # a login attempt ->

    un = getpass("username: ").encode() + Domains.USERNAME
    pw = getpass("passphrase: ").encode() + Domains.PASSPHRASE

    try:
        Passcrypt.verify(pw_hash, pw, aad=un, ttl=24 * 3600)
    except Passcrypt.InvalidPassphrase as auth_fail:
        app.post_mortem(error=auth_fail)
    except Passcrypt.TimestampExpired as expired_hash:
        # 24-hour registration expired
        app.post_mortem(error=expired_hash)

    """

    __slots__ = ()

    vars().update(
        {f"_{var}": val for var, val in passcrypt.__dict__.items()}
    )

    # An operator of a passphrase database may add a static secret value
    # to the class, referred to as a `pepper`. That value can be set in
    # this variable & will then augment all hashes produced by the class
    # with that additional secret entropy. The operator is in charge of
    # storing this value securely so it can be reused when the program
    # restarts. This value SHOULD NOT be stored in the same database
    # where the hashes are stored.
    PEPPER: bytes = b""

    TimestampExpired = TimestampExpired
    InvalidPassphrase = InvalidPassphrase
    ImproperPassphrase = ImproperPassphrase

    def __new__(
        cls,
        mb: int = _DEFAULT_MB,
        cpu: int = _DEFAULT_CPU,
        cores: int = _DEFAULT_CORES,
        tag_size: int = _DEFAULT_SCHEMA_TAG_SIZE,
        salt_size: int = _DEFAULT_SCHEMA_SALT_SIZE,
    ) -> "PasscryptInstance":
        """
        Stores user-defined settings within an object so that they can
        automatically be passed into mirrored calls to the class'
        methods, simulating the behavior of instance methods.
        """
        return PasscryptInstance(
            mb=mb,
            cpu=cpu,
            cores=cores,
            tag_size=tag_size,
            salt_size=salt_size,
        )

    @staticmethod
    def _work_memory_prover(session: PasscryptSession) -> bytes:
        """
        Returns the digest of a keyed scanning function. It sequentially
        passes over a memory cache with an intuitive & tunable amount of
        difficulty. This scheme is secret independent with regard to how
        it chooses to pass over memory.

        Through proofs of work & memory, it ensures an attacker
        attempting to crack a passphrase hash cannot complete the
        algorithm substantially faster by storing more memory than
        what's already necessary, or with substantially less memory, by
        dropping cache entries, without drastically increasing the
        computational cost.
        """
        ram, update, digest, row_size, total_size = session
        assert total_size == len(ram)
        column_start_indexes = range(0, row_size, 336)
        row_start_indexes = [*range(0, total_size, row_size)]
        for column_start in column_start_indexes:
            for row_start in row_start_indexes:
                index = row_start + column_start
                ref_row_start = -row_start - row_size
                reflection = ref_row_start + column_start + 168
                ref_end = reflection + 168
                ref_end = ref_end if ref_end < 0 else None

                update(ram[row_start : row_start + row_size])
                ram[index : index + 168] = digest(168)

                update(ram[ref_row_start : ref_row_start + row_size])
                ram[reflection:ref_end] = digest(168)
        for iteration in range(session.cpu + 2):
            seek = 168 * iteration
            ram[seek : seek + 84] = digest(84)
            update(ram)
        return digest(session.tag_size)

    @classmethod
    def _passcrypt(cls, session: PasscryptSession) -> bytes:
        """
        This method implements an Argon2i-like passphrase-based key
        derivation function that's designed to be resistant to cache-
        timing side-channel attacks & time-memory trade-offs.
        """
        session.prepare_session().allocate_ram()
        return cls._work_memory_prover(session)

    @classmethod
    async def anew(
        cls,
        passphrase: bytes,
        salt: bytes,
        *,
        aad: bytes = _DEFAULT_AAD,
        mb: int = _DEFAULT_MB,
        cpu: int = _DEFAULT_CPU,
        cores: int = _DEFAULT_CORES,
        tag_size: int = _DEFAULT_TAG_SIZE,
    ) -> bytes:
        """
        Returns just the ``tag_size``-byte hash of the ``passphrase``
        when processed with the given ``salt``, ``aad`` & difficulty
        settings.

        ``passphrase``: A 12-byte or greater entropic value that
                contains the user's desired entropy & cryptographic
                strength. A passphrase is ideally a compilation of
                words, symbols & numbers which are easy for the user to
                remember, but difficult for anyone else to guess even if
                they know precise details about who the user is & their
                characteristics / tendencies.

        ``salt``: An ephemeral, uniform 8-byte or greater entropic
                value. SHOULD BE RANDOMLY GENERATED, its main purpose
                is to be unpredictable.

        ``aad``: An arbitrary bytes value a user decides to categorize
                the hash with. It is authenticated as associated data &
                safely permutes hashes created with different ``aad``.

        ``mb``: The int number of Mebibytes (MiB) the user desires for
                this run of the algorithm to cost to compute.

        ``cpu``: The int number of iterations over the entire memory
                cache that are executed for this run of the algorithm.
                The size & computational cost of each row of the memory
                cache is also linearly proportional to this parameter.

        ``cores``: The int number of separate processes that will be
                pooled to compute this run of the algorithm.

        ``tag_size``: The int length of the hash that will be output at
                the end of this run of the algorithm.

        NOTICE: The passcrypt algorithm can be highly memory intensive.
        These resources may not be freed up, & often are not, because of
        python quirks around memory management. To force the release of
        these resources, we run the function in another process which
        guarantees the release.
        """
        if not PasscryptSession.specification.is_cores(cores):
            raise PasscryptIssue.invalid_cores(cores)
        try:
            sessions = []
            total_mb = int_as_bytes(mb)
            core_mb = math.ceil(mb / cores)
            async for core in abytes_range.root(cores):
                core_aad = canonical_pack(cls.PEPPER, aad, core, total_mb)
                session = PasscryptSession(
                    passphrase,
                    salt,
                    aad=core_aad,
                    mb=core_mb,
                    cpu=cpu,
                    cores=cores,
                    tag_size=tag_size,
                )
                kw = dict(session=session, probe_frequency=0.001)
                sessions.append(
                    await Processes.asubmit(cls._passcrypt, **kw)
                )
            for core, session in enumerate(sessions):
                sessions[core] = await session.aresult()
            return await axi_mix(b"".join(sessions), size=tag_size)
        except Exception as error:
            if Processes._pool._broken:
                Processes.reset_pool()
                raise Issue.broken_pool_restarted() from error
            raise error

    @classmethod
    def new(
        cls,
        passphrase: bytes,
        salt: bytes,
        *,
        aad: bytes = _DEFAULT_AAD,
        mb: int = _DEFAULT_MB,
        cpu: int = _DEFAULT_CPU,
        cores: int = _DEFAULT_CORES,
        tag_size: int = _DEFAULT_TAG_SIZE,
    ) -> bytes:
        """
        Returns just the ``tag_size``-byte hash of the ``passphrase``
        when processed with the given ``salt``, ``aad`` & difficulty
        settings.

        ``passphrase``: A 12-byte or greater entropic value that
                contains the user's desired entropy & cryptographic
                strength. A passphrase is ideally a compilation of
                words, symbols & numbers which are easy for the user to
                remember, but difficult for anyone else to guess even if
                they know precise details about who the user is & their
                characteristics / tendencies.

        ``salt``: An ephemeral, uniform 8-byte or greater entropic
                value. SHOULD BE RANDOMLY GENERATED, its main purpose
                is to be unpredictable.

        ``aad``: An arbitrary bytes value a user decides to categorize
                the hash with. It is authenticated as associated data &
                safely permutes hashes created with different ``aad``.

        ``mb``: The int number of Mebibytes (MiB) the user desires for
                this run of the algorithm to cost to compute.

        ``cpu``: The int number of iterations over the entire memory
                cache that are executed for this run of the algorithm.
                The size & computational cost of each row of the memory
                cache is also linearly proportional to this parameter.

        ``cores``: The int number of separate processes that will be
                pooled to compute this run of the algorithm.

        ``tag_size``: The int length of the hash that will be output at
                the end of this run of the algorithm.

        NOTICE: The passcrypt algorithm can be highly memory intensive.
        These resources may not be freed up, & often are not, because of
        python quirks around memory management. To force the release of
        these resources, we run the function in another process which
        guarantees the release.
        """
        if not PasscryptSession.specification.is_cores(cores):
            raise PasscryptIssue.invalid_cores(cores)
        try:
            sessions = []
            total_mb = int_as_bytes(mb)
            core_mb = math.ceil(mb / cores)
            for core in bytes_range.root(cores):
                core_aad = canonical_pack(cls.PEPPER, aad, core, total_mb)
                session = PasscryptSession(
                    passphrase,
                    salt,
                    aad=core_aad,
                    mb=core_mb,
                    cpu=cpu,
                    cores=cores,
                    tag_size=tag_size,
                )
                kw = dict(session=session, probe_frequency=0.001)
                sessions.append(Processes.submit(cls._passcrypt, **kw))
            for core, session in enumerate(sessions):
                sessions[core] = session.result()
            return xi_mix(b"".join(sessions), size=tag_size)
        except Exception as error:
            if Processes._pool._broken:
                Processes.reset_pool()
                raise Issue.broken_pool_restarted() from error
            raise error

    @classmethod
    async def ahash_passphrase(
        cls,
        passphrase: bytes,
        *,
        aad: bytes = _DEFAULT_AAD,
        mb: int = _DEFAULT_MB,
        cpu: int = _DEFAULT_CPU,
        cores: int = _DEFAULT_CORES,
        tag_size: int = _DEFAULT_SCHEMA_TAG_SIZE,
        salt_size: int = _DEFAULT_SCHEMA_SALT_SIZE,
    ) -> bytes:
        """
        Returns the passcrypt difficulty settings, salt & hash of the
        ``passphrase`` in a single raw bytes sequence for convenient
        storage. The salt here is automatically generated.

        ``passphrase``: A 12-byte or greater entropic value that
                contains the user's desired entropy & cryptographic
                strength. A passphrase is ideally a compilation of
                words, symbols & numbers which are easy for the user to
                remember, but difficult for anyone else to guess even if
                they know precise details about who the user is & their
                characteristics / tendencies.

        ``aad``: An arbitrary bytes value a user decides to categorize
                the hash with. It is authenticated as associated data &
                safely permutes hashes created with different ``aad``.

        ``mb``: The int number of Mebibytes (MiB) the user desires for
                this run of the algorithm to cost to compute.

        ``cpu``: The int number of iterations over the entire memory
                cache that are executed for this run of the algorithm.
                The size & computational cost of each row of the memory
                cache is also linearly proportional to this parameter.

        ``cores``: The int number of separate processes that will be
                pooled to compute this run of the algorithm.

        ``tag_size``: The int length of the hash that will be output at
                the end of this run of the algorithm.

        ``salt_size``: The int length of the salt that will be generated
                & attached to the hash for this run of the algorithm.

         _____________________________________
        |                                     |
        |   Format Diagram: Passcrypt Hash    |
        |_____________________________________|
         ______________________________________________________________
        |                                    |                         |
        |               Header               |          Body           |
        |-------|-------|------|------|------|--------|----------------|
        | time  |  mb   | cpu  | cores| Slen |  salt  |      tag       |
        |  8-   |  3-   |  1-  |  1-  |  1-  |  Slen- |      >=16-     |
        | bytes | bytes | byte | byte | byte |  bytes |     bytes      |
        |_______|_______|______|______|______|________|________________|
        |                                                              |
        |                          >=34-bytes                          |
        |______________________________________________________________|

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import Passcrypt, Domains
        from getpass import getpass


        Passcrypt.PEPPER = bytes.fromhex(getpass("hexidecimal pepper: "))

        # registration ->

        un = getpass("username: ").encode() + Domains.USERNAME
        pw = getpass("passphrase: ").encode() + Domains.PASSPHRASE

        pw_hash = await Passcrypt.ahash_passphrase(pw, aad=un, mb=128)


        # a login attempt ->

        un = getpass("username: ").encode() + Domains.USERNAME
        pw = getpass("passphrase: ").encode() + Domains.PASSPHRASE

        try:
            await Passcrypt.averify(pw_hash, pw, aad=un, ttl=24 * 3600)
        except Passcrypt.InvalidPassphrase as auth_fail:
            app.post_mortem(error=auth_fail)
        except Passcrypt.TimestampExpired as expired_hash:
            # 24-hour registration expired
            app.post_mortem(error=expired_hash)

        """
        timestamp = await ns_clock.amake_timestamp()
        salt = token_bytes(salt_size)
        tag = await cls.anew(
            passphrase,
            salt,
            aad=timestamp + aad,
            mb=mb,
            cpu=cpu,
            cores=cores,
            tag_size=tag_size,
        )
        return PasscryptHash(
            timestamp=timestamp,
            mb=mb,
            cpu=cpu,
            cores=cores,
            salt=salt,
            tag=tag,
        ).export_hash()

    @classmethod
    def hash_passphrase(
        cls,
        passphrase: bytes,
        *,
        aad: bytes = _DEFAULT_AAD,
        mb: int = _DEFAULT_MB,
        cpu: int = _DEFAULT_CPU,
        cores: int = _DEFAULT_CORES,
        tag_size: int = _DEFAULT_SCHEMA_TAG_SIZE,
        salt_size: int = _DEFAULT_SCHEMA_SALT_SIZE,
    ) -> bytes:
        """
        Returns the passcrypt difficulty settings, salt & hash of the
        ``passphrase`` in a single raw bytes sequence for convenient
        storage. The salt here is automatically generated.

        ``passphrase``: A 12-byte or greater entropic value that
                contains the user's desired entropy & cryptographic
                strength. A passphrase is ideally a compilation of
                words, symbols & numbers which are easy for the user to
                remember, but difficult for anyone else to guess even if
                they know precise details about who the user is & their
                characteristics / tendencies.

        ``aad``: An arbitrary bytes value a user decides to categorize
                the hash with. It is authenticated as associated data &
                safely permutes hashes created with different ``aad``.

        ``mb``: The int number of Mebibytes (MiB) the user desires for
                this run of the algorithm to cost to compute.

        ``cpu``: The int number of iterations over the entire memory
                cache that are executed for this run of the algorithm.
                The size & computational cost of each row of the memory
                cache is also linearly proportional to this parameter.

        ``cores``: The int number of separate processes that will be
                pooled to compute this run of the algorithm.

        ``tag_size``: The int length of the hash that will be output at
                the end of this run of the algorithm.

        ``salt_size``: The int length of the salt that will be generated
                & attached to the hash for this run of the algorithm.

         _____________________________________
        |                                     |
        |   Format Diagram: Passcrypt Hash    |
        |_____________________________________|
         ______________________________________________________________
        |                                    |                         |
        |               Header               |          Body           |
        |-------|-------|------|------|------|--------|----------------|
        | time  |  mb   | cpu  | cores| Slen |  salt  |      tag       |
        |  8-   |  3-   |  1-  |  1-  |  1-  |  Slen- |      >=16-     |
        | bytes | bytes | byte | byte | byte |  bytes |     bytes      |
        |_______|_______|______|______|______|________|________________|
        |                                                              |
        |                          >=34-bytes                          |
        |______________________________________________________________|

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import Passcrypt, Domains
        from getpass import getpass


        Passcrypt.PEPPER = bytes.fromhex(getpass("hexidecimal pepper: "))

        # registration ->

        un = getpass("username: ").encode() + Domains.USERNAME
        pw = getpass("passphrase: ").encode() + Domains.PASSPHRASE

        pw_hash = Passcrypt.hash_passphrase(pw, aad=un, mb=128)


        # a login attempt ->

        un = getpass("username: ").encode() + Domains.USERNAME
        pw = getpass("passphrase: ").encode() + Domains.PASSPHRASE

        try:
            Passcrypt.verify(pw_hash, pw, aad=un, ttl=24 * 3600)
        except Passcrypt.InvalidPassphrase as auth_fail:
            app.post_mortem(error=auth_fail)
        except Passcrypt.TimestampExpired as expired_hash:
            # 24-hour registration expired
            app.post_mortem(error=expired_hash)

        """
        timestamp = ns_clock.make_timestamp()
        salt = token_bytes(salt_size)
        tag = cls.new(
            passphrase,
            salt,
            aad=timestamp + aad,
            mb=mb,
            cpu=cpu,
            cores=cores,
            tag_size=tag_size,
        )
        return PasscryptHash(
            timestamp=timestamp,
            mb=mb,
            cpu=cpu,
            cores=cores,
            salt=salt,
            tag=tag,
        ).export_hash()

    @classmethod
    async def averify(
        cls,
        composed_passcrypt_hash: bytes,
        passphrase: bytes,
        *,
        aad: bytes = _DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
        mb_allowed: range = _MB_RESOURCE_SAFETY_RANGE,
        cpu_allowed: range = _CPU_RESOURCE_SAFETY_RANGE,
        cores_allowed: range = _CORES_RESOURCE_SAFETY_RANGE,
    ) -> None:
        """
        Verifies that a supplied ``passphrase`` was indeed used to build
        the ``composed_passcrypt_hash``.

        Runs the passcrypt algorithm on the ``passphrase`` with the
        parameters specified in the ``composed_passcrypt_hash`` value's
        attached metadata. If the result doesn't match the hash in
        ``composed_passcrypt_hash`` then `Passcrypt.InvalidPassphrase`
        is raised. The ``composed_passcrypt_hash`` passed into this
        method must be raw bytes.

        ``aad``: An arbitrary bytes value a user decides to categorize
                the hash with. It is authenticated as associated data &
                safely permutes hashes created with different ``aad``.

        ``ttl``: An amount of seconds which dictate the allowable age of
                a ``composed_passcrypt_hash``. The associated timestamp,
                which is attached to the hash, helps ensure the tag is
                unique by separating each tag created across time into
                distinct domains.

        ``mb_allowed``: A `builtins.range` object which includes all
                allowable values for the `mb` (Mebibyte) resource cost.
                Raises `ResourceWarning` if the `mb` specified in the
                provided hash falls outside of that range.

        ``cpu_allowed``: A `builtins.range` object which includes all
                allowable values for the `cpu` resource cost. Raises
                `ResourceWarning` if the `cpu` specified in the provided
                hash falls outside of that range.

        ``cores_allowed``: A `builtins.range` object which includes all
                allowable values for the `cores` resource cost. Raises
                `ResourceWarning` if the `cores` specified in the
                provided hash falls outside of that range.

         _____________________________________
        |                                     |
        |   Format Diagram: Passcrypt Hash    |
        |_____________________________________|
         ______________________________________________________________
        |                                    |                         |
        |               Header               |          Body           |
        |-------|-------|------|------|------|--------|----------------|
        | time  |  mb   | cpu  | cores| Slen |  salt  |      tag       |
        |  8-   |  3-   |  1-  |  1-  |  1-  |  Slen- |      >=16-     |
        | bytes | bytes | byte | byte | byte |  bytes |     bytes      |
        |_______|_______|______|______|______|________|________________|
        |                                                              |
        |                          >=34-bytes                          |
        |______________________________________________________________|

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import Passcrypt, Domains
        from getpass import getpass


        Passcrypt.PEPPER = bytes.fromhex(getpass("hexidecimal pepper: "))

        # registration ->

        un = getpass("username: ").encode() + Domains.USERNAME
        pw = getpass("passphrase: ").encode() + Domains.PASSPHRASE

        pw_hash = await Passcrypt.ahash_passphrase(pw, aad=un, mb=128)


        # a login attempt ->

        un = getpass("username: ").encode() + Domains.USERNAME
        pw = getpass("passphrase: ").encode() + Domains.PASSPHRASE

        try:
            await Passcrypt.averify(pw_hash, pw, aad=un, ttl=24 * 3600)
        except Passcrypt.InvalidPassphrase as auth_fail:
            app.post_mortem(error=auth_fail)
        except Passcrypt.TimestampExpired as expired_hash:
            # 24-hour registration expired
            app.post_mortem(error=expired_hash)

        """
        parts = PasscryptHash().import_hash(composed_passcrypt_hash)
        await ns_clock.atest_timestamp(parts.timestamp, ttl * NS_TO_S_RATIO)
        parts.in_allowed_ranges(mb_allowed, cpu_allowed, cores_allowed)
        untrusted_hash = await cls.anew(
            passphrase,
            parts.salt,
            aad=parts.timestamp + aad,
            mb=parts.mb,
            cpu=parts.cpu,
            cores=parts.cores,
            tag_size=parts.tag_size,
        )
        if not bytes_are_equal(untrusted_hash, parts.tag):
            raise PasscryptIssue.verification_failed()

    @classmethod
    def verify(
        cls,
        composed_passcrypt_hash: bytes,
        passphrase: bytes,
        *,
        aad: bytes = _DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
        mb_allowed: range = _MB_RESOURCE_SAFETY_RANGE,
        cpu_allowed: range = _CPU_RESOURCE_SAFETY_RANGE,
        cores_allowed: range = _CORES_RESOURCE_SAFETY_RANGE,
    ) -> None:
        """
        Verifies that a supplied ``passphrase`` was indeed used to build
        the ``composed_passcrypt_hash``.

        Runs the passcrypt algorithm on the ``passphrase`` with the
        parameters specified in the ``composed_passcrypt_hash`` value's
        attached metadata. If the result doesn't match the hash in
        ``composed_passcrypt_hash`` then `Passcrypt.InvalidPassphrase`
        is raised. The ``composed_passcrypt_hash`` passed into this
        method must be raw bytes.

        ``aad``: An arbitrary bytes value a user decides to categorize
                the hash with. It is authenticated as associated data &
                safely permutes hashes created with different ``aad``.

        ``ttl``: An amount of seconds which dictate the allowable age of
                a ``composed_passcrypt_hash``. The associated timestamp,
                which is attached to the hash, helps ensure the tag is
                unique by separating each tag created across time into
                distinct domains.

        ``mb_allowed``: A `builtins.range` object which includes all
                allowable values for the `mb` (Mebibyte) resource cost.
                Raises `ResourceWarning` if the `mb` specified in the
                provided hash falls outside of that range.

        ``cpu_allowed``: A `builtins.range` object which includes all
                allowable values for the `cpu` resource cost. Raises
                `ResourceWarning` if the `cpu` specified in the provided
                hash falls outside of that range.

        ``cores_allowed``: A `builtins.range` object which includes all
                allowable values for the `cores` resource cost. Raises
                `ResourceWarning` if the `cores` specified in the
                provided hash falls outside of that range.

         _____________________________________
        |                                     |
        |   Format Diagram: Passcrypt Hash    |
        |_____________________________________|
         ______________________________________________________________
        |                                    |                         |
        |               Header               |          Body           |
        |-------|-------|------|------|------|--------|----------------|
        | time  |  mb   | cpu  | cores| Slen |  salt  |      tag       |
        |  8-   |  3-   |  1-  |  1-  |  1-  |  Slen- |      >=16-     |
        | bytes | bytes | byte | byte | byte |  bytes |     bytes      |
        |_______|_______|______|______|______|________|________________|
        |                                                              |
        |                          >=34-bytes                          |
        |______________________________________________________________|

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import Passcrypt, Domains
        from getpass import getpass


        Passcrypt.PEPPER = bytes.fromhex(getpass("hexidecimal pepper: "))

        # registration ->

        un = getpass("username: ").encode() + Domains.USERNAME
        pw = getpass("passphrase: ").encode() + Domains.PASSPHRASE


        pw_hash = Passcrypt.hash_passphrase(pw, aad=un, mb=128)

        # a login attempt ->

        un = getpass("username: ").encode() + Domains.USERNAME
        pw = getpass("passphrase: ").encode() + Domains.PASSPHRASE

        try:
            Passcrypt.verify(pw_hash, pw, aad=un, ttl=24 * 3600)
        except Passcrypt.InvalidPassphrase as auth_fail:
            app.post_mortem(error=auth_fail)
        except Passcrypt.TimestampExpired as expired_hash:
            # 24-hour registration expired
            app.post_mortem(error=expired_hash)

        """
        parts = PasscryptHash().import_hash(composed_passcrypt_hash)
        ns_clock.test_timestamp(parts.timestamp, ttl * NS_TO_S_RATIO)
        parts.in_allowed_ranges(mb_allowed, cpu_allowed, cores_allowed)
        untrusted_hash = cls.new(
            passphrase,
            parts.salt,
            aad=parts.timestamp + aad,
            mb=parts.mb,
            cpu=parts.cpu,
            cores=parts.cores,
            tag_size=parts.tag_size,
        )
        if not bytes_are_equal(untrusted_hash, parts.tag):
            raise PasscryptIssue.verification_failed()


class PasscryptInstance(FrozenInstance):
    """
    Gives the user objects which mirrors calls to `Passcrypt` methods
    with automated passing of instance settings.
    """

    __slots__ = ("_settings",)

    TimestampExpired = TimestampExpired
    InvalidPassphrase = InvalidPassphrase
    ImproperPassphrase = ImproperPassphrase

    def __init__(
        self, mb: int, cpu: int, cores: int, tag_size: int, salt_size: int
    ) -> None:
        """
        Stores user-defined settings so they can automatically be passed
        into `Passcrypt` methods when they are called.
        """
        self._settings = PasscryptSettings(
            mb=mb,
            cpu=cpu,
            cores=cores,
            tag_size=tag_size,
            salt_size=salt_size,
        )
        PasscryptSession._validate_settings(**self._settings)

    @wraps(Passcrypt.ahash_passphrase.__func__)
    async def ahash_passphrase(
        self,
        *args: t.Iterable[bytes],
        **kwargs: t.Dict[str, t.Union[bytes, int]],
    ) -> bytes:
        """
        Forwards calls to the `Passcrypt.ahash_passphrase` method with
        the instance settings & the specified ``args`` & ``kwargs``.
        """
        return await Passcrypt.ahash_passphrase(
            *args, **{**self._settings, **kwargs}
        )

    @wraps(Passcrypt.hash_passphrase.__func__)
    def hash_passphrase(
        self,
        *args: t.Iterable[bytes],
        **kwargs: t.Dict[str, t.Union[bytes, int]],
    ) -> bytes:
        """
        Forwards calls to the `Passcrypt.hash_passphrase` method with
        the instance settings & the specified ``args`` & ``kwargs``.
        """
        return Passcrypt.hash_passphrase(
            *args, **{**self._settings, **kwargs}
        )

    @wraps(Passcrypt.averify.__func__)
    async def averify(
        self,
        *args: t.Iterable[bytes],
        **kwargs: t.Dict[str, t.Union[bytes, int, range]],
    ) -> None:
        """
        Forwards calls to the `Passcrypt.averify` method with the
        specified ``args`` & ``kwargs``.
        """
        await Passcrypt.averify(*args, **kwargs)

    @wraps(Passcrypt.verify.__func__)
    def verify(
        self,
        *args: t.Iterable[bytes],
        **kwargs: t.Dict[str, t.Union[bytes, int, range]],
    ) -> None:
        """
        Forwards calls to the `Passcrypt.verify` method with the
        specified ``args`` & ``kwargs``.
        """
        Passcrypt.verify(*args, **kwargs)


class Curve25519:
    """
    Contains a collection of class methods & values that simplify the
    usage of the cryptography library, as well as pointers to values in
    the cryptography library.
    """

    __slots__ = ()

    _PUBLIC_BYTES_ENUM = {
        "encoding": serialization.Encoding.Raw,
        "format": serialization.PublicFormat.Raw,
    }
    _PRIVATE_BYTES_ENUM = {
        "encoding": serialization.Encoding.Raw,
        "format": serialization.PrivateFormat.Raw,
        "encryption_algorithm": serialization.NoEncryption(),
    }

    X25519PublicKey = X25519PublicKey
    X25519PrivateKey = X25519PrivateKey
    Ed25519PublicKey = Ed25519PublicKey
    Ed25519PrivateKey = Ed25519PrivateKey

    cryptography = cryptography
    exceptions = cryptography.exceptions
    hazmat = cryptography.hazmat
    serialization = serialization

    @staticmethod
    async def aed25519_key() -> Ed25519PrivateKey:
        """
        Returns an ``Ed25519PrivateKey`` from the cryptography package
        used to make elliptic curve signatures of data.
        """
        await asleep()
        return Ed25519PrivateKey.generate()

    @staticmethod
    def ed25519_key() -> Ed25519PrivateKey:
        """
        Returns an ``Ed25519PrivateKey`` from the cryptography package
        used to make elliptic curve signatures of data.
        """
        return Ed25519PrivateKey.generate()

    @staticmethod
    async def ax25519_key() -> X25519PrivateKey:
        """
        Returns a ``X25519PrivateKey`` from the cryptography package for
        use in an elliptic curve diffie-hellman exchange.
        """
        await asleep()
        return X25519PrivateKey.generate()

    @staticmethod
    def x25519_key() -> X25519PrivateKey:
        """
        Returns a ``X25519PrivateKey`` from the cryptography package for
        use in an elliptic curve diffie-hellman exchange.
        """
        return X25519PrivateKey.generate()

    @classmethod
    async def apublic_bytes(
        cls,
        key: t.Union[
            X25519PrivateKey,
            Ed25519PrivateKey,
            X25519PublicKey,
            Ed25519PublicKey,
        ],
    ) -> bytes:
        """
        Returns the public key bytes of either an ``X25519PrivateKey``,
        ``X25519PublicKey``, ``Ed25519PublicKey`` or ``Ed25519PrivateKey``
        object from the cryptography package.
        """
        await asleep()
        key_types = (
            X25519PrivateKey,
            Ed25519PrivateKey,
            X25519PublicKey,
            Ed25519PublicKey,
        )
        if not issubclass(key.__class__, key_types):
            raise Issue.value_must_be_type("key", key_types)
        elif hasattr(key, "public_key"):
            public_key = key.public_key()
        else:
            public_key = key
        return public_key.public_bytes(**cls._PUBLIC_BYTES_ENUM)

    @classmethod
    def public_bytes(
        cls,
        key: t.Union[
            X25519PrivateKey,
            Ed25519PrivateKey,
            X25519PublicKey,
            Ed25519PublicKey,
        ],
    ) -> bytes:
        """
        Returns the public key bytes of either an ``X25519PrivateKey``,
        ``X25519PublicKey``, ``Ed25519PublicKey`` or ``Ed25519PrivateKey``
        object from the cryptography package.
        """
        key_types = (
            X25519PrivateKey,
            Ed25519PrivateKey,
            X25519PublicKey,
            Ed25519PublicKey,
        )
        if not issubclass(key.__class__, key_types):
            raise Issue.value_must_be_type("key", key_types)
        elif hasattr(key, "public_key"):
            public_key = key.public_key()
        else:
            public_key = key
        return public_key.public_bytes(**cls._PUBLIC_BYTES_ENUM)

    @classmethod
    async def asecret_bytes(
        cls, secret_key: t.Union[X25519PrivateKey, Ed25519PrivateKey]
    ) -> bytes:
        """
        Returns the secret key bytes of either an ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` from the cryptography package.
        """
        await asleep()
        key_types = (X25519PrivateKey, Ed25519PrivateKey)
        if not issubclass(secret_key.__class__, key_types):
            raise Issue.value_must_be_type("secret_key", key_types)
        return secret_key.private_bytes(**cls._PRIVATE_BYTES_ENUM)

    @classmethod
    def secret_bytes(
        cls, secret_key: t.Union[X25519PrivateKey, Ed25519PrivateKey]
    ) -> bytes:
        """
        Returns the secret key bytes of either an ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` from the cryptography package.
        """
        key_types = (X25519PrivateKey, Ed25519PrivateKey)
        if not issubclass(secret_key.__class__, key_types):
            raise Issue.value_must_be_type("secret_key", key_types)
        return secret_key.private_bytes(**cls._PRIVATE_BYTES_ENUM)

    @staticmethod
    async def aexchange(
        secret_key: X25519PrivateKey, public_key: bytes
    ) -> bytes:
        """
        Returns the shared key bytes derived from an elliptic curve key
        exchange with the user's ``secret_key`` key, & their communicating
        peer's ``public_key`` public key's bytes or hex value.
        """
        await asleep()
        return secret_key.exchange(
            X25519PublicKey.from_public_bytes(public_key)
        )

    @staticmethod
    def exchange(secret_key: X25519PrivateKey, public_key: bytes) -> bytes:
        """
        Returns the shared key bytes derived from an elliptic curve key
        exchange with the user's ``secret_key`` key, & their communicating
        peer's ``public_key`` public key's bytes or hex value.
        """
        return secret_key.exchange(
            X25519PublicKey.from_public_bytes(public_key)
        )


class Base25519(FrozenInstance):
    """
    Collects the shared functionality between the ``X25519`` & ``Ed25519``
    classes.
    """

    __slots__ = ("_public_key", "_secret_key")

    _Curve25519 = Curve25519

    _exceptions = Curve25519.exceptions

    PublicKey = None
    SecretKey = None

    def _process_public_key(
        self,
        public_key: t.Union[
            str,
            bytes,
            X25519PrivateKey,
            Ed25519PrivateKey,
            X25519PublicKey,
            Ed25519PublicKey,
        ],
    ) -> t.Union[X25519PublicKey, Ed25519PublicKey]:
        """
        Accepts a ``public_key`` in either hex, bytes, ``X25519PublicKey``,
        ``X25519PrivateKey``, ``Ed25519PublicKey`` or ``Ed25519PrivateKey``
        format. Returns an instantiaed public key associated with the
        subclass inhereting this method.
        """
        if not public_key:
            raise Issue.no_value_specified("public key")
        elif public_key.__class__ is str:
            public_key = bytes.fromhex(public_key)
        elif issubclass(
            public_key.__class__,
            (self.PublicKey, self.SecretKey, self.__class__)
        ):
            public_key = self._Curve25519.public_bytes(public_key)
        elif public_key.__class__ is not bytes:
            raise Issue.value_must_be_type("public_key", "valid key type")
        return self.PublicKey.from_public_bytes(public_key)

    def _process_secret_key(
        self,
        secret_key: t.Union[
            str, bytes, X25519PrivateKey, Ed25519PrivateKey
        ],
    ) -> t.Union[Ed25519PrivateKey, X25519PrivateKey]:
        """
        Accepts a ``secret_key`` in either hex, bytes, ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` format. Returns an instantiaed secret
        key associated with the subclass inhereting this method.
        """
        if not secret_key:
            raise Issue.no_value_specified("secret key")
        elif secret_key.__class__ is str:
            secret_key = bytes.fromhex(secret_key)
        elif issubclass(
            secret_key.__class__, (self.SecretKey, self.__class__)
        ):
            secret_key = self._Curve25519.secret_bytes(secret_key)
        elif secret_key.__class__ is not bytes:
            raise Issue.value_must_be_type("secret_key", "valid key type")
        return self.SecretKey.from_private_bytes(secret_key)

    async def aimport_public_key(
        self,
        public_key: t.Union[
            str,
            bytes,
            X25519PrivateKey,
            Ed25519PrivateKey,
            X25519PublicKey,
            Ed25519PublicKey,
        ],
    ) -> "self":
        """
        Populates an instance from the received ``public_key`` that is
        of either hex, bytes, ``X25519PublicKey``, ``X25519PrivateKey``,
        ``Ed25519PublicKey`` or ``Ed25519PrivateKey`` type.
        """
        await asleep()
        if hasattr(self, "_public_key"):
            raise Issue.value_already_set("public key", "the instance")
        self._public_key = self._process_public_key(public_key)
        return self

    def import_public_key(
        self,
        public_key: t.Union[
            str,
            bytes,
            X25519PrivateKey,
            Ed25519PrivateKey,
            X25519PublicKey,
            Ed25519PublicKey,
        ],
    ) -> "self":
        """
        Populates an instance from the received ``public_key`` that is
        of either hex, bytes, ``X25519PublicKey``, ``X25519PrivateKey``,
        ``Ed25519PublicKey`` or ``Ed25519PrivateKey`` type.
        """
        if hasattr(self, "_public_key"):
            raise Issue.value_already_set("public key", "the instance")
        self._public_key = self._process_public_key(public_key)
        return self

    async def aimport_secret_key(
        self,
        secret_key: t.Union[
            str, bytes, X25519PrivateKey, Ed25519PrivateKey
        ],
    ) -> "self":
        """
        Populates an instance from the received ``secret_key`` that is
        of either hex, bytes, ``X25519PrivateKey`` or ``Ed25519PrivateKey``
        type.
        """
        await asleep()
        if hasattr(self, "_public_key") or hasattr(self, "_secret_key"):
            raise Issue.value_already_set(f"key", "the instance")
        self._secret_key = self._process_secret_key(secret_key)
        self._public_key = self.PublicKey.from_public_bytes(
            await self._Curve25519.apublic_bytes(self._secret_key)
        )
        return self

    def import_secret_key(
        self,
        secret_key: t.Union[
            str, bytes, X25519PrivateKey, Ed25519PrivateKey
        ],
    ) -> "self":
        """
        Populates an instance from the received ``secret_key`` that is
        of either hex, bytes, ``X25519PrivateKey`` or ``Ed25519PrivateKey``
        type.
        """
        if hasattr(self, "_public_key") or hasattr(self, "_secret_key"):
            raise Issue.value_already_set(f"key", "the instance")
        self._secret_key = self._process_secret_key(secret_key)
        self._public_key = self.PublicKey.from_public_bytes(
            self._Curve25519.public_bytes(self._secret_key)
        )
        return self

    @property
    def secret_key(self) -> t.Union[X25519PrivateKey, Ed25519PrivateKey]:
        """
        Returns the instantiated & populated SecretKey of the associated
        sublass inhereting this method.
        """
        return self._secret_key

    @property
    def public_key(self) -> t.Union[X25519PublicKey, Ed25519PublicKey]:
        """
        Returns the instantiated & populated PublicKey of the associated
        sublass inhereting this method.
        """
        return self._public_key

    @property
    def secret_bytes(self) -> bytes:
        """
        Returns the secret bytes of the instance's instantiated &
        populated SecretKey of the associated sublass inhereting this
        method.
        """
        return self._Curve25519.secret_bytes(self._secret_key)

    @property
    def public_bytes(self) -> bytes:
        """
        Returns the public bytes of the instance's instantiated &
        populated PublicKey of the associated sublass inhereting this
        method.
        """
        return self._Curve25519.public_bytes(self._public_key)

    def has_secret_key(self) -> bool:
        """
        Returns a boolean of whether the instance contains a secret key.
        """
        return hasattr(self, "_secret_key")

    def has_public_key(self) -> bool:
        """
        Returns a boolean of whether the instance contains a public key.
        """
        return hasattr(self, "_public_key")


class Ed25519(Base25519):
    """
    This class is used to create stateful objects that simplify usage of
    the cryptography library's ed25519 protocol.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp import Ed25519

    # In a land, long ago ->
    alices_key = Ed25519().generate()
    internet.send(alices_key.public_bytes)

    # Alice wants to sign a document so that Bob can prove she wrote it.
    # So, Alice sends her public key bytes of the key she wants to
    # associate with her identity, the document & the signature ->
    document = b"DesignDocument.cad"
    signed_document = alices_key.sign(document)
    message = {
        "document": document,
        "signature": signed_document,
        "public_key": alices_key.public_bytes,
    }
    internet.send(message)

    # In a land far away ->
    alices_message = internet.receive()

    # Bob sees the message from Alice! Bob already knows Alice's public
    # key & she has reason believe it is genuinely hers. She'll then
    # verify the signed document ->
    assert alices_message["public_key"] == alices_public_key
    alice_verifier = Ed25519().import_public_key(alices_public_key)
    alice_verifier.verify(
        alices_message["signature"], alices_message["document"]
    )
    internet.send(b"Beautiful work, Alice! Thanks ^u^")

    # The verification didn't throw an exception! So, Bob knows the file
    # was signed by Alice.
    """

    __slots__ = ("_public_key", "_secret_key")

    InvalidSignature = Base25519._exceptions.InvalidSignature
    PublicKey = Curve25519.Ed25519PublicKey
    SecretKey = Curve25519.Ed25519PrivateKey

    async def agenerate(self) -> "self":
        """
        Generates a new secret key used for signing bytes data &
        populates the instance with it & its associated public key. This
        method returns the instance for convenience in instantiating a
        stateful object with await Ed25519().agenerate().
        """
        key = await self._Curve25519.aed25519_key()
        await self.aimport_secret_key(key)
        return self

    def generate(self) -> "self":
        """
        Generates a new secret key used for signing bytes data &
        populates the instance with it & its associated public key. This
        method returns the instance for convenience in instantiating a
        stateful object with Ed25519().generate().
        """
        key = self._Curve25519.ed25519_key()
        self.import_secret_key(key)
        return self

    async def asign(self, data: bytes) -> bytes:
        """
        Signs some bytes ``data`` with the instance's secret key.
        """
        await asleep()
        return self.secret_key.sign(data)

    def sign(self, data: bytes) -> bytes:
        """
        Signs some bytes ``data`` with the instance's secret key.
        """
        return self.secret_key.sign(data)

    async def averify(
        self,
        signature: bytes,
        data: bytes,
        *,
        public_key: t.Union[None, str, bytes, Ed25519PublicKey] = None,
    ) -> None:
        """
        Receives a ``signature`` to verify data with the instance's
        public key. If the ``public_key`` keyword-only argument is
        used, then that key is used instead of the instance key to run
        the verification.
        """
        if public_key:
            await asleep()
            public_key = self._process_public_key(public_key)
        else:
            public_key = self.public_key
        await asleep()
        public_key.verify(signature, data)

    def verify(
        self,
        signature: bytes,
        data: bytes,
        *,
        public_key: t.Union[None, str, bytes, Ed25519PublicKey] = None,
    ) -> None:
        """
        Receives a ``signature`` to verify data with the instance's
        public key. If the ``public_key`` keyword-only argument is
        used, then that key is used instead of the instance key to run
        the verification.
        """
        if public_key:
            public_key = self._process_public_key(public_key)
        else:
            public_key = self.public_key
        public_key.verify(signature, data)


class X25519(Base25519):
    """
    This class is used to create stateful objects that simplify usage of
    the cryptography library's x25519 protocol.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    user_alice = X25519().generate()
    # Alice wants to create a shared key with Bob. So, Alice sends the
    # public key bytes of her new key to bob ->
    internet.send(user_alice.public_bytes.hex())

    # In a land far away ->
    alices_message = internet.receive()

    # Bob sees the message from Alice! So she creates a key to accept
    # the exchange & sends the public bytes back to Alice ->
    user_bob = await X25519().agenerate()
    shared_key = user_bob.exchange(alices_message)
    internet.send(user_bob.public_bytes.hex())

    # When Alice receives Bob's public key & finishes the exchange, they
    # will have a shared symmetric key to encrypt messages to one
    # another.
    bobs_response = internet.receive()
    shared_key = user_alice.exchange(bobs_response)

    This protocol is not secure against active adversaries that can
    manipulate the information while its in transit between Alice &
    Bob. Each public key should only be used once.
    """

    __slots__ = ("_public_key", "_secret_key")

    PublicKey = Curve25519.X25519PublicKey
    SecretKey = Curve25519.X25519PrivateKey

    async def agenerate(self) -> "self":
        """
        Generates a new secret key used for a single elliptic curve
        diffie-hellman exchange, or as an argument to one of the 3dh or
        2dh generators in X25519.protocols. This populates the instance
        with the secret key & its associated public key. This method
        returns the instance for convenience in instantiating a stateful
        object with await X25519().agenerate().
        """
        key = await self._Curve25519.ax25519_key()
        await self.aimport_secret_key(key)
        return self

    def generate(self) -> "self":
        """
        Generates a new secret key used for a single elliptic curve
        diffie-hellman exchange, or as an argument to one of the 3dh or
        2dh generators in X25519.protocols. This populates the instance
        with the secret key & its associated public key. This method
        returns the instance for convenience in instantiating a stateful
        object with await X25519().generate().
        """
        key = self._Curve25519.x25519_key()
        self.import_secret_key(key)
        return self

    async def aexchange(
        self, public_key: t.Union[X25519PublicKey, bytes, str]
    ) -> bytes:
        """
        Takes in a public key from a communicating party & uses the
        instance's secret key to do an elliptic curve diffie-hellman
        exchange & returns the resulting secret shared bytes.
        """
        await asleep()
        public_key = self._process_public_key(public_key)
        return await self._Curve25519.aexchange(
            self._secret_key,
            await self._Curve25519.apublic_bytes(public_key),
        )

    def exchange(
        self, public_key: t.Union[X25519PublicKey, bytes, str]
    ) -> bytes:
        """
        Takes in a public key from a communicating party & uses the
        instance's secret key to do an elliptic curve diffie-hellman
        exchange & returns the resulting secret shared bytes.
        """
        public_key = self._process_public_key(public_key)
        return self._Curve25519.exchange(
            self._secret_key, self._Curve25519.public_bytes(public_key)
        )

    @classmethod
    @comprehension()
    async def adh2_client(cls) -> Comprende:
        """
        Generates an ephemeral ``X25519`` secret key which is used to
        start a 2DH client key exchange. This key is yielded as public
        key bytes. Then the server's two public keys should be sent into
        this coroutine when they're received. When this coroutine
        reaches the raise statement, a primed ``sha3_512`` kdf object
        will be accessible from the ``aresult`` method of this generator.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import X25519

        async with X25519.protocols.adh2_client() as exchange:
            client_hello = await exchange()
            response = internet.post(client_hello)
            await exchange(response)

        shared_key_kdf = await exchange.aresult()
        """
        domain = Domains.DH2
        my_ephemeral_key = await cls().agenerate()
        peer_identity_key, peer_ephemeral_key = yield (
            my_ephemeral_key.public_bytes
        )
        shared_key_ad = await my_ephemeral_key.aexchange(peer_identity_key)
        shared_key_cd = await my_ephemeral_key.aexchange(peer_ephemeral_key)
        raise Comprende.ReturnValue(
            DomainKDF(
                domain,
                my_ephemeral_key.public_bytes,
                peer_identity_key,
                peer_ephemeral_key,
                key=shared_key_ad + shared_key_cd,
            )
        )

    @classmethod
    @comprehension()
    def dh2_client(cls) -> Comprende:
        """
        Generates an ephemeral ``X25519`` secret key which is used to
        start a 2DH client key exchange. This key is yielded as public
        key bytes. Then the server's two public keys should be sent into
        this coroutine when they're received. When this coroutine
        reaches the return statement, a primed ``sha3_512`` kdf object
        will be accessible from the ``result`` method of this generator.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import X25519

        with X25519.protocols.dh2_client() as exchange:
            client_hello = exchange()
            response = internet.post(client_hello)
            exchange(response)

        shared_key_kdf = exchange.result()
        """
        domain = Domains.DH2
        my_ephemeral_key = cls().generate()
        peer_identity_key, peer_ephemeral_key = yield (
            my_ephemeral_key.public_bytes
        )
        shared_key_ad = my_ephemeral_key.exchange(peer_identity_key)
        shared_key_cd = my_ephemeral_key.exchange(peer_ephemeral_key)
        return DomainKDF(
            domain,
            my_ephemeral_key.public_bytes,
            peer_identity_key,
            peer_ephemeral_key,
            key=shared_key_ad + shared_key_cd,
        )

    @comprehension()
    async def adh2_server(self, peer_ephemeral_key: bytes) -> Comprende:
        """
        Takes in the user's ``X25519`` secret key & a peer's public key
        bytes to enact a 2DH key exchange. This yields the user's two
        public keys as bytes, one from the secret key which was passed
        in as an argument, one which is ephemeral. When this coroutine
        reaches the raise statement, a primed ``sha3_512`` kdf object
        will be accessible from the ``aresult`` method of this generator.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import X25519

        # This key may be used again as an identity for this protocol
        ecdhe_key = await X25519().agenerate()

        client_ephemeral_key = internet.receive()

        async with ecdhe_key.adh2_server(client_ephemeral_key) as exchange:
            internet.send(await exchange.aexhaust())

        shared_key_kdf = await exchange.aresult()
        """
        domain = Domains.DH2
        my_identity_key = self
        my_ephemeral_key = await self.__class__().agenerate()
        yield my_identity_key.public_bytes, my_ephemeral_key.public_bytes
        shared_key_ad = await my_identity_key.aexchange(peer_ephemeral_key)
        shared_key_cd = await my_ephemeral_key.aexchange(peer_ephemeral_key)
        raise Comprende.ReturnValue(
            DomainKDF(
                domain,
                peer_ephemeral_key,
                my_identity_key.public_bytes,
                my_ephemeral_key.public_bytes,
                key=shared_key_ad + shared_key_cd,
            )
        )

    @comprehension()
    def dh2_server(self, peer_ephemeral_key: bytes) -> Comprende:
        """
        Takes in the user's ``X25519`` secret key & a peer's public key
        bytes to enact a 2DH key exchange. This yields the user's two
        public keys as bytes, one from the secret key which was passed
        in as an argument, one which is ephemeral. When this coroutine
        reaches the return statement, a primed ``sha3_512`` kdf object
        will be accessible from the ``result`` method of this generator.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import X25519

        # This key may be used again as an identity for this protocol
        ecdhe_key = X25519().generate()

        client_ephemeral_key = internet.receive()

        with ecdhe_key.dh2_server(client_ephemeral_key) as exchange:
            internet.send(exchange.exhaust())

        shared_key_kdf = exchange.result()
        """
        domain = Domains.DH2
        my_identity_key = self
        my_ephemeral_key = self.__class__().generate()
        yield my_identity_key.public_bytes, my_ephemeral_key.public_bytes
        shared_key_ad = my_identity_key.exchange(peer_ephemeral_key)
        shared_key_cd = my_ephemeral_key.exchange(peer_ephemeral_key)
        return DomainKDF(
            domain,
            peer_ephemeral_key,
            my_identity_key.public_bytes,
            my_ephemeral_key.public_bytes,
            key=shared_key_ad + shared_key_cd,
        )

    @comprehension()
    async def adh3_client(self) -> Comprende:
        """
        Takes in the user's ``X25519`` secret key to enact a 3DH key
        exchange with a peer. This yields the user's two public keys as
        bytes, one from the secret key which was passed in as an
        argument, one which is ephemeral. When this coroutine reaches
        the raise statement, a primed ``DomainKDF`` object will be
        accessible from the ``aresult`` method of this generator.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import X25519

        # This key may be used again as an identity for this protocol
        ecdhe_key = await X25519().agenerate()

        async with ecdhe_key.adh3_client() as exchange:
            client_hello = await exchange()
            response = internet.post(client_hello)
            await exchange(response)

        shared_key_kdf = await exchange.aresult()
        """
        domain = Domains.DH3
        my_identity_key = self
        my_ephemeral_key = await self.__class__().agenerate()
        peer_identity_key, peer_ephemeral_key = yield (
            my_identity_key.public_bytes,
            my_ephemeral_key.public_bytes,
        )
        shared_key_ad = await my_ephemeral_key.aexchange(peer_identity_key)
        shared_key_bc = await my_identity_key.aexchange(peer_ephemeral_key)
        shared_key_cd = await my_ephemeral_key.aexchange(peer_ephemeral_key)
        raise Comprende.ReturnValue(
            DomainKDF(
                domain,
                my_identity_key.public_bytes,
                my_ephemeral_key.public_bytes,
                peer_identity_key,
                peer_ephemeral_key,
                key=shared_key_ad + shared_key_bc + shared_key_cd,
            )
        )

    @comprehension()
    def dh3_client(self) -> Comprende:
        """
        Takes in the user's ``X25519`` secret key to enact a 3DH key
        exchange with a peer. This yields the user's two public keys as
        bytes, one from the secret key which was passed in as an
        argument, one which is ephemeral. When this coroutine reaches
        the return statement, a primed ``DomainKDF`` object will be
        accessible from the ``result`` method of this generator.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import X25519

        # This key may be used again as an identity for this protocol
        ecdhe_key = X25519().generate()

        with ecdhe_key.dh3_client() as exchange:
            client_hello = exchange()
            response = internet.post(client_hello)
            exchange(response)

        shared_key_kdf = exchange.result()
        """
        domain = Domains.DH3
        my_identity_key = self
        my_ephemeral_key = self.__class__().generate()
        peer_identity_key, peer_ephemeral_key = yield (
            my_identity_key.public_bytes,
            my_ephemeral_key.public_bytes,
        )
        shared_key_ad = my_ephemeral_key.exchange(peer_identity_key)
        shared_key_bc = my_identity_key.exchange(peer_ephemeral_key)
        shared_key_cd = my_ephemeral_key.exchange(peer_ephemeral_key)
        return DomainKDF(
            domain,
            my_identity_key.public_bytes,
            my_ephemeral_key.public_bytes,
            peer_identity_key,
            peer_ephemeral_key,
            key=shared_key_ad + shared_key_bc + shared_key_cd,
        )

    @comprehension()
    async def adh3_server(
        self, peer_identity_key: bytes, peer_ephemeral_key: bytes
    ) -> Comprende:
        """
        Takes in the user's ``X25519`` secret key & two of a peer's
        public keys bytes to enact a 3DH deniable key exchange. This
        yields the user's two public keys as bytes, one from the secret
        key which was passed in as an argument, one which is ephemeral.
        When this coroutine reaches the raise statement, a primed
        ``DomainKDF`` object will be accessible from the ``aresult``
        method of this generator.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import X25519

        # This key may be used again as an identity for this protocol
        ecdhe_key = await X25519().agenerate()

        identity_key, ephemeral_key = client_keys = internet.receive()

        server = ecdhe_key.adh3_server(identity_key, ephemeral_key)
        async with server as exchange:
            internet.send(await exchange.aexhaust())

        shared_key_kdf = await exchange.aresult()
        """
        domain = Domains.DH3
        my_identity_key = self
        my_ephemeral_key = await self.__class__().agenerate()
        yield my_identity_key.public_bytes, my_ephemeral_key.public_bytes
        shared_key_ad = await my_identity_key.aexchange(peer_ephemeral_key)
        shared_key_bc = await my_ephemeral_key.aexchange(peer_identity_key)
        shared_key_cd = await my_ephemeral_key.aexchange(peer_ephemeral_key)
        raise Comprende.ReturnValue(
            DomainKDF(
                domain,
                peer_identity_key,
                peer_ephemeral_key,
                my_identity_key.public_bytes,
                my_ephemeral_key.public_bytes,
                key=shared_key_ad + shared_key_bc + shared_key_cd,
            )
        )

    @comprehension()
    def dh3_server(
        self, peer_identity_key: bytes, peer_ephemeral_key: bytes
    ) -> Comprende:
        """
        Takes in the user's ``X25519`` secret key & two of a peer's
        public keys bytes to enact a 3DH deniable key exchange. This
        yields the user's two public keys as bytes, one from the secret
        key which was passed in as an argument, one which is ephemeral.
        When this coroutine reaches the raise statement, a primed
        ``DomainKDF`` object will be accessible from the ``result``
        method of this generator.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import X25519

        # This key may be used again as an identity for this protocol
        ecdhe_key = X25519().generate()

        identity_key, ephemeral_key = client_keys = internet.receive()

        server = ecdhe_key.dh3_server(identity_key, ephemeral_key)
        with server as exchange:
            internet.send(exchange.exhaust())

        shared_key_kdf = exchange.result()
        """
        domain = Domains.DH3
        my_identity_key = self
        my_ephemeral_key = self.__class__().generate()
        yield my_identity_key.public_bytes, my_ephemeral_key.public_bytes
        shared_key_ad = my_identity_key.exchange(peer_ephemeral_key)
        shared_key_bc = my_ephemeral_key.exchange(peer_identity_key)
        shared_key_cd = my_ephemeral_key.exchange(peer_ephemeral_key)
        return DomainKDF(
            domain,
            peer_identity_key,
            peer_ephemeral_key,
            my_identity_key.public_bytes,
            my_ephemeral_key.public_bytes,
            key=shared_key_ad + shared_key_bc + shared_key_cd,
        )


class PackageSigner:
    """
    Provides an intuitive API for users to sign their own packages.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    import json
    from getpass import getpass
    from aiootp import PackageSigner

    signer = PackageSigner(
        package=__package__,
        version=__version__,
        author=__author__,
        license=__license__,
    )
    signer.connect_to_secure_database(
        passphrase=getpass("database passphrase:\n"),
        salt=getpass("database salt:\n"),
        path=getpass("secure directory:\n"),
    )

    with open("MANIFEST.in", "r") as manifest:
        filename_sheet = manifest.read().split("\n")

    for line in filename_sheet:
        if not line.startswith("include"):
            continue
        filename = line.strip().split(" ")[-1]
        with open(filename, "rb") as source_file:
            signer.add_file(filename, source_file.read())

    signer.sign_package()
    signer.db.save_database()
    package_signature_summary = signer.summarize()
    """

    __slots__ = ("_db", "_scope", "files")

    _Hasher = sha384
    _Signer = Ed25519

    _CHECKSUM = CHECKSUM
    _CHECKSUMS = CHECKSUMS
    _CLASS = "PackageSigner"
    _PUBLIC_CREDENTIALS = PUBLIC_CREDENTIALS
    _SCOPE = SCOPE
    _SIGNATURE = SIGNATURE
    _SIGNING_KEY = SIGNING_KEY
    _VERSIONS = VERSIONS

    InvalidSignature = Ed25519._exceptions.InvalidSignature

    @classmethod
    def _database_template(cls) -> t.Dict[str, t.Union[str, t.JSONObject]]:
        """
        Returns the default instance package database values for
        initializing new databases.
        """
        return {
            cls._SIGNING_KEY: "",
            cls._VERSIONS: {},
            cls._PUBLIC_CREDENTIALS: {},
        }

    @classmethod
    def generate_signing_key(cls) -> _Signer:
        """
        Generates a new `Ed25519` secret signing key object.
        """
        return cls._Signer().generate()

    def __init__(
        self,
        package: str,
        version: str,
        date: t.Optional[int] = None,
        **scopes: t.JSONObject,
    ) -> None:
        """
        Sets the instance's package scope attributes & default file
        checksums container.
        """
        self.files = PackageSignerFiles()
        self._scope = PackageSignerScope(
            package=package,
            version=version,
            date=date if date else day_clock.time(),
            **scopes,
        )

    def __repr__(self) -> str:
        """
        Displays the instance's declared scope.
        """
        cls = self.__class__.__qualname__
        return str(f"{cls}({self._scope})")

    @property
    def _public_credentials(self) -> t.JSONObject:
        """
        Returns public credentials from the instance's secure database.
        """
        return self.db[self._scope.package][self._PUBLIC_CREDENTIALS]

    @property
    def signing_key(self) -> _Signer:
        """
        Returns the package's secret signing key from the instance's
        encrypted database in an `Ed25519` object.
        """
        package = self._scope.package
        aad = Domains.PACKAGE_SIGNER + package.encode()
        encrypted_key = self.db[package][self._SIGNING_KEY]
        if not encrypted_key:
            raise PackageSignerIssue.signing_key_hasnt_been_set()
        key = self.db.read_token(encrypted_key, aad=aad)
        return self._Signer().import_secret_key(key)

    @property
    def db(self) -> "Database":
        """
        Returns the instance's database object, or alerts the user to
        connect to a secure database if it isn't yet set.
        """
        try:
            return self._db
        except AttributeError:
            raise PackageSignerIssue.must_connect_to_secure_database()

    @property
    def _checksums(self) -> t.Dict[str, str]:
        """
        Returns the instance's package filenames & their hexdigests in
        a JSON ready dictionary.
        """
        return {
            filename: hasher.hexdigest()
            for filename, hasher in sorted(self.files.items())
        }

    @property
    def _summary(self) -> t.JSONObject:
        """
        Collects the instance's package file checksums, names, public
        credentials, version scopes & the package's public signing key
        into a json-ready dictionary.
        """
        return {
            self._CHECKSUMS: {
                filename: hexdigest
                for filename, hexdigest in self._checksums.items()
            },
            self._PUBLIC_CREDENTIALS: {
                name: credential
                for name, credential in sorted(
                    self._public_credentials.items()
                )
            },
            self._SCOPE: {
                name: value for name, value in sorted(self._scope.items())
            },
            self._SIGNING_KEY: self.signing_key.public_bytes.hex(),
        }

    @property
    def _checksum(self) -> bytes:
        """
        Returns the digest of the current package summary.
        """
        return self._Hasher(json.dumps(self._summary).encode()).digest()

    @property
    def _signature(self) -> bytes:
        """
        Returns the stored package summary signature.
        """
        try:
            versions = self.db[self._scope.package][self._VERSIONS]
            return bytes.fromhex(versions[self._scope.version])
        except KeyError:
            raise PackageSignerIssue.package_hasnt_been_signed()

    def connect_to_secure_database(
        self,
        *secret_credentials: t.Iterable[bytes],
        username: bytes,
        passphrase: bytes,
        salt: bytes = b"",
        path: t.OptionalPathStr = None,
        **passcrypt_settings: t.PasscryptKWsNew,
    ) -> "self":
        """
        Opens an encrypted database connection using the Passcrypt
        passphrase-based key derivation function, a ``passphrase`` & any
        available additional credentials a user may have. If a database
        doesn't already exist, then a new one is created with default
        values.
        """
        from .databases import Database

        self._db = Database.generate_profile(
            self._CLASS.encode(),
            *secret_credentials,
            username=username,
            passphrase=passphrase,
            salt=salt,
            path=path,
            **passcrypt_settings,
        )
        try:
            self.db.query_tag(self._scope.package, cache=True)
        except LookupError:
            self.db[self._scope.package] = self._database_template()
        finally:
            return self

    def update_scope(self, **scopes) -> "self":
        """
        Updates the package scopes to qualify the package signature of
        the current package version within the instance.
        """
        self._scope.namespace.update(scopes)
        return self

    def update_public_credentials(
        self, **credentials: t.Dict[str, t.JSONSerializable]
    ) -> "self":
        """
        Updates the public credentials to be associated with the package
        signature & stores them in the instance's database cache. The
        database must be saved separately to save them to disk.
        """
        package = self._scope.package
        self.db[package][self._PUBLIC_CREDENTIALS].update(credentials)
        return self

    def update_signing_key(
        self, signing_key: t.Union[str, bytes, Ed25519PrivateKey, Ed25519]
    ) -> "self":
        """
        Updates the package's secret signing key as an encrypted token
        within the instance's database cache. The database must be saved
        separately to save the encrypted signing key to disk.
        """
        if signing_key.__class__ is not self._Signer:
            signing_key = self._Signer().import_secret_key(signing_key)
        package = self._scope.package
        aad = Domains.PACKAGE_SIGNER + package.encode()
        self.db[package][self._SIGNING_KEY] = self.db.make_token(
            signing_key.secret_bytes, aad=aad
        ).decode()
        return self

    def add_file(self, filename: str, file_data: bytes) -> "self":
        """
        Stores a ``filename`` & the hash object of the file's bytes type
        contents in the instance's `files` attribute mapping.
        """
        self.files[filename] = self._Hasher(file_data)
        return self

    def sign_package(self) -> "self":
        """
        Signs the package summary checksum & stores it in the instance's
        secure database cache. The database must be saved separately to
        save the signature to disk.
        """
        checksum = self._checksum
        self.db[self._scope.package][self._VERSIONS].update(
            {self._scope.version: self.signing_key.sign(checksum).hex()}
        )
        return self

    def summarize(self) -> t.JSONObject:
        """
        Assures the stored package checksum signature matches the
        current checksum of the package summary. If valid, the summary
        is returned along with the package checksum & its signature in
        a dictionary.
        """
        checksum = self._checksum
        signature = self._signature
        signing_key = self.signing_key
        try:
            signing_key.verify(signature, checksum)
        except self.InvalidSignature:
            raise PackageSignerIssue.out_of_sync_package_signature()
        return {
            self._CHECKSUM: checksum.hex(),
            **self._summary,
            self._SIGNATURE: signature.hex(),
        }


class PackageVerifier:
    """
    Provides an intuitive API for verifying package summaries produced
    by `PackageSigner` objects.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp import PackageVerifier

    verifier = PackageVerifier(public_signing_key, path="")
    verifier.verify_summary(package_signature_summary)
    """

    __slots__ = (
        "_path",
        "_checksum",
        "_signature",
        "_signing_key",
        "_summary_dictionary",
    )

    _Hasher = sha384
    _Signer = Ed25519

    _CHECKSUM = CHECKSUM
    _CHECKSUMS = CHECKSUMS
    _SIGNATURE = SIGNATURE
    _SIGNING_KEY = SIGNING_KEY

    InvalidSignature = Ed25519._exceptions.InvalidSignature

    def __init__(
        self,
        public_signing_key: t.Union[str, bytes, Ed25519PublicKey, Ed25519],
        *,
        path: t.OptionalPathStr = None,
        verify_files: bool = True,
    ) -> None:
        """
        Receives the bytes type public signing key a user expects a
        package to be signed by, & stores it within the instance. The
        ``path`` keyword argument is the root location where all of the
        source files can be reached via the relative paths of the files
        declared in the summary. If instead the source files will not be
        checked for validity & only the validity of the signature will
        be assertained, the ``verify_files`` keyword can be set falsey.
        """
        if public_signing_key.__class__ is not self._Signer:
            key = self._Signer().import_public_key(public_signing_key)
        else:
            key = public_signing_key
        self._signing_key = key
        if verify_files:
            self._path = Path(path).absolute()
        elif path:
            raise Issue.unused_parameters("path", "not verifying files")

    @property
    def _summary_bytes(self) -> bytes:
        """
        Returns the UTF-8 encoded JSON package signature summary sans
        the package checksum & signature for hashing.
        """
        return json.dumps(self._summary_dictionary).encode()

    def _import_summary(
        self, summary: t.Dict[str, t.JSONSerializable]
    ) -> None:
        """
        Verifies the package summary checksum & stores its values within
        the instance.
        """
        summary = self._summary_dictionary = {**summary}
        self._checksum = bytes.fromhex(summary.pop(self._CHECKSUM))
        self._signature = bytes.fromhex(summary.pop(self._SIGNATURE))
        if self._Hasher(self._summary_bytes).digest() != self._checksum:
            raise Issue.invalid_value("package summary checksum")

    def _verify_file_checksums(self, summary: dict) -> None:
        """
        Verifies the files declared in the summary by loading them from
        the filesystem & calculating their digests for a match.
        """
        path = self._path
        files = summary[self._CHECKSUMS]
        for file_path, purported_hexdigest in files.items():
            purported_digest = bytes.fromhex(purported_hexdigest)
            with open(path / file_path, "rb") as source_file:
                digest = self._Hasher(source_file.read()).digest()
                if not bytes_are_equal(purported_digest, digest):
                    raise PackageSignerIssue.invalid_file_digest(file_path)

    def verify_summary(
        self,
        summary: t.Union[
            t.Dict[str, t.JSONSerializable], t.JSONDeserializable
        ],
    ) -> None:
        """
        Verifies the purported checksum of a package summary & the
        signature of the checksum.
        """
        if summary.__class__ is not dict:
            summary = json.loads(summary)
        purported_signing_key = bytes.fromhex(summary[self._SIGNING_KEY])
        if purported_signing_key != self._signing_key.public_bytes:
            raise Issue.invalid_value("summary's public signing key")
        self._import_summary(summary)
        if hasattr(self, "_path"):
            self._verify_file_checksums(summary)
        self._signing_key.verify(self._signature, self._checksum)


module_api = dict(
    _KeyAADBundle=KeyAADBundle,
    DomainKDF=DomainKDF,
    Ed25519=Ed25519,
    PackageSigner=PackageSigner,
    PackageVerifier=PackageVerifier,
    Passcrypt=Passcrypt,
    PasscryptSession=PasscryptSession,
    X25519=X25519,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    abytes_keys=abytes_keys,
    agenerate_key=agenerate_key,
    amnemonic=amnemonic,
    bytes_keys=bytes_keys,
    generate_key=generate_key,
    mnemonic=mnemonic,
)

