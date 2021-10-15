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
    "ciphers",
    "AsyncDatabase",
    "Chunky2048",
    "Database",
    "DomainKDF",
    "Passcrypt",
    "StreamHMAC",
    "abytes_decrypt",
    "abytes_encrypt",
    "abytes_keys",
    "ajson_decrypt",
    "ajson_encrypt",
    "bytes_decrypt",
    "bytes_encrypt",
    "bytes_keys",
    "json_decrypt",
    "json_encrypt",
]


__doc__ = (
    "A collection of low-level tools & higher level abstractions which "
    "can be used to create custom security tools, or as pre-assembled r"
    "ecipes, including the package's main MRAE / AEAD pseudo-one-time-p"
    "ad cipher called `Chunky2048`."
)


import hmac
import json
import base64
from functools import wraps
from functools import partial
from collections import deque
from hashlib import sha3_256, sha3_512, shake_256
from ._exceptions import *
from ._typing import Typing
from .paths import *
from .paths import Path
from .asynchs import *
from .asynchs import asleep, gather, time
from .commons import *
from .commons import chunky2048_constants, passcrypt_constants
from commons import *  # import the module's constants
from ._containers import *
from _containers import *
from .randoms import csprng, acsprng
from .randoms import generate_salt, agenerate_salt
from .generics import Hasher
from .generics import BytesIO
from .generics import Domains
from .generics import Padding
from .generics import AsyncInit
from .generics import gentools
from .generics import data, adata
from .generics import cycle, acycle
from .generics import unpack, aunpack
from .generics import sha3__256, asha3__256
from .generics import sha3__512, asha3__512
from .generics import is_async_function
from .generics import lru_cache, alru_cache
from .generics import Comprende, comprehension
from .generics import int_to_base, aint_to_base
from .generics import sha3__256_hmac, asha3__256_hmac
from .generics import sha3__512_hmac, asha3__512_hmac
from .generics import bytes_are_equal, abytes_are_equal


async def atest_key_salt_aad(key: bytes, salt: bytes, aad: bytes):
    """
    Validates the main symmetric user ``key``, ephemeral ``salt``, &
    ``aad`` authenticated associated data for the `Chunky2048` cipher.
    """
    if key.__class__ is not bytes:
        raise Issue.value_must_be_type("main key", bytes)
    elif len(key) < MINIMUM_KEY_BYTES:
        raise KeyAADIssue.invalid_key()
    elif salt.__class__ is not bytes:
        raise Issue.value_must_be_type("salt", bytes)
    elif len(salt) != SALT_BYTES:
        raise KeyAADIssue.invalid_salt()
    elif aad.__class__ is not bytes:
        raise Issue.value_must_be_type("aad", bytes)


def test_key_salt_aad(key: bytes, salt: bytes, aad: bytes):
    """
    Validates the main symmetric user ``key``, ephemeral ``salt``, &
    ``aad`` authenticated associated data for the `Chunky2048` cipher.
    """
    if key.__class__ is not bytes:
        raise Issue.value_must_be_type("main key", bytes)
    elif len(key) < MINIMUM_KEY_BYTES:
        raise KeyAADIssue.invalid_key()
    elif salt.__class__ is not bytes:
        raise Issue.value_must_be_type("salt", bytes)
    elif len(salt) != SALT_BYTES:
        raise KeyAADIssue.invalid_salt()
    elif aad.__class__ is not bytes:
        raise Issue.value_must_be_type("aad", bytes)


async def amake_salt_non_deterministic(
    salt: bytes, *, disable: bool = False
):
    """
    Prevents a deterministic salt from being used for an encryption
    procedure without explicitly passing the appropriate flag to do so.
    Returns a random 24-byte salt otherwise.
    """
    if disable:
        return salt if salt else await agenerate_salt(size=SALT_BYTES)
    elif salt:
        raise Issue.unsafe_determinism()
    else:
        return await agenerate_salt(size=SALT_BYTES)


def make_salt_non_deterministic(salt: bytes, *, disable: bool = False):
    """
    Prevents a deterministic salt from being used for an encryption
    procedure without explicitly passing the appropriate flag to do so.
    Returns a random 24-byte salt otherwise.
    """
    if disable:
        return salt if salt else generate_salt(size=SALT_BYTES)
    elif salt:
        raise Issue.unsafe_determinism()
    else:
        return generate_salt(size=SALT_BYTES)


async def asingle_use_key(
    key: Typing.Optional[bytes] = None,
    *,
    salt: Typing.Optional[bytes] = None,
    aad: bytes = b"aad",
    allow_dangerous_determinism: bool = False,
):
    """
    Returns a mapping containing a unique combination of a ``key``,
    ``salt`` & ``aad`` whose use is limited TO A SINGLE encryption /
    decryption round. The reuse of the same permutation of ``key``,
    ``salt`` & ``aad`` for multiple different messages **completely**
    breaks the security of the encryption algorithm if the correct
    padding, available from the `Padding` class, on the plaintext is not
    used.

    New ``key`` & ``salt`` values are returned in the mapping if neither
    are specified. The returned ``aad`` defaults to b"aad", as it does
    across the package.
    """
    key_and_salt = key and salt
    key = key if key else await acsprng()
    salt = await amake_salt_non_deterministic(
        salt, disable=allow_dangerous_determinism or not key_and_salt
    )
    await atest_key_salt_aad(key, salt, aad)
    return KeySaltAAD(key, salt, aad)


def single_use_key(
    key: Typing.Optional[bytes] = None,
    *,
    salt: Typing.Optional[bytes] = None,
    aad: bytes = b"aad",
    allow_dangerous_determinism: bool = False,
):
    """
    Returns a mapping containing a unique combination of a ``key``,
    ``salt`` & ``aad`` whose use is limited TO A SINGLE encryption /
    decryption round. The reuse of the same permutation of ``key``,
    ``salt`` & ``aad`` for multiple different messages **completely**
    breaks the security of the encryption algorithm if the correct
    padding, available from the `Padding` class, on the plaintext is not
    used.

    New ``key`` & ``salt`` values are returned in the mapping if neither
    are specified. The returned ``aad`` defaults to b"aad", as it does
    across the package.
    """
    key_and_salt = key and salt
    key = key if key else csprng()
    salt = make_salt_non_deterministic(
        salt, disable=allow_dangerous_determinism or not key_and_salt
    )
    test_key_salt_aad(key, salt, aad)
    return KeySaltAAD(key, salt, aad)


class KeyAADBundle:
    """
    A public interface for managing a key, salt & associated data bundle
    which is to be used for ONLY ONE encryption. If a unique bundle is
    used for more than one encryption, then the security of the
    `Chunky2048` cipher may be greatly damaged.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.

    ``salt``: An ephemeral, random 24-byte value that MUST BE USED ONLY
            ONCE for each encryption. This value is sent in the clear
            along with the ciphertext.

    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of ``key`` & ``salt``.
    """

    __slots__ = ("__keys", "_bundle", "_mode", "_registers", "_siv")

    _generate_bundle = staticmethod(single_use_key)
    _agenerate_bundle = staticmethod(asingle_use_key)

    @staticmethod
    def _test_siv(siv):
        """
        Assures the ``siv`` is a bytes value & is 24-bytes.
        """
        if siv.__class__ is not bytes:
            raise Issue.value_must_be_type("siv", bytes)
        elif len(siv) != SIV_BYTES:
            raise Issue.invalid_length("siv", SIV_BYTES)
        return True

    @classmethod
    async def aunsafe(
        cls, key: bytes, salt: bytes, aad: bytes = b"aad", siv: bytes = b""
    ):
        """
        Allows instances to be used in the `bytes_keys` & `abytes_keys`
        coroutines without checking for unsafe reuse or checking for the
        correct lengths of the ``key``, ``salt``, ``aad`` & ``siv``
        values. This is useful for when the coroutines are needed as
        cryptographically secure pseudo-random number generators outside
        of the context of `Chunky2048` cipher.

        WARNING: This initializer SHOULD NOT be used within the
        `Chunky2048` cipher's interfaces which expect a `key_bundle`.
        """
        try:
            await asleep()
            return cls.unsafe(key, salt, aad, siv)
        finally:
            await asleep()

    @classmethod
    def unsafe(
        cls, key: bytes, salt: bytes, aad: bytes = b"aad", siv: bytes = b""
    ):
        """
        Allows instances to be used in the `bytes_keys` & `abytes_keys`
        coroutines without checking for unsafe reuse or checking for the
        correct lengths of the ``key``, ``salt``, ``aad`` & ``siv``
        values. This is useful for when the coroutines are needed as
        cryptographically secure pseudo-random number generators outside
        of the context of the `Chunky2048` cipher.

        WARNING: This initializer SHOULD NOT be used within the
        `Chunky2048` cipher's interfaces which expect a `key_bundle`.
        """
        self = cls.__new__(cls)
        if siv:
            self._test_siv(siv)
        self._siv: bytes = siv
        self._mode = KeyAADMode()
        self._registers = NoRegisters()
        self._bundle = KeySaltAAD(key, salt, aad)
        self._initialize_keys()
        return self

    def __init__(
        self,
        key: Typing.Optional[bytes] = None,
        *,
        salt: Typing.Optional[bytes] = None,
        aad: bytes = b"aad",
        siv: bytes = b"",
        allow_dangerous_determinism: bool = False,
    ):
        """
        Stores the ``key``, ``salt`` & ``aad`` associated data in a
        private object which is queried through this class' interface.
        Since the ``siv`` should only be passed when the bundle is to be
        used for decryption, the ``allow_dangerous_determinism`` keyword-
        only argument doesn't need to be passed when the ``siv`` is.
        """
        if siv:
            self._test_siv(siv)
            allow_dangerous_determinism = True
        self._siv: bytes = siv
        self._mode = KeyAADMode()
        self._registers = KeyAADBundleRegisters()
        self._bundle: KeySaltAAD = self._generate_bundle(
            key=key,
            salt=salt,
            aad=aad,
            allow_dangerous_determinism=allow_dangerous_determinism,
        )
        self._initialize_keys()

    def __iter__(self):
        """
        Yields the instance's key, salt then the associated aad data.
        """
        yield self._bundle.key
        yield self._bundle.salt
        yield self._bundle.aad

    def _initialize_keys(self):
        """
        Sets up standardized seeds for the `Chunky2048` cipher's KDFs.
        """
        self.__keys = Chunky2048Keys()
        # main kdf
        domain = Domains.KDF + Domains.SEED
        summary = b"||".join(self)
        self.__keys.kdf = kdf = sha3_512(domain + summary)
        # seeds
        self.__keys.seed_0 = seed_0 = kdf.digest()
        kdf.update(domain + seed_0)
        self.__keys.seed_1 = kdf.digest()

    async def _agenerate_algorithm_keys(self):
        """
        Starts the `Chunky2048` cipher's async keystream generator, &
        uses its first 128-byte output to derive the keys & sha3_256 MAC
        object needed by the algorithm.
        """
        # init keystream
        self.__keys.keystream = keystream = abytes_keys.root(self)
        self.__keys.primer_key = primer_key = await keystream.asend(None)
        # init stream hmac
        domain = Domains.SHMAC
        self.__keys.shmac_mac = sha3_256(primer_key + domain)  # Update with 136 bytes
        self.__keys.shmac_key = primer_key[:KEY_BYTES]
        # init padding key
        self.__keys.padding_key = primer_key[-PADDING_KEY_BYTES:]
        await self._mode.aset_async_mode()

    def _generate_algorithm_keys(self):
        """
        Starts the `Chunky2048` cipher's sync keystream generator, &
        uses its first 128-byte output to derive the keys & sha3_256 MAC
        object needed by the algorithm.
        """
        # init keystream
        self.__keys.keystream = keystream = bytes_keys.root(self)
        self.__keys.primer_key = primer_key = keystream.send(None)
        # init stream hmac
        domain = Domains.SHMAC
        self.__keys.shmac_mac = sha3_256(primer_key + domain)  # Update with 136 bytes
        self.__keys.shmac_key = primer_key[:KEY_BYTES]
        # init padding key
        self.__keys.padding_key = primer_key[-PADDING_KEY_BYTES:]
        self._mode.set_sync_mode()

    async def async_mode(self):
        """
        Sets the instance up to run async key derivation.
        """
        await self._agenerate_algorithm_keys()
        return self

    def sync_mode(self):
        """
        Sets the instance up to run sync key derivation.
        """
        self._generate_algorithm_keys()
        return self

    def _register_validator(self, validator):
        """
        Registers the validator which will be tied to the instance for a
        single run of the `Chunky2048` cipher. Reusing an instance or
        the same validator for multiple cipher calls is NOT SAFE, & is
        disallowed by this registration.
        """
        if hasattr(self._registers, "validator"):
            raise KeyAADIssue.validator_already_registered()
        self._registers.register("validator", validator)

    def _register_keystream(self):
        """
        Registers the keystream which will be tied to the instance for a
        single run of the `Chunky2048` cipher. Reusing an instance is
        NOT SAFE, & is disallowed by this registration.
        """
        if hasattr(self._registers, "keystream"):
            raise KeyAADIssue.keystream_already_registered()
        else:
            self._registers.register("keystream", True)

    @property
    def _keys(self):
        """
        Returns the private iterable of the instance & its seeds.
        """
        return self.__keys.__iter__()

    @property
    def _kdf(self):
        """
        Returns the private KDF the instance used to create its seeds.
        """
        return self.__keys.kdf

    @property
    def _seed(self):
        """
        Returns the private seed the instance produces for use within
        the `(a)bytes_keys` coroutine generators.
        """
        return self.__keys.seed_1

    @property
    def _padding_key(self):
        """
        Returns the private key which is appended to the plaintext in
        the `Padding` class to find the end of a message if it, along
        with the inner header, doesn't precisely fill the 256-byte block.
        """
        return self.__keys.padding_key

    @property
    def _shmac_key(self):
        """
        Returns the private authentication key used in the `StreamHMAC`
        class to produce secure message tags.
        """
        return self.__keys.shmac_key

    @property
    def _shmac_mac(self):
        """
        Returns the private `sha3_256` object used by the `StreamHMAC`
        class.
        """
        return self.__keys.shmac_mac

    @property
    def _keystream(self):
        """
        Returns the private keystream coroutine used in the `Chunky2048`
        cipher to encrypt / decrypt data. The coroutine can be either
        async or sync depending on what mode the instance is set to.
        """
        return self.__keys.keystream

    @property
    def key(self):
        """
        Returns the main, longer-term symmetric user ``key``. It should
        be a uniform 64-byte value.
        """
        return self._bundle.key

    @property
    def salt(self):
        """
        Returns the random 24-byte ``salt``.
        """
        return self._bundle.salt

    @property
    def aad(self):
        """
        Returns the ``aad`` authenticated associated data bytes.
        """
        return self._bundle.aad

    @property
    def siv(self):
        """
        Returns the 24-byte ``siv`` that was attached to ciphertext or
        derived from the first plaintext block.
        """
        return self._siv


async def akeypair_ratchets(key_bundle: KeyAADBundle):
    """
    Returns a 64-byte seed value & the method pointers of three
    ``hashlib.sha3_512`` objects that have been primed in different ways
    with the hashes of the ``key_bundle``'s `key`, `salt` & `aad` values.
    The returned values can be used to construct a symmetric keypair
    ratchet algorithm.
    """
    await asleep()
    keys, seed_0, seed_1 = key_bundle._keys
    domain = Domains.CHUNKY_2048
    seed_kdf = sha3_512(seed_1 + domain + seed_0 + Domains.SEED)
    left_kdf = sha3_512(seed_kdf.digest() + domain + seed_0 + LEFT_PAD)
    right_kdf = sha3_512(left_kdf.digest() + domain + seed_0 + RIGHT_PAD)
    keys.add_keystream_kdfs(seed_kdf, left_kdf, right_kdf)
    await asleep()
    return (
        seed_1,
        seed_kdf.update,
        seed_kdf.digest,
        left_kdf.update,
        left_kdf.digest,
        right_kdf.update,
        right_kdf.digest,
    )


def keypair_ratchets(key_bundle: KeyAADBundle):
    """
    Returns a 64-byte seed value & the method pointers of three
    ``hashlib.sha3_512`` objects that have been primed in different ways
    with the hashes of the ``key_bundle``'s `key`, `salt` & `aad` values.
    The returned values can be used to construct a symmetric keypair
    ratchet algorithm.
    """
    keys, seed_0, seed_1 = key_bundle._keys
    domain = Domains.CHUNKY_2048
    seed_kdf = sha3_512(seed_1 + domain + seed_0 + Domains.SEED)
    left_kdf = sha3_512(seed_kdf.digest() + domain + seed_0 + LEFT_PAD)
    right_kdf = sha3_512(left_kdf.digest() + domain + seed_0 + RIGHT_PAD)
    keys.add_keystream_kdfs(seed_kdf, left_kdf, right_kdf)
    return (
        seed_1,
        seed_kdf.update,
        seed_kdf.digest,
        left_kdf.update,
        left_kdf.digest,
        right_kdf.update,
        right_kdf.digest,
    )


@comprehension()
async def abytes_keys(key_bundle: KeyAADBundle):
    """
    An efficient async coroutine which produces an unending, non-
    repeating, deterministic stream of bytes key material.

    Each iteration yields 128 bytes, iteratively derived by the mixing &
    hashing of the permutation of the user's key, salt & aad, previous
    hashed results, & the ``entropy`` users may send into this async
    generator as an async coroutine.

    Algorithm diagram:

    R = 64-byte ratchet key (output of the seed KDF)
    D = 8-byte domain separator (left or right padding constant)
    r = 72-byte bitrate (blocksize of each round)
    c = 128-byte capacity (hidden inner state)
    f = The round permutation function
    O = 64-byte output key

               R           D
               |           |
    |----------⊕---------|-⊕-|-----------------------------------------|
    |            r           |                    c                    |
    |------------------------|-----------------------------------------|
                 |                                |
            |------------------------------------------|
            |                    f                     |
            |------------------------------------------|
                 |                                |
    |------------------------|-----------------------------------------|
    |            r           |                    c                    |
    |---------V----------|---|-----------------------------------------|
              |
              O

                    seed_kdf.update(seed║mac_or_user_entropy║R)
                    R = seed_kdf.digest()

    Do this procedure for the left & right kdfs, concatenate & retrieve
    their outputs, repeat this cycle each iteration. It's important that
    the placement of the ratchet key (R) exactly overlaps with the
    placement of the 64 bytes which will become the output key (O).
    """
    key_bundle._register_keystream()
    seed, s_update, s_digest, l_update, l_digest, r_update, r_digest = (
        await akeypair_ratchets(key_bundle)
    )
    while True:
        ratchet_key = s_digest()
        l_update(ratchet_key + LEFT_PAD)  # update with 72-bytes
        r_update(ratchet_key + RIGHT_PAD)  # update with 72-bytes
        entropy = yield l_digest() + r_digest()
        await asleep()
        s_update(seed + entropy if entropy else SEED_PAD + ratchet_key)


@comprehension()
def bytes_keys(key_bundle: KeyAADBundle):
    """
    An efficient sync coroutine which produces an unending, non-
    repeating, deterministic stream of bytes key material.

    Each iteration yields 128 bytes, iteratively derived by the mixing &
    hashing of the permutation of the user's key, salt & aad, previous
    hashed results, & the ``entropy`` users may send into this generator
    as a coroutine.

    Algorithm diagram:

    R = 64-byte ratchet key (output of the seed KDF)
    D = 8-byte domain separator (left or right padding constant)
    r = 72-byte bitrate (blocksize of each round)
    c = 128-byte capacity (hidden inner state)
    f = The round permutation function
    O = 64-byte output key

               R           D
               |           |
    |----------⊕---------|-⊕-|-----------------------------------------|
    |            r           |                    c                    |
    |------------------------|-----------------------------------------|
                 |                                |
            |------------------------------------------|
            |                    f                     |
            |------------------------------------------|
                 |                                |
    |------------------------|-----------------------------------------|
    |            r           |                    c                    |
    |---------V----------|---|-----------------------------------------|
              |
              O

                    seed_kdf.update(seed║mac_or_user_entropy║R)
                    R = seed_kdf.digest()

    Do this procedure for the left & right kdfs, concatenate & retrieve
    their outputs, repeat this cycle each iteration. It's important that
    the placement of the ratchet key (R) exactly overlaps with the
    placement of the 64 bytes which will become the output key (O).
    """
    key_bundle._register_keystream()
    seed, s_update, s_digest, l_update, l_digest, r_update, r_digest = (
        keypair_ratchets(key_bundle)
    )
    while True:
        ratchet_key = s_digest()
        l_update(ratchet_key + LEFT_PAD)  # update with 72-bytes
        r_update(ratchet_key + RIGHT_PAD)  # update with 72-bytes
        entropy = yield l_digest() + r_digest()
        s_update(seed + entropy if entropy else SEED_PAD + ratchet_key)


class StreamHMAC:
    """
    This class is used as an inline validator for ciphertext streams as
    they are being created & decrypted. Its design was inspired by AES-GCM,
    but uses a sha3_256 hash function instead of Galois multiplication,
    the authenticated associated data is used within key derivation, &
    an SIV is derived from the first block of ciphertext.
    """

    __slots__ = (
        "_aupdate",
        "_auth_key",
        "_avalidated_xor",
        "_finalized",
        "_key_bundle",
        "_last_digest",
        "_mac",
        "_mode",
        "_result",
        "_result_is_ready",
        "_siv",
        "_update",
        "_validated_xor",
    )

    _DECRYPTION: str = DECRYPTION
    _ENCRYPTION: str = ENCRYPTION

    _key_type = sha3_512
    _type = sha3_256

    def __init__(self, key_bundle: KeyAADBundle):
        """
        Begins a stateful hash object that's used to calculate a keyed-
        message authentication code referred to as an hmac. The instance
        uses derived key material from the provided KeyAADBundle.
        """
        if not issubclass(key_bundle.__class__, KeyAADBundle):
            raise Issue.value_must_be_type("key_bundle", KeyAADBundle)
        self._mode = None
        self._finalized = False
        self._result_is_ready = False
        self._register_key_bundle(key_bundle)
        self._update = self._placeholder_update
        self._aupdate = self._aplaceholder_update

    def _register_key_bundle(self, key_bundle: KeyAADBundle):
        """
        Registers the `KeyAADBundle` object which will be tied to the
        instance for a single run of the `Chunky2048` cipher. Reusing an
        instance or the same ``key_bundle`` for multiple cipher calls is
        NOT SAFE, & is disallowed by this registration.
        """
        key_bundle._mode.validate()
        self._key_bundle = key_bundle
        key_bundle._register_validator(self)
        self._mac = key_bundle._shmac_mac
        self._last_digest = self._mac.digest()
        self._auth_key = key_bundle._shmac_key
        self.siv = key_bundle.siv

    @property
    def mode(self):
        """
        Returns the mode which the instance was instructed to be in by
        the user.
        """
        return self._mode

    @property
    def siv(self):
        """
        Returns the instance's synthetic IV, which is used as a seed to
        the encryption key stream algorithm. It's derived from the first
        block of plaintext during the padding phase. The ``siv`` is
        attached to the ciphertext.
        """
        return self._siv

    @siv.setter
    def siv(self, value: bytes):
        """
        An interface for setting the instance's SIV & assist users by
        warning against invalid usage.
        """
        if getattr(self, "_siv", None):
            raise Issue.value_already_set("siv", str(self._siv))
        elif value:
            self._siv = value
            self._key_bundle._siv = value
            self._mac.update(value)
        else:
            self._siv = b""

    def for_encryption(self):
        """
        Instructs the HMAC validator instance to prepare itself for
        validating ciphertext within the `xor` generator as plaintext
        is being encrypted.

        Usage Example:

        from aiootp import gentools, StreamHMAC, KeyAADBundle

        aad = b"known associated data"
        key_bundle = KeyAADBundle(key, aad=aad).sync_mode()
        shmac = StreamHMAC(key_bundle).for_encryption()
        stream = gentools.plaintext_stream(
            b"some bytes of plaintext...", key_bundle
        )

        with stream.bytes_encipher(key_bundle, shmac) as ciphering:
            return {
                "ciphertext": ciphering.join(b""),
                "hmac": shmac.finalize(),
                "salt": key_bundle.salt,
                "synthetic_iv": key_bundle.siv,
            }
        """
        if self._mode:
            raise Issue.value_already_set("validator", self._mode)
        elif self._finalized:
            raise SHMACIssue.already_finalized()
        elif self._siv:
            raise SHMACIssue.invalid_siv_usage()
        self._mode = self._ENCRYPTION
        self._update = self._update_mac
        self._aupdate = self._aupdate_mac
        self._validated_xor = self._xor_then_hash
        self._avalidated_xor = self._axor_then_hash
        return self

    def for_decryption(self):
        """
        Instructs the HMAC validator instance to prepare itself for
        validating ciphertext within the `xor` generator as it's being
        decrypted.

        Usage Example:

        from aiootp import gentools, StreamHMAC, KeyAADBundle, Padding

        salt = message["salt"]
        siv = message["synthetic_iv"]
        aad = b"known associated data"
        key_bundle = KeyAADBundle(key, salt=salt, aad=aad, siv=siv)
        shmac = StreamHMAC(key_bundle.sync_mode()).for_decryption()
        stream = gentools.data(message["ciphertext"])

        with stream.bytes_decipher(key_bundle, shmac) as deciphering:
            padded_plaintext = deciphering.join(b"")
            shmac.finalize()
            shmac.test_hmac(message["hmac"])

        plaintext = Padding.depad_plaintext(
            padded_plaintext, key_bundle, ttl=60
        )
        """
        if self._mode:
            raise Issue.value_already_set("validator", self._mode)
        elif self._finalized:
            raise SHMACIssue.already_finalized()
        elif not self._siv:
            raise SHMACIssue.invalid_siv_usage()
        self._mode = self._DECRYPTION
        self._update = self._update_mac
        self._aupdate = self._aupdate_mac
        self._validated_xor = self._hash_then_xor
        self._avalidated_xor = self._ahash_then_xor
        return self

    async def aupdate_key(self, entropic_material: bytes):
        """
        This method provides a public interface for updating the SHMAC
        key during validation of the stream of ciphertext. This allows
        users to ratchet their authentication key & have the validator
        track when the key changes & validate the change.
        """
        if self._finalized:
            raise SHMACIssue.already_finalized()
        await asleep()
        mac = self._mac.digest()
        payload = (Domains.KDF, self._auth_key, entropic_material, mac)
        kdf = self._key_bundle._kdf
        kdf.update(b"".join(payload))
        self._auth_key = key = kdf.digest()
        self._mac.update(key)
        return self

    def update_key(self, entropic_material: bytes):
        """
        This method provides a public interface for updating the SHMAC
        key during validation of the stream of ciphertext. This allows
        users to ratchet their authentication key & have the validator
        track when the key changes & validate the change.
        """
        if self._finalized:
            raise SHMACIssue.already_finalized()
        mac = self._mac.digest()
        payload = (Domains.KDF, self._auth_key, entropic_material, mac)
        kdf = self._key_bundle._kdf
        kdf.update(b"".join(payload))
        self._auth_key = key = kdf.digest()
        self._mac.update(key)
        return self

    async def _aplaceholder_update(self, *a, **kw):
        """
        This method is overwritten with the propper functionality when a
        cipher mode is declared with either the `for_encryption` or
        `for_decryption` methods. This interface helps use the object
        correctly.
        """
        raise SHMACIssue.no_cipher_mode_declared()

    def _placeholder_update(self, *a, **kw):
        """
        This method is overwritten with the propper functionality when a
        cipher mode is declared with either the `for_encryption` or
        `for_decryption` methods. This interface helps use the object
        correctly.
        """
        raise SHMACIssue.no_cipher_mode_declared()

    async def _aupdate_mac(self, ciphertext_block: bytes):
        """
        This method is called automatically when an instance is passed
        into the low-level `(a)bytes_encipher` / `(a)bytes_decipher`
        generators as a `validator`. It updates the instance's mac
        object with the ``ciphertext_block``.
        """
        self._last_digest = self._mac.digest()
        self._mac.update(ciphertext_block)
        return self

    def _update_mac(self, ciphertext_block: bytes):
        """
        This method is called automatically when an instance is passed
        into the low-level `(a)bytes_encipher` / `(a)bytes_decipher`
        generators as a `validator`. It updates the instance's mac
        object with the ``ciphertext_block``.
        """
        self._last_digest = self._mac.digest()
        self._mac.update(ciphertext_block)
        return self

    async def _axor_then_hash(
        self,
        plaintext_block: bytes,
        key_chunk: bytes,
        *,
        _from_bytes: Typing.Callable = int.from_bytes,
    ):
        """
        This method is inserted as the instance's `_avalidated_xor`
        method after the user chooses the encryption mode. The mode is
        chosen by calling the `for_encryption` method. It receives a
        ``plaintext_block`` & ``key_chunk``, & xors them into a 256-byte
        `ciphertext_block` used to update the instance's mac object
        before being returned.
        """
        try:
            ciphertext_block = (
                _from_bytes(plaintext_block, "big")
                ^ _from_bytes(key_chunk, "big")
            ).to_bytes(BLOCKSIZE, "big")
            await self._aupdate(ciphertext_block)
            return ciphertext_block
        except OverflowError:
            raise Issue.exceeded_blocksize()

    def _xor_then_hash(
        self,
        plaintext_block: bytes,
        key_chunk: bytes,
        *,
        _from_bytes: Typing.Callable = int.from_bytes,
    ):
        """
        This method is inserted as the instance's `_validated_xor`
        method after the user chooses the encryption mode. The mode is
        chosen by calling the `for_encryption` method. It receives a
        ``plaintext_block`` & ``key_chunk``, & xors them into a 256-byte
        `ciphertext_block` used to update the instance's mac object
        before being returned.
        """
        try:
            ciphertext_block = (
                _from_bytes(plaintext_block, "big")
                ^ _from_bytes(key_chunk, "big")
            ).to_bytes(BLOCKSIZE, "big")
            self._update(ciphertext_block)
            return ciphertext_block
        except OverflowError:
            raise Issue.exceeded_blocksize()

    async def _ahash_then_xor(
        self,
        ciphertext_block: bytes,
        key_chunk: bytes,
        *,
        _from_bytes: Typing.Callable = int.from_bytes,
    ):
        """
        This method is inserted as the instance's `_avalidated_xor`
        method after the user chooses the decryption mode. The mode is
        chosen by calling the `for_decryption` method. It receives a
        ``ciphertext_block`` & ``key_chunk``, uses the ciphertext to
        update the instance's mac object, then returns the 256-byte
        plaintext.
        """
        try:
            await self._aupdate(ciphertext_block)
            return (
                _from_bytes(ciphertext_block, "big")
                ^ _from_bytes(key_chunk, "big")
            ).to_bytes(BLOCKSIZE, "big")
        except OverflowError:
            raise Issue.exceeded_blocksize()

    def _hash_then_xor(
        self,
        ciphertext_block: bytes,
        key_chunk: bytes,
        *,
        _from_bytes: Typing.Callable = int.from_bytes,
    ):
        """
        This method is inserted as the instance's `_validated_xor`
        method after the user chooses the decryption mode. The mode is
        chosen by calling the `for_decryption` method. It receives a
        ``ciphertext_block`` & ``key_chunk``, uses the ciphertext to
        update the instance's mac object, then returns the 256-byte
        plaintext.
        """
        try:
            self._update(ciphertext_block)
            return (
                _from_bytes(ciphertext_block, "big")
                ^ _from_bytes(key_chunk, "big")
            ).to_bytes(BLOCKSIZE, "big")
        except OverflowError:
            raise Issue.exceeded_blocksize()

    @staticmethod
    async def _ablock_id_metadata(next_block: bytes, block_id_size: int):
        """
        Returns 8-bytes of metadata of the requested block ID size &
        the size of the next block.
        """
        await asleep()
        if block_id_size < MINIMUM_BLOCK_ID_BYTES:
            raise SHMACIssue.block_id_is_too_small(block_id_size)
        elif block_id_size > MAX_BLOCK_ID_BYTES:
            raise SHMACIssue.block_id_is_too_big(block_id_size)
        id_size = block_id_size.to_bytes(4, "big")
        blocksize = len(next_block).to_bytes(4, "big")
        return id_size + blocksize

    @staticmethod
    def _block_id_metadata(next_block: bytes, block_id_size: int):
        """
        Returns 8-bytes of metadata of the requested block ID size &
        the size of the next block.
        """
        if block_id_size < MINIMUM_BLOCK_ID_BYTES:
            raise SHMACIssue.block_id_is_too_small(block_id_size)
        elif block_id_size > MAX_BLOCK_ID_BYTES:
            raise SHMACIssue.block_id_is_too_big(block_id_size)
        id_size = block_id_size.to_bytes(4, "big")
        blocksize = len(next_block).to_bytes(4, "big")
        return id_size + blocksize

    async def _aget_block_id_mac(self):
        """
        Returns a correct mac digest considering that during encryption
        the instance is updated before the block id is generated, & it
        must be checked by an instance during decryption before being
        updated.
        """
        await asleep()
        if self._mode == self._ENCRYPTION:
            return self._last_digest
        elif self._mode == self._DECRYPTION:
            return self._mac.digest()
        else:
            raise SHMACIssue.no_cipher_mode_declared()

    def _get_block_id_mac(self):
        """
        Returns a correct mac digest considering that during encryption
        the instance is updated before the block id is generated, & it
        must be checked by an instance during decryption before being
        updated.
        """
        if self._mode == self._ENCRYPTION:
            return self._last_digest
        elif self._mode == self._DECRYPTION:
            return self._mac.digest()
        else:
            raise SHMACIssue.no_cipher_mode_declared()

    async def anext_block_id(
        self, next_block: bytes, *, size: int = BLOCK_ID_BYTES
    ):
        """
        Returns a ``size``-byte block id derived from the current state
        & the supplied ``next_block`` chunk of ciphertext. These block
        ids can be used to detect out-of-order messages, as well as
        ciphertext forgeries, without altering the internal state. This
        allows for robust decryption of ciphertext streams & mitigates
        adversarial attempts to crash communication channels.

        Usage Example (Encryption): # when the `key` & `aad` are already
                                    # shared

        from aiootp import gentools, StreamHMAC, KeyAADBundle

        async def aciphertext_stream():
            plaintext_bytes = b"example plaintext..."
            key_bundle = await KeyAADBundle(key, aad=aad).async_mode()
            shmac = StreamHMAC(key_bundle).for_encryption()
            datastream = gentools.aplaintext_stream(
                plaintext_bytes, key_bundle
            )
            cipherstream = datastream.abytes_encipher(key_bundle, shmac)

            first_ciphertext_block = await cipherstream()
            yield key_bundle.salt, key_bundle.siv
            yield (
                await shmac.anext_block_id(first_ciphertext_block),
                first_ciphertext_block,
            )
            async for ciphertext_block in cipherstream:
                yield (
                    await shmac.anext_block_id(ciphertext_block),
                    ciphertext_block,
                )


        Usage Example (Decryption): # when the `key` & `aad` are already
                                    # shared

        from collections import deque
        from aiootp import gentools, StreamHMAC, KeyAADBundle, Padding

        cipherstream = aciphertext_stream()
        salt, siv = await cipherstream.asend(None)
        key_bundle = KeyAADBundle(key, salt=salt, aad=aad, siv=siv)
        shmac = StreamHMAC(await key_bundle.async_mode()).for_decryption()

        ciphertext = deque()
        deciphering = gentools.apopleft(ciphertext).abytes_decipher(
            key_bundle, validator=shmac
        )

        padded_plaintext = b""
        async for block_id, ciphertext_block in cipherstream:
            await shmac.atest_next_block_id(block_id, ciphertext_block)
            ciphertext.append(ciphertext_block)
            padded_plaintext += await deciphering()

        assert plaintext_bytes == await Padding.adepad_plaintext(
            padded_plaintext, key_bundle, ttl=60
        )
        """
        payload = (
            Domains.BLOCK_ID,
            await self._ablock_id_metadata(next_block, size),
            self._auth_key,
            await self._aget_block_id_mac(),
            next_block,
        )
        block_id = self._type(b"".join(payload))
        return block_id.digest()[:size]

    def next_block_id(
        self, next_block: bytes, *, size: int = BLOCK_ID_BYTES
    ):
        """
        Returns a ``size``-byte block id derived from the current state
        & the supplied ``next_block`` chunk of ciphertext. These block
        ids can be used to detect out-of-order messages, as well as
        ciphertext forgeries, without altering the internal state. This
        allows for robust decryption of ciphertext streams & mitigates
        adversarial attempts to crash communication channels.

        Usage Example (Encryption): # when the `key` & `aad` are already
                                    # shared

        from aiootp import gentools, StreamHMAC, KeyAADBundle

        def ciphertext_stream():
            plaintext_bytes = b"example plaintext..."
            key_bundle = KeyAADBundle(key, aad=aad).sync_mode()
            shmac = StreamHMAC(key_bundle).for_encryption()
            datastream = gentools.plaintext_stream(
                plaintext_bytes, key_bundle
            )
            cipherstream = datastream.bytes_encipher(key_bundle, shmac)

            first_ciphertext_block = cipherstream()
            yield key_bundle.salt, key_bundle.siv
            yield (
                shmac.next_block_id(first_ciphertext_block),
                first_ciphertext_block,
            )
            for ciphertext_block in cipherstream:
                yield (
                    shmac.next_block_id(ciphertext_block),
                    ciphertext_block,
                )


        Usage Example (Decryption): # when the `key` & `aad` are already
                                    # shared

        from collections import deque
        from aiootp import gentools, StreamHMAC, KeyAADBundle, Padding

        cipherstream = ciphertext_stream()
        salt, siv = cipherstream.asend(None)
        key_bundle = KeyAADBundle(key, salt=salt, aad=aad, siv=siv)
        shmac = StreamHMAC(key_bundle.sync_mode()).for_decryption()

        ciphertext = deque()
        deciphering = gentools.popleft(ciphertext).bytes_decipher(
            key_bundle, validator=shmac
        )

        padded_plaintext = b""
        async for block_id, ciphertext_block in cipherstream:
            shmac.test_next_block_id(block_id, ciphertext_block)
            ciphertext.append(ciphertext_block)
            padded_plaintext += deciphering()

        assert plaintext_bytes == Padding.depad_plaintext(
            padded_plaintext, key_bundle, ttl=60
        )
        """
        payload = (
            Domains.BLOCK_ID,
            self._block_id_metadata(next_block, size),
            self._auth_key,
            self._get_block_id_mac(),
            next_block,
        )
        block_id = self._type(b"".join(payload))
        return block_id.digest()[:size]

    async def acurrent_digest(
        self, *, obj: Typing.Union[sha3_256, sha3_512] = _type
    ):
        """
        Returns a secure digest that authenticates the ciphertext up to
        the current point of execution of the StreamHMAC algorithm. It
        incorporates the number of blocks of ciphertext blocks processed,
        the encoded key derived from the user's key, salt, & aad, as
        well as the hashing object's current & previous digest.

        Usage Example (Encryption): # when the `key` & `aad` are already
                                    # shared
        import aiootp
        from aiootp import gentools, StreamHMAC, KeyAADBundle

        async def acipher_stream():
            plaintext_bytes = b"example plaintext..."
            aad = b"known associated data"
            key_bundle = await KeyAADBundle(key, aad=aad).async_mode()
            shmac = StreamHMAC(key_bundle).for_encryption()

            datastream = gentools.aplaintext_stream(
                plaintext_bytes, key_bundle
            )
            cipherstream = datastream.abytes_encipher(key_bundle, shmac)

            first_ciphertext_block = await cipherstream()
            yield key_bundle.salt, shmac.siv
            yield await shmac.acurrent_digest(), first_ciphertext_block
            async for ciphertext_block in cipherstream:
                yield await shmac.acurrent_digest(), ciphertext_block


        Usage Example (Decryption): # when the `key` & `aad` are already
                                    # shared
        from collections import deque
        import aiootp
        from aiootp import gentools, StreamHMAC, KeyAADBundle, Padding

        cipherstream = acipher_stream()
        aad = b"known associated data"
        salt, siv = await cipherstream.asend(None)
        key_bundle = KeyAADBundle(key, salt=salt, aad=aad, siv=siv)
        shmac = StreamHMAC(await key_bundle.async_mode()).for_decryption()

        ciphertext = deque()
        deciphering = gentools.apopleft(ciphertext).abytes_decipher(
            key_bundle, validator=shmac
        )

        padded_plaintext = b""
        async for digest, ciphertext_block in cipherstream:
            ciphertext.append(ciphertext_block)
            plaintext_chunk = await deciphering()
            await shmac.atest_current_digest(digest)
            padded_plaintext += plaintext_chunk

        assert b"example plaintext..." == await Padding.adepad_plaintext(
            padded_plaintext, key_bundle, ttl=60
        )
        """
        await asleep()
        payload = (
            Domains.DIGEST,
            self._auth_key,
            self._mac.digest(),
            self._last_digest,
        )
        return obj(b"".join(payload)).digest()

    def current_digest(
        self, *, obj: Typing.Union[sha3_256, sha3_512] = _type
    ):
        """
        Returns a secure digest that authenticates the ciphertext up to
        the current point of execution of the StreamHMAC algorithm. It
        incorporates the number of blocks of ciphertext blocks processed,
        the encoded key derived from the user's key, salt, & aad, as
        well as the hashing object's current & previous digest.

        Usage Example (Encryption): # when the `key` & `aad` are already
                                    # shared
        import aiootp
        from aiootp import gentools, StreamHMAC, KeyAADBundle

        def cipher_stream():
            plaintext_bytes = b"example plaintext..."
            aad = b"known associated data"
            key_bundle = KeyAADBundle(key, aad=aad).sync_mode()
            shmac = StreamHMAC(key_bundle).for_encryption()

            datastream = gentools.plaintext_stream(
                plaintext_bytes, key_bundle
            )
            cipherstream = datastream.bytes_encipher(key_bundle, shmac)

            first_ciphertext_block = cipherstream()
            yield key_bundle.salt, shmac.siv
            yield shmac.current_digest(), first_ciphertext_block
            for ciphertext_block in cipherstream:
                yield shmac.current_digest(), ciphertext_block


        Usage Example (Decryption): # when the `key` & `aad` are already
                                    # shared

        from collections import deque
        import aiootp
        from aiootp import gentools, StreamHMAC, KeyAADBundle, Padding

        cipherstream = cipher_stream()
        aad = b"known associated data"
        salt, siv = cipherstream.send(None)
        key_bundle = KeyAADBundle(key, salt=salt, aad=aad, siv=siv)
        shmac = StreamHMAC(key_bundle.sync_mode()).for_decryption()

        ciphertext = deque()
        deciphering = gentools.popleft(ciphertext).bytes_decipher(
            key_bundle, validator=shmac
        )

        padded_plaintext = b""
        for digest, ciphertext_block in cipherstream:
            ciphertext.append(ciphertext_block)
            plaintext_chunk = deciphering()
            shmac.test_current_digest(digest)
            padded_plaintext += plaintext_chunk

        assert b"example plaintext..." == Padding.depad_plaintext(
            padded_plaintext, key_bundle, ttl=60
        )
        """
        payload = (
            Domains.DIGEST,
            self._auth_key,
            self._mac.digest(),
            self._last_digest,
        )
        return obj(b"".join(payload)).digest()

    async def _aset_final_result(self):
        """
        Caps off the instance's validation hash object & populates the
        instance's final result with an HMAC of its state. This signals
        the end of a stream of data that can be validated with the
        current instance.
        """
        key = Domains.SHMAC + self._auth_key
        await self._aupdate(key)
        payload = self._last_digest + self._mac.digest()
        self._result = hmac.new(key, payload, self._type).digest()

    def _set_final_result(self):
        """
        Caps off the instance's validation hash object & populates the
        instance's final result with an HMAC of its state. This signals
        the end of a stream of data that can be validated with the
        current instance.
        """
        key = Domains.SHMAC + self._auth_key
        self._update(key)
        payload = self._last_digest + self._mac.digest()
        self._result = hmac.new(key, payload, self._type).digest()

    async def afinalize(self):
        """
        Caps off the instance's validation hash object & populates the
        instance's final result with an HMAC of its state. This signals
        the end of a stream of data that can be validated with the
        current instance.
        """
        if self._finalized:
            raise SHMACIssue.already_finalized()
        self._finalized = True
        await self._aset_final_result()
        self._result_is_ready = True
        self._mac = DeletedAttribute(SHMACIssue.already_finalized)
        return self._result

    def finalize(self):
        """
        Caps off the instance's validation hash object & populates the
        instance's final result with an HMAC of its state. This signals
        the end of a stream of data that can be validated with the
        current instance.
        """
        if self._finalized:
            raise SHMACIssue.already_finalized()
        self._finalized = True
        self._set_final_result()
        self._result_is_ready = True
        self._mac = DeletedAttribute(SHMACIssue.already_finalized)
        return self._result

    async def aresult(self):
        """
        Returns the instance's final result which is the secure HMAC of
        the ciphertext that was processed through the instance.
        """
        if not self._result_is_ready:
            raise SHMACIssue.validation_incomplete()
        return self._result

    def result(self):
        """
        Returns the instance's final result which is the secure HMAC of
        the ciphertext that was processed through the instance.
        """
        if not self._result_is_ready:
            raise SHMACIssue.validation_incomplete()
        return self._result

    async def atest_next_block_id(
        self, untrusted_block_id: bytes, next_block: bytes
    ):
        """
        Does a timing-safe comparison of a supplied ``untrusted_block_id``
        with a derived block id of the supplied ``next_block`` chunk of
        ciphertext. Raises `ValueError` if the untrusted block id is
        invalid. These block id checks can detect out of order messages,
        or ciphertext forgeries, without altering the internal state.
        This allows for robust decryption of ciphertext streams &
        mitigates adversarial attempts to crash a communication channel.
        """
        if untrusted_block_id.__class__ is not bytes:
            raise Issue.value_must_be_type("untrusted_block_id", bytes)
        size = len(untrusted_block_id)
        block_id = await self.anext_block_id(next_block, size=size)
        if await abytes_are_equal(untrusted_block_id, block_id):
            return True
        else:
            raise Issue.invalid_value("next_block_id")

    def test_next_block_id(
        self, untrusted_block_id: bytes, next_block: bytes
    ):
        """
        Does a timing-safe comparison of a supplied ``untrusted_block_id``
        with a derived block id of the supplied ``next_block`` chunk of
        ciphertext. Raises `ValueError` if the untrusted block id is
        invalid. These block id checks can detect out of order messages,
        or ciphertext forgeries, without altering the internal state.
        This allows for robust decryption of ciphertext streams &
        mitigates adversarial attempts to crash a communication channel.
        """
        if untrusted_block_id.__class__ is not bytes:
            raise Issue.value_must_be_type("untrusted_block_id", bytes)
        size = len(untrusted_block_id)
        block_id = self.next_block_id(next_block, size=size)
        if bytes_are_equal(untrusted_block_id, block_id):
            return True
        else:
            raise Issue.invalid_value("next_block_id")

    async def atest_current_digest(self, untrusted_digest: bytes):
        """
        Does a time-safe comparison of a supplied ``untrusted_digest``
        with the output of the instance's current digest of an
        unfinished stream of ciphertext. Raises `ValueError` if the
        instance's current digest doesn't match.
        """
        if untrusted_digest.__class__ is not bytes:
            raise Issue.value_must_be_type("untrusted_digest", bytes)
        if await abytes_are_equal(
            untrusted_digest, await self.acurrent_digest()
        ):
            return True
        else:
            raise Issue.invalid_value("current_digest")

    def test_current_digest(self, untrusted_digest: bytes):
        """
        Does a time-safe comparison of a supplied ``untrusted_digest``
        with the output of the instance's current digest of an
        unfinished stream of ciphertext. Raises `ValueError` if the
        instance's current digest doesn't match.
        """
        if untrusted_digest.__class__ is not bytes:
            raise Issue.value_must_be_type("untrusted_digest", bytes)
        if bytes_are_equal(untrusted_digest, self.current_digest()):
            return True
        else:
            raise Issue.invalid_value("current_digest")

    async def atest_hmac(self, untrusted_hmac: bytes):
        """
        Does a time-safe comparison of a supplied ``untrusted_hmac``
        with the instance's final result hmac. Raises `ValueError` if
        the hmac doesn't match.
        """
        if untrusted_hmac.__class__ is not bytes:
            raise Issue.value_must_be_type("untrusted_hmac", bytes)
        elif await abytes_are_equal(untrusted_hmac, await self.aresult()):
            return True
        else:
            raise Issue.invalid_value("HMAC of data stream")

    def test_hmac(self, untrusted_hmac: bytes):
        """
        Does a time-safe comparison of a supplied ``untrusted_hmac``
        with the instance's final result hmac. Raises `ValueError` if
        the hmac doesn't match.
        """
        if untrusted_hmac.__class__ is not bytes:
            raise Issue.value_must_be_type("untrusted_hmac", bytes)
        elif bytes_are_equal(untrusted_hmac, self.result()):
            return True
        else:
            raise Issue.invalid_value("HMAC of data stream")


class SyntheticIV:
    """
    Manages the derivation & application of synthetic IVs which improve
    the salt reuse / misuse resistance of the package's online AEAD
    cipher. This class is handled automatically within the `(a)bytes_xor`
    generators & the `StreamHMAC` class. The required plaintext padding
    is handled within the `Padding` class.
    """

    _BLOCKSIZE: int = BLOCKSIZE
    _DECRYPTION: str = DECRYPTION
    _ENCRYPTION: str = ENCRYPTION
    _SIV_BYTES: str = SIV_BYTES
    _SIV_NIBBLES: int = SIV_NIBBLES
    _SIV_KEY_BYTES: int = SIV_KEY_BYTES
    _SIV_KEY_NIBBLES: int = SIV_KEY_NIBBLES

    @classmethod
    async def amake_siv(cls, plaintext_block: bytes, validator: StreamHMAC):
        """
        Returns a 24-byte, truncated keyed-hash of a plaintext block to
        be used as a synthetic IV to improve the salt reuse / misuse
        resistance of a stream of key material.
        """
        await asleep()
        payload = (
            Domains.SIV,
            Domains.SIV_KEY,
            validator._auth_key,
            validator._mac.digest(),
            plaintext_block,
        )
        return sha3_256(b"".join(payload)).digest()[: cls._SIV_BYTES]

    @classmethod
    def make_siv(cls, plaintext_block: bytes, validator: StreamHMAC):
        """
        Returns a 24-byte, truncated keyed-hash of a plaintext block to
        be used as a synthetic IV to improve the salt reuse / misuse
        resistance of a stream of key material.
        """
        payload = (
            Domains.SIV,
            Domains.SIV_KEY,
            validator._auth_key,
            validator._mac.digest(),
            plaintext_block,
        )
        return sha3_256(b"".join(payload)).digest()[: cls._SIV_BYTES]

    @classmethod
    async def avalidated_xor(
        cls,
        datastream: Typing.AsyncDatastream,
        keystream: Typing.Callable,
        validator: StreamHMAC,
    ):
        """
        Derives the synthetic IV from the beginning of the plaintext &
        seeds it into both the keystream & the validator.

        This method ciphers/deciphers the first block of plaintext/
        ciphertext depending on whether the validator has been set to
        encryption or decryption modes. It feeds a syncthetic IV value,
        which is derived from the keyed-hash of the first block of
        plaintext & is attached to the ciphertext, into the keystream
        coroutine prior to xoring the first block. This improves the
        cipher's salt reuse/misuse resistance since if either the first
        232 bytes of plaintext are unique, or the 24-byte inner header
        is unique, then the entire stream of key material will be unique.
        The inner header is prepended to the first plaintext block, &
        consists of an 8-byte timestamp & a 16-byte random & ephemeral
        SIV-key. This inner header is applied during message padding
        from within the `Padding` class.
        """
        try:
            first_block = await datastream.asend(None)
        except StopAsyncIteration:
            raise Issue.stream_is_empty()
        if validator.mode == cls._ENCRYPTION:
            siv = await cls.amake_siv(first_block, validator)
            validator.siv = siv
        else:
            siv = validator.siv
        key_chunk = await keystream(siv) + await keystream(siv)
        return await validator._avalidated_xor(first_block, key_chunk)

    @classmethod
    def validated_xor(
        cls,
        datastream: Typing.Datastream,
        keystream: Typing.Callable,
        validator: StreamHMAC,
    ):
        """
        Derives the synthetic IV from the beginning of the plaintext &
        seeds it into both the keystream & the validator.

        This method ciphers/deciphers the first block of plaintext/
        ciphertext depending on whether the validator has been set to
        encryption or decryption modes. It feeds a syncthetic IV value,
        which is derived from the keyed-hash of the first block of
        plaintext & is attached to the ciphertext, into the keystream
        coroutine prior to xoring the first block. This improves the
        cipher's salt reuse/misuse resistance since if either the first
        232 bytes of plaintext are unique, or the 24-byte inner header
        is unique, then the entire stream of key material will be unique.
        The inner header is prepended to the first plaintext block, &
        consists of an 8-byte timestamp & a 16-byte random & ephemeral
        SIV-key. This inner header is applied during message padding
        from within the `Padding` class.
        """
        try:
            first_block = datastream.send(None)
        except StopIteration:
            raise Issue.stream_is_empty()
        if validator.mode == cls._ENCRYPTION:
            siv = validator.siv = cls.make_siv(first_block, validator)
        else:
            siv = validator.siv
        key_chunk = keystream(siv) + keystream(siv)
        return validator._validated_xor(first_block, key_chunk)


async def _axor_shortcuts(
    data: Typing.AsyncOrSyncDatastream,
    key: Typing.AsyncKeystream,
    validator: StreamHMAC,
):
    """
    Returns a series of function pointers that allow their efficient use
    within the `Chunky2048` cipher's low-level xor generators. This is
    done to improve readability & the efficiency of the cipher's
    execution time.
    """
    if not hasattr(data, "asend"):
        data = aunpack.root(data)
    return (
        data,
        key.asend,
        validator._avalidated_xor,
        validator._mac.digest,
    )


def _xor_shortcuts(
    data: Typing.Datastream,
    key: Typing.Keystream,
    validator: StreamHMAC,
):
    """
    Returns a series of function pointers that allow their efficient use
    within the `Chunky2048` cipher's low-level xor generators. This is
    done to improve readability & the efficiency of the cipher's
    execution time.
    """
    if not hasattr(data, "send"):
        data = unpack.root(data)
    return (
        data,
        key.send,
        validator._validated_xor,
        validator._mac.digest,
    )


@comprehension()
async def abytes_xor(
    data: Typing.AsyncOrSyncDatastream,
    *,
    key: Typing.AsyncKeystream,
    validator: StreamHMAC,
):
    """
    `Chunky2048` - an online MRAE / AEAD pseudo one-time pad cipher
    implementation.

    Gathers both an iterable of 256-byte blocks of ``data``, & a
    non-repeating generator of deterministic bytes ``key`` material,
    then bitwise xors the streams together, producing `Chunky2048`
    ciphertext or plaintext chunks 256 bytes long. The keystream MUST
    produce 128-bytes of key material each iteration, as each output is
    paired with another to reach exactly 256 pseudo-random bytes for
    each block.

    Restricting the ciphertext to a distinct size is a measure to
    protect the metadata of plaintext from adversaries that could make
    informed guesses of the plaintext given accurate sizes of its
    chunks.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes or
    less per iteration or security WILL BE BROKEN by directly leaking
    plaintext. The plaintext MUST be padded using the `Padding` class in
    order to add salt reuse / misuse resistance (MRAE) to the cipher.

    WARNING: ``key`` MUST produce key chunks of exactly 128 bytes per
    iteration or security WILL BE BROKEN by directly leaking plaintext.
    """
    datastream, keystream, validated_xor, shmac_digest = (
        await _axor_shortcuts(data, key, validator)
    )
    yield await SyntheticIV.avalidated_xor(datastream, keystream, validator)
    async for block in datastream:
        seed = shmac_digest()
        key_chunk = await keystream(seed) + await keystream(seed)
        yield await validated_xor(block, key_chunk)


@comprehension()
def bytes_xor(
    data: Typing.Datastream,
    *,
    key: Typing.Keystream,
    validator: StreamHMAC,
):
    """
    `Chunky2048` - an online MRAE / AEAD pseudo one-time pad cipher
    implementation.

    Gathers both an iterable of 256-byte blocks of ``data``, & a
    non-repeating generator of deterministic bytes ``key`` material,
    then bitwise xors the streams together, producing `Chunky2048`
    ciphertext or plaintext chunks 256 bytes long. The keystream MUST
    produce 128-bytes of key material each iteration, as each output is
    paired with another to reach exactly 256 pseudo-random bytes for
    each block.

    Restricting the ciphertext to a distinct size is a measure to
    protect the metadata of plaintext from adversaries that could make
    informed guesses of the plaintext given accurate sizes of its
    chunks.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes or
    less per iteration or security WILL BE BROKEN by directly leaking
    plaintext. The plaintext MUST be padded using the `Padding` class in
    order to add salt reuse / misuse resistance (MRAE) to the cipher.

    WARNING: ``key`` MUST produce key chunks of exactly 128 bytes per
    iteration or security WILL BE BROKEN by directly leaking plaintext.
    """
    datastream, keystream, validated_xor, shmac_digest = _xor_shortcuts(
        data, key, validator
    )
    yield SyntheticIV.validated_xor(datastream, keystream, validator)
    for block in datastream:
        seed = shmac_digest()
        key_chunk = keystream(seed) + keystream(seed)
        yield validated_xor(block, key_chunk)


@comprehension()
async def aplaintext_stream(data: bytes, key_bundle: KeyAADBundle):
    """
    Takes in plaintext bytes ``data``, then pads & yields it in 256-byte
    chunks per iteration. The plaintext padding is done in two separate
    ways:
        First, an 8-byte timestamp & a 16-byte ephemeral SIV-key are
    prepended to the plaintext. This makes the first block, & the SIV
    which is derived from it, globally unique. This allows the cipher to
    be both online & be strongly salt-reuse/misuse resistant, counter to
    the findings in https://eprint.iacr.org/2015/189.pdf.
        Second, the `key`, `salt` & `aad` that are stored in the
    ``key_bundle`` are used to derive 32 pseudo-random padding bytes
    which are appended to the plaintext. Then random padding bytes are
    appended to make the resulting plaintext a multiple of the 256-byte
    blocksize. The details can be found in the `Padding` class.
    """
    plaintext = await Padding.apad_plaintext(data, key_bundle)
    async for block in adata.root(plaintext):
        yield block


@comprehension()
def plaintext_stream(data: bytes, key_bundle: KeyAADBundle):
    """
    Takes in plaintext bytes ``data``, then pads & yields it in 256-byte
    chunks per iteration. The plaintext padding is done in two separate
    ways:
        First, an 8-byte timestamp & a 16-byte ephemeral SIV-key are
    prepended to the plaintext. This makes the first block, & the SIV
    which is derived from it, globally unique. This allows the cipher to
    be both online & be strongly salt-reuse/misuse resistant, counter to
    the findings in https://eprint.iacr.org/2015/189.pdf.
        Second, the `key`, `salt` & `aad` that are stored in the
    ``key_bundle`` are used to derive 32 pseudo-random padding bytes
    which are appended to the plaintext. Then random padding bytes are
    appended to make the resulting plaintext a multiple of the 256-byte
    blocksize. The details can be found in the `Padding` class.
    """
    plaintext = Padding.pad_plaintext(data, key_bundle)
    yield from gentools.data.root(plaintext)


def abytes_encipher(
    data: Typing.AsyncOrSyncDatastream,
    key_bundle: KeyAADBundle,
    validator: StreamHMAC,
):
    """
    A low-level function which returns an async generator that runs this
    package's online MRAE / AEAD `Chunky2048` cipher.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes
    or less per iteration or security WILL BE BROKEN by directly
    leaking plaintext. The plaintext MUST also be padded using the
    `Padding` class in order to add salt reuse / misuse resistance
    (MRAE) to the cipher.

    WARNING: The generator does not provide authentication of the
    ciphertexts or associated data it handles. Nor does it do any
    message padding or sufficient checking of inputs for adequacy. Those
    are functionalities which must be obtained through other means. Just
    passing in a ``validator`` will not authenticate ciphertext
    itself. The `finalize` or `afinalize` methods must be called on
    the ``validator`` once all of the cipehrtext has been created /
    decrypted. Then the final HMAC is available from the `aresult`
    & `result` methods, & can be tested against untrusted HMACs
    with the `atest_hmac` & `test_hmac` methods. The validator also
    has `(a)current_digest` & `(a)next_block_id` methods that can be
    used to authenticate unfinished streams of cipehrtext.
    """
    if validator.mode != ENCRYPTION:
        raise Issue.must_set_value("validator", ENCRYPTION)
    elif not issubclass(key_bundle.__class__, KeyAADBundle):
        raise Issue.value_must_be_type("key_bundle", KeyAADBundle)
    elif key_bundle._mode != ASYNC:
        raise KeyAADIssue.mode_isnt_correct(ASYNC)
    return abytes_xor.root(
        data, key=key_bundle._keystream, validator=validator
    )


def bytes_encipher(
    data: Typing.Datastream,
    key_bundle: KeyAADBundle,
    validator: StreamHMAC,
):
    """
    A low-level function which returns a generator that runs this
    package's online MRAE / AEAD `Chunky2048` cipher.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes
    or less per iteration or security WILL BE BROKEN by directly
    leaking plaintext. The plaintext MUST also be padded using the
    `Padding` class in order to add salt reuse / misuse resistance
    (MRAE) to the cipher.

    WARNING: The generator does not provide authentication of the
    ciphertexts or associated data it handles. Nor does it do any
    message padding or sufficient checking of inputs for adequacy. Those
    are functionalities which must be obtained through other means. Just
    passing in a ``validator`` will not authenticate ciphertext
    itself. The `finalize` or `afinalize` methods must be called on
    the ``validator`` once all of the cipehrtext has been created /
    decrypted. Then the final HMAC is available from the `aresult`
    & `result` methods, & can be tested against untrusted HMACs
    with the `atest_hmac` & `test_hmac` methods. The validator also
    has `(a)current_digest` & `(a)next_block_id` methods that can be
    used to authenticate unfinished streams of cipehrtext.
    """
    if validator.mode != ENCRYPTION:
        raise Issue.must_set_value("validator", ENCRYPTION)
    elif not issubclass(key_bundle.__class__, KeyAADBundle):
        raise Issue.value_must_be_type("key_bundle", KeyAADBundle)
    elif key_bundle._mode != SYNC:
        raise KeyAADIssue.mode_isnt_correct(SYNC)
    return bytes_xor.root(
        data, key=key_bundle._keystream, validator=validator
    )


def abytes_decipher(
    data: Typing.AsyncOrSyncDatastream,
    key_bundle: KeyAADBundle,
    validator: StreamHMAC,
):
    """
    A low-level function which returns an async generator that runs this
    package's online MRAE / AEAD `Chunky2048` cipher.

    WARNING: The generator does not provide authentication of the
    ciphertexts or associated data it handles. Nor does it do any
    message padding or sufficient checking of inputs for adequacy. Those
    are functionalities which must be obtained through other means. Just
    passing in a ``validator`` will not authenticate ciphertext
    itself. The `finalize` or `afinalize` methods must be called on
    the ``validator`` once all of the cipehrtext has been created /
    decrypted. Then the final HMAC is available from the `aresult`
    & `result` methods, & can be tested against untrusted HMACs
    with the `atest_hmac` & `test_hmac` methods. The validator also
    has `(a)current_digest` & `(a)next_block_id` methods that can be
    used to authenticate unfinished streams of cipehrtext.
    """
    if validator.mode != DECRYPTION:
        raise Issue.must_set_value("validator", DECRYPTION)
    elif not issubclass(key_bundle.__class__, KeyAADBundle):
        raise Issue.value_must_be_type("key_bundle", KeyAADBundle)
    elif key_bundle._mode != ASYNC:
        raise KeyAADIssue.mode_isnt_correct(ASYNC)
    return abytes_xor.root(
        data, key=key_bundle._keystream, validator=validator
    )


def bytes_decipher(
    data: Typing.Datastream,
    key_bundle: KeyAADBundle,
    validator: StreamHMAC,
):
    """
    A low-level function which returns a generator that runs this
    package's online MRAE / AEAD `Chunky2048` cipher.

    WARNING: The generator does not provide authentication of the
    ciphertexts or associated data it handles. Nor does it do any
    message padding or sufficient checking of inputs for adequacy. Those
    are functionalities which must be obtained through other means. Just
    passing in a ``validator`` will not authenticate ciphertext
    itself. The `finalize` or `afinalize` methods must be called on
    the ``validator`` once all of the cipehrtext has been created /
    decrypted. Then the final HMAC is available from the `aresult`
    & `result` methods, & can be tested against untrusted HMACs
    with the `atest_hmac` & `test_hmac` methods. The validator also
    has `(a)current_digest` & `(a)next_block_id` methods that can be
    used to authenticate unfinished streams of cipehrtext.
    """
    if validator.mode != DECRYPTION:
        raise Issue.must_set_value("validator", DECRYPTION)
    elif not issubclass(key_bundle.__class__, KeyAADBundle):
        raise Issue.value_must_be_type("key_bundle", KeyAADBundle)
    elif key_bundle._mode != SYNC:
        raise KeyAADIssue.mode_isnt_correct(SYNC)
    return bytes_xor.root(
        data, key=key_bundle._keystream, validator=validator
    )


async def ajson_encrypt(
    data: Typing.JSONSerializable,
    key: bytes,
    *,
    salt: Typing.Optional[bytes] = None,
    aad: bytes = b"aad",
):
    """
    A high-level public interface to the package's MRAE / AEAD
    `Chunky2048` cipher.

    Returns the `Chunky2048` ciphertext of any JSON serializable ``data``.
    The returned bytes contain the ephemeral 24-byte salt, a 24-byte SIV,
    & a 32-byte HMAC used to verify the integrity & authenticity of the
    ciphertext & the values used to create it.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.
    ``salt``: An ephemeral, random 24-byte value that MUST BE USED ONLY
            ONCE for each encryption. This value is sent in the clear
            along with the ciphertext.
    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of ``key`` & ``salt``.
    """
    return await abytes_encrypt(
        json.dumps(data).encode(), key=key, salt=salt, aad=aad
    )


def json_encrypt(
    data: Typing.JSONSerializable,
    key: bytes,
    *,
    salt: Typing.Optional[bytes] = None,
    aad: bytes = b"aad",
):
    """
    A high-level public interface to the package's MRAE / AEAD
    `Chunky2048` cipher.

    Returns the `Chunky2048` ciphertext of any JSON serializable ``data``.
    The returned bytes contain the ephemeral 24-byte salt, a 24-byte SIV,
    & a 32-byte HMAC used to verify the integrity & authenticity of the
    ciphertext & the values used to create it.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.
    ``salt``: An ephemeral, random 24-byte value that MUST BE USED ONLY
            ONCE for each encryption. This value is sent in the clear
            along with the ciphertext.
    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of ``key`` & ``salt``.
    """
    return bytes_encrypt(
        json.dumps(data).encode(), key=key, salt=salt, aad=aad
    )


async def ajson_decrypt(
    data: bytes, key: bytes, *, aad: bytes = b"aad", ttl: int = 0
):
    """
    A high-level public interface to the package's MRAE / AEAD
    `Chunky2048` cipher.

    Returns the loaded plaintext JSON object from the bytes ciphertext
    ``data``. The ``data`` bytes contain a 24-byte ephemeral salt, a
    24-byte SIV & a 32-byte HMAC used to verify the integrity &
    authenticity of the ciphertext & the values used to create it.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.
    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of ``key`` & ``salt``.
    ``ttl``: An amount of seconds that dictate the allowable age of
            the decrypted message.
    """
    return json.loads(await abytes_decrypt(data, key=key, aad=aad, ttl=ttl))


def json_decrypt(
    data: bytes, key: bytes, *, aad: bytes = b"aad", ttl: int = 0
):
    """
    A high-level public interface to the package's MRAE / AEAD
    `Chunky2048` cipher.

    Returns the loaded plaintext JSON object from the bytes ciphertext
    ``data``. The ``data`` bytes contain a 24-byte ephemeral salt, a
    24-byte SIV & a 32-byte HMAC used to verify the integrity &
    authenticity of the ciphertext & the values used to create it.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.
    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of ``key`` & ``salt``.
    ``ttl``: An amount of seconds that dictate the allowable age of
            the decrypted message.
    """
    return json.loads(bytes_decrypt(data, key=key, aad=aad, ttl=ttl))


async def abytes_encrypt(
    data: bytes,
    key: bytes,
    *,
    salt: Typing.Optional[bytes] = None,
    aad: bytes = b"aad",
):
    """
    A high-level public interface to the package's MRAE / AEAD
    `Chunky2048` cipher.

    Returns the `Chunky2048` ciphertext of any bytes type ``data``. The
    returned bytes contain the ephemeral 24-byte salt, a 24-byte SIV, &
    a 32-byte HMAC used to verify the integrity & authenticity of the
    ciphertext & the values used to create it.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.
    ``salt``: An ephemeral, random 24-byte value that MUST BE USED ONLY
            ONCE for each encryption. This value is sent in the clear
            along with the ciphertext.
    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of ``key`` & ``salt``.
    """
    key_bundle = await KeyAADBundle(
        key=key, salt=salt, aad=aad, allow_dangerous_determinism=True
    ).async_mode()
    shmac = StreamHMAC(key_bundle).for_encryption()
    data = aplaintext_stream.root(data, key_bundle)
    ciphering = abytes_encipher(data, key_bundle, shmac)
    ciphertext = (
        b"".join([block async for block in ciphering]),
        shmac.siv,
        key_bundle.salt,
        await shmac.afinalize(),
    )
    return b"".join(ciphertext[::-1])


def bytes_encrypt(
    data: bytes,
    key: bytes,
    *,
    salt: Typing.Optional[bytes] = None,
    aad: bytes = b"aad",
):
    """
    A high-level public interface to the package's MRAE / AEAD
    `Chunky2048` cipher.

    Returns the `Chunky2048` ciphertext of any bytes type ``data``. The
    returned bytes contain the ephemeral 24-byte salt, a 24-byte SIV, &
    a 32-byte HMAC used to verify the integrity & authenticity of the
    ciphertext & the values used to create it.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.
    ``salt``: An ephemeral, random 24-byte value that MUST BE USED ONLY
            ONCE for each encryption. This value is sent in the clear
            along with the ciphertext.
    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of ``key`` & ``salt``.
    """
    key_bundle = KeyAADBundle(
        key=key, salt=salt, aad=aad, allow_dangerous_determinism=True
    ).sync_mode()
    shmac = StreamHMAC(key_bundle).for_encryption()
    data = plaintext_stream.root(data, key_bundle)
    ciphertext = (
        b"".join(bytes_encipher(data, key_bundle, shmac)),
        shmac.siv,
        key_bundle.salt,
        shmac.finalize(),
    )
    return b"".join(ciphertext[::-1])


async def abytes_decrypt(
    data: bytes, key: bytes, *, aad: bytes = b"aad", ttl: int = 0
):
    """
    A high-level public interface to the package's MRAE / AEAD
    `Chunky2048` cipher.

    Returns the plaintext bytes from the bytes ciphertext ``data``. The
    ``data`` bytes contain a 24-byte ephemeral salt, a 24-byte SIV & a
    32-byte HMAC used to verify the integrity & authenticity of the
    ciphertext & the values used to create it.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.
    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of ``key`` & ``salt``.
    ``ttl``: An amount of seconds that dictate the allowable age of
            the decrypted message.
    """
    data = Ciphertext(data)
    key_bundle = await KeyAADBundle(
        key=key, salt=data.salt, aad=aad, siv=data.synthetic_iv
    ).async_mode()
    shmac = StreamHMAC(key_bundle).for_decryption()
    ciphertext = adata.root(data.ciphertext)
    deciphering = abytes_decipher(ciphertext, key_bundle, shmac)
    plaintext = b"".join([block async for block in deciphering])
    await shmac.afinalize()
    await shmac.atest_hmac(data.hmac)
    return await Padding.adepad_plaintext(plaintext, key_bundle, ttl=ttl)


def bytes_decrypt(
    data: bytes, key: bytes, *, aad: bytes = b"aad", ttl: int = 0
):
    """
    A high-level public interface to the package's MRAE / AEAD
    `Chunky2048` cipher.

    Returns the plaintext bytes from the bytes ciphertext ``data``. The
    ``data`` bytes contain a 24-byte ephemeral salt, a 24-byte SIV & a
    32-byte HMAC used to verify the integrity & authenticity of the
    ciphertext & the values used to create it.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.
    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of ``key`` & ``salt``.
    ``ttl``: An amount of seconds that dictate the allowable age of
            the decrypted message.
    """
    data = Ciphertext(data)
    key_bundle = KeyAADBundle(
        key=key, salt=data.salt, aad=aad, siv=data.synthetic_iv
    ).sync_mode()
    shmac = StreamHMAC(key_bundle).for_decryption()
    ciphertext = gentools.data.root(data.ciphertext)
    plaintext = b"".join(bytes_decipher(ciphertext, key_bundle, shmac))
    shmac.finalize()
    shmac.test_hmac(data.hmac)
    return Padding.depad_plaintext(plaintext, key_bundle, ttl=ttl)


class Chunky2048:
    """
    An efficient high-level public interface to the package's online
    MRAE / AEAD pseudo one-time pad cipher implementation. This
    implementation is built primarily out of async & sync generators as
    data processing pipelines & communication coroutines.

    key = aiootp.csprng()
    cipher = aiootp.Chunky2048(key)

    encrypted = cipher.bytes_encrypt(b"binary data")
    assert isinstance(encrypted, bytes)
    decrypted = cipher.bytes_decrypt(encrypted)
    assert decrypted == b"binary data"

    encrypted = cipher.json_encrypt({"any": "JSON serializable object"})
    assert isinstance(encrypted, bytes)
    decrypted = cipher.json_decrypt(encrypted)
    assert decrypted == {"any": "JSON serializable object"}

    # Encrypted & authenticated urlsafe tokens can be created too ->
    token = cipher.make_token(b"binary data")
    print(token)
    b'''KGqiGdVlTI7AjiA3KS9BCNw5JE-Vr57D2a9P_330HvmPK9e5YFkX4pJ19mYqb_f5
    u9z__ZtUoS9m7OYqZmoFB6zwaDvIQXXc9qY7VzATEHxyyjGFlTW-hKq08ma8-Dkzcx'x
    YtgC7xPOu_wax6HtX_3nCFuV27OPp6mivfhKv3nXEVG_vdayBNW0AeeEvB0jhXubo_u9
    41JY_Egif3Dl3GemrPcGuPhYyWNO19tfypqZIAt2GmsBVm-k9dZTvNqcn5fRptCSvGuQ
    PC5AemvzJvUFZWvzOLnBTEUdMy6gXOwnVI-CrGpHzeUqTEwAldyn9R-H15YvcRaUQQuJ
    eRm_lo_f7eEHJtPXt9M84U7r6tjDpNajMnGG-MRbyWmYCpBXH0dx4Myuh9MfDA9F43Mz
    0vT2DAuWaFYRO-yPkRGk3NmTbAEGgV_o_L7LO0bE4aLka'''
    assert b"binary data" == cipher.read_token(token)
    """

    __slots__ = ("_key",)

    _CONSTANTS = chunky2048_constants
    _IO = BytesIO

    def __init__(self, key: Typing.Optional[bytes] = None):
        """
        Creates an efficient object which manages a main encryption key
        for use in the `Chunky2048` cipher.
        """
        self._key = key if key else csprng()

    @property
    def key(self):
        """
        Returns the instance's main symmetric key.
        """
        return self._key

    async def ajson_encrypt(
        self,
        data: Typing.JSONSerializable,
        *,
        salt: Typing.Optional[bytes] = None,
        aad: bytes = b"aad",
    ):
        """
        A high-level public interface to the package's MRAE / AEAD
        `Chunky2048` cipher.

        ``salt`` is a uniform & ephemeral 24-byte value. ``aad`` is
        authenticated associated data which also permutes the cipher's
        internal derived keys.
        """
        return await ajson_encrypt(data, key=self.key, salt=salt, aad=aad)

    def json_encrypt(
        self,
        data: Typing.JSONSerializable,
        *,
        salt: Typing.Optional[bytes] = None,
        aad: bytes = b"aad",
    ):
        """
        A high-level public interface to the package's MRAE / AEAD
        `Chunky2048` cipher.

        ``salt`` is a uniform & ephemeral 24-byte value. ``aad`` is
        authenticated associated data which also permutes the cipher's
        internal derived keys.
        """
        return json_encrypt(data, key=self.key, salt=salt, aad=aad)

    async def ajson_decrypt(
        self, data: bytes, *, aad: bytes = b"aad", ttl: int = 0
    ):
        """
        A high-level public interface to the package's MRAE / AEAD
        `Chunky2048` cipher.

        ``ttl`` is the maximum age of a ciphertext, in seconds, that'll
        be allowed during validation. The age in measured from a
        timestamp that is removed from the plaintext data. ``aad`` is
        authenticated associated data which also permutes the cipher's
        internal derived keys.
        """
        return await ajson_decrypt(data, key=self.key, aad=aad, ttl=ttl)

    def json_decrypt(
        self, data: bytes, *, aad: bytes = b"aad", ttl: int = 0
    ):
        """
        A high-level public interface to the package's MRAE / AEAD
        `Chunky2048` cipher.

        ``ttl`` is the maximum age of a ciphertext, in seconds, that'll
        be allowed during validation. The age in measured from a
        timestamp that is removed from the plaintext data. ``aad`` is
        authenticated associated data which also permutes the cipher's
        internal derived keys.
        """
        return json_decrypt(data, key=self.key, aad=aad, ttl=ttl)

    async def abytes_encrypt(
        self,
        data: bytes,
        *,
        salt: Typing.Optional[bytes] = None,
        aad: bytes = b"aad",
    ):
        """
        A high-level public interface to the package's MRAE / AEAD
        `Chunky2048` cipher.

        ``salt`` is a uniform & ephemeral 24-byte value. ``aad`` is
        authenticated associated data which also permutes the cipher's
        internal derived keys.
        """
        return await abytes_encrypt(data, key=self.key, salt=salt, aad=aad)

    def bytes_encrypt(
        self,
        data: bytes,
        *,
        salt: Typing.Optional[bytes] = None,
        aad: bytes = b"aad",
    ):
        """
        A high-level public interface to the package's MRAE / AEAD
        `Chunky2048` cipher.

        ``salt`` is a uniform & ephemeral 24-byte value. ``aad`` is
        authenticated associated data which also permutes the cipher's
        internal derived keys.
        """
        return bytes_encrypt(data, key=self.key, salt=salt, aad=aad)

    async def abytes_decrypt(
        self, data: bytes, *, aad: bytes = b"aad", ttl: int = 0
    ):
        """
        A high-level public interface to the package's MRAE / AEAD
        `Chunky2048` cipher.

        ``ttl`` is the maximum age of a ciphertext, in seconds, that'll
        be allowed during validation. The age in measured from a
        timestamp that is removed from the plaintext data. ``aad`` is
        authenticated associated data which also permutes the  cipher's
        internal derived keys.
        """
        return await abytes_decrypt(data, key=self.key, aad=aad, ttl=ttl)

    def bytes_decrypt(
        self, data: bytes, *, aad: bytes = b"aad", ttl: int = 0
    ):
        """
        A high-level public interface to the package's MRAE / AEAD
        `Chunky2048` cipher.

        ``ttl`` is the maximum age of a ciphertext, in seconds, that'll
        be allowed during validation. The age in measured from a
        timestamp that is removed from the plaintext data. ``aad`` is
        authenticated associated data which also permutes the  cipher's
        internal derived keys.
        """
        return bytes_decrypt(data, key=self.key, aad=aad, ttl=ttl)

    async def amake_token(self, data: bytes, *, aad: bytes = b"aad"):
        """
        A high-level public interface to the package's MRAE / AEAD
        `Chunky2048` cipher.

        Encrypts ``data`` with the instance key & returns a urlsafe
        encoded ciphertext token. ``aad`` is authenticated associated
        data which also permutes the cipher's internal derived keys.
        """
        if data.__class__ is not bytes:
            raise Issue.value_must_be_type("plaintext ``data``", bytes)
        ciphertext = await self.abytes_encrypt(data, aad=aad)
        return await self._IO.abytes_to_urlsafe(ciphertext)

    def make_token(self, data: bytes, *, aad: bytes = b"aad"):
        """
        A high-level public interface to the package's MRAE / AEAD
        `Chunky2048` cipher.

        Encrypts ``data`` with the instance key & returns a urlsafe
        encoded ciphertext token. ``aad`` is authenticated associated
        data which also permutes the cipher's internal derived keys.
        """
        if data.__class__ is not bytes:
            raise Issue.value_must_be_type("plaintext ``data``", bytes)
        ciphertext = self.bytes_encrypt(data, aad=aad)
        return self._IO.bytes_to_urlsafe(ciphertext)

    async def aread_token(
        self,
        token: Typing.Base64URLSafe,
        *,
        aad: bytes = b"aad",
        ttl: int = 0,
    ):
        """
        A high-level public interface to the package's MRAE / AEAD
        `Chunky2048` cipher.

        Decodes a ciphertext token & returns the decrypted token data.
        ``ttl`` is the maximum age of a token, in seconds, that will
        be allowed during the token's validation. The age in measured
        from a timestamp that is removed from the plaintext token data.
        ``aad`` is authenticated associated data which also permutes the
        cipher's internal derived keys.
        """
        if token.__class__ is not bytes:
            token = token.encode()
        ciphertext = await self._IO.aurlsafe_to_bytes(token)
        return await self.abytes_decrypt(ciphertext, aad=aad, ttl=ttl)

    def read_token(
        self,
        token: Typing.Base64URLSafe,
        *,
        aad: bytes = b"aad",
        ttl: int = 0,
    ):
        """
        A high-level public interface to the package's MRAE / AEAD
        `Chunky2048` cipher.

        Decodes a ciphertext token & returns the decrypted token data.
        ``ttl`` is the maximum age of a token, in seconds, that will
        be allowed during the token's validation. The age in measured
        from a timestamp that is removed from the plaintext token data.
        ``aad`` is authenticated associated data which also permutes the
        cipher's internal derived keys.
        """
        if token.__class__ is not bytes:
            token = token.encode()
        ciphertext = self._IO.urlsafe_to_bytes(token)
        return self.bytes_decrypt(ciphertext, aad=aad, ttl=ttl)

    @comprehension(chained=True)
    async def _abytes_encipher(
        self: Comprende, key_bundle: KeyAADBundle, validator: StreamHMAC
    ):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        this package's online MRAE / AEAD `Chunky2048` cipher.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all generators that
        are decorated with `comprehension` can encrypt valid plaintext
        byte streams.

        WARNING: ``self`` MUST produce plaintext in chunks of 256 bytes
        or less per iteration or security WILL BE BROKEN by directly
        leaking plaintext. The plaintext MUST also be padded using the
        `Padding` class in order to add salt reuse / misuse resistance
        (MRAE) to the cipher.

        WARNING: The generator does not provide authentication of the
        ciphertexts or associated data it handles. Nor does it do any
        message padding or sufficient checking of inputs for adequacy.
        Those are functionalities which must be obtained through other
        means. Just passing in a ``validator`` will not authenticate
        ciphertext itself. The `finalize` or `afinalize` methods must be
        called on the ``validator`` once all of the cipehrtext has been
        created / decrypted. Then the final HMAC is available from the
        `aresult` & `result` methods, & can be tested against untrusted
        HMACs with the `atest_hmac` & `test_hmac` methods. The validator
        also has `(a)current_digest` & `(a)next_block_id` methods that
        can be used to authenticate unfinished streams of cipehrtext.
        """
        async for block in abytes_encipher(
            data=self, key_bundle=key_bundle, validator=validator
        ):
            yield block

    @comprehension(chained=True)
    def _bytes_encipher(
        self: Comprende, key_bundle: KeyAADBundle, validator: StreamHMAC
    ):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        this package's online MRAE / AEAD `Chunky2048` cipher.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all generators that
        are decorated with `comprehension` can encrypt valid plaintext
        byte streams.

        WARNING: ``self`` MUST produce plaintext in chunks of 256 bytes
        or less per iteration or security WILL BE BROKEN by directly
        leaking plaintext. The plaintext MUST also be padded using the
        `Padding` class in order to add salt reuse / misuse resistance
        (MRAE) to the cipher.

        WARNING: The generator does not provide authentication of the
        ciphertexts or associated data it handles. Nor does it do any
        message padding or sufficient checking of inputs for adequacy.
        Those are functionalities which must be obtained through other
        means. Just passing in a ``validator`` will not authenticate
        ciphertext itself. The `finalize` or `afinalize` methods must be
        called on the ``validator`` once all of the cipehrtext has been
        created / decrypted. Then the final HMAC is available from the
        `aresult` & `result` methods, & can be tested against untrusted
        HMACs with the `atest_hmac` & `test_hmac` methods. The validator
        also has `(a)current_digest` & `(a)next_block_id` methods that
        can be used to authenticate unfinished streams of cipehrtext.
        """
        yield from bytes_encipher(
            data=self, key_bundle=key_bundle, validator=validator
        )

    @comprehension(chained=True)
    async def _abytes_decipher(
        self: Comprende, key_bundle: KeyAADBundle, validator: StreamHMAC
    ):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        this package's online MRAE / AEAD `Chunky2048` cipher.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all generators that
        are decorated with `comprehension` can decrypt valid ciphertext
        byte streams.

        WARNING: The generator does not provide authentication of the
        ciphertexts or associated data it handles. Nor does it do any
        message padding or sufficient checking of inputs for adequacy.
        Those are functionalities which must be obtained through other
        means. Just passing in a ``validator`` will not authenticate
        ciphertext itself. The `finalize` or `afinalize` methods must be
        called on the ``validator`` once all of the cipehrtext has been
        created / decrypted. Then the final HMAC is available from the
        `aresult` & `result` methods, & can be tested against untrusted
        HMACs with the `atest_hmac` & `test_hmac` methods. The validator
        also has `(a)current_digest` & `(a)next_block_id` methods that
        can be used to authenticate unfinished streams of cipehrtext.
        """
        async for block in abytes_decipher(
            data=self, key_bundle=key_bundle, validator=validator
        ):
            yield block

    @comprehension(chained=True)
    def _bytes_decipher(
        self: Comprende, key_bundle: KeyAADBundle, validator: StreamHMAC
    ):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        this package's online MRAE / AEAD `Chunky2048` cipher.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all generators that
        are decorated with `comprehension` can decrypt valid ciphertext
        byte streams.

        WARNING: The generator does not provide authentication of the
        ciphertexts or associated data it handles. Nor does it do any
        message padding or sufficient checking of inputs for adequacy.
        Those are functionalities which must be obtained through other
        means. Just passing in a ``validator`` will not authenticate
        ciphertext itself. The `finalize` or `afinalize` methods must be
        called on the ``validator`` once all of the cipehrtext has been
        created / decrypted. Then the final HMAC is available from the
        `aresult` & `result` methods, & can be tested against untrusted
        HMACs with the `atest_hmac` & `test_hmac` methods. The validator
        also has `(a)current_digest` & `(a)next_block_id` methods that
        can be used to authenticate unfinished streams of cipehrtext.
        """
        yield from bytes_decipher(
            data=self, key_bundle=key_bundle, validator=validator
        )


class Passcrypt:
    """
    This class is used to implement an Argon2id-like passphrase-based
    key derivation function that's designed to be resistant to cache-
    timing side-channel attacks & time-memory trade-offs.

    It's hybrid data dependant / independant. The algorithm requires a
    tunable amount of memory (in kilobytes) & cpu time to compute. If
    the memory cost is too high, it can eat up all the ram on a machine
    very quickly. The ``cpu`` time cost is linearly proportional to the
    number of sha3_512 hashes of cache columns that are calculated per
    column. The ``hardness`` parameter measures the minimum number of
    columns in the memory cache.

    The algorithm initializes all the columns for the cache using the
    `bytes_keys` generator after being fed the passphrase, salt & the
    hash of all the parameters. The number of columns is computed
    dynamically to reach the specified memory cost considering the ``cpu``
    cost also sequentially adds 128 bytes of sha3_512 digests to the
    cache ``cpu`` * columns number of times. The effect is that, hashing
    the bytes in a column, is same as a proving knowledge of the state
    of that column for all past passes over the cache.

    The sequential passes involve a current column index, the index of
    the current index's reflection across the cache, & an index chosen
    pseudo-randomly using the current digest of the sha3_512 object that
    does all of the hashing.

    This algorithm is also decribed by this diagram:


           _____width of the cache is the # of columns______
          |                                                 |
          v              initial memory cache               v
    row-> |-------------------------------------------------| each
    row-> |-------------------------------------------------| element in
                                                              a row is
                                                              64-bytes.
                                pseudo-random selection
                                          |
    ram = |--------'----------------------'--------'--------| each column
        = |--------'----------------------'--------'--------| is hashed
        = |ooooooooO                               Xxxxxxxxx| & added to
                   |   ->                     <-   |          sequentially,
                 index                        reflection      first the
                                                              index, then
                           reflection                         the reflection.
                          <-   |
    ram = |-'------------------'-------'--------------------| A pseudo-
        = |-'------------------'-------'--------------------| random index
        = |o'oooooooooooooooooo'ooooxxx'xxxxxxxxxxxxxxxxxxxx| is hashed at
        = | |                  XxxxxoooO                    | the start of
            |                          |   ->                 each round
    pseudo-random selection          index                    to randomize
                                                              that round's
       pseudo-random selection                                two digests.
                 |
    ram = |--'---'---------------------------------------'--| Each index,
        = |--'---'---------------------------------------'--| reflection,
        = |oo'ooo'ooooooooooooooooooxxxxxxxxxxxxxxxxxxxxx'xx| & pseudo-
        = |xx'xxx'xxxxxxxxxxxxxxxxxxooooooooooooooooooooo'oo| random index
        = |ooO                                           Xxx| tuple represents
             |   ->                                 <-   |    one round.
           index                                    reflection
                                   |
                                   |
                                   v Continue until there are
                                     2 * (cpu + 1) total rows,
                                     completing cpu * columns
                                     total rounds.
    `kb` == rows * columns * 64
    rows == 2 * (`cpu` + 1)
    columns == `kb` / (128 * (`cpu` + 1))

    proof = sha3_512(initial_memory_cache[-1] + H(args))
    The ``proof`` hashing object is used to do all hashing in the
    algorithm, which helps assure the algorithm must be run sequentially.
    """

    vars().update(
        {f"_{name}": value for name, value in passcrypt_constants.items()}
    )

    def __init__(
        self,
        kb: int = _DEFAULT_KB,
        cpu: int = _DEFAULT_CPU,
        hardness: int = _DEFAULT_HARDNESS,
    ):
        """
        Stores a dict of user-defined settings which are automatically
        passed into instance methods when they are called.
        """
        self._validate_settings(kb=kb, cpu=cpu, hardness=hardness)
        self._settings = dict(kb=kb, cpu=cpu, hardness=hardness)
        instance = self.__dict__
        for method in self._instance_methods:
            method = method.__func__
            name = method.__name__
            instance[name] = wraps(method)(
                partial(method, self, **self._settings)
            )

    @staticmethod
    def _validate_inputs(passphrase: bytes, salt: bytes):
        """
        Makes sure ``passphrase`` & ``salt`` are truthy. Throws
        `ValueError` if not.
        """
        if passphrase.__class__ is not bytes:
            raise Issue.value_must_be_type("passphrase", bytes)
        elif not passphrase:
            raise Issue.no_value_specified("passphrase")
        elif salt.__class__ is not bytes:
            raise Issue.value_must_be_type("salt", bytes)
        elif not salt:
            raise Issue.no_value_specified("salt")

    @staticmethod
    def _validate_settings(kb: int, cpu: int, hardness: int):
        """
        Ensures the values ``kb``, ``cpu`` and ``hardness`` passed into
        this module's Argon2id-like, passphrase-based key derivation
        function are within acceptable bounds & types. Then performs a
        calculation to determine how many iterations of the ``bytes_keys``
        generator will sum to the desired number of kilobytes, taking
        into account that for every element in that cache, 2 * ``cpu``
        number of extra sha3_512 hashes will be added to the cache as
        proofs of memory & work.
        """
        if (
            hardness < 256
            or hardness >= 4294967296
            or hardness.__class__ is not int
        ):
            raise PasscryptIssue.invalid_hardness(hardness)
        elif cpu < 2 or cpu >= 65536 or cpu.__class__ is not int:
            raise PasscryptIssue.invalid_cpu(cpu)
        elif kb < 256 or kb >= 4294967296 or kb.__class__ is not int:
            raise PasscryptIssue.invalid_kb(kb)

    @classmethod
    def cache_width(cls, kb: int, cpu: int, hardness: int):
        """
        Returns the width of the cache that will be built given the
        desired amount of kilobytes ``kb`` & the depth of hash updates &
        proofs ``cpu`` that will be computed & added to the cache
        sequentially. This should help users determine optimal ratios
        for their applications.

        Explanation:
        user_input = kb
        desired_bytes = 1024 * user_input
        build_size = 128 * build_iterations
        proof_size = (64 + 64) * build_iterations * cpu
        desired_bytes == build_size + proof_size
        # solve for build_iterations given cpu & kb
        width = build_iterations
        width = (1024 * kb) // (128 * (cpu + 1))
        width = (8 * kb) // (cpu + 1)
        """
        cls._validate_settings(kb, cpu, hardness)
        width = int((8 * kb) / (cpu + 1))
        return width if width >= hardness else hardness

    @staticmethod
    def _work_memory_prover(
        proof: sha3_512, ram: Typing.List[bytes], cpu: int
    ):
        """
        Returns the key scanning function which combines sequential
        passes over the memory cache with a pseudo-random selection
        algorithm which makes the scheme hybrid data-dependent /
        independent. It ensures an attacker attempting to crack a
        passphrase hash cannot complete the algorithm substantially
        faster by storing more memory than what is already necessary, or
        substantially less memory intensive by dropping cache entries
        without drastically increasing the computational cost.
        """

        def keyed_scanner():
            nonlocal digest

            for _ in range(cpu):
                index = next_index()
                reflection = -index - 1

                update(choose() + ram[index])
                ram[index] += summarize()

                update(ram[reflection])
                digest = summarize()
                ram[reflection] += digest
            return digest

        update = proof.update
        summarize = proof.digest
        digest = summarize()
        cache_width = len(ram)
        to_int = int.from_bytes
        next_index = cycle.root(range(cache_width)).__next__
        choose = lambda: ram[to_int(digest, "big") % cache_width]
        return keyed_scanner

    @classmethod
    async def _apasscrypt(
        cls,
        passphrase: bytes,
        salt: bytes,
        *,
        kb: int = _DEFAULT_KB,
        cpu: int = _DEFAULT_CPU,
        hardness: int = _DEFAULT_HARDNESS,
    ):
        """
        An implementation of an Argon2id-like passphrase-based key
        derivation function that's designed to be resistant to cache-
        timing side-channel attacks & time-memory trade-offs.

        It's hybrid data dependant / independant. The algorithm requires
        a tunable amount of memory (in kilobytes) & cpu time to compute.
        If the memory cost is too high, it can eat up all the ram on a
        machine very quickly. The ``cpu`` time cost is linearly
        proportional to the number of sha3_512 hashes of cache columns
        that are calculated per column. The ``hardness`` parameter
        measures the minimum number of columns in the memory cache.

        The algorithm initializes all the columns for the cache using
        the `abytes_keys` generator after being fed the passphrase, salt
        & the hash of all the parameters. The number of columns is
        computed dynamically to reach the specified memory cost
        considering the ``cpu`` cost also sequentially adds 128 bytes of
        sha3_512 digests to the cache ``cpu`` * columns number of times.
        The effect is that, hashing the bytes in a column, is same as a
        proving knowledge of the state of that column for all past
        passes over the cache.

        The sequential passes involve a current column index, the index
        of the current index's reflection across the cache, & an index
        chosen pseudo-randomly using the current digest of the sha3_512
        object that does all of the hashing.

        `kb` == rows * columns * 64
        rows == 2 * (`cpu` + 1)
        columns == `kb` / (128 * (`cpu` + 1))
        """
        cache_width = cls.cache_width(kb, cpu, hardness)
        args = sha3__512(passphrase, salt, kb, cpu, hardness, hex=False)

        key_bundle = KeyAADBundle.unsafe(passphrase, salt=salt, aad=args)
        cache_builder = abytes_keys.root(key_bundle).asend
        ram = [await cache_builder(None) for _ in range(cache_width)]

        proof = sha3_512(Domains.PASSCRYPT + ram[-1] + args)
        prove = cls._work_memory_prover(proof, ram, cpu)
        for element in ram:
            prove()
            await asleep()
        return proof.digest()

    @classmethod
    def _passcrypt(
        cls,
        passphrase: bytes,
        salt: bytes,
        *,
        kb: int = _DEFAULT_KB,
        cpu: int = _DEFAULT_CPU,
        hardness: int = _DEFAULT_HARDNESS,
    ):
        """
        An implementation of an Argon2id-like passphrase-based key
        derivation function that's designed to be resistant to cache-
        timing side-channel attacks & time-memory trade-offs.

        It's hybrid data dependant / independant. The algorithm requires
        a tunable amount of memory (in kilobytes) & cpu time to compute.
        If the memory cost is too high, it can eat up all the ram on a
        machine very quickly. The ``cpu`` time cost is linearly
        proportional to the number of sha3_512 hashes of cache columns
        that are calculated per column. The ``hardness`` parameter
        measures the minimum number of columns in the memory cache.

        The algorithm initializes all the columns for the cache using
        the `bytes_keys` generator after being fed the passphrase, salt
        & the hash of all the parameters. The number of columns is
        computed dynamically to reach the specified memory cost
        considering the ``cpu`` cost also sequentially adds 128 bytes of
        sha3_512 digests to the cache ``cpu`` * columns number of times.
        The effect is that, hashing the bytes in a column, is same as a
        proving knowledge of the state of that column for all past
        passes over the cache.

        The sequential passes involve a current column index, the index
        of the current index's reflection across the cache, & an index
        chosen pseudo-randomly using the current digest of the sha3_512
        object that does all of the hashing.

        `kb` == rows * columns * 64
        rows == 2 * (`cpu` + 1)
        columns == `kb` / (128 * (`cpu` + 1))
        """
        cache_width = cls.cache_width(kb, cpu, hardness)
        args = sha3__512(passphrase, salt, kb, cpu, hardness, hex=False)

        key_bundle = KeyAADBundle.unsafe(passphrase, salt=salt, aad=args)
        cache_builder = bytes_keys.root(key_bundle).send
        ram = [cache_builder(None) for _ in range(cache_width)]

        proof = sha3_512(Domains.PASSCRYPT + ram[-1] + args)
        prove = cls._work_memory_prover(proof, ram, cpu)
        for element in ram:
            prove()
        return proof.digest()

    @classmethod
    async def anew(
        cls,
        passphrase: bytes,
        salt: bytes,
        *,
        kb: int = _DEFAULT_KB,
        cpu: int = _DEFAULT_CPU,
        hardness: int = _DEFAULT_HARDNESS,
    ):
        """
        Returns just the 64-byte passcrypt hash of the ``passphrase``
        when mixed with the given ``salt`` & difficulty settings.

        NOTICE: The passcrypt algorithm can be highly memory intensive.
        These resources may not be freed up, & often are not, because of
        python quirks around memory management. To force the release of
        these resources, we run the function in another process which
        guarantees the release.
        """
        cls._validate_inputs(passphrase, salt)
        cls._validate_settings(kb, cpu, hardness)
        return await Processes.anew(
            cls._passcrypt,
            passphrase,
            salt,
            kb=kb,
            cpu=cpu,
            hardness=hardness,
            probe_frequency=0.01,
        )

    @classmethod
    def new(
        cls,
        passphrase: bytes,
        salt: bytes,
        *,
        kb: int = _DEFAULT_KB,
        cpu: int = _DEFAULT_CPU,
        hardness: int = _DEFAULT_HARDNESS,
    ):
        """
        Returns just the 64-byte passcrypt hash of the ``passphrase``
        when mixed with the given ``salt`` & difficulty settings.

        NOTICE: The passcrypt algorithm can be highly memory intensive.
        These resources may not be freed up, & often are not, because of
        python quirks around memory management. To force the release of
        these resources, we run the function in another process which
        guarantees the release.
        """
        cls._validate_inputs(passphrase, salt)
        cls._validate_settings(kb, cpu, hardness)
        return Processes.new(
            cls._passcrypt,
            passphrase,
            salt,
            kb=kb,
            cpu=cpu,
            hardness=hardness,
            probe_frequency=0.01,
        )

    @classmethod
    async def _acompose_passcrypt_hash(
        cls,
        passphrase_hash: bytes,
        salt: bytes,
        *,
        kb: int,
        cpu: int,
        hardness: int,
    ):
        """
        Attaches the difficulty settings & salt to the passcrypt hash
        of the passphrase.
        """
        await asleep()
        passcrypt_hash = (
            kb.to_bytes(cls._KB_BYTES, "big"),
            cpu.to_bytes(cls._CPU_BYTES, "big"),
            hardness.to_bytes(cls._HARDNESS_BYTES, "big"),
            salt[: cls._SALT_BYTES],
            passphrase_hash[: cls._PASSPHRASE_HASH_BYTES],
        )
        return b"".join(passcrypt_hash)

    @classmethod
    def _compose_passcrypt_hash(
        cls,
        passphrase_hash: bytes,
        salt: bytes,
        *,
        kb: int,
        cpu: int,
        hardness: int,
    ):
        """
        Attaches the difficulty settings & salt to the passcrypt hash
        of the passphrase.
        """
        passcrypt_hash = (
            kb.to_bytes(cls._KB_BYTES, "big"),
            cpu.to_bytes(cls._CPU_BYTES, "big"),
            hardness.to_bytes(cls._HARDNESS_BYTES, "big"),
            salt[: cls._SALT_BYTES],
            passphrase_hash[: cls._PASSPHRASE_HASH_BYTES],
        )
        return b"".join(passcrypt_hash)

    @classmethod
    async def _adecompose_passcrypt_hash(cls, raw_passcrypt_hash: bytes):
        """
        Separates the passcrypt hash, salt & difficulty settings &
        returns them in a namespace object available by dotted lookup.
        """
        await asleep()
        SCHEMA_BYTES = cls._PASSCRYPT_SCHEMA_BYTES
        if len(raw_passcrypt_hash) != SCHEMA_BYTES:
            raise Issue.invalid_length("passcrypt hash", SCHEMA_BYTES)
        return PasscryptHash(raw_passcrypt_hash)

    @classmethod
    def _decompose_passcrypt_hash(cls, raw_passcrypt_hash: bytes):
        """
        Separates the passcrypt hash, salt & difficulty settings &
        returns them in a namespace object available by dotted lookup.
        """
        SCHEMA_BYTES = cls._PASSCRYPT_SCHEMA_BYTES
        if len(raw_passcrypt_hash) != SCHEMA_BYTES:
            raise Issue.invalid_length("passcrypt hash", SCHEMA_BYTES)
        return PasscryptHash(raw_passcrypt_hash)

    @classmethod
    async def ahash_passphrase_raw(
        cls,
        passphrase: bytes,
        *,
        kb: int = _DEFAULT_KB,
        cpu: int = _DEFAULT_CPU,
        hardness: int = _DEFAULT_HARDNESS,
    ):
        """
        Returns the passcrypt difficulty settings, salt & hash of the
        ``passphrase`` in a single raw bytes sequence for convenient
        storage. The salt here is automatically generated.

        Metadata hash layout:
        4-bytes - 2-bytes - 4-bytes - 32-bytes - 64-bytes
          kb        cpu     hardness    salt       hash
        """
        salt = (await acsprng())[: cls._SALT_BYTES]
        passphrase_hash = await cls.anew(
            passphrase, salt, kb=kb, cpu=cpu, hardness=hardness
        )
        return await cls._acompose_passcrypt_hash(
            passphrase_hash, salt, kb=kb, cpu=cpu, hardness=hardness
        )

    @classmethod
    def hash_passphrase_raw(
        cls,
        passphrase: bytes,
        *,
        kb: int = _DEFAULT_KB,
        cpu: int = _DEFAULT_CPU,
        hardness: int = _DEFAULT_HARDNESS,
    ):
        """
        Returns the passcrypt difficulty settings, salt & hash of the
        ``passphrase`` in a single raw bytes sequence for convenient
        storage. The salt here is automatically generated.

        Metadata hash layout:
        4-bytes - 2-bytes - 4-bytes - 32-bytes - 64-bytes
          kb        cpu     hardness    salt       hash
        """
        salt = csprng()[: cls._SALT_BYTES]
        passphrase_hash = cls.new(
            passphrase, salt, kb=kb, cpu=cpu, hardness=hardness
        )
        return cls._compose_passcrypt_hash(
            passphrase_hash, salt, kb=kb, cpu=cpu, hardness=hardness
        )

    @classmethod
    async def ahash_passphrase(
        cls,
        passphrase: bytes,
        *,
        kb: int = _DEFAULT_KB,
        cpu: int = _DEFAULT_CPU,
        hardness: int = _DEFAULT_HARDNESS,
    ):
        """
        Returns the passcrypt difficulty settings, salt & hash of the
        ``passphrase`` in a single urlsafe base64 encoded string for
        convenient storage. The salt here is automatically generated.

        Metadata hash layout:
        4-bytes - 2-bytes - 4-bytes - 32-bytes - 64-bytes
          kb        cpu     hardness    salt       hash
        """
        raw_passcrypt_hash = await cls.ahash_passphrase_raw(
            passphrase, kb=kb, cpu=cpu, hardness=hardness
        )
        return await BytesIO.abytes_to_urlsafe(raw_passcrypt_hash)

    @classmethod
    def hash_passphrase(
        cls,
        passphrase: bytes,
        *,
        kb: int = _DEFAULT_KB,
        cpu: int = _DEFAULT_CPU,
        hardness: int = _DEFAULT_HARDNESS,
    ):
        """
        Returns the passcrypt difficulty settings, salt & hash of the
        ``passphrase`` in a single urlsafe base64 encoded string for
        convenient storage. The salt here is automatically generated.

        Metadata hash layout:
        4-bytes - 2-bytes - 4-bytes - 32-bytes - 64-bytes
          kb        cpu     hardness    salt       hash
        """
        raw_passcrypt_hash = cls.hash_passphrase_raw(
            passphrase, kb=kb, cpu=cpu, hardness=hardness
        )
        return BytesIO.bytes_to_urlsafe(raw_passcrypt_hash)

    @classmethod
    async def averify_raw(
        cls, composed_passcrypt_hash: bytes, passphrase: bytes
    ):
        """
        Verifies that a supplied ``passphrase`` was indeed used to build
        the ``composed_passcrypt_hash``.

        Runs the passcrypt algorithm on the ``passphrase`` with the
        parameters specified in the ``composed_passcrypt_hash`` value's
        attached metadata. If the result doesn't match the hash in
        ``composed_passcrypt_hash`` then `ValueError` is raised. The
        ``composed_passcrypt_hash`` passed into this method must be
        raw bytes.
        """
        parts = await cls._adecompose_passcrypt_hash(
            composed_passcrypt_hash
        )
        untrusted_hash = await cls.anew(
            passphrase,
            parts.salt,
            kb=parts.kb,
            cpu=parts.cpu,
            hardness=parts.hardness,
        )
        if not await abytes_are_equal(
            untrusted_hash[: cls._PASSPHRASE_HASH_BYTES],
            parts.passphrase_hash,
        ):
            raise Issue.invalid_value("passphrase")
        return True

    @classmethod
    def verify_raw(cls, composed_passcrypt_hash: bytes, passphrase: bytes):
        """
        Verifies that a supplied ``passphrase`` was indeed used to build
        the ``composed_passcrypt_hash``.

        Runs the passcrypt algorithm on the ``passphrase`` with the
        parameters specified in the ``composed_passcrypt_hash`` value's
        attached metadata. If the result doesn't match the hash in
        ``composed_passcrypt_hash`` then `ValueError` is raised. The
        ``composed_passcrypt_hash`` passed into this method must be
        raw bytes.
        """
        parts = cls._decompose_passcrypt_hash(composed_passcrypt_hash)
        untrusted_hash = cls.new(
            passphrase,
            parts.salt,
            kb=parts.kb,
            cpu=parts.cpu,
            hardness=parts.hardness,
        )
        if not bytes_are_equal(
            untrusted_hash[: cls._PASSPHRASE_HASH_BYTES],
            parts.passphrase_hash,
        ):
            raise Issue.invalid_value("passphrase")
        return True

    @classmethod
    async def averify(
        cls,
        composed_passcrypt_hash: Typing.Base64URLSafe,
        passphrase: bytes,
    ):
        """
        Verifies that a supplied ``passphrase`` was indeed used to build
        the ``composed_passcrypt_hash``.

        Runs the passcrypt algorithm on the ``passphrase`` with the
        parameters specified in the ``composed_passcrypt_hash`` value's
        attached metadata. If the result doesn't match the hash in
        ``composed_passcrypt_hash`` then `ValueError` is raised. The
        ``composed_passcrypt_hash`` passed into this method must be
        urlsafe base64 encoded.
        """
        if composed_passcrypt_hash.__class__ is str:
            composed_passcrypt_hash = composed_passcrypt_hash.encode()
        return await cls.averify_raw(
            await BytesIO.aurlsafe_to_bytes(composed_passcrypt_hash),
            passphrase,
        )

    @classmethod
    def verify(
        cls,
        composed_passcrypt_hash: Typing.Base64URLSafe,
        passphrase: bytes,
    ):
        """
        Verifies that a supplied ``passphrase`` was indeed used to build
        the ``composed_passcrypt_hash``.

        Runs the passcrypt algorithm on the ``passphrase`` with the
        parameters specified in the ``composed_passcrypt_hash`` value's
        attached metadata. If the result doesn't match the hash in
        ``composed_passcrypt_hash`` then `ValueError` is raised. The
        ``composed_passcrypt_hash`` passed into this method must be
        urlsafe base64 encoded.
        """
        if composed_passcrypt_hash.__class__ is str:
            composed_passcrypt_hash = composed_passcrypt_hash.encode()
        return cls.verify_raw(
            BytesIO.urlsafe_to_bytes(composed_passcrypt_hash), passphrase
        )

    _instance_methods = {
        # The kb, cpu & hardness settings automatically get passed into
        # these methods when called from an instance of the class.
        new,
        anew,
        hash_passphrase,
        ahash_passphrase,
        hash_passphrase_raw,
        ahash_passphrase_raw,
    }


class DomainKDF:
    """
    Creates objects able to derive domain & payload-specific HMAC hashes.
    """

    __slots__ = ("_domain", "_key", "_payload")

    _hmac = staticmethod(hmac.new)
    _sha3_256 = sha3_256
    _sha3_512 = sha3_512
    _shake_256 = shake_256

    @staticmethod
    def _type_check(domain: bytes, payload: bytes, key: bytes):
        """
        Assure that all arguments to the initializer are bytes objects.
        """
        if domain.__class__ is not bytes:
            raise Issue.value_must_be_type("domain", bytes)
        elif payload.__class__ is not bytes:
            raise Issue.value_must_be_type("payload", bytes)
        elif key.__class__ is not bytes:
            raise Issue.value_must_be_type("key", bytes)

    def __init__(self, domain: bytes, payload: bytes = b"", *, key: bytes):
        """
        Validate the input values before initializing the object.
        """
        self._type_check(domain, payload, key)
        self._domain = domain
        self._key = domain + sha3_512(domain + key).digest()
        self._payload = sha3_512(self._key + payload)

    async def aupdate(self, payload: bytes):
        """
        Updates the payload object with additional payload. This allows
        large amounts of data to be used for key derivation without a
        large in-memory cost.
        """
        await asleep()
        self._payload.update(payload)
        return self

    def update(self, payload: bytes):
        """
        Updates the payload object with additional payload. This allows
        large amounts of data to be used for key derivation without a
        large in-memory cost.
        """
        self._payload.update(payload)
        return self

    async def aupdate_key(self, entropic_material: bytes):
        """
        Derive's a new instance key from the its domain, new ``key``
        material & the previous key.
        """
        await asleep()
        key = self._key + entropic_material
        self._key = self._domain + sha3_512(key).digest()
        return self

    def update_key(self, entropic_material: bytes):
        """
        Derive's a new instance key from the its domain, new ``key``
        material & the previous key.
        """
        key = self._key + entropic_material
        self._key = self._domain + sha3_512(key).digest()
        return self

    async def _amake_hmac(self, *, hasher: Typing.Callable):
        """
        Returns an hmac object which has been given the instance's key,
        the digest of the instance's payload, & the hashing type passed
        into the ``hasher`` keyword argument.
        """
        await asleep()
        return self._hmac(self._key, self._payload.digest(), hasher)

    def _make_hmac(self, *, hasher: Typing.Callable):
        """
        Returns an hmac object which has been given the instance's key,
        the digest of the instance's payload, & the hashing type passed
        into the ``hasher`` keyword argument.
        """
        return self._hmac(self._key, self._payload.digest(), hasher)

    async def asha3_256(self, *, context: bytes = b""):
        """
        Return the sha3_256_hmac of the instance's state.
        """
        obj = await self._amake_hmac(hasher=self._sha3_256)
        obj.update(context) if context else 0
        return obj.digest()

    def sha3_256(self, *, context: bytes = b""):
        """
        Return the sha3_256_hmac of the instance's state.
        """
        obj = self._make_hmac(hasher=self._sha3_256)
        obj.update(context) if context else 0
        return obj.digest()

    async def asha3_512(self, *, context: bytes = b""):
        """
        Return the sha3_512_hmac of the instance's state.
        """
        obj = await self._amake_hmac(hasher=self._sha3_512)
        obj.update(context) if context else 0
        return obj.digest()

    def sha3_512(self, *, context: bytes = b""):
        """
        Return the sha3_512_hmac of the instance's state.
        """
        obj = self._make_hmac(hasher=self._sha3_512)
        obj.update(context) if context else 0
        return obj.digest()

    async def ashake_256(self, size: int, *, context: bytes = b""):
        """
        Return the sha3_512_hmac of the instance's state.
        """
        await asleep()
        obj = self._shake_256(self._key + self._payload.digest())
        obj.update(context) if context else 0
        return obj.digest(size)

    def shake_256(self, size: int, *, context: bytes = b""):
        """
        Return the sha3_512_hmac of the instance's state.
        """
        obj = self._shake_256(self._key + self._payload.digest())
        obj.update(context) if context else 0
        return obj.digest(size)

    async def apasscrypt(
        self,
        salt: bytes,
        *,
        context: bytes = b"",
        kb: int = Passcrypt._DEFAULT_KB,
        cpu: int = Passcrypt._DEFAULT_CPU,
        hardness: int = Passcrypt._DEFAULT_HARDNESS,
    ):
        """
        Runs the instance's state through the passcrypt algorithm &
        returns the resulting hash as bytes.
        """
        domain = Domains.PASSCRYPT
        value = await self.asha3_512(context=domain + context + salt)
        settings = dict(kb=kb, cpu=cpu, hardness=hardness)
        return await Passcrypt.anew(value, salt=salt, **settings)

    def passcrypt(
        self,
        salt: bytes,
        *,
        context: bytes = b"",
        kb: int = Passcrypt._DEFAULT_KB,
        cpu: int = Passcrypt._DEFAULT_CPU,
        hardness: int = Passcrypt._DEFAULT_HARDNESS,
    ):
        """
        Runs the instance's state through the passcrypt algorithm &
        returns the resulting hash as bytes.
        """
        domain = Domains.PASSCRYPT
        value = self.sha3_512(context=domain + context + salt)
        settings = dict(kb=kb, cpu=cpu, hardness=hardness)
        return Passcrypt.new(value, salt=salt, **settings)


class AsyncDatabase(metaclass=AsyncInit):
    """
    This class creates databases which enable the disk persistence of
    any bytes or JSON serializable native python data-types, with fully
    transparent, asynchronous encryption / decryption using the
    library's `Chunky2048` cipher.

    Usage Example:

    key = await aiootp.acsprng()
    db = await AsyncDatabase(key)

    # Elements in a database are organized by user-defined tags ->
    db["income"] = 32000

    # Databases can store any JSON serializable data ->
    db["dict"] = {0: 1, 2: 3, 4: 5}
    db["lists"] = ["juice", ["nested juice"]]

    # As well as raw bytes ->
    db["bytes"] = b"value..."

    # Retrieve items by their tags ->
    db["dict"]
    >>> {0: 1, 2: 3, 4: 5}

    # Save changes to disk ->
    await db.asave_database()

    # Create child databases using what are called metatags ->
    taxes = await db.ametatag("taxes")
    taxes[2020] = {"jan": 130.25, "feb": 163.23, "mar": 149.68}
    assert taxes == db.taxes
    assert taxes[2020] == db.taxes[2020]

    # Delete a child database ->
    await db.adelete_metatag("taxes")

    # Purge the filesystem of the database files ->
    await db.adelete_database()
    """

    IO = BytesIO

    directory: Typing.Path = DatabasePath()

    _BASE_38_TABLE: str = Tables.BASE_38
    _KDF: bytes = Domains.KDF
    _HMAC: bytes = Domains.HMAC
    _SALT: bytes = Domains.SALT
    _SEED: bytes = Domains.SEED
    _UUID: bytes = Domains.UUID
    _TOKEN: bytes = Domains.TOKEN
    _MANIFEST: bytes = Domains.MANIFEST
    _FILENAME: bytes = Domains.FILENAME
    _FILE_KEY: bytes = Domains.FILE_KEY
    _METATAG_KEY: bytes = Domains.METATAG_KEY
    _METATAGS: bytes = sha3_256(Domains.METATAG + Domains.FILENAME).digest()

    @classmethod
    async def abase64_encode(cls, byte_sequence: bytes):
        """
        Encodes a raw ``bytes_sequence`` into a urlsafe base64 string.
        """
        await asleep()
        return base64.urlsafe_b64encode(byte_sequence).decode()

    @classmethod
    async def abase64_decode(cls, base64_sequence: Typing.AnyStr):
        """
        Decodes a urlsafe base64 string or bytes sequence into raw bytes.
        """
        await asleep()
        if base64_sequence.__class__ is not bytes:
            base64_sequence = base64_sequence.encode()
        return base64.urlsafe_b64decode(base64_sequence)

    @classmethod
    def _hex_to_base38(cls, hex_string: str):
        """
        Returns the received ``hex_string`` in base38 encoding.
        """
        return int_to_base(
            int(hex_string, 16), base=38, table=cls._BASE_38_TABLE
        )

    @classmethod
    async def _ahex_to_base38(cls, hex_string: str):
        """
        Returns the received ``hex_hash`` in base38 encoding.
        """
        return await aint_to_base(
            int(hex_string, 16), base=38, table=cls._BASE_38_TABLE
        )

    @classmethod
    async def aprofile_exists(cls, tokens: ProfileTokens):
        """
        Tests if a profile that ``tokens`` would open has saved a salt
        file on the user filesystem. Retruens false if not.
        """
        filename = await paths.adeniable_filename(tokens._bytes_key)
        path = (DatabasePath() / "secure") / filename
        return path.exists()

    @classmethod
    async def agenerate_profile_tokens(
        cls,
        *credentials: Typing.Iterable[Typing.Any],
        username: Typing.Any,
        passphrase: Typing.Any,
        salt: Typing.Any = None,
        kb: int = 32768,
        cpu: int = 3,
        hardness: int = 1024,
    ):
        """
        Runs a very expensive key derivation function to build keys
        for users to open a database with only access to potentially
        weakly entropic credentials & the filesystem.

        Usage Example:

        tokens = await aiootp.AsyncDatabase.agenerate_profile_tokens(
            "server_url",     # Any number of arguments can be passed
            "email_address",  # here as additional, optional credentials.
            username="username",
            passphrase="passphrase",
            salt="optional salt keyword argument",
        )

        db = await aiootp.AsyncDatabase.agenerate_profile(tokens)
        """
        await asleep()
        UUID = cls._UUID
        summary = str((salt, passphrase, *credentials, username)).encode()
        uuid = await asha3__512_hmac(UUID + summary, key=summary, hex=False)
        key = await Passcrypt.anew(
            summary, uuid, kb=kb, cpu=cpu, hardness=hardness
        )
        return ProfileTokens(key, uuid)

    @classmethod
    async def _agenerate_profile_salt(
        cls, tokens: ProfileTokens, directory: Path
    ):
        """
        Creates or loads a salt value saved on the user filesystem to
        help add more entropy to their key derivation functions when
        preparing to open a profile database.
        """
        tokens._salt_path = await paths.AsyncSecurePath(
            path=directory, key=tokens._bytes_key
        )
        tokens._salt = await paths._aread_salt_file(tokens._salt_path)
        return tokens._salt

    @classmethod
    async def _agenerate_profile_login_key(cls, tokens: ProfileTokens):
        """
        Combines the output of the expensive key derivation functions &
        the salt stored on the filesystem gathered in preparation to
        safely open a profile database.
        """
        tokens.login_key = await Passcrypt.anew(
            tokens._bytes_key, tokens._salt
        )
        return tokens.login_key

    @classmethod
    async def agenerate_profile(
        cls, tokens: ProfileTokens, directory: Path = directory, **kw
    ):
        """
        Creates & loads a profile database for a user from the ``tokens``
        passed in.

        Usage Example:

        tokens = await aiootp.AsyncDatabase.agenerate_profile_tokens(
            "server_url",     # Any number of arguments can be passed
            "email_address",  # here as additional, optional credentials.
            username="username",
            passphrase="passphrase",
            salt="optional salt keyword argument",
        )

        db = await aiootp.AsyncDatabase.agenerate_profile(tokens)
        """
        await cls._agenerate_profile_salt(tokens, directory=directory)
        await cls._agenerate_profile_login_key(tokens)
        tokens.profile = await cls(
            key=tokens.login_key, depth=10000, directory=directory, **kw
        )
        if not tokens.profile._root_path.is_file():
            await tokens.profile.asave_database()
        return tokens.profile

    @classmethod
    async def aload_profile(cls, tokens: ProfileTokens, **kw):
        """
        Loads a profile database for a user from the ``tokens`` passed
        in. Throws ``LookupError`` if the profile has not yet been
        generated.
        """
        if not await cls.aprofile_exists(tokens):
            raise DatabaseIssue.missing_profile()
        return await cls.agenerate_profile(tokens, **kw)

    @classmethod
    async def adelete_profile(cls, tokens: ProfileTokens):
        """
        Deletes the profile's salt saved on the filesystem & all of its
        database files.
        """
        try:
            await tokens.profile.adelete_database()
        except AttributeError:
            await cls.aload_profile(tokens, preload=False)
            await tokens.profile.adelete_database()
        await asynchs.aos.remove(tokens._salt_path)

    async def __init__(
        self,
        key: bytes,
        *,
        depth: int = 0,  # >= 5000 if ``key`` is weak
        preload: bool = False,
        directory: Typing.Union[Path, str] = directory,
        metatag: bool = False,
        silent: bool = True,
    ):
        """
        Sets a database object's basic key generators & cryptographic
        values based on the unique permutations of the ``key`` &
        ``depth`` values. If ``key`` is a passphrase, or has very
        low entropy, then ``depth`` should be a larger number.
        However, using the `generate_profile_tokens` & `generate_profile`
        methods would be a safer choice for opening a database with a
        potentially weak passphrase.

        ``preload``:    This boolean value tells the object to -- True --
            load all of the stored database values from the filesystem
            into the cache during initialization, or -- False -- skip
            the loading stage. This can save time up front so users can
            pay the cost of loading data only when that value is needed.

        ``directory``:  This value is the string or ``Pathlib.Path``
            object that points to the filesystem location where the
            database files reside / will be saved. By default, stores
            values in the directory "databases" relative to the package
            source code.

        ``metatag``:    This boolean value tells the class whether to
            prepare itself as a sub-database or not, which generally
            means less storage overhead used to secure its cryptographic
            material. Parent databases that are not metatags store a
            random salt value in their ``self._root_path`` file.

        ``silent``:     This boolean value tells the class to surpress
            exceptions when loading files so that errors in the database
            don't prevent a user from logging in.
        """
        self._silent = silent
        self._corrupted_files = {}
        self._cache = Namespace()
        self._manifest = Namespace()
        self.directory = await self._aformat_directory(directory)
        self._is_metatag = True if metatag else False
        self._root_key, self._root_hash, self._root_filename = (
            await self._ainitialize_keys(key, depth)
        )
        await self._aload_manifest()
        await self._ainitialize_metatags()
        await self.aload_database(silent=silent, preload=preload)

    @classmethod
    async def _aformat_directory(cls, path: Typing.OptionalPathStr):
        """
        Returns a `pathlib.Path` object to the user-specified ``path``
        if given, else returns a copy of the default database directory
        `Path` object.
        """
        if path == None:
            return Path(cls.directory).absolute()
        return Path(path).absolute()

    @classmethod
    async def _aderive_root_key(cls, key: bytes, depth: int):
        """
        Returns a root key derived from the user supplied key & context
        data.
        """
        key_aad = KeyAADBundle.unsafe(
            key=key,
            salt=b"derive database:",
            aad=repr((cls._KDF, depth)).encode(),
        )
        return await abytes_keys(key_aad)[depth]()

    @classmethod
    async def _aderive_root_hash(cls, root_key: bytes):
        """
        Returns a hash derived from the instance's root key.
        """
        return await asha3__512_hmac(
            cls._KDF + root_key, key=root_key, hex=False
        )

    @classmethod
    async def _aderive_root_filename(cls, root_hash: bytes):
        """
        Returns a 24-byte hash encoded in base38 used as the instance's
        manifest filename.
        """
        root_filename_hash = await asha3__256_hmac(
            cls._FILENAME + root_hash, key=root_hash
        )
        return await cls._ahex_to_base38(root_filename_hash[:48])

    @classmethod
    async def _ainitialize_keys(cls, key: bytes, depth: int = 0):
        """
        Derives the database's cryptographic root key material and the
        filename of the manifest ledger.
        """
        root_key = await cls._aderive_root_key(key, depth)
        root_hash = await cls._aderive_root_hash(root_key)
        root_filename = await cls._aderive_root_filename(root_hash)
        return root_key, root_hash, root_filename

    @property
    def _root_path(self):
        """
        Returns a ``pathlib.Path`` object that points to the file that
        contains the manifest ledger.
        """
        return self.directory / self._root_filename

    @property
    def _maintenance_files(self):
        """
        Returns the filenames of entries in the database that refer to
        administrative values used by objects to track and coordinate
        themselves internally.
        """
        return {self._root_filename, self._metatags_filename}

    @property
    def tags(self):
        """
        Returns a list of all user-defined names for values stored in
        the database object.
        """
        manifest = self._manifest
        return {
            getattr(manifest, filename)
            for filename in self._maintenance_files.symmetric_difference(
                manifest
            )
        }

    @property
    def filenames(self):
        """
        Returns a list of all derived filenames of user-defined tags
        stored in the database object.
        """
        manifest = self._manifest.namespace
        return {
            filename
            for filename in self._maintenance_files.symmetric_difference(
                manifest
            )
        }

    @property
    def metatags(self):
        """
        Returns the list of metatags that a database contains.
        """
        return set(
            self._manifest.namespace.get(self._metatags_filename, [])
        )

    @property
    def _root_salt_filename(self):
        """
        Returns the filename of the database's root salt.
        """
        key = self._root_key
        payload = self._root_hash
        domain = self._SALT + self._FILENAME
        filename = DomainKDF(domain, payload, key=key).sha3_256()
        return self._hex_to_base38(filename.hex()[:48])

    @property
    def _root_salt_path(self):
        """
        Returns the path of the database's root salt file if the
        instance is not a metatag.
        """
        if not self._is_metatag:
            return self.directory / self._root_salt_filename

    async def _aroot_encryption_key(
        self, filename: bytes, salt: Typing.Optional[bytes]
    ):
        """
        Takes a ``filename`` & ``salt`` to construct a unique symmetric
        cryptographic key with preliminary database key material.
        """
        await asleep()
        domain = self._KDF + self._FILE_KEY
        key = self._root_hash
        payload = self._root_key + repr((salt, filename)).encode()
        return await DomainKDF(domain, payload, key=key).asha3_512()

    async def _aopen_manifest(self):
        """
        Loads an existing manifest file ledger from the filesystem.
        """
        ciphertext = await self.IO.aread(path=self._root_path)
        salt = self._root_session_salt = ciphertext[SALT_SLICE]
        key = await self._aroot_encryption_key(self._MANIFEST, salt)
        return await ajson_decrypt(ciphertext, key=key)

    async def _aload_root_salt(self):
        """
        Pulls the root salt from the filesystem for a database instance,
        or retrieves it from the manifest file if the database is a
        metatag. Returns the result.
        """
        if self._is_metatag:
            await asleep()
            salt = self._manifest[self._root_filename]
        else:
            encrypted_root_salt = await self.IO.aread(
                path=self._root_salt_path
            )
            key = await self._aroot_encryption_key(self._SALT, salt=None)
            salt = await ajson_decrypt(encrypted_root_salt, key=key)
        return bytes.fromhex(salt)

    async def _agenerate_root_salt(self):
        """
        Returns a 32 byte hex salt for a metatag database, or a 64 byte
        hex salt otherwise.
        """
        if self._is_metatag:
            return await agenerate_salt(self._root_hash, size=32)
        else:
            return await acsprng(self._root_hash)

    async def _ainstall_root_salt(self, salt: bytes):
        """
        Gives the manifest knowledge of the database's root ``salt``.
        This salt is the source of entropy for the database that is not
        derived from the user's key that opens the database. This salt
        is saved in the manifest if the database is a metatag, or the
        salt is saved in its own file if the database is a main parent
        database.
        """
        if self._is_metatag:
            self._manifest[self._root_filename] = salt.hex()
        else:
            self._manifest[self._root_filename] = 0

    async def _agenerate_root_seed(self):
        """
        Returns a key that is derived from the database's main key &
        the root salt's entropy.
        """
        domain = self._SEED
        key = self.__root_salt
        payload = self._root_hash + self._root_key
        return await DomainKDF(domain, payload, key=key).asha3_512()

    async def _aload_manifest(self):
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """
        if self._root_path.exists():
            self._manifest = Namespace(await self._aopen_manifest())
            root_salt = await self._aload_root_salt()
        else:
            self._manifest = Namespace()
            self._root_session_salt = await agenerate_salt(size=SALT_BYTES)
            root_salt = await self._agenerate_root_salt()
            await self._ainstall_root_salt(root_salt)

        self.__root_salt = root_salt
        self._root_seed = await self._agenerate_root_seed()

    async def _ainitialize_metatags(self):
        """
        Initializes the values that organize database metatags, which
        are children databases contained within their parent.
        """
        self._metatags_filename = await self.afilename(self._METATAGS)
        if not self.metatags:
            self._manifest[self._metatags_filename] = []

    async def aload_tags(self, *, silent: bool = False):
        """
        Specifically loads all of the database's tag values into the
        cache.
        """
        tags = self.tags
        if not tags:
            await asleep()
            return self

        tag_values = (
            self.aquery_tag(tag, silent=silent, cache=True) for tag in tags
        )
        await gather(*tag_values, return_exceptions=True)
        return self

    async def aload_metatags(
        self, *, preload: bool = True, silent: bool = False
    ):
        """
        Specifically loads all of the database's metatag values into the
        cache. If the ``preload`` keyword argument is falsey then the
        metatag references are populated in the database's instance
        dictionary, but their internal values are not loaded.
        """
        metatags_set = set(self.metatags)
        if not metatags_set:
            await asleep()
            return self

        metatags = (
            self.ametatag(metatag, preload=preload, silent=silent)
            for metatag in metatags_set
        )
        await gather(*metatags, return_exceptions=True)
        return self

    async def aload_database(
        self,
        *,
        manifest: bool = False,
        silent: bool = False,
        preload: bool = True,
    ):
        """
        Loads all the database object's values from the filesystem into
        the database cache. This brings the database values into the
        cache, enables up-to-date bracket lookup of tag values & dotted
        lookup of metatags. Otherwise, values would have to be queried
        using the awaitable ``aquery`` & ``ametatag`` methods.
        """
        if manifest:
            await self._aload_manifest()
        if preload:
            await self.aload_tags(silent=silent)
        await self.aload_metatags(silent=silent, preload=preload)
        return self

    @lru_cache(maxsize=256)
    def _filename(self, tag: Typing.Optional[str]):
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        domain = self._FILENAME
        payload = repr(tag).encode()
        key = self._root_hash + self._root_seed
        filename = DomainKDF(domain, payload, key=key).sha3_256().hex()
        return self._hex_to_base38(filename[:48])

    @alru_cache(maxsize=256)
    async def afilename(self, tag: Typing.Optional[str]):
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        await asleep()
        domain = self._FILENAME
        payload = repr(tag).encode()
        key = self._root_hash + self._root_seed
        filename = await DomainKDF(domain, payload, key=key).asha3_256()
        return await self._ahex_to_base38(filename.hex()[:48])

    async def amake_hmac(self, data: Typing.DeterministicRepr):
        """
        Derives an HMAC hash of the supplied ``data`` with a unique
        permutation of the database's keys & a domain-specific kdf.
        """
        await asleep()
        domain = self._HMAC
        payload = data if data.__class__ is bytes else repr(data).encode()
        key = self._root_seed + self._root_hash
        return await DomainKDF(domain, payload, key=key).asha3_256()

    async def atest_hmac(
        self, data: Typing.DeterministicRepr, untrusted_hmac: bytes
    ):
        """
        Tests if the ``hmac`` of ``data`` is valid using the instance's
        keys & a timing-safe comparison.
        """
        if not hmac:
            raise Issue.no_value_specified("untrusted_hmac")
        true_hmac = await self.amake_hmac(data)
        if await abytes_are_equal(untrusted_hmac, true_hmac):
            return True
        else:
            raise Issue.invalid_value("HMAC of data stream")

    async def _aencryption_key(self, filename: str, salt: bytes):
        """
        Takes a ``filename`` & ``salt`` to contruct a unique symmetric
        cryptographic key.
        """
        await asleep()
        domain = self._FILE_KEY
        key = self._root_seed
        payload = self.__root_salt + salt + filename.encode()
        return await DomainKDF(domain, payload, key=key).asha3_512()

    async def abytes_encrypt(
        self, plaintext: bytes, *, filename: str = "", aad: bytes = b"aad"
    ):
        """
        Encrypts the ``plaintext`` bytes with keys specific to the
        ``filename`` value & returns the ciphertext bytes.
        """
        salt = await agenerate_salt(size=SALT_BYTES)
        key = await self._aencryption_key(filename, salt)
        return await abytes_encrypt(plaintext, key, salt=salt, aad=aad)

    async def ajson_encrypt(
        self,
        plaintext: Typing.JSONSerializable,
        *,
        filename: str = "",
        aad: bytes = b"aad",
    ):
        """
        Encrypts the JSON serializable ``plaintext`` object with keys
        specific to the ``filename`` value & returns the ciphertext
        bytes.
        """
        salt = await agenerate_salt(size=SALT_BYTES)
        key = await self._aencryption_key(filename, salt)
        return await ajson_encrypt(plaintext, key, salt=salt, aad=aad)

    async def amake_token(
        self, plaintext: bytes, *, filename: str = "", aad: bytes = b"aad"
    ):
        """
        Encrypts the ``plaintext`` bytes with keys specific to the
        ``filename`` value & base64 encodes the resulting ciphertext
        bytes.
        """
        key = await self._aencryption_key(filename, self._TOKEN)
        return await Chunky2048(key).amake_token(plaintext, aad=aad)

    async def abytes_decrypt(
        self,
        ciphertext: bytes,
        *,
        filename: str = "",
        aad: bytes = b"aad",
        ttl: int = 0,
    ):
        """
        Decrypts the ``ciphertext`` bytes with keys specific to the
        ``filename`` value & returns the plaintext bytes. ``ttl`` is the
        amount of seconds that dictate the allowable age of the
        decrypted message.
        """
        salt = ciphertext[SALT_SLICE]
        key = await self._aencryption_key(filename, salt)
        return await abytes_decrypt(ciphertext, key, aad=aad, ttl=ttl)

    async def ajson_decrypt(
        self,
        ciphertext: bytes,
        *,
        filename: str = "",
        aad: bytes = b"aad",
        ttl: int = 0,
    ):
        """
        Decrypts the ``ciphertext`` bytes with keys specific to the
        ``filename`` value & JSON loads the resulting plaintext bytes.
        ``ttl`` is the amount of seconds that dictate the allowable age
        of the decrypted message.
        """
        salt = ciphertext[SALT_SLICE]
        key = await self._aencryption_key(filename, salt)
        return await ajson_decrypt(ciphertext, key, aad=aad, ttl=ttl)

    async def aread_token(
        self,
        token: Typing.Base64URLSafe,
        *,
        filename: str = "",
        aad: bytes = b"aad",
        ttl: int = 0,
    ):
        """
        Decrypts the base64 encoded ``token`` with keys specific to the
        ``filename`` value & returns the plaintext bytes. ``ttl`` is the
        amount of seconds that dictate the allowable age of the
        decrypted message.
        """
        key = await self._aencryption_key(filename, self._TOKEN)
        return await Chunky2048(key).aread_token(token, aad=aad, ttl=ttl)

    async def _asave_ciphertext(self, filename: str, ciphertext: bytes):
        """
        Saves the encrypted value ``ciphertext`` in the database file
        called ``filename``.
        """
        path = self.directory / filename
        await self.IO.awrite(path=path, ciphertext=ciphertext)

    async def aset_tag(
        self, tag: str, data: Typing.JSONSerializable, *, cache: bool = True
    ):
        """
        Allows users to add the value ``data`` under the name ``tag``
        into the database.
        """
        filename = await self.afilename(tag)
        setattr(self._cache, filename, data)
        setattr(self._manifest, filename, tag)
        if not cache:
            await self.asave_tag(tag, drop_cache=True)

    async def _aquery_ciphertext(
        self, filename: str, *, silent: bool = False
    ):
        """
        Retrieves the value stored in the database which has the given
        ``filename``.
        """
        try:
            path = self.directory / filename
            return await self.IO.aread(path=path)
        except FileNotFoundError as corrupt_database:
            self._corrupted_files[filename] = True
            if not silent:
                raise DatabaseIssue.file_not_found(filename)

    async def aquery_tag(
        self, tag: str, *, silent: bool = False, cache: bool = False
    ):
        """
        Allows users to retrieve the value stored under the name ``tag``
        from the database.
        """
        filename = await self.afilename(tag)
        if filename in self._cache:
            return getattr(self._cache, filename)
        ciphertext = await self._aquery_ciphertext(filename, silent=silent)
        if not ciphertext:
            return
        result = await self.abytes_decrypt(ciphertext, filename=filename)
        if result[:BYTES_FLAG_SIZE] == BYTES_FLAG:
            result = result[BYTES_FLAG_SIZE:]  # Remove bytes value flag
        else:
            result = json.loads(result)
        if cache:
            setattr(self._cache, filename, result)
        return result

    async def _adelete_file(self, filename: str, *, silent=False):
        """
        Deletes a file in the database directory by ``filename``.
        """
        try:
            await asynchs.aos.remove(self.directory / filename)
        except FileNotFoundError as error:
            if not silent:
                raise error from None

    async def apop_tag(
        self, tag: str, *, admin: bool = False, silent: bool = False
    ):
        """
        Returns a value from the database by it's ``tag`` & deletes the
        associated file in the database directory.
        """
        failures = deque()
        filename = await self.afilename(tag)
        if filename in self._maintenance_files and not admin:
            raise DatabaseIssue.cant_delete_maintenance_files()
        try:
            value = await self.aquery_tag(tag, cache=False)
        except FileNotFoundError as error:
            value = None
            failures.appendleft(error)
        try:
            del self._manifest[filename]
        except KeyError as error:
            failures.appendleft(error)
        try:
            del self._cache[filename]
        except KeyError as error:
            pass
        try:
            await self._adelete_file(filename)
        except FileNotFoundError as error:
            failures.appendleft(error)
        if failures and not silent:
            raise DatabaseIssue.tag_file_doesnt_exist(tag)
        return value

    async def arollback_tag(self, tag: str, *, cache: bool = False):
        """
        Clears the new ``tag`` data from the cache which undoes any
        recent changes. If the ``tag`` data was never saved to disk,
        then removing it from the cache will prevent it from being
        saved in the database.
        """
        filename = await self.afilename(tag)
        file_exists = (self.directory / filename).is_file()
        tag_is_stored = filename in self._manifest
        if tag_is_stored and not file_exists:
            delattr(self._manifest, filename)
        elif not tag_is_stored and not file_exists:
            raise DatabaseIssue.tag_file_doesnt_exist(tag)
        if filename in self._cache:
            delattr(self._cache, filename)
            await self.aquery_tag(tag, cache=True) if cache else 0
        await asleep()

    async def aclear_cache(self):
        """
        Clears all recent changes in the cache, but this doesn't clear
        a database's metatag caches.
        """
        self._cache.namespace.clear()
        await asleep()

    async def _ametatag_key(self, tag: str):
        """
        Derives the metatag's database key given a user-defined ``tag``.
        """
        await asleep()
        key = self.__root_salt
        domain = self._METATAG_KEY
        payload = self._root_seed + repr(tag).encode()
        return await DomainKDF(domain, payload, key=key).asha3_512()

    async def ametatag(
        self, tag: str, *, preload: bool = False, silent: bool = False
    ):
        """
        Allows a user to create a child database with the name ``tag``
        accessible by dotted lookup from the parent database. Child
        databases are synchronized by their parents automatically.

        Usage Example:

        # Create a parent database ->
        key = aiootp.csprng()
        parent = await AsyncDatabase(key)

        # Name the child database ->
        tag = "sub_database"
        child = await parent.ametatag(tag)

        # The child is now accessible from the parent by the tag ->
        assert child == parent.sub_database
        """
        if tag in self.__class__.__dict__:
            raise Issue.cant_overwrite_existing_attribute(tag)
        elif tag in self.__dict__:
            if issubclass(self.__dict__[tag].__class__, self.__class__):
                return self.__dict__[tag]
            else:
                raise Issue.cant_overwrite_existing_attribute(tag)
        self.__dict__[tag] = await self.__class__(
            key=await self._ametatag_key(tag),
            depth=0,
            preload=preload,
            directory=self.directory,
            metatag=True,
            silent=silent,
        )
        if tag not in self.metatags:
            getattr(self._manifest, self._metatags_filename).append(tag)
        return self.__dict__[tag]

    async def adelete_metatag(self, tag: str):
        """
        Removes the child database named ``tag``.
        """
        if tag not in self.metatags:
            raise DatabaseIssue.no_existing_metatag(tag)
        sub_db = await self.ametatag(tag)
        await sub_db.adelete_database()
        self.__dict__.pop(tag)
        self.metatags.remove(tag)

    async def _anullify(self):
        """
        Clears the database's memory caches & instance variables of all
        values so a deleted database no longer makes changes to the
        filesystem.
        """
        self._manifest.namespace.clear()
        self._cache.namespace.clear()
        self.__dict__.clear()
        await asleep()

    async def adelete_database(self):
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        for metatag in self.metatags:
            sub_db = await self.ametatag(metatag, preload=False)
            await sub_db.adelete_database()
        for filename in self._manifest.namespace:
            await self._adelete_file(filename, silent=True)
        await self._adelete_file(self._root_salt_filename, silent=True)
        await self._anullify()

    async def _aencrypt_manifest(self, salt: bytes):
        """
        Takes a ``salt`` & returns the database's manifest encrypted.
        """
        manifest = self._manifest.namespace
        key = await self._aroot_encryption_key(self._MANIFEST, salt)
        return await ajson_encrypt(manifest, key=key, salt=salt)

    async def _asave_manifest(self, ciphertext: Typing.DictCiphertext):
        """
        Writes the manifest ledger to disk. It contains all database
        filenames & special cryptographic values for initializing the
        database's key derivation functions.
        """
        if not ciphertext:
            raise DatabaseIssue.invalid_write_attempt()
        await self.IO.awrite(path=self._root_path, ciphertext=ciphertext)

    async def _asave_root_salt(self, salt: bytes):
        """
        Writes a non-metatag database instance's root salt to disk as a
        separate file.
        """
        key = await self._aroot_encryption_key(self._SALT, salt=None)
        await self.IO.awrite(
            path=self._root_salt_path,
            ciphertext=await ajson_encrypt(salt.hex(), key=key),
        )

    async def _aclose_manifest(self):
        """
        Prepares for & writes the manifest ledger to disk. The manifest
        contains all database filenames & other metadata used to
        organize databases.
        """
        if not self._is_metatag:
            await self._asave_root_salt(self.__root_salt)
        salt = await agenerate_salt(size=SALT_BYTES)
        manifest = await self._aencrypt_manifest(salt)
        self._root_session_salt = salt
        await self._asave_manifest(manifest)

    async def _asave_file(self, filename: str, *, admin: bool = False):
        """
        Writes the cached value for a user-specified ``filename`` to the
        user filesystem.
        """
        value = getattr(self._cache, filename)
        if value.__class__ is bytes:
            value = BYTES_FLAG + value  # Assure not reloaded as JSON
        else:
            value = json.dumps(value).encode()
        ciphertext = await self.abytes_encrypt(value, filename=filename)
        await self._asave_ciphertext(filename, ciphertext)

    async def _asave_tags(self):
        """
        Writes the database's user-defined tags to disk.
        """
        filenames = self._cache.namespace
        saves = (self._asave_file(filename) for filename in filenames)
        await gather(*saves, return_exceptions=True)

    async def _asave_metatags(self):
        """
        Writes the database's child databases to disk.
        """
        db = self.__dict__
        saves = (db[metatag].asave_database() for metatag in self.metatags)
        await gather(*saves, return_exceptions=True)

    async def asave_tag(
        self, tag: str, *, admin: bool = False, drop_cache: bool = False
    ):
        """
        Writes the cached value for a user-specified ``tag`` to the user
        filesystem.
        """
        filename = await self.afilename(tag)
        try:
            await self._asave_file(filename, admin=admin)
            if drop_cache and hasattr(self._cache, filename):
                delattr(self._cache, filename)
        except AttributeError:
            raise DatabaseIssue.tag_file_doesnt_exist(tag)

    async def asave_database(self):
        """
        Writes the database's values to disk with transparent encryption.
        """
        if self._root_filename not in self._manifest:
            raise DatabaseIssue.key_has_been_deleted()
        await self._aclose_manifest()
        await gather(
            self._asave_metatags(),
            self._asave_tags(),
            return_exceptions=True,
        )

    async def amirror_database(self, database):
        """
        Copies over all of the stored & loaded values, tags & metatags
        from the ``database`` object passed into this function.
        """
        async for tag, value in aunpack.root(database):
            await self.aset_tag(tag, value)
        for metatag in database.metatags:
            my_metatag = await self.ametatag(metatag)
            await my_metatag.amirror_database(database.__dict__[metatag])

    def __contains__(self, tag: str):
        """
        Checks the cache & manifest for the filename associated with the
        user-defined ``tag``.
        """
        filename = self._filename(tag)
        return filename in self._manifest or filename in self._cache

    def __bool__(self):
        """
        Returns True if the instance dictionary is populated or the
        manifast is saved to the filesystem.
        """
        return bool(self.__dict__)

    async def __aenter__(self):
        """
        The context manager automatically writes database changes made
        by a user to disk.
        """
        return self

    async def __aexit__(
        self, exc_type=None, exc_value=None, traceback=None
    ):
        """
        The context manager automatically writes database changes made
        by a user to disk.
        """
        await self.asave_database()

    async def __aiter__(self):
        """
        Provides an interface to the names & values stored in databases.
        """
        silent = self._silent
        for tag in self.tags:
            yield (
                tag,
                await self.aquery_tag(tag, silent=silent, cache=False),
            )

    def __setitem__(self, tag: str, data: Typing.JSONSerializable):
        """
        Allows users to add the value ``data`` under the name ``tag``
        into the database.
        """
        filename = self._filename(tag)
        setattr(self._cache, filename, data)
        setattr(self._manifest, filename, tag)

    def __getitem__(self, tag: str):
        """
        Allows users to retrieve the value stored under the name ``tag``
        from the database cache.
        """
        filename = self._filename(tag)
        if filename in self._cache:
            return getattr(self._cache, filename)

    def __delitem__(self, tag: str):
        """
        Allows users to delete the value stored under the name ``tag``
        from the database.
        """
        filename = self._filename(tag)
        try:
            del self._manifest[filename]
        except KeyError:
            pass
        try:
            del self._cache[filename]
        except KeyError:
            pass
        try:
            (self.directory / filename).unlink()
        except FileNotFoundError:
            pass

    __len__ = lambda self: (
        len(self._manifest) - len(self._maintenance_files)
    )


class Database:
    """
    This class creates databases which enable the disk persistence of
    any bytes or JSON serializable native python data-types, with fully
    transparent encryption / decryption using the library's `Chunky2048`
    cipher.

    Usage Example:

    key = aiootp.csprng()
    db = Database(key)

    # Elements in a database are organized by user-defined tags ->
    db["income"] = 32000

    # Databases can store any JSON serializable data ->
    db["dict"] = {0: 1, 2: 3, 4: 5}
    db["lists"] = ["juice", ["nested juice"]]

    # As well as raw bytes ->
    db["bytes"] = b"value..."

    # Retrieve items by their tags ->
    db["dict"]
    >>> {0: 1, 2: 3, 4: 5}

    # Save changes to disk ->
    db.save_database()

    # Create child databases using what are called metatags ->
    taxes = db.metatag("taxes")
    taxes[2020] = {"jan": 130.25, "feb": 163.23, "mar": 149.68}
    assert taxes == db.taxes
    assert taxes[2020] == db.taxes[2020]

    # Delete a child database ->
    db.delete_metatag("taxes")

    # Purge the filesystem of the database files ->
    db.delete_database()
    """

    IO = BytesIO

    directory: Typing.Path = DatabasePath()

    _BASE_38_TABLE: str = Tables.BASE_38
    _KDF: bytes = Domains.KDF
    _HMAC: bytes = Domains.HMAC
    _SALT: bytes = Domains.SALT
    _SEED: bytes = Domains.SEED
    _UUID: bytes = Domains.UUID
    _TOKEN: bytes = Domains.TOKEN
    _MANIFEST: bytes = Domains.MANIFEST
    _FILENAME: bytes = Domains.FILENAME
    _FILE_KEY: bytes = Domains.FILE_KEY
    _PASSCRYPT: bytes = Domains.PASSCRYPT
    _METATAG_KEY: bytes = Domains.METATAG_KEY
    _METATAGS: bytes = sha3_256(Domains.METATAG + Domains.FILENAME).digest()

    @classmethod
    def base64_encode(cls, byte_sequence: bytes):
        """
        Encodes a raw ``bytes_sequence`` into a urlsafe base64 string.
        """
        return base64.urlsafe_b64encode(byte_sequence).decode()

    @classmethod
    def base64_decode(cls, base64_sequence: Typing.AnyStr):
        """
        Decodes a urlsafe base64 string or bytes sequence into raw bytes.
        """
        if base64_sequence.__class__ is not bytes:
            base64_sequence = base64_sequence.encode()
        return base64.urlsafe_b64decode(base64_sequence)

    @classmethod
    def _hex_to_base38(cls, hex_string: str):
        """
        Returns the received ``hex_string`` in base38 encoding.
        """
        return int_to_base(
            int(hex_string, 16), base=38, table=cls._BASE_38_TABLE
        )

    @classmethod
    def profile_exists(cls, tokens: ProfileTokens):
        """
        Tests if a profile that ``tokens`` would open has saved a salt
        file on the user filesystem. Retruens false if not.
        """
        filename = paths.deniable_filename(tokens._bytes_key)
        path = (DatabasePath() / "secure") / filename
        return path.exists()

    @classmethod
    def generate_profile_tokens(
        cls,
        *credentials: Typing.Iterable[Typing.Any],
        username: Typing.Any,
        passphrase: Typing.Any,
        salt: Typing.Any = None,
        kb: int = 32768,
        cpu: int = 3,
        hardness: int = 1024,
    ):
        """
        Runs a very expensive key derivation function to build keys
        for users to open a database with only access to potentially
        weakly entropic credentials & the filesystem.

        Usage Example:

        tokens = aiootp.Database.generate_profile_tokens(
            "server_url",     # Any number of arguments can be passed
            "email_address",  # here as additional, optional credentials.
            username="username",
            passphrase="passphrase",
            salt="optional salt keyword argument",
        )

        db = aiootp.Database.generate_profile(tokens)
        """
        UUID = cls._UUID
        summary = str((salt, passphrase, *credentials, username)).encode()
        uuid = sha3__512_hmac(UUID + summary, key=summary, hex=False)
        key = Passcrypt.new(
            summary, uuid, kb=kb, cpu=cpu, hardness=hardness
        )
        return ProfileTokens(key, uuid)

    @classmethod
    def _generate_profile_salt(
        cls, tokens: ProfileTokens, directory: Path
    ):
        """
        Creates or loads a salt value saved on the user filesystem to
        help add more entropy to their key derivation functions when
        preparing to open a profile database.
        """
        tokens._salt_path = paths.SecurePath(
            path=directory, key=tokens._bytes_key
        )
        tokens._salt = paths._read_salt_file(tokens._salt_path)
        return tokens._salt

    @classmethod
    def _generate_profile_login_key(cls, tokens: ProfileTokens):
        """
        Combines the output of the expensive key derivation functions &
        the salt stored on the filesystem gathered in preparation to
        safely open a profile database.
        """
        tokens.login_key = Passcrypt.new(tokens._bytes_key, tokens._salt)
        return tokens.login_key

    @classmethod
    def generate_profile(
        cls, tokens: ProfileTokens, directory: Path = directory, **kw
    ):
        """
        Creates & loads a profile database for a user from the ``tokens``
        passed in.

        Usage Example:

        tokens = aiootp.Database.generate_profile_tokens(
            "server_url",     # Any number of arguments can be passed
            "email_address",  # here as additional, optional credentials.
            username="username",
            passphrase="passphrase",
            salt="optional salt keyword argument",
        )

        db = aiootp.Database.generate_profile(tokens)
        """
        cls._generate_profile_salt(tokens, directory=directory)
        cls._generate_profile_login_key(tokens)
        tokens.profile = cls(
            key=tokens.login_key, depth=10000, directory=directory, **kw
        )
        if not tokens.profile._root_path.is_file():
            tokens.profile.save_database()
        return tokens.profile

    @classmethod
    def load_profile(cls, tokens: ProfileTokens, **kw):
        """
        Loads a profile database for a user from the ``tokens`` passed
        in. Throws ``LookupError`` if the profile has not yet been
        generated.
        """
        if not cls.profile_exists(tokens):
            raise DatabaseIssue.missing_profile()
        return cls.generate_profile(tokens, **kw)

    @classmethod
    def delete_profile(cls, tokens: ProfileTokens):
        """
        Deletes the profile's salt saved on the filesystem & all of its
        database files.
        """
        try:
            tokens.profile.delete_database()
        except AttributeError:
            cls.load_profile(tokens, preload=False)
            tokens.profile.delete_database()
        tokens._salt_path.unlink()

    def __init__(
        self,
        key: bytes,
        *,
        depth: int = 0,  # >= 5000 if ``key`` is weak
        preload: bool = False,
        directory: Typing.Path = directory,
        metatag: bool = False,
        silent: bool = True,
    ):
        """
        Sets a database object's basic key generators & cryptographic
        values based on the unique permutations of the ``key`` &
        ``depth`` values. If ``key`` is a passphrase, or has very
        low entropy, then ``depth`` should be a larger number.
        However, using the `generate_profile_tokens` & `generate_profile`
        methods would be a safer choice for opening a database with a
        potentially weak passphrase.

        ``preload``:    This boolean value tells the object to -- True --
            load all of the stored database values from the filesystem
            into the cache during initialization, or -- False -- skip
            the loading stage. This can save time up front so users can
            pay the cost of loading data only when that value is needed.

        ``directory``:  This value is the string or ``Pathlib.Path``
            object that points to the filesystem location where the
            database files reside / will be saved. By default, stores
            values in the directory "databases" relative to the package
            source code.

        ``metatag``:    This boolean value tells the class whether to
            prepare itself as a sub-database or not, which generally
            means less storage overhead used to secure its cryptographic
            material. Parent databases that are not metatags store a
            random salt value in their ``self._root_path`` file.

        ``silent``:     This boolean value tells the class to surpress
            exceptions when loading files so that errors in the database
            don't prevent a user from logging in.
        """
        self._silent = silent
        self._corrupted_files = {}
        self._cache = Namespace()
        self._manifest = Namespace()
        self.directory = self._format_directory(directory)
        self._is_metatag = True if metatag else False
        self._root_key, self._root_hash, self._root_filename = self._initialize_keys(
            key, depth
        )
        self._load_manifest()
        self._initialize_metatags()
        self.load_database(silent=silent, preload=preload)

    @classmethod
    def _format_directory(cls, path: Typing.OptionalPathStr):
        """
        Returns a `pathlib.Path` object to the user-specified ``path``
        if given, else returns a copy of the default database directory
        `Path` object.
        """
        if path == None:
            return Path(cls.directory).absolute()
        return Path(path).absolute()

    @classmethod
    def _derive_root_key(cls, key: bytes, depth: int):
        """
        Returns a root key derived from the user supplied key & context
        data.
        """
        key_aad = KeyAADBundle.unsafe(
            key=key,
            salt=b"derive database:",
            aad=repr((cls._KDF, depth)).encode(),
        )
        return bytes_keys(key_aad)[depth]()

    @classmethod
    def _derive_root_hash(cls, root_key: bytes):
        """
        Returns a hash derived from the instance's root key.
        """
        return sha3__512_hmac(cls._KDF + root_key, key=root_key, hex=False)

    @classmethod
    def _derive_root_filename(cls, root_hash: bytes):
        """
        Returns a 24-byte hash encoded in base38 used as the instance's
        manifest filename.
        """
        root_filename_hash = sha3__256_hmac(
            cls._FILENAME + root_hash, key=root_hash
        )
        return cls._hex_to_base38(root_filename_hash[:48])

    @classmethod
    def _initialize_keys(cls, key: bytes, depth: int = 0):
        """
        Derives the database's cryptographic root key material and the
        filename of the manifest ledger.
        """
        root_key = cls._derive_root_key(key, depth)
        root_hash = cls._derive_root_hash(root_key)
        root_filename = cls._derive_root_filename(root_hash)
        return root_key, root_hash, root_filename

    @property
    def _root_path(self):
        """
        Returns a ``pathlib.Path`` object that points to the file that
        contains the manifest ledger.
        """
        return self.directory / self._root_filename

    @property
    def _maintenance_files(self):
        """
        Returns the filenames of entries in the database that refer to
        administrative values used by objects to track and coordinate
        themselves internally.
        """
        return {self._root_filename, self._metatags_filename}

    @property
    def tags(self):
        """
        Returns a list of all user-defined names for values stored in
        the database object.
        """
        manifest = self._manifest
        return {
            getattr(manifest, filename)
            for filename in self._maintenance_files.symmetric_difference(
                manifest
            )
        }

    @property
    def filenames(self):
        """
        Returns a list of all derived filenames of user-defined tags
        stored in the database object.
        """
        manifest = self._manifest.namespace
        return {
            filename
            for filename in self._maintenance_files.symmetric_difference(
                manifest
            )
        }

    @property
    def metatags(self):
        """
        Returns the list of metatags that a database contains.
        """
        return set(
            self._manifest.namespace.get(self._metatags_filename, [])
        )

    @property
    def _root_salt_filename(self):
        """
        Returns the filename of the database's root salt.
        """
        key = self._root_key
        payload = self._root_hash
        domain = self._SALT + self._FILENAME
        filename = DomainKDF(domain, payload, key=key).sha3_256()
        return self._hex_to_base38(filename.hex()[:48])

    @property
    def _root_salt_path(self):
        """
        Returns the path of the database's root salt file if the
        instance is not a metatag.
        """
        if not self._is_metatag:
            return self.directory / self._root_salt_filename

    def _root_encryption_key(
        self, filename: bytes, salt: Typing.Optional[bytes]
    ):
        """
        Takes a ``filename`` & ``salt`` to construct a unique symmetric
        cryptographic key with preliminary database key material.
        """
        domain = self._KDF + self._FILE_KEY
        key = self._root_hash
        payload = self._root_key + repr((salt, filename)).encode()
        return DomainKDF(domain, payload, key=key).sha3_512()

    def _open_manifest(self):
        """
        Loads an existing manifest file ledger from the filesystem.
        """
        ciphertext = self.IO.read(path=self._root_path)
        salt = self._root_session_salt = ciphertext[SALT_SLICE]
        key = self._root_encryption_key(self._MANIFEST, salt)
        return json_decrypt(ciphertext, key=key)

    def _load_root_salt(self):
        """
        Pulls the root salt from the filesystem for a database instance,
        or retrieves it from the manifest file if the database is a
        metatag. Returns the result.
        """
        if self._is_metatag:
            salt = self._manifest[self._root_filename]
        else:
            encrypted_root_salt = self.IO.read(path=self._root_salt_path)
            key = self._root_encryption_key(self._SALT, salt=None)
            salt = json_decrypt(encrypted_root_salt, key=key)
        return bytes.fromhex(salt)

    def _generate_root_salt(self):
        """
        Returns a 32 byte hex salt for a metatag database, or a 64 byte
        hex salt otherwise.
        """
        if self._is_metatag:
            return generate_salt(self._root_hash, size=32)
        else:
            return csprng(self._root_hash)

    def _install_root_salt(self, salt: bytes):
        """
        Gives the manifest knowledge of the database's root ``salt``.
        This salt is the source of entropy for the database that is not
        derived from the user's key that opens the database. This salt
        is saved in the manifest if the database is a metatag, or the
        salt is saved in its own file if the database is a main parent
        database.
        """
        if self._is_metatag:
            self._manifest[self._root_filename] = salt.hex()
        else:
            self._manifest[self._root_filename] = 0

    def _generate_root_seed(self):
        """
        Returns a key that is derived from the database's main key &
        the root salt's entropy.
        """
        domain = self._SEED
        key = self.__root_salt
        payload = self._root_hash + self._root_key
        return DomainKDF(domain, payload, key=key).sha3_512()

    def _load_manifest(self):
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """
        if self._root_path.exists():
            self._manifest = Namespace(self._open_manifest())
            root_salt = self._load_root_salt()
        else:
            self._manifest = Namespace()
            self._root_session_salt = generate_salt(size=SALT_BYTES)
            root_salt = self._generate_root_salt()
            self._install_root_salt(root_salt)

        self.__root_salt = root_salt
        self._root_seed = self._generate_root_seed()

    def _initialize_metatags(self):
        """
        Initializes the values that organize database metatags, which
        are children databases contained within their parent.
        """
        self._metatags_filename = self.filename(self._METATAGS)
        if not self.metatags:
            self._manifest[self._metatags_filename] = []

    def load_tags(self, *, silent: bool = False):
        """
        Specifically loads all of the database's tag values into the
        cache.
        """
        for tag in self.tags:
            self.query_tag(tag, silent=silent, cache=True)
        return self

    def load_metatags(self, *, preload: bool = True, silent: bool = False):
        """
        Specifically loads all of the database's metatag values into the
        cache. If the ``preload`` keyword argument is falsey then the
        metatag references are populated in the database's instance
        dictionary, but their internal values are not loaded.
        """
        for metatag in set(self.metatags):
            self.metatag(metatag, preload=preload, silent=silent)
        return self

    def load_database(
        self,
        *,
        silent: bool = False,
        manifest: bool = False,
        preload: bool = True,
    ):
        """
        Loads all the database object's values from the filesystem into
        the database cache. This brings the database values into the
        cache, enables up-to-date bracket lookup of tag values & dotted
        lookup of metatags.
        """
        if manifest:
            self._load_manifest()
        if preload:
            self.load_tags(silent=silent)
        self.load_metatags(preload=preload, silent=silent)
        return self

    @lru_cache(maxsize=256)
    def filename(self, tag: Typing.Optional[str]):
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        domain = self._FILENAME
        payload = repr(tag).encode()
        key = self._root_hash + self._root_seed
        filename = DomainKDF(domain, payload, key=key).sha3_256().hex()
        return self._hex_to_base38(filename[:48])

    def make_hmac(self, data: Typing.DeterministicRepr):
        """
        Derives an HMAC hash of the supplied ``data`` with a unique
        permutation of the database's keys & a domain-specific kdf.
        """
        domain = self._HMAC
        payload = data if data.__class__ is bytes else repr(data).encode()
        key = self._root_seed + self._root_hash
        return DomainKDF(domain, payload, key=key).sha3_256()

    def test_hmac(
        self, data: Typing.DeterministicRepr, untrusted_hmac: bytes
    ):
        """
        Tests if the ``hmac`` of ``data`` is valid using the instance's
        keys & a timing-safe comparison.
        """
        if not hmac:
            raise Issue.no_value_specified("untrusted_hmac")
        true_hmac = self.make_hmac(data)
        if bytes_are_equal(untrusted_hmac, true_hmac):
            return True
        else:
            raise Issue.invalid_value("HMAC of data stream")

    def _encryption_key(self, filename: str, salt: bytes):
        """
        Takes a ``filename`` & ``salt`` to contruct a unique symmetric
        cryptographic key.
        """
        domain = self._FILE_KEY
        key = self._root_seed
        payload = self.__root_salt + salt + filename.encode()
        return DomainKDF(domain, payload, key=key).sha3_512()

    def bytes_encrypt(
        self, plaintext: bytes, *, filename: str = "", aad: bytes = b"aad"
    ):
        """
        Encrypts the ``plaintext`` bytes with keys specific to the
        ``filename`` value & returns the ciphertext bytes.
        """
        salt = generate_salt(size=SALT_BYTES)
        key = self._encryption_key(filename, salt)
        return bytes_encrypt(plaintext, key, salt=salt, aad=aad)

    def json_encrypt(
        self,
        plaintext: Typing.JSONSerializable,
        *,
        filename: str = "",
        aad: bytes = b"aad",
    ):
        """
        Encrypts the JSON serializable ``plaintext`` object with keys
        specific to the ``filename`` value & returns the ciphertext
        bytes.
        """
        salt = generate_salt(size=SALT_BYTES)
        key = self._encryption_key(filename, salt)
        return json_encrypt(plaintext, key, salt=salt, aad=aad)

    def make_token(
        self, plaintext: bytes, *, filename: str = "", aad: bytes = b"aad"
    ):
        """
        Encrypts the ``plaintext`` bytes with keys specific to the
        ``filename`` value & base64 encodes the resulting ciphertext
        bytes.
        """
        key = self._encryption_key(filename, self._TOKEN)
        return Chunky2048(key).make_token(plaintext, aad=aad)

    def bytes_decrypt(
        self,
        ciphertext: bytes,
        *,
        filename: str = "",
        aad: bytes = b"aad",
        ttl: int = 0
    ):
        """
        Decrypts the ``ciphertext`` bytes with keys specific to the
        ``filename`` value & returns the plaintext bytes. ``ttl`` is the
        amount of seconds that dictate the allowable age of the
        decrypted message.
        """
        salt = ciphertext[SALT_SLICE]
        key = self._encryption_key(filename, salt)
        return bytes_decrypt(ciphertext, key, aad=aad, ttl=ttl)

    def json_decrypt(
        self,
        ciphertext: bytes,
        *,
        filename: str = "",
        aad: bytes = b"aad",
        ttl: int = 0
    ):
        """
        Decrypts the ``ciphertext`` bytes with keys specific to the
        ``filename`` value & JSON loads the resulting plaintext bytes.
        ``ttl`` is the amount of seconds that dictate the allowable age
        of the decrypted message.
        """
        salt = ciphertext[SALT_SLICE]
        key = self._encryption_key(filename, salt)
        return json_decrypt(ciphertext, key=key, aad=aad, ttl=ttl)

    def read_token(
        self,
        token: Typing.Base64URLSafe,
        *,
        filename: str = "",
        aad: bytes = b"aad",
        ttl: int = 0,
    ):
        """
        Decrypts the base64 encoded ``token`` with keys specific to the
        ``filename`` value & returns the plaintext bytes. ``ttl`` is the
        amount of seconds that dictate the allowable age of the
        decrypted message.
        """
        key = self._encryption_key(filename, self._TOKEN)
        return Chunky2048(key).read_token(token, aad=aad, ttl=ttl)

    def _save_ciphertext(self, filename: str, ciphertext: bytes):
        """
        Saves the encrypted value ``ciphertext`` in the database file
        called ``filename``.
        """
        path = self.directory / filename
        self.IO.write(path=path, ciphertext=ciphertext)

    def set_tag(
        self, tag: str, data: Typing.JSONSerializable, *, cache: bool = True
    ):
        """
        Allows users to add the value ``data`` under the name ``tag``
        into the database.
        """
        filename = self.filename(tag)
        setattr(self._cache, filename, data)
        setattr(self._manifest, filename, tag)
        if not cache:
            self.save_tag(tag, drop_cache=True)

    def _query_ciphertext(self, filename: str, *, silent: bool = False):
        """
        Retrieves the value stored in the database which has the given
        ``filename``.
        """
        try:
            path = self.directory / filename
            return self.IO.read(path=path)
        except FileNotFoundError as corrupt_database:
            self._corrupted_files[filename] = True
            if not silent:
                raise DatabaseIssue.file_not_found(filename)

    def query_tag(
        self, tag: str, *, silent: bool = False, cache: bool = False
    ):
        """
        Allows users to retrieve the value stored under the name ``tag``
        from the database.
        """
        filename = self.filename(tag)
        if filename in self._cache:
            return getattr(self._cache, filename)
        ciphertext = self._query_ciphertext(filename, silent=silent)
        if not ciphertext:
            return
        result = self.bytes_decrypt(ciphertext, filename=filename)
        if result[:BYTES_FLAG_SIZE] == BYTES_FLAG:
            result = result[BYTES_FLAG_SIZE:]  # Remove bytes value flag
        else:
            result = json.loads(result)
        if cache:
            setattr(self._cache, filename, result)
        return result

    def _delete_file(self, filename: str, *, silent=False):
        """
        Deletes a file in the database directory by ``filename``.
        """
        try:
            (self.directory / filename).unlink()
        except FileNotFoundError as error:
            if not silent:
                raise error from None

    def pop_tag(
        self, tag: str, *, admin: bool = False, silent: bool = False
    ):
        """
        Returns a value from the database by it's ``tag`` & deletes the
        associated file in the database directory.
        """
        failures = deque()
        filename = self.filename(tag)
        if filename in self._maintenance_files and not admin:
            raise DatabaseIssue.cant_delete_maintenance_files()
        try:
            value = self.query_tag(tag, cache=False)
        except FileNotFoundError as error:
            value = None
            failures.appendleft(error)
        try:
            del self._manifest[filename]
        except KeyError as error:
            failures.appendleft(error)
        try:
            del self._cache[filename]
        except KeyError as error:
            pass
        try:
            self._delete_file(filename)
        except FileNotFoundError as error:
            failures.appendleft(error)
        if failures and not silent:
            raise DatabaseIssue.tag_file_doesnt_exist(tag)
        return value

    def rollback_tag(self, tag: str, *, cache: bool = False):
        """
        Clears the new ``tag`` data from the cache which undoes any
        recent changes. If the ``tag`` data was never saved to disk,
        then removing it from the cache will prevent it from being
        saved in the database.
        """
        filename = self.filename(tag)
        file_exists = (self.directory / filename).is_file()
        tag_is_stored = filename in self._manifest
        if tag_is_stored and not file_exists:
            delattr(self._manifest, filename)
        elif not tag_is_stored and not file_exists:
            raise DatabaseIssue.tag_file_doesnt_exist(tag)
        if filename in self._cache:
            delattr(self._cache, filename)
            self.query_tag(tag, cache=True) if cache else 0

    def clear_cache(self):
        """
        Clears all recent changes in the cache, but this doesn't clear
        a database's metatag caches.
        """
        self._cache.namespace.clear()

    def _metatag_key(self, tag: str):
        """
        Derives the metatag's database key given a user-defined ``tag``.
        """
        key = self.__root_salt
        domain = self._METATAG_KEY
        payload = self._root_seed + repr(tag).encode()
        return DomainKDF(domain, payload, key=key).sha3_512()

    def metatag(
        self, tag: str, *, preload: bool = False, silent: bool = False
    ):
        """
        Allows a user to create a child database with the name ``tag``
        accessible by dotted lookup from the parent database. Child
        databases are synchronized by their parents automatically.

        Usage Example:

        # Create a parent database ->
        key = aiootp.csprng()
        parent = Database(key)

        # Name the child database ->
        tag = "sub_database"
        child = await parent.ametatag(tag)

        # The child is now accessible from the parent by the tag ->
        assert child == parent.sub_database
        """
        if tag in self.__class__.__dict__:
            raise Issue.cant_overwrite_existing_attribute(tag)
        elif tag in self.__dict__:
            if issubclass(self.__dict__[tag].__class__, self.__class__):
                return self.__dict__[tag]
            else:
                raise Issue.cant_overwrite_existing_attribute(tag)
        self.__dict__[tag] = self.__class__(
            key=self._metatag_key(tag),
            depth=0,
            preload=preload,
            directory=self.directory,
            metatag=True,
            silent=silent,
        )
        if tag not in self.metatags:
            getattr(self._manifest, self._metatags_filename).append(tag)
        return self.__dict__[tag]

    def delete_metatag(self, tag: str):
        """
        Removes the child database named ``tag``.
        """
        if tag not in self.metatags:
            raise DatabaseIssue.no_existing_metatag(tag)
        self.metatag(tag).delete_database()
        self.__dict__.pop(tag)
        self.metatags.remove(tag)

    def _nullify(self):
        """
        Clears the database's memory caches & instance variables of all
        values so a deleted database no longer makes changes to the
        filesystem.
        """
        self._manifest.namespace.clear()
        self._cache.namespace.clear()
        self.__dict__.clear()

    def delete_database(self):
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        for metatag in self.metatags:
            self.metatag(metatag, preload=False).delete_database()
        for filename in self._manifest.namespace:
            self._delete_file(filename, silent=True)
        self._delete_file(self._root_salt_filename, silent=True)
        self._nullify()

    def _encrypt_manifest(self, salt: bytes):
        """
        Takes a ``salt`` & returns the database's manifest encrypted.
        """
        manifest = self._manifest.namespace
        key = self._root_encryption_key(self._MANIFEST, salt)
        return json_encrypt(manifest, key=key, salt=salt)

    def _save_manifest(self, ciphertext: bytes):
        """
        Writes the manifest ledger to disk. It contains all database
        filenames & special cryptographic values for initializing the
        database's key derivation functions.
        """
        if not ciphertext:
            raise DatabaseIssue.invalid_write_attempt()
        self.IO.write(path=self._root_path, ciphertext=ciphertext)

    def _save_root_salt(self, salt: bytes):
        """
        Writes a non-metatag database instance's root salt to disk as a
        separate file.
        """
        key = self._root_encryption_key(self._SALT, salt=None)
        self.IO.write(
            path=self._root_salt_path,
            ciphertext=json_encrypt(salt.hex(), key=key),
        )

    def _close_manifest(self):
        """
        Prepares for & writes the manifest ledger to disk. The manifest
        contains all database filenames & other metadata used to
        organize databases.
        """
        if not self._is_metatag:
            self._save_root_salt(self.__root_salt)
        salt = generate_salt(size=SALT_BYTES)
        manifest = self._encrypt_manifest(salt)
        self._root_session_salt = salt
        self._save_manifest(manifest)

    def _save_file(self, filename: str, *, admin: bool = False):
        """
        Writes the cached value for a user-specified ``filename`` to the
        user filesystem.
        """
        value = getattr(self._cache, filename)
        if value.__class__ is bytes:
            value = BYTES_FLAG + value  # Assure not reloaded as JSON
        else:
            value = json.dumps(value).encode()
        ciphertext = self.bytes_encrypt(value, filename=filename)
        self._save_ciphertext(filename, ciphertext)

    def _save_tags(self):
        """
        Writes the database's user-defined tags to disk.
        """
        for filename in self._cache.namespace:
            self._save_file(filename)

    def _save_metatags(self):
        """
        Writes the database's child databases to disk.
        """
        db = self.__dict__
        for metatag in self.metatags:
            db[metatag].save_database()

    def save_tag(
        self, tag: str, *, admin: bool = False, drop_cache: bool = False
    ):
        """
        Writes the cached value for a user-specified ``tag`` to the user
        filesystem.
        """
        filename = self.filename(tag)
        try:
            self._save_file(filename, admin=admin)
            if drop_cache and hasattr(self._cache, filename):
                delattr(self._cache, filename)
        except AttributeError:
            raise DatabaseIssue.tag_file_doesnt_exist(tag)

    def save_database(self):
        """
        Writes the database's values to disk with transparent encryption.
        """
        if self._root_filename not in self._manifest:
            raise DatabaseIssue.key_has_been_deleted()
        self._close_manifest()
        self._save_metatags()
        self._save_tags()

    def mirror_database(self, database):
        """
        Copies over all of the stored & loaded values, tags & metatags
        from the ``database`` object passed into this function.
        """
        if issubclass(database.__class__, self.__class__):
            for tag, value in database:
                self.set_tag(tag, value)
        else:
            # Works with async databases, but doesn't load unloaded values
            for tag in database.tags:
                self.set_tag(tag, database[tag])
        for metatag in set(database.metatags):
            my_metatag = self.metatag(metatag)
            my_metatag.mirror_database(database.__dict__[metatag])

    def __contains__(self, tag: str):
        """
        Checks the cache & manifest for the filename associated with the
        user-defined ``tag``.
        """
        filename = self.filename(tag)
        return filename in self._manifest or filename in self._cache

    def __bool__(self):
        """
        Returns True if the instance dictionary is populated or the
        manifast is saved to the filesystem.
        """
        return bool(self.__dict__)

    def __enter__(self):
        """
        The context manager automatically writes database changes made
        by a user to disk.
        """
        return self

    def __exit__(self, exc_type=None, exc_value=None, traceback=None):
        """
        The context manager automatically writes database changes made
        by a user to disk.
        """
        self.save_database()

    def __iter__(self):
        """
        Provides an interface to the names & values stored in databases.
        """
        silent = self._silent
        for tag in self.tags:
            yield tag, self.query_tag(tag, silent=silent, cache=False)

    def __getitem__(self, tag: str):
        """
        Allows users to retrieve the value stored under the name ``tag``
        from the database cache.
        """
        filename = self.filename(tag)
        if filename in self._cache:
            return getattr(self._cache, filename)

    __delitem__ = pop_tag
    __setitem__ = vars()["set_tag"]
    __len__ = lambda self: (
        len(self._manifest) - len(self._maintenance_files)
    )


extras = dict(
    AsyncDatabase=AsyncDatabase,
    Chunky2048=Chunky2048,
    Database=Database,
    StreamHMAC=StreamHMAC,
    SyntheticIV=SyntheticIV,
    __doc__=__doc__,
    __main_exports__=__all__,
    __package__=__package__,
    _abytes_xor=abytes_xor,
    _akeypair_ratchets=akeypair_ratchets,
    _asingle_use_key=asingle_use_key,
    _atest_key_salt_aad=atest_key_salt_aad,
    _bytes_xor=bytes_xor,
    _keypair_ratchets=keypair_ratchets,
    _single_use_key=single_use_key,
    _test_key_salt_aad=test_key_salt_aad,
    abytes_decipher=abytes_decipher,
    abytes_decrypt=abytes_decrypt,
    abytes_encipher=abytes_encipher,
    abytes_encrypt=abytes_encrypt,
    ajson_decrypt=ajson_decrypt,
    ajson_encrypt=ajson_encrypt,
    bytes_decipher=bytes_decipher,
    bytes_decrypt=bytes_decrypt,
    bytes_encipher=bytes_encipher,
    bytes_encrypt=bytes_encrypt,
    json_decrypt=json_decrypt,
    json_encrypt=json_encrypt,
)


ciphers = commons.make_module("ciphers", mapping=extras)

