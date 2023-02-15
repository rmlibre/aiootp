# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "AsyncCipherStream",
    "AsyncDecipherStream",
    "Chunky2048",
    "CipherStream",
    "DecipherStream",
    "abytes_decrypt",
    "abytes_encrypt",
    "ajson_decrypt",
    "ajson_encrypt",
    "bytes_decrypt",
    "bytes_encrypt",
    "json_decrypt",
    "json_encrypt",
]


__doc__ = (
    "A collection of low-level tools & higher level abstractions which "
    "can be used to create custom security tools, or as pre-assembled r"
    "ecipes, including the package's main online salt reuse / misuse re"
    "sistant, tweakable AEAD cipher called `Chunky2048`."
)


import io
import hmac
import json
import base64
from collections import deque
from secrets import token_bytes
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from .__constants import *
from ._containers import *
from ._exceptions import *
from ._typing import Typing as t
from .paths import Path, DatabasePath
from .asynchs import AsyncInit, asleep, gather
from .commons import DeletedAttribute
from .commons import make_module
from .gentools import comprehension
from .gentools import data as _data
from .gentools import adata
from .gentools import unpack, aunpack
from .gentools import popleft, apopleft
from .randoms import csprng, acsprng
from .randoms import generate_iv
from .randoms import generate_key, agenerate_key
from .randoms import generate_salt, agenerate_salt
from .generics import Domains, Padding, BytesIO, Clock
from .generics import encode_key, aencode_key
from .generics import hash_bytes, ahash_bytes
from .generics import int_as_base, aint_as_base
from .generics import int_as_bytes, aint_as_bytes
from .generics import len_as_bytes, alen_as_bytes
from .generics import bytes_as_int, abytes_as_int
from .generics import canonical_pack, acanonical_pack
from .generics import bytes_are_equal, abytes_are_equal
from .generics import fullblock_ljust, afullblock_ljust


clock = Clock(SECONDS)


async def atest_key_salt_aad(key: bytes, salt: bytes, aad: bytes) -> None:
    """
    Validates the main symmetric user ``key``, ephemeral ``salt``, &
    ``aad`` authenticated associated data for the `Chunky2048` cipher.
    """
    if key.__class__ is not bytes:
        raise Issue.value_must_be_type("main key", bytes)
    elif len(key) < MIN_KEY_BYTES:
        raise KeyAADIssue.invalid_key()
    elif salt.__class__ is not bytes:
        raise Issue.value_must_be_type("salt", bytes)
    elif len(salt) != SALT_BYTES:
        raise KeyAADIssue.invalid_salt(SALT_BYTES)
    elif aad.__class__ is not bytes:
        raise Issue.value_must_be_type("aad", bytes)


def test_key_salt_aad(key: bytes, salt: bytes, aad: bytes) -> None:
    """
    Validates the main symmetric user ``key``, ephemeral ``salt``, &
    ``aad`` authenticated associated data for the `Chunky2048` cipher.
    """
    if key.__class__ is not bytes:
        raise Issue.value_must_be_type("main key", bytes)
    elif len(key) < MIN_KEY_BYTES:
        raise KeyAADIssue.invalid_key()
    elif salt.__class__ is not bytes:
        raise Issue.value_must_be_type("salt", bytes)
    elif len(salt) != SALT_BYTES:
        raise KeyAADIssue.invalid_salt(SALT_BYTES)
    elif aad.__class__ is not bytes:
        raise Issue.value_must_be_type("aad", bytes)


async def amake_non_deterministic_salt(
    salt: t.Optional[bytes], *, disable: bool = False
) -> bytes:
    """
    Prevents a deterministic salt from being used for an encryption
    procedure without explicitly passing the appropriate flag to do so.
    Returns a random 16-byte salt otherwise.
    """
    if disable:
        return salt if salt else await agenerate_salt(SALT_BYTES)
    elif salt:
        raise Issue.unsafe_determinism()
    else:
        return await agenerate_salt(SALT_BYTES)


def make_non_deterministic_salt(
    salt: t.Optional[bytes], *, disable: bool = False
) -> bytes:
    """
    Prevents a deterministic salt from being used for an encryption
    procedure without explicitly passing the appropriate flag to do so.
    Returns a random 16-byte salt otherwise.
    """
    if disable:
        return salt if salt else generate_salt(SALT_BYTES)
    elif salt:
        raise Issue.unsafe_determinism()
    else:
        return generate_salt(SALT_BYTES)


async def asingle_use_key_bundle(
    key: t.Optional[bytes] = None,
    *,
    salt: t.Optional[bytes] = None,
    aad: bytes = DEFAULT_AAD,
    allow_dangerous_determinism: bool = False,
) -> KeySaltAAD:
    """
    Returns a mapping containing a unique combination of a ``key``,
    ``salt`` & ``aad`` whose use is limited TO A SINGLE encryption /
    decryption round. The reuse of the same permutation of ``key``,
    ``salt`` & ``aad`` for multiple different messages reduces the
    security of the cipher to the randomly generated `iv` & the inner-
    header of the plaintext, which is padding provided by the `Padding`
    class.

    New ``key`` & ``salt`` values are returned in the mapping if neither
    are specified.
    """
    key_and_salt = key and salt
    key = key if key else await acsprng()
    salt = await amake_non_deterministic_salt(
        salt, disable=allow_dangerous_determinism or not key_and_salt
    )
    await atest_key_salt_aad(key, salt, aad)
    return KeySaltAAD(key, salt, aad)


def single_use_key_bundle(
    key: t.Optional[bytes] = None,
    *,
    salt: t.Optional[bytes] = None,
    aad: bytes = DEFAULT_AAD,
    allow_dangerous_determinism: bool = False,
) -> KeySaltAAD:
    """
    Returns a mapping containing a unique combination of a ``key``,
    ``salt`` & ``aad`` whose use is limited TO A SINGLE encryption /
    decryption round. The reuse of the same permutation of ``key``,
    ``salt`` & ``aad`` for multiple different messages reduces the
    security of the cipher to the randomly generated `iv` & the inner-
    header of the plaintext, which is padding provided by the `Padding`
    class.

    New ``key`` & ``salt`` values are returned in the mapping if neither
    are specified.
    """
    key_and_salt = key and salt
    key = key if key else csprng()
    salt = make_non_deterministic_salt(
        salt, disable=allow_dangerous_determinism or not key_and_salt
    )
    test_key_salt_aad(key, salt, aad)
    return KeySaltAAD(key, salt, aad)


class Chunky2048KDFs:
    """
    A private type which is responsible for initializing the keystream
    key-derivation & mac objects for the `Chunky2048` cipher.
    """

    __slots__ = ("_summary", "_key")

    _SEED_KDF_SALT: bytes = Domains.encode_constant(
        b"chunky2048_seed_kdf_salt", size=SEED_KDF_BLOCKSIZE
    )
    _LEFT_KDF_SALT: bytes = Domains.encode_constant(
        b"chunky2048_left_kdf_salt", size=LEFT_KDF_BLOCKSIZE
    )
    _RIGHT_KDF_SALT: bytes = Domains.encode_constant(
        b"chunky2048_right_kdf_salt", size=RIGHT_KDF_BLOCKSIZE
    )
    _SHMAC_MAC_SALT: bytes = Domains.encode_constant(
        b"chunky2048_shmac_mac_salt", size=SHMAC_BLOCKSIZE
    )

    _new_seed_kdf: callable = shake_128(_SEED_KDF_SALT).copy
    _new_left_kdf: callable = shake_128(_LEFT_KDF_SALT).copy
    _new_right_kdf: callable = shake_128(_RIGHT_KDF_SALT).copy
    _new_shmac_mac: callable = shake_128(_SHMAC_MAC_SALT).copy

    _KDF_TYPES = {
        # This offset is intended to reduce the potential control an
        # adversary can exert when the StreamHMAC object's digest is
        # being xor'd into the seed_kdf's state by spreading each update
        # in half over two different blocks.
        # ----------------------------------vvvvvvvvvvvvvvv
        SEED_KDF: (_new_seed_kdf, SEED_PAD, SEED_KDF_OFFSET),
        LEFT_KDF: (_new_left_kdf, LEFT_PAD, b""),
        RIGHT_KDF: (_new_right_kdf, RIGHT_PAD, b""),
        SHMAC: (_new_shmac_mac, SHMAC_PAD, b""),
    }

    # Cause ciphertexts to be unique & plaintexts to be scrambled for
    # any distinct variations of the cipher if the package is modified.
    # IMPORTANT FOR SECURITY. (https://eprint.iacr.org/2016/292.pdf)
    # DO NOT OVERRIDE TO PROVIDE ITER-OP.
    METADATA = canonical_pack(
        int_as_bytes(EPOCH_NS, size=16),
        int_as_bytes(BLOCKSIZE, size=2),
        int_as_bytes(BLOCK_ID_BYTES, size=1),
        int_as_bytes(SHMAC_BYTES, size=1),
        int_as_bytes(SALT_BYTES, size=1),
        int_as_bytes(IV_BYTES, size=1),
        int_as_bytes(TIMESTAMP_BYTES, size=1),
        int_as_bytes(SIV_KEY_BYTES, size=2),
        int_as_bytes(MIN_PADDING_BLOCKS, size=2),
        pad=b"",
        int_bytes=1,
    )

    def __init__(self, summary: bytes, *, key: bytes) -> "self":
        """
        Stores the full metadata & values summary provided by the
        `KeyAADBundle`.
        """
        self._summary = summary
        self._key = key

    def __iter__(self) -> "self":
        """
        Yields a set of fresh seed, left & right KDFs & the shmac for
        the instance's given summary.
        """
        yield self._initialize_chunky2048_kdf(SEED_KDF)
        yield self._initialize_chunky2048_kdf(LEFT_KDF)
        yield self._initialize_chunky2048_kdf(RIGHT_KDF)
        yield self._initialize_chunky2048_kdf(SHMAC)

    def _initialize_chunky2048_kdf(self, kdf_name: str) -> SHAKE_128_TYPE:
        """
        A generalized KDF initializer which works for the seed, left &
        right KDFs, & the StreamHMAC MAC.
        """
        factory, pad, offset = self._KDF_TYPES[kdf_name]
        kdf = factory()
        kdf.update(
            encode_key(self._key, kdf.block_size, pad=pad)
            + fullblock_ljust(self._summary, kdf.block_size, pad=pad)
            + offset
        )
        return kdf


class KeyAADBundle:
    """
    A low-level interface for managing a key, salt, iv & authenticated
    associated data bundle which is to be used for ONLY ONE encryption.
    If a unique bundle is used for more than one encryption, then the
    security of the `Chunky2048` cipher may be greatly damaged.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.

    ``salt``: An ephemeral, uniform 16-byte salt value. Automatically
            generated during encryption if not supplied. SHOULD BE
            USED ONLY ONCE for each encryption. Any repeats can harm
            anonymity & unnecessarily forces ciphertext security to rely
            on the salt reuse / misuse properties of the cipher. This
            value can be sent in the clear along with the ciphertext.

    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of `key`, `salt` & `iv`.

    ``iv``: An ephemeral, uniform 16-byte value, generated automatically
            & at random by the encryption algorithm. Helps ensure salt
            reuse / misue security even if the `key`, `salt` & `aad` are
            the same for ~2**64 messages. This value can be sent in the
            clear along with the ciphertext.
    """

    __slots__ = (
        "__keys",
        "_bundle",
        "_mode",
        "_registers",
        "_iv",
        "_iv_given_by_user",
    )

    _generate_bundle = staticmethod(single_use_key_bundle)
    _agenerate_bundle = staticmethod(asingle_use_key_bundle)

    @staticmethod
    def _test_iv(iv: bytes) -> None:
        """
        Assures the ``iv`` is a 16-byte bytestring.
        """
        if iv.__class__ is not bytes:
            raise Issue.value_must_be_type("iv", bytes)
        elif len(iv) != IV_BYTES:
            raise Issue.invalid_length("iv", IV_BYTES)

    def _set_iv(self, iv: bytes) -> bool:
        """
        Sets the instance's ``iv`` if it passes tests. Returns `True`
        if the ``iv`` was given by the user, otherwise returns `False`
        to indicate a fresh value was randomly sampled. The ``iv``
        should NOT be set by the user during encryption! Creating a new
        random IV during encryption ensures the user cannot accidentally
        prevent the derived key material from being fresh, & salt reuse
        / misue security even if the `key`, `salt` & `aad` are the same
        for ~2**64 messages.
        """
        if iv:
            self._test_iv(iv)
            self._iv = iv
            self._iv_given_by_user = True
            return True
        else:
            self._iv = generate_iv(IV_BYTES)
            self._iv_given_by_user = False
            return False

    @classmethod
    async def aunsafe(
        cls,
        key: bytes,
        salt: bytes = b"",
        aad: bytes = DEFAULT_AAD,
        iv: bytes = b"",
    ) -> "self":
        """
        Allows instances to be used in the `(a)bytes_keys` coroutines
        without checking for unsafe reuse or checking for the
        correctness of the ``key``, ``salt``, ``aad`` & ``iv`` values.

        This is useful for when the coroutines are needed as CSPRNGs,
        or KDFs, outside of the context of the `Chunky2048` cipher.
        --------
        WARNING: DO NOT use this initializer within other `Chunky2048`
        -------- cipher interfaces which expect a `key_bundle`.
        """
        try:
            await asleep()
            return cls.unsafe(key, salt, aad, iv)
        finally:
            await asleep()

    @classmethod
    def unsafe(
        cls,
        key: bytes,
        salt: bytes = b"",
        aad: bytes = DEFAULT_AAD,
        iv: bytes = b"",
    ) -> "self":
        """
        Allows instances to be used in the `(a)bytes_keys` coroutines
        without checking for unsafe reuse or checking for the
        correctness of the ``key``, ``salt``, ``aad`` & ``iv`` values.

        This is useful for when the coroutines are needed as CSPRNGs,
        or KDFs, outside of the context of the `Chunky2048` cipher.
        --------
        WARNING: DO NOT use this initializer within other `Chunky2048`
        -------- cipher interfaces which expect a `key_bundle`.
        """
        self = cls.__new__(cls)
        self._iv: bytes = iv
        self._mode = KeyAADMode()
        self._registers = NoRegisters()
        self._bundle = KeySaltAAD(key, salt, aad)
        self._initialize_keys()
        return self

    def __init__(
        self,
        key: t.Optional[bytes] = None,
        *,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
        iv: bytes = b"",
        allow_dangerous_determinism: bool = False,
    ) -> "self":
        """
        Stores the ``key``, ``salt`` & ``aad`` in a private object, &
        initializes the keys & KDFs for this permutation of the values.

        Since the ``iv`` should only be passed when the bundle is to be
        used for decryption, the ``allow_dangerous_determinism`` keyword-
        only argument doesn't need to be passed when the ``iv`` is.
        """
        override = self._set_iv(iv) or allow_dangerous_determinism
        self._mode = KeyAADMode()
        self._registers = KeyAADBundleRegisters()
        self._bundle: KeySaltAAD = self._generate_bundle(
            key=key,
            salt=salt,
            aad=aad,
            allow_dangerous_determinism=override,
        )
        self._initialize_keys()

    def __iter__(self) -> "self":
        """
        Yields the instance's salt, authenticated associated data then
        the IV, along with the contextual data the cipher is being run
        in.
        """
        yield self._bundle.salt
        yield self._bundle.aad
        yield self._iv
        yield Chunky2048KDFs.METADATA

    def _initialize_keys(self) -> None:
        """
        Creates a canonicalized summary for the `Chunky2048` cipher's
        KDFs.
        """
        self.__keys = keys = Chunky2048Keys()
        # encode key material, salt & aad with their length metadata
        summary = canonical_pack(*self, pad=b"", int_bytes=4)
        # keystream kdfs
        kdfs = Chunky2048KDFs(summary, key=self._bundle.key)
        keys.seed_kdf, keys.left_kdf, keys.right_kdf, keys.shmac_mac = kdfs

    async def _agenerate_algorithm_keys(self) -> None:
        """
        Starts the `Chunky2048` cipher's async keystream generator. This
        stores its first 256-byte output to mask the first block of
        plaintext after it retrieves the inner-header for use as an SIV
        to uniquely randomize the keystream. See `SyntheticIV`.
        """
        keys = self.__keys
        # init keystream
        keys.keystream = keystream = abytes_keys.root(self)
        keys.primer_key = primer_key = await keystream.asend(None)  # 256-bytes
        if len(primer_key) != BLOCKSIZE:
            raise Issue.invalid_length("keystream key", BLOCKSIZE)

    def _generate_algorithm_keys(self) -> None:
        """
        Starts the `Chunky2048` cipher's sync keystream generator. This
        stores its first 256-byte output to mask the first block of
        plaintext after it retrieves the inner-header for use as an SIV
        to uniquely randomize the keystream. See `SyntheticIV`.
        """
        keys = self.__keys
        # init keystream
        keys.keystream = keystream = bytes_keys.root(self)
        keys.primer_key = primer_key = keystream.send(None)  # 256-bytes
        if len(primer_key) != BLOCKSIZE:
            raise Issue.invalid_length("keystream key", BLOCKSIZE)

    async def async_mode(self) -> "self":
        """
        Sets the instance up to run async `Chunky2048` key derivation.
        """
        await self._agenerate_algorithm_keys()
        self._mode.set_async_mode()
        return self

    def sync_mode(self) -> "self":
        """
        Sets the instance up to run sync `Chunky2048` key derivation.
        """
        self._generate_algorithm_keys()
        self._mode.set_sync_mode()
        return self

    def _register_shmac(self, shmac) -> None:
        """
        Registers the shmac which will be tied to the instance for a
        single run of the `Chunky2048` cipher. Reusing an instance or
        the same shmac for multiple cipher calls is NOT SAFE, & is
        disallowed by this registration.
        """
        if hasattr(self._registers, "shmac"):
            raise KeyAADIssue.shmac_already_registered()
        self._registers.register("shmac", shmac)

    def _register_keystream(self) -> None:
        """
        Registers the keystream which will be tied to the instance for a
        single run of the `Chunky2048` cipher. Reusing an instance is
        NOT SAFE, & is disallowed by this registration.
        """
        if hasattr(self._registers, "keystream"):
            raise KeyAADIssue.keystream_already_registered()
        self._registers.register("keystream", True)

    @property
    def _keys(self) -> t.Generator[None, SHAKE_128_TYPE, None]:
        """
        Returns the private iterable of the KDFs used by `Chunky2048`.
        """
        return self.__keys.__iter__()

    @property
    def _kdf(self) -> SEED_KDF_TYPE:
        """
        Returns the private seed KDF.
        """
        return self.__keys.seed_kdf

    @property
    def _shmac_mac(self) -> SHMAC_TYPE:
        """
        Returns the private `shake_128` MAC object used by the
        `StreamHMAC` class.
        """
        return self.__keys.shmac_mac

    @property
    def _keystream(self) -> t.Union[
        t.Generator[bytes, bytes, None],
        t.AsyncGenerator[bytes, bytes],
    ]:
        """
        Returns the private keystream coroutine used in the `Chunky2048`
        cipher to encrypt / decrypt data. The coroutine can be either
        async or sync depending on what mode the instance is set to.
        """
        return self.__keys.keystream

    @property
    def _primer_key(self) -> bytes:
        """
        Returns the private primer key used by the `SyntheticIV` class
        to mask the timestamp & IV-key prepended to plaintexts during
        the message padding phase.
        """
        return self.__keys.primer_key

    @property
    def key(self) -> bytes:
        """
        Returns the main, longer-term symmetric user ``key``. It must be
        be AT LEAST 64 bytes, but any larger key length is also
        supported.
        """
        return self._bundle.key

    @property
    def salt(self) -> bytes:
        """
        Returns the ephemeral, uniform 16-byte salt value. Automatically
        generated during encryption if not supplied. SHOULD BE USED ONLY
        ONCE for each encryption. Any repeats reduce salt reuse / misuse
        security by 64 bits. It also harms anonymity. This value can be
        sent in the clear along with the ciphertext.
        """
        return self._bundle.salt

    @property
    def aad(self) -> bytes:
        """
        Returns the authenticated associated data, ``aad``, which is
        also used to securely alter derived key material per unique
        permutation of `salt`, `iv` & user `key`.
        .
        """
        return self._bundle.aad

    @property
    def iv(self) -> bytes:
        """
        Returns the 16-byte ephemeral, uniform ``iv`` value, generated
        automatically & at random by the encryption algorithm. Helps
        ensure salt reuse / misue security even if the `key`, `salt` &
        `aad` are the same for ~2**64 messages. This value can be sent
        in the clear along with the ciphertext.
        """
        return self._iv


async def akeystream_ratchets(key_bundle: KeyAADBundle) -> t.Tuple[
    t.Callable[[bytes], None],
    t.Callable[[int], bytes],
    t.Callable[[bytes], None],
    t.Callable[[int], bytes],
    t.Callable[[bytes], None],
    t.Callable[[int], bytes],
]:
    """
    Returns the method pointers of three ``hashlib.shake_128`` objects
    that have been primed in different ways with the ``key_bundle``'s
    `key`, `salt`, `aad` & `iv` values.

    The returned values are used to construct a key ratchet algorithm.
    """
    await asleep()
    seed_kdf, left_kdf, right_kdf = key_bundle._keys
    return (
        seed_kdf.update,
        seed_kdf.digest,
        left_kdf.update,
        left_kdf.digest,
        right_kdf.update,
        right_kdf.digest,
    )


def keystream_ratchets(key_bundle: KeyAADBundle) -> t.Tuple[
    t.Callable[[bytes], None],
    t.Callable[[int], bytes],
    t.Callable[[bytes], None],
    t.Callable[[int], bytes],
    t.Callable[[bytes], None],
    t.Callable[[int], bytes],
]:
    """
    Returns the method pointers of three ``hashlib.shake_128`` objects
    that have been primed in different ways with the ``key_bundle``'s
    `key`, `salt`, `aad` & `iv` values.

    The returned values are used to construct a key ratchet algorithm.
    """
    seed_kdf, left_kdf, right_kdf = key_bundle._keys
    return (
        seed_kdf.update,
        seed_kdf.digest,
        left_kdf.update,
        left_kdf.digest,
        right_kdf.update,
        right_kdf.digest,
    )


@comprehension()
async def abytes_keys(
    key_bundle: t.Optional[KeyAADBundle] = None
) -> t.AsyncGenerator[bytes, bytes]:
    """
    An efficient async coroutine which produces an unending, non-
    repeating, deterministic stream of bytes key material.

    Each iteration yields 256 bytes, iteratively derived by the mixing &
    hashing of the permutation of the salt, aad, iv & user key, previous
    hashed results, & the ``entropy`` users may send into this generator
    as a coroutine.

     _____________________________________
    |                                     |
    |     Usage Example: As a CSPRNG      |
    |_____________________________________|

    keystream = aiootp.abytes_keys()  # REPEATS OUTPUTS IF COPIED INTO A
    async for subkey in keystream:    # NEWLY FORKED PROCESS
        assert len(subkey) == 256
        assert type(subkey) is bytes
        new_subkey = await keystream(b"user can add more entropy here")

     _____________________________________
    |                                     |
    |         Algorithm Diagram:          |
    |_____________________________________|

    R = 336-byte ratchet key (output of the seed KDF)
    r = 168-byte bitrate (blocksize of each round for left & right KDFs)
    c = 32-byte capacity (hidden inner state for left & right KDFs)
    f = The round permutation function
    O = 128-byte output key

    left & right KDFs ->

                       R[::2]  (the right kdf receives R[1::2] instead)
                       |
    |------------------⊕----------------------------|------------------|
    |                  r                            |      c           |
    |-----------------------------------------------|------------------|
                       |                                   |
          |-----------------------------------------------------|
          |                         f                           |
          |-----------------------------------------------------|
                       |                                   |
    |--------------------------------------|--------|------------------|
    |                  r                   |        |      c           |
    |------------------V-------------------|--------|------------------|
                       |
                       O

    after both left & right KDFs have been updated ->

                    seed_kdf.update(user_entropy or R[-r:])
                    R = seed_kdf.digest(2 * r)

    Do this procedure for the left & right kdfs, retrieve & concatenate
    their outputs, repeat this cycle each iteration.
    """
    if not key_bundle:
        key_bundle = KeyAADBundle(aad=Domains.CSPRNG)
    key_bundle._register_keystream()
    (
        s_update,
        s_digest,
        l_update,
        l_digest,
        r_update,
        r_digest,
    ) = await akeystream_ratchets(key_bundle)
    while True:
        ratchet_key = s_digest(SEED_KDF_DOUBLE_BLOCKSIZE)  # extract 336 bytes
        l_update(ratchet_key[LEFT_RATCHET_KEY_SLICE])   # update with 168 even index bytes
        r_update(ratchet_key[RIGHT_RATCHET_KEY_SLICE])  # update with 168 odd index bytes
        entropy = yield l_digest(HALF_BLOCKSIZE) + r_digest(HALF_BLOCKSIZE)
        await asleep()
        s_update(
            entropy if entropy else ratchet_key[SEED_RATCHET_KEY_SLICE]
        )
        # last 168 bytes -----------------------^^^^^^^^^^^^^^^^^^^^^^


@comprehension()
def bytes_keys(
    key_bundle: t.Optional[KeyAADBundle] = None
) -> t.Generator[bytes, bytes, None]:
    """
    An efficient sync coroutine which produces an unending, non-
    repeating, deterministic stream of bytes key material.

    Each iteration yields 256 bytes, iteratively derived by the mixing &
    hashing of the permutation of the salt, aad, iv & user key, previous
    hashed results, & the ``entropy`` users may send into this generator
    as a coroutine.

     _____________________________________
    |                                     |
    |     Usage Example: As a CSPRNG      |
    |_____________________________________|

    keystream = aiootp.bytes_keys()  # REPEATS OUTPUTS IF COPIED INTO A
    for subkey in keystream:         # NEWLY FORKED PROCESS
        assert len(subkey) == 256
        assert type(subkey) is bytes
        new_subkey = keystream(b"user can add more entropy here")

     _____________________________________
    |                                     |
    |         Algorithm Diagram:          |
    |_____________________________________|

    R = 336-byte ratchet key (output of the seed KDF)
    r = 168-byte bitrate (blocksize of each round for left & right KDFs)
    c = 32-byte capacity (hidden inner state for left & right KDFs)
    f = The round permutation function
    O = 128-byte output key

    left & right KDFs ->

                       R[::2]  (the right kdf receives R[1::2] instead)
                       |
    |------------------⊕----------------------------|------------------|
    |                  r                            |      c           |
    |-----------------------------------------------|------------------|
                       |                                   |
          |-----------------------------------------------------|
          |                         f                           |
          |-----------------------------------------------------|
                       |                                   |
    |--------------------------------------|--------|------------------|
    |                  r                   |        |      c           |
    |------------------V-------------------|--------|------------------|
                       |
                       O

    after both left & right KDFs have been updated ->

                    seed_kdf.update(user_entropy or R[-r:])
                    R = seed_kdf.digest(2 * r)

    Do this procedure for the left & right KDFs, retrieve & concatenate
    their outputs, repeat this cycle each iteration.
    """
    if not key_bundle:
        key_bundle = KeyAADBundle(aad=Domains.CSPRNG)
    key_bundle._register_keystream()
    (
        s_update,
        s_digest,
        l_update,
        l_digest,
        r_update,
        r_digest,
    ) = keystream_ratchets(key_bundle)
    while True:
        ratchet_key = s_digest(SEED_KDF_DOUBLE_BLOCKSIZE)  # extract 336 bytes
        l_update(ratchet_key[LEFT_RATCHET_KEY_SLICE])   # update with 168 even index bytes
        r_update(ratchet_key[RIGHT_RATCHET_KEY_SLICE])  # update with 168 odd index bytes
        entropy = yield l_digest(HALF_BLOCKSIZE) + r_digest(HALF_BLOCKSIZE)
        s_update(
            entropy if entropy else ratchet_key[SEED_RATCHET_KEY_SLICE]
        )
        # last 168 bytes -----------------------^^^^^^^^^^^^^^^^^^^^^^


class StreamHMAC:
    """
    This class is used as an inline validator for ciphertext streams as
    they are being created & decrypted. Its design was inspired by AES-
    GCM, but it's key committing, uses SHA3 for ciphertext validation,
    feeds its state at each step into the keystream generator & can be
    used to validate each ciphertext block to mitigate the dangers
    related to release of unverified plaintexts.
    """

    __slots__ = (
        "_aupdate",
        "_avalidated_xor",
        "_current_digest",
        "_is_finalized",
        "_key_bundle",
        "_previous_digest",
        "_mac",
        "_mode",
        "_result",
        "_result_is_ready",
        "_update",
        "_validated_xor",
    )

    _DECRYPTION: str = DECRYPTION
    _ENCRYPTION: str = ENCRYPTION

    _new_block_id_mac: callable = shake_128(
        Domains.encode_constant(
            b"chunky2048_shmac_block_id_mac", size=SHAKE_128_BLOCKSIZE
        )
    ).copy

    InvalidBlockID = InvalidBlockID
    InvalidSHMAC = InvalidSHMAC

    def __init__(self, key_bundle: KeyAADBundle) -> "self":
        """
        Begins a stateful hash object that's used to calculate a keyed-
        message authentication code referred to as a shmac, as well as
        block IDs to validate ciphertext streams that have not yet been
        completed. The instance uses derived key material from the
        provided KeyAADBundle.
        """
        if not issubclass(key_bundle.__class__, KeyAADBundle):
            raise Issue.value_must_be_type("key_bundle", KeyAADBundle)
        self._mode = None
        self._is_finalized = False
        self._result_is_ready = False
        self._register_key_bundle(key_bundle)
        self._update = self._placeholder_update    # Don't allow updates
        self._aupdate = self._aplaceholder_update  # unless mode is set

    def _register_key_bundle(self, key_bundle: KeyAADBundle) -> None:
        """
        Registers the `KeyAADBundle` object which will be tied to the
        instance for a single run of the `Chunky2048` cipher. Reusing an
        instance or the same ``key_bundle`` for multiple cipher calls is
        NOT SAFE, & is disallowed by this registration.
        """
        key_bundle._mode.validate()
        self._key_bundle = key_bundle
        key_bundle._register_shmac(self)
        self._mac = mac = key_bundle._shmac_mac
        self._previous_digest = self._current_digest = mac.digest(
            SHMAC_BLOCKSIZE
        )

    @property
    def mode(self) -> str:
        """
        Returns the mode which the instance was instructed to be in by
        the user by calling `_for_encryption` or `_for_decryption`.
        """
        return self._mode

    def _for_encryption(self) -> "self":
        """
        Instructs the SHMAC instance to prepare itself for validating
        ciphertext within the `(a)bytes_xor` generator as plaintext is
        being encrypted.

         --------------------------------------------------------------
        | PRIVATE: Use high-level Chunky2048 or (Async)CipherStream    |
        |          instead!                                            |
         --------------------------------------------------------------
        """
        if self._mode:
            raise Issue.value_already_set("shmac", self._mode)
        elif self._is_finalized:
            raise SHMACIssue.already_finalized()
        elif self._key_bundle._iv_given_by_user:
            raise SHMACIssue.invalid_iv_usage()
        self._mode = self._ENCRYPTION
        self._update = self._update_mac
        self._aupdate = self._aupdate_mac
        self._validated_xor = self._xor_then_hash
        self._avalidated_xor = self._axor_then_hash
        return self

    def _for_decryption(self) -> "self":
        """
        Instructs the SHMAC instance to prepare itself for validating
        ciphertext within the `(a)bytes_xor` generator as it's being
        decrypted.

         --------------------------------------------------------------
        | PRIVATE: Use high-level Chunky2048 or (Async)DecipherStream  |
        |          instead!                                            |
         --------------------------------------------------------------
        """
        if self._mode:
            raise Issue.value_already_set("shmac", self._mode)
        elif self._is_finalized:
            raise SHMACIssue.already_finalized()
        elif not self._key_bundle._iv_given_by_user:
            raise SHMACIssue.invalid_iv_usage()
        self._mode = self._DECRYPTION
        self._update = self._update_mac
        self._aupdate = self._aupdate_mac
        self._validated_xor = self._hash_then_xor
        self._avalidated_xor = self._ahash_then_xor
        return self

    async def _aplaceholder_update(self, *a, **kw) -> None:
        """
        This method is overwritten with the propper functionality when a
        cipher mode is declared with either the `_for_encryption` or
        `_for_decryption` methods. This interface helps ensure correct
        usage of the object.
        """
        raise SHMACIssue.no_cipher_mode_declared()

    def _placeholder_update(self, *a, **kw) -> None:
        """
        This method is overwritten with the propper functionality when a
        cipher mode is declared with either the `_for_encryption` or
        `_for_decryption` methods. This interface helps ensure correct
        usage of the object.
        """
        raise SHMACIssue.no_cipher_mode_declared()

    async def _aupdate_mac(self, ciphertext_block: bytes) -> "self":
        """
        This method is called automatically when an instance is passed
        into the low-level `(a)bytes_encipher` / `(a)bytes_decipher`
        generators. It updates the instance's mac object with the
        ``ciphertext_block`` & stores its previous digest in case the
        instance is needed to create / validate `block_id`s.
        """
        await asleep()
        mac = self._mac
        self._previous_digest = self._current_digest
        mac.update(ciphertext_block)
        self._current_digest = mac.digest(SHMAC_BLOCKSIZE)
        return self

    def _update_mac(self, ciphertext_block: bytes) -> "self":
        """
        This method is called automatically when an instance is passed
        into the low-level `(a)bytes_encipher` / `(a)bytes_decipher`
        generators. It updates the instance's mac object with the
        ``ciphertext_block`` & stores its previous digest in case the
        instance is needed to create / validate `block_id`s.
        """
        mac = self._mac
        self._previous_digest = self._current_digest
        mac.update(ciphertext_block)
        self._current_digest = mac.digest(SHMAC_BLOCKSIZE)
        return self

    async def _axor_then_hash(
        self,
        plaintext_block: bytes,
        key_chunk: bytes,
        *,
        _from_bytes: t.Callable[..., int] = int.from_bytes,
    ) -> bytes:
        """
        This method is inserted as the instance's `_avalidated_xor`
        method after the user chooses the encryption mode. The mode is
        chosen by calling the `_for_encryption` method. It receives a
        ``plaintext_block`` & ``key_chunk``, & xors them into a 256-byte
        `ciphertext_block` used to update the instance's mac object
        before being returned.
        """
        try:
            ciphertext_block = (
                _from_bytes(plaintext_block, BIG)
                ^ _from_bytes(key_chunk, BIG)
            ).to_bytes(BLOCKSIZE, BIG)
            await self._aupdate(ciphertext_block)
            return ciphertext_block
        except OverflowError:
            raise Issue.exceeded_blocksize(BLOCKSIZE)

    def _xor_then_hash(
        self,
        plaintext_block: bytes,
        key_chunk: bytes,
        *,
        _from_bytes: t.Callable[..., int] = int.from_bytes,
    ) -> bytes:
        """
        This method is inserted as the instance's `_validated_xor`
        method after the user chooses the encryption mode. The mode is
        chosen by calling the `_for_encryption` method. It receives a
        ``plaintext_block`` & ``key_chunk``, & xors them into a 256-byte
        `ciphertext_block` used to update the instance's mac object
        before being returned.
        """
        try:
            ciphertext_block = (
                _from_bytes(plaintext_block, BIG)
                ^ _from_bytes(key_chunk, BIG)
            ).to_bytes(BLOCKSIZE, BIG)
            self._update(ciphertext_block)
            return ciphertext_block
        except OverflowError:
            raise Issue.exceeded_blocksize(BLOCKSIZE)

    async def _ahash_then_xor(
        self,
        ciphertext_block: bytes,
        key_chunk: bytes,
        *,
        _from_bytes: t.Callable[..., int] = int.from_bytes,
    ) -> bytes:
        """
        This method is inserted as the instance's `_avalidated_xor`
        method after the user chooses the decryption mode. The mode is
        chosen by calling the `_for_decryption` method. It receives a
        ``ciphertext_block`` & ``key_chunk``, uses the ciphertext to
        update the instance's mac object, then returns the 256-byte
        plaintext.
        """
        try:
            await self._aupdate(ciphertext_block)
            return (
                _from_bytes(ciphertext_block, BIG)
                ^ _from_bytes(key_chunk, BIG)
            ).to_bytes(BLOCKSIZE, BIG)
        except OverflowError:
            raise Issue.exceeded_blocksize(BLOCKSIZE)

    def _hash_then_xor(
        self,
        ciphertext_block: bytes,
        key_chunk: bytes,
        *,
        _from_bytes: t.Callable[..., int] = int.from_bytes,
    ) -> bytes:
        """
        This method is inserted as the instance's `_validated_xor`
        method after the user chooses the decryption mode. The mode is
        chosen by calling the `_for_decryption` method. It receives a
        ``ciphertext_block`` & ``key_chunk``, uses the ciphertext to
        update the instance's mac object, then returns the 256-byte
        plaintext.
        """
        try:
            self._update(ciphertext_block)
            return (
                _from_bytes(ciphertext_block, BIG)
                ^ _from_bytes(key_chunk, BIG)
            ).to_bytes(BLOCKSIZE, BIG)
        except OverflowError:
            raise Issue.exceeded_blocksize(BLOCKSIZE)

    @staticmethod
    def _test_block_id_size(size: int) -> None:
        """
        Raises errors if the requested `block_id` ``size`` is not within
        the allowed bounds.
        """
        if size < MIN_BLOCK_ID_BYTES:
            raise SHMACIssue.block_id_is_too_small(size)
        elif size > MAX_BLOCK_ID_BYTES:
            raise SHMACIssue.block_id_is_too_big(size)

    def _get_block_id_mac(self) -> None:
        """
        Returns a correct mac digest considering that during encryption
        the instance is updated before the block id is generated, & it
        must be checked by an instance during decryption before being
        updated.
        """
        if self._mode == self._ENCRYPTION:
            return self._previous_digest
        elif self._mode == self._DECRYPTION:
            return self._current_digest
        else:
            raise SHMACIssue.no_cipher_mode_declared()

    async def anext_block_id(
        self,
        next_block: bytes,
        *,
        size: int = BLOCK_ID_BYTES,
        aad: bytes = DEFAULT_AAD,
        _join: t.Callable[..., bytes] = b"".join
    ) -> bytes:
        """
        Returns a ``size``-byte block id derived from the current state
        & the supplied ``next_block`` chunk of ciphertext. These block
        ids can be used to detect out-of-order messages, as well as
        ciphertext forgeries, without altering the internal state. This
        allows for robust decryption of ciphertext streams, mitigates
        adversarial attempts to crash communication channels & allows
        release of plaintexts without waiting for the stream to end.

        Additional ``aad`` for each block may be specified if desired,
        however the ``aad`` passed into this method DO NOT alter the
        keystream. Only used to create block ids that authenticate the
        additional data.

         --------------------------------------------------------------
        | PRIVATE: Use high-level Chunky2048 or (Async)CipherStream    |
        |          instead!                                            |
         --------------------------------------------------------------
        """
        await asleep()
        self._test_block_id_size(size)
        mac = self._new_block_id_mac()
        payload = (
            self._get_block_id_mac(),
            size.to_bytes(1, BIG),
            len(aad).to_bytes(8, BIG),
            aad,
            len(next_block).to_bytes(8, BIG),
            next_block,
        )
        mac.update(_join(payload))
        return mac.digest(size)

    def next_block_id(
        self,
        next_block: bytes,
        *,
        size: int = BLOCK_ID_BYTES,
        aad: bytes = DEFAULT_AAD,
        _join: t.Callable[..., bytes] = b"".join
    ) -> bytes:
        """
        Returns a ``size``-byte block id derived from the current state
        & the supplied ``next_block`` chunk of ciphertext. These block
        ids can be used to detect out-of-order messages, as well as
        ciphertext forgeries, without altering the internal state. This
        allows for robust decryption of ciphertext streams & mitigates
        adversarial attempts to crash communication channels & allows
        release of plaintexts without waiting for the stream to end.

        Additional ``aad`` for each block may be specified if desired,
        however the ``aad`` passed into this method DO NOT alter the
        keystream. Only used to create block ids that authenticate the
        additional data.

         --------------------------------------------------------------
        | PRIVATE: Use high-level Chunky2048 or (Async)CipherStream    |
        |          instead!                                            |
         --------------------------------------------------------------
        """
        self._test_block_id_size(size)
        mac = self._new_block_id_mac()
        payload = (
            self._get_block_id_mac(),
            size.to_bytes(1, BIG),
            len(aad).to_bytes(8, BIG),
            aad,
            len(next_block).to_bytes(8, BIG),
            next_block,
        )
        mac.update(_join(payload))
        return mac.digest(size)

    async def _aset_final_result(self) -> None:
        """
        Caps off the instance's validation hash object & populates the
        instance's final result with a SHMAC of its state. This signals
        the end of a stream of data that can be validated with the
        current instance.
        """
        await asleep()
        self._mac.update(
            self._key_bundle._kdf.digest(SHMAC_DOUBLE_BLOCKSIZE)
        )
        self._result = self._mac.digest(SHMAC_BYTES)

    def _set_final_result(self) -> None:
        """
        Caps off the instance's validation hash object & populates the
        instance's final result with a SHMAC of its state. This signals
        the end of a stream of data that can be validated with the
        current instance.
        """
        self._mac.update(
            self._key_bundle._kdf.digest(SHMAC_DOUBLE_BLOCKSIZE)
        )
        self._result = self._mac.digest(SHMAC_BYTES)

    async def afinalize(self) -> bytes:
        """
        Caps off the instance's validation hash object & populates the
        instance's final result with an SHMAC of its state. This signals
        the end of a stream of data that can be validated with the
        current instance.
        """
        if self._is_finalized:
            raise SHMACIssue.already_finalized()
        self._is_finalized = True
        await self._aset_final_result()
        self._result_is_ready = True
        self._mac = DeletedAttribute(SHMACIssue.already_finalized)
        return self._result

    def finalize(self) -> bytes:
        """
        Caps off the instance's validation hash object & populates the
        instance's final result with an SHMAC of its state. This signals
        the end of a stream of data that can be validated with the
        current instance.
        """
        if self._is_finalized:
            raise SHMACIssue.already_finalized()
        self._is_finalized = True
        self._set_final_result()
        self._result_is_ready = True
        self._mac = DeletedAttribute(SHMACIssue.already_finalized)
        return self._result

    async def aresult(self) -> bytes:
        """
        Returns the instance's final result which is the secure SHMAC of
        the ciphertext that was processed through the instance.
        """
        await asleep()
        if not self._result_is_ready:
            raise SHMACIssue.validation_incomplete()
        return self._result

    def result(self) -> bytes:
        """
        Returns the instance's final result which is the secure SHMAC of
        the ciphertext that was processed through the instance.
        """
        if not self._result_is_ready:
            raise SHMACIssue.validation_incomplete()
        return self._result

    async def atest_next_block_id(
        self,
        untrusted_block_id: bytes,
        next_block: bytes,
        aad: bytes = DEFAULT_AAD,
    ) -> None:
        """
        Does a timing-safe comparison of a supplied ``untrusted_block_id``
        with a derived block id of the supplied ``next_block`` chunk of
        ciphertext. Raises `InvalidBlockID`, subclass of `ValueError`,
        if the untrusted block id is invalid. These block id checks can
        detect out of order messages, or ciphertext forgeries, without
        altering the internal state. This allows for robust decryption of
        ciphertext streams, mitigates adversarial attempts to crash a
        communication channel & allows release of plaintexts without
        waiting for the stream to end.

        Additional ``aad`` for each block may be specified if desired.
        """
        if untrusted_block_id.__class__ is not bytes:
            raise Issue.value_must_be_type("untrusted_block_id", bytes)
        size = len(untrusted_block_id)
        block_id = await self.anext_block_id(next_block, size=size, aad=aad)
        if not bytes_are_equal(untrusted_block_id, block_id):
            raise SHMACIssue.invalid_block_id()

    def test_next_block_id(
        self,
        untrusted_block_id: bytes,
        next_block: bytes,
        aad: bytes = DEFAULT_AAD,
    ) -> None:
        """
        Does a timing-safe comparison of a supplied ``untrusted_block_id``
        with a derived block id of the supplied ``next_block`` chunk of
        ciphertext. Raises `InvalidBlockID`, subclass of `ValueError`,
        if the untrusted block id is invalid. These block id checks can
        detect out of order messages, or ciphertext forgeries, without
        altering the internal state. This allows for robust decryption of
        ciphertext streams, mitigates adversarial attempts to crash a
        communication channel & allows release of plaintexts without
        waiting for the stream to end.

        Additional ``aad`` for each block may be specified if desired.
        """
        if untrusted_block_id.__class__ is not bytes:
            raise Issue.value_must_be_type("untrusted_block_id", bytes)
        size = len(untrusted_block_id)
        block_id = self.next_block_id(next_block, size=size, aad=aad)
        if not bytes_are_equal(untrusted_block_id, block_id):
            raise SHMACIssue.invalid_block_id()

    async def atest_shmac(self, untrusted_shmac: bytes) -> None:
        """
        Does a time-safe comparison of a supplied ``untrusted_shmac``
        with the instance's final result shmac. Raises `InvalidSHMAC`,
        subclass of `ValueError`, if the shmac doesn't match.
        """
        if untrusted_shmac.__class__ is not bytes:
            raise Issue.value_must_be_type("untrusted_shmac", bytes)
        shmac = await self.aresult()
        if not bytes_are_equal(untrusted_shmac, shmac):
            raise SHMACIssue.invalid_shmac()

    def test_shmac(self, untrusted_shmac: bytes) -> None:
        """
        Does a time-safe comparison of a supplied ``untrusted_shmac``
        with the instance's final result shmac. Raises `InvalidSHMAC`,
        subclass of `ValueError`, if the shmac doesn't match.
        """
        if untrusted_shmac.__class__ is not bytes:
            raise Issue.value_must_be_type("untrusted_shmac", bytes)
        shmac = self.result()
        if not bytes_are_equal(untrusted_shmac, shmac):
            raise SHMACIssue.invalid_shmac()


class SyntheticIV:
    """
    Manages the derivation & application of synthetic IVs which improve
    the salt reuse / misuse resistance of the package's online,
    tweakable AEAD cipher, `Chunky2048`. This class is handled
    automatically within the `(a)bytes_xor` generators, & works in
    collaboration with the `StreamHMAC` class. The required plaintext
    padding is handled within the `Padding` class.

     _____________________________________
    |                                     |
    |    Algorithm Diagram: Encryption    |
    |_____________________________________|
     ------------------------------------------------------------------
    |      inner-header      |        first block of plaintext         |
    | timestamp |  siv-key   |                                         |
    |  4-bytes  |  16-bytes  |               236-bytes                 |
     ------------------------------------------------------------------
    |---------------------- entire first block ------------------------|
                                     |
                                     |
    first 256-byte keystream key ----⊕
                                     |
                                     |
                                     V
                          masked plaintext block
     ------------------------------------------------------------------
    |  masked inner-header   |     first block of masked plaintext     |
     ------------------------------------------------------------------
                             |----- the 236-byte masked plaintext -----|
                                                  |
                                                  |
    siv = inner-header + shmac.digest(148)        |
    keystream(siv)[10:246] -----------------------⊕
                                                  |
                                                  |
                                                  V
     ------------------------------------------------------------------
    |  masked inner-header   |       first block of ciphertext         |
     ------------------------------------------------------------------
    |--------------- entire first block of ciphertext -----------------|

    shmac.update(entire_first_block_of_ciphertext)


     _____________________________________
    |                                     |
    |    Algorithm Diagram: Decryption    |
    |_____________________________________|
     ------------------------------------------------------------------
    |  masked inner-header   |        first block of ciphertext        |
     ------------------------------------------------------------------
    |---------------------- entire first block ------------------------|
                                     |
                                     |
    first 256-byte keystream key ----⊕
                                     |
                                     |
                                     V
                        unmasked ciphertext block
     ------------------------------------------------------------------
    |      inner-header      |   first block of unmasked ciphertext    |
     ------------------------------------------------------------------
                             |--- the 236-byte unmasked ciphertext ----|
                                                  |
                                                  |
    siv = inner-header + shmac.digest(148)        |
    keystream(siv)[10:246] -----------------------⊕
                                                  |
                                                  |
                                                  V
     ------------------------------------------------------------------
    |      inner-header      |         first block of plaintext        |
    | timestamp |  siv-key   |                                         |
    |  4-bytes  |  16-bytes  |               236-bytes                 |
     ------------------------------------------------------------------

    shmac.update(entire_first_block_of_ciphertext)
    """

    __slots__ = ()

    _BLOCKSIZE: int = BLOCKSIZE
    _DECRYPTION: str = DECRYPTION
    _ENCRYPTION: str = ENCRYPTION
    _DIGEST_SLICE: slice = slice(10, -10)

    @classmethod
    def _mask_block(
        cls, block: bytes, primer_key: bytes
    ) -> t.Tuple[bytes, int]:
        """
        Extracts the inner-header prepended to the first block of
        plaintext containing the 4-byte timestamp of the message & the
        random 16-byte IV-key. Then enciphers the first block with the
        first 256-byte key produced by the cipher's keystream.

        This inner-header is used as a seed to randomize the keystream
        & improve the cipher's salt reuse / misuse security. The first
        block will later be enciphered with the next randomized key,
        except for the inner-header which will remain masked & able to
        be deciphered without knowledge of the inner-header.

        Returns the inner-header & the partially enciphered first block.
        """
        header = block[INNER_HEADER_SLICE]
        masked_block = bytes_as_int(primer_key) ^ bytes_as_int(block)
        return header, masked_block

    @classmethod
    def _unmask_block(
        cls, block: bytes, primer_key: bytes
    ) -> t.Tuple[bytes, int]:
        """
        Deciphers the first block of ciphertext with the first 256-byte
        key produced by the cipher's keystream. This reveals the inner-
        header containing the 4-byte timestamp of the message & the
        random 16-byte IV-key.

        This inner-header is used to randomize the keystream & improve
        the cipher's salt reuse / misuse security. The remainder of the
        first block will be deciphered with the new key produced by the
        keystream after being seeded with the inner-header.

        Returns the inner-header & the partially deciphered first block.
        """
        unmasked_block = bytes_as_int(primer_key) ^ bytes_as_int(block)
        header = int_as_bytes(
            unmasked_block, size=BLOCKSIZE
        )[INNER_HEADER_SLICE]
        return header, unmasked_block

    @classmethod
    async def _asynthesize_key(
        cls,
        header: bytes,
        keystream: t.Callable[[bytes], bytes],
        shmac: StreamHMAC,
    ) -> bytes:
        """
        Uses the inner-``header`` & ``shmac`` object's current digest to
        create an ephemeral SIV which leads to the derivation of the
        encryption key for the first block of message data.
        """
        whole_header = len(header)
        siv = header + shmac._current_digest[:-whole_header]
        half_header = whole_header // 2
        middle_part = slice(half_header, BLOCKSIZE - half_header)
        return (await keystream(siv))[middle_part]

    @classmethod
    def _synthesize_key(
        cls, header: bytes,
        keystream: t.Callable[[bytes], bytes],
        shmac: StreamHMAC,
    ) -> bytes:
        """
        Uses the inner-``header`` & ``shmac`` object's current digest to
        create an ephemeral SIV which leads to the derivation of the
        encryption key for the first block of message data.
        """
        whole_header = len(header)
        siv = header + shmac._current_digest[:-whole_header]
        half_header = whole_header // 2
        middle_part = slice(half_header, BLOCKSIZE - half_header)
        return keystream(siv)[middle_part]

    @classmethod
    async def _aunique_cipher(
        cls,
        block: bytes,
        keystream: t.Callable[[bytes], t.Awaitable[bytes]],
        shmac: StreamHMAC,
    ) -> bytes:
        """
        Uses a masking & encryption algorithm to pull secret ephemeral
        data from the plaintext header to protect the payload of the
        ciphertext with more salt reuse / misuse resistance.
        """
        primer_key = shmac._key_bundle._primer_key
        header, masked_block = cls._mask_block(block, primer_key)
        key_chunk = await cls._asynthesize_key(header, keystream, shmac)
        ciphertext = int_as_bytes(
            masked_block ^ bytes_as_int(key_chunk), size=BLOCKSIZE
        )
        await shmac._aupdate_mac(ciphertext)
        return ciphertext

    @classmethod
    def _unique_cipher(
        cls,
        block: bytes,
        keystream: t.Callable[[bytes], bytes],
        shmac: StreamHMAC,
    ) -> bytes:
        """
        Uses a masking & encryption algorithm to pull secret ephemeral
        data from the plaintext header to protect the payload of the
        ciphertext with more salt reuse / misuse resistance.
        """
        primer_key = shmac._key_bundle._primer_key
        header, masked_block = cls._mask_block(block, primer_key)
        key_chunk = cls._synthesize_key(header, keystream, shmac)
        ciphertext = int_as_bytes(
            masked_block ^ bytes_as_int(key_chunk), size=BLOCKSIZE
        )
        shmac._update_mac(ciphertext)
        return ciphertext

    @classmethod
    async def _aunique_decipher(
        cls,
        block: bytes,
        keystream: t.Callable[[bytes], t.Awaitable[bytes]],
        shmac: StreamHMAC,
    ) -> bytes:
        """
        Uses an unmasking & decryption algorithm to pull secret
        ephemeral data from the plaintext header to protect the payload
        of the ciphertext with more salt reuse / misuse resistance.
        """
        primer_key = shmac._key_bundle._primer_key
        header, unmasked_block = cls._unmask_block(block, primer_key)
        key_chunk = await cls._asynthesize_key(header, keystream, shmac)
        await shmac._aupdate_mac(block)
        return int_as_bytes(
            unmasked_block ^ bytes_as_int(key_chunk), size=BLOCKSIZE
        )

    @classmethod
    def _unique_decipher(
        cls,
        block: bytes,
        keystream: t.Callable[[bytes], bytes],
        shmac: StreamHMAC,
    ) -> bytes:
        """
        Uses an unmasking & decryption algorithm to pull secret
        ephemeral data from the plaintext header to protect the payload
        of the ciphertext with more salt reuse / misuse resistance.
        """
        primer_key = shmac._key_bundle._primer_key
        header, unmasked_block = cls._unmask_block(block, primer_key)
        key_chunk = cls._synthesize_key(header, keystream, shmac)
        shmac._update_mac(block)
        return int_as_bytes(
            unmasked_block ^ bytes_as_int(key_chunk), size=BLOCKSIZE
        )

    @classmethod
    async def avalidated_xor(
        cls,
        datastream: t.AsyncDatastream,
        keystream: t.Callable[[bytes], t.Awaitable[bytes]],
        shmac: StreamHMAC,
    ) -> bytes:
        """
        Derives the synthetic IV from the timestamp & ephemeral SIV-key
        in the plaintext header then seeds it into the keystream to
        randomize it before encrypting the first block of payload data.

        This method ciphers/deciphers the first block of plaintext/
        ciphertext depending on whether the shmac has been set to
        encryption or decryption modes.

        This improves the cipher's salt reuse / misuse resistance since:
        if either the 4-byte timestamp or ephemeral SIV-key are unique,
        then the entire stream of key material will be unique.

        The inner header & footer are applied during message padding by
        the `Padding` class.
        """
        try:
            block = await datastream.asend(None)
        except StopAsyncIteration:
            raise Issue.stream_is_empty()
        if shmac._mode == cls._ENCRYPTION:
            return await cls._aunique_cipher(block, keystream, shmac)
        else:
            return await cls._aunique_decipher(block, keystream, shmac)

    @classmethod
    def validated_xor(
        cls,
        datastream: t.Datastream,
        keystream: t.Callable[[bytes], bytes],
        shmac: StreamHMAC,
    ) -> bytes:
        """
        Derives the synthetic IV from the timestamp & ephemeral SIV-key
        in the plaintext header then seeds it into the keystream to
        randomize it before encrypting the first block of payload data.

        This method ciphers/deciphers the first block of plaintext/
        ciphertext depending on whether the shmac has been set to
        encryption or decryption modes.

        This improves the cipher's salt reuse / misuse resistance since:
        if either the 4-byte timestamp or ephemeral SIV-key are unique,
        then the entire stream of key material will be unique.

        The inner header & footer are applied during message padding by
        the `Padding` class.
        """
        try:
            block = datastream.send(None)
        except StopIteration:
            raise Issue.stream_is_empty()
        if shmac._mode == cls._ENCRYPTION:
            return cls._unique_cipher(block, keystream, shmac)
        else:
            return cls._unique_decipher(block, keystream, shmac)


async def _axor_shortcuts(
    data: t.AsyncOrSyncDatastream,
    key: t.AsyncKeystream,
    shmac: StreamHMAC,
) -> t.Tuple[
    t.AsyncGenerator[None, bytes],
    t.Callable[[bytes], bytes],
    t.Callable[..., bytes],
]:
    """
    Returns a series of function pointers that allow their efficient use
    within the `Chunky2048` cipher's low-level xor generators. This is
    done to improve readability & the efficiency of the cipher's
    execution time.
    """
    if not hasattr(data, "asend"):
        data = aunpack.root(data)
    return (data, key.asend, shmac._avalidated_xor)


def _xor_shortcuts(
    data: t.Datastream,
    key: t.Keystream,
    shmac: StreamHMAC,
) -> t.Tuple[
    t.Generator[None, bytes, None],
    t.Callable[[bytes], bytes],
    t.Callable[..., bytes],
]:
    """
    Returns a series of function pointers that allow their efficient use
    within the `Chunky2048` cipher's low-level xor generators. This is
    done to improve readability & the efficiency of the cipher's
    execution time.
    """
    if not hasattr(data, "send"):
        data = unpack.root(data)
    return (data, key.send, shmac._validated_xor)


async def abytes_xor(
    data: t.AsyncOrSyncDatastream,
    *,
    key: t.AsyncKeystream,
    shmac: StreamHMAC,
) -> t.AsyncGenerator[None, bytes]:
    """
    `Chunky2048` - an online, salt reuse / misuse resistant, tweakable
    AEAD pseudo one-time pad cipher implementation.

    Gathers both an iterable of 256-byte blocks of ``data``, & a
    non-repeating generator of deterministic bytes ``key`` material,
    then bitwise xors the streams together, producing `Chunky2048`
    ciphertext or plaintext chunks 256 bytes long. The ciphertext is
    then fed into the ``shmac`` for validation.

    The keystream MUST produce 256-bytes of key material each iteration.

    Restricting the ciphertext to multiples of 256-bytes is a measure to
    protect the metadata of plaintext from adversaries that could make
    informed guesses of the plaintext given accurate size measures.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes or
    less per iteration or security WILL BE BROKEN by directly leaking
    plaintext. The cipher is designed for plaintext to be padded using
    the `Padding` class.

    WARNING: ``key`` MUST produce key chunks of exactly 256 bytes per
    iteration or security WILL BE BROKEN by directly leaking plaintext.
    """
    datastream, keystream, validated_xor = await _axor_shortcuts(
        data, key, shmac
    )
    yield await SyntheticIV.avalidated_xor(datastream, keystream, shmac)
    async for block in datastream:
        yield await validated_xor(
            block, await keystream(shmac._current_digest)
        )


def bytes_xor(
    data: t.Datastream,
    *,
    key: t.Keystream,
    shmac: StreamHMAC,
) -> t.Generator[None, bytes, None]:
    """
    `Chunky2048` - an online, salt reuse / misuse resistant, tweakable
    AEAD pseudo one-time pad cipher implementation.

    Gathers both an iterable of 256-byte blocks of ``data``, & a
    non-repeating generator of deterministic bytes ``key`` material,
    then bitwise xors the streams together, producing `Chunky2048`
    ciphertext or plaintext chunks 256 bytes long. The ciphertext is
    then fed into the ``shmac`` for validation.

    The keystream MUST produce 256-bytes of key material each iteration.

    Restricting the ciphertext to multiples of 256-bytes is a measure to
    protect the metadata of plaintext from adversaries that could make
    informed guesses of the plaintext given accurate size measures.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes or
    less per iteration or security WILL BE BROKEN by directly leaking
    plaintext. The cipher is designed for plaintext to be padded using
    the `Padding` class.

    WARNING: ``key`` MUST produce key chunks of exactly 256 bytes per
    iteration or security WILL BE BROKEN by directly leaking plaintext.
    """
    datastream, keystream, validated_xor = _xor_shortcuts(data, key, shmac)
    yield SyntheticIV.validated_xor(datastream, keystream, shmac)
    for block in datastream:
        yield validated_xor(block, keystream(shmac._current_digest))


def abytes_encipher(
    data: t.AsyncOrSyncDatastream, shmac: StreamHMAC
) -> t.AsyncGenerator[None, bytes]:
    """
    A low-level function which returns an async generator that runs this
    package's online, salt reuse / misuse resistant, tweakable AEAD
    cipher, `Chunky2048`.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes
    or less per iteration or security WILL BE BROKEN by directly
    leaking plaintext. The cipher is designed for plaintext be padded
    using the `Padding` class.

    WARNING: The generator does not provide authentication of the
    ciphertexts or associated data it handles. Nor does it do any
    message padding or sufficient checking of inputs for adequacy. Those
    are functionalities which must be obtained through other means. Just
    passing in a ``shmac`` will not authenticate ciphertext
    itself. The `finalize` or `afinalize` methods must be called on
    the ``shmac`` once all of the cipehrtext has been created /
    decrypted. Then the final SHMAC is available from the `aresult`
    & `result` methods, & can be tested against untrusted SHMACs
    with the `(a)test_shmac` methods. The shmac also has
    `(a)next_block_id` methods that can be used to authenticate
    unfinished streams of cipehrtext on the fly.
    """
    key_bundle = shmac._key_bundle
    if shmac._mode != ENCRYPTION:
        raise Issue.must_set_value("shmac", ENCRYPTION)
    elif not issubclass(key_bundle.__class__, KeyAADBundle):
        raise Issue.value_must_be_type("key_bundle", KeyAADBundle)
    elif key_bundle._mode != ASYNC:
        raise KeyAADIssue.mode_isnt_correct(ASYNC)
    return abytes_xor(data, key=key_bundle._keystream, shmac=shmac)


def bytes_encipher(
    data: t.Datastream, shmac: StreamHMAC
) -> t.Generator[None, bytes, None]:
    """
    A low-level function which returns an sync generator that runs this
    package's online, salt reuse / misuse resistant, tweakable AEAD
    cipher, `Chunky2048`.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes
    or less per iteration or security WILL BE BROKEN by directly
    leaking plaintext. The cipher is designed for plaintext be padded
    using the `Padding` class.

    WARNING: The generator does not provide authentication of the
    ciphertexts or associated data it handles. Nor does it do any
    message padding or sufficient checking of inputs for adequacy. Those
    are functionalities which must be obtained through other means. Just
    passing in a ``shmac`` will not authenticate ciphertext
    itself. The `finalize` or `afinalize` methods must be called on
    the ``shmac`` once all of the cipehrtext has been created /
    decrypted. Then the final SHMAC is available from the `aresult`
    & `result` methods, & can be tested against untrusted SHMACs
    with the `(a)test_shmac` methods. The shmac also has
    `(a)next_block_id` methods that can be used to authenticate
    unfinished streams of cipehrtext on the fly.
    """
    key_bundle = shmac._key_bundle
    if shmac._mode != ENCRYPTION:
        raise Issue.must_set_value("shmac", ENCRYPTION)
    elif not issubclass(key_bundle.__class__, KeyAADBundle):
        raise Issue.value_must_be_type("key_bundle", KeyAADBundle)
    elif key_bundle._mode != SYNC:
        raise KeyAADIssue.mode_isnt_correct(SYNC)
    return bytes_xor(data, key=key_bundle._keystream, shmac=shmac)


def abytes_decipher(
    data: t.AsyncOrSyncDatastream, shmac: StreamHMAC
) -> t.AsyncGenerator[None, bytes]:
    """
    A low-level function which returns an async generator that runs this
    package's online, salt reuse / misuse resistant, tweakable AEAD
    cipher, `Chunky2048`.

    WARNING: The generator does not provide authentication of the
    ciphertexts or associated data it handles. Nor does it do any
    message padding or sufficient checking of inputs for adequacy. Those
    are functionalities which must be obtained through other means. Just
    passing in a ``shmac`` will not authenticate ciphertext
    itself. The `finalize` or `afinalize` methods must be called on
    the ``shmac`` once all of the cipehrtext has been created /
    decrypted. Then the final SHMAC is available from the `aresult`
    & `result` methods, & can be tested against untrusted SHMACs
    with the `(a)test_shmac` methods. The shmac also has
    `(a)next_block_id` methods that can be used to authenticate
    unfinished streams of cipehrtext on the fly.
    """
    key_bundle = shmac._key_bundle
    if shmac._mode != DECRYPTION:
        raise Issue.must_set_value("shmac", DECRYPTION)
    elif not issubclass(key_bundle.__class__, KeyAADBundle):
        raise Issue.value_must_be_type("key_bundle", KeyAADBundle)
    elif key_bundle._mode != ASYNC:
        raise KeyAADIssue.mode_isnt_correct(ASYNC)
    return abytes_xor(data, key=key_bundle._keystream, shmac=shmac)


def bytes_decipher(
    data: t.Datastream, shmac: StreamHMAC
) -> t.Generator[None, bytes, None]:
    """
    A low-level function which returns an sync generator that runs this
    package's online, salt reuse / misuse resistant, tweakable AEAD
    cipher, `Chunky2048`.

    WARNING: The generator does not provide authentication of the
    ciphertexts or associated data it handles. Nor does it do any
    message padding or sufficient checking of inputs for adequacy. Those
    are functionalities which must be obtained through other means. Just
    passing in a ``shmac`` will not authenticate ciphertext
    itself. The `finalize` or `afinalize` methods must be called on
    the ``shmac`` once all of the cipehrtext has been created /
    decrypted. Then the final SHMAC is available from the `aresult`
    & `result` methods, & can be tested against untrusted SHMACs
    with the `(a)test_shmac` methods. The shmac also has
    `(a)next_block_id` methods that can be used to authenticate
    unfinished streams of cipehrtext on the fly.
    """
    key_bundle = shmac._key_bundle
    if shmac._mode != DECRYPTION:
        raise Issue.must_set_value("shmac", DECRYPTION)
    elif not issubclass(key_bundle.__class__, KeyAADBundle):
        raise Issue.value_must_be_type("key_bundle", KeyAADBundle)
    elif key_bundle._mode != SYNC:
        raise KeyAADIssue.mode_isnt_correct(SYNC)
    return bytes_xor(data, key=key_bundle._keystream, shmac=shmac)


class AsyncCipherStream(metaclass=AsyncInit):
    """
    A high-level public interface to the package's online, salt reuse /
    misuse resistant, tweakable AEAD cipher, `Chunky2048`.

    Since this class handles ciphertext validation automatically, all
    decrypted plaintexts are verified & can be released with ~1 / 2**96
    chance of block ID collisions.

    Pads, encrypts & authenticates bytes-type plaintext streams,
    converting them into `Chunky2048` ciphertext streams. The plaintext
    streams are processed in blocks of 256-bytes. Each block is
    prepended with their 24-byte `block_id` authentication tag. The
    total ciphertext length for each block is then 280-bytes & is
    referred to as a packet.

    Validation using `StreamHMAC` `block_id`'s provides robustness to
    communication channels. It does so by detecting forgeries & out-of-
    order messages without changing its internal state. If a tag fails
    to validate, the cipher stream can continue functioning once the
    authentic messages, in their correct order, begin coming in.
    --------
    HOWEVER: The more blocks that are allowed to fail without aborting,
    -------- the more chances an attacker has to spoof the 24-byte tag.

     _____________________________________
    |                                     |
    |      Usage Example: Encryption      |
    |_____________________________________|


    stream = await AsyncCipherStream(key, aad=session.transcript)
    session.transmit(salt=stream.salt, iv=stream.iv)

    for plaintext in session.upload.buffer(4 * stream.PACKETSIZE):
        await stream.abuffer(plaintext)
        async for block_id, ciphertext in stream:
            session.send_packet(block_id + ciphertext)

    async for block_id, ciphertext in stream.afinalize():
        session.send_packet(block_id + ciphertext)

    # Give option to check for further validity ------------------------
    # Cryptographically asserts stream is done. ------------------------
    session.transmit(shmac=await stream.shmac.afinalize())
    """

    __slots__ = (
        "_aad",
        "_buffer",
        "_byte_count",
        "_cipher",
        "_is_digesting",
        "_is_finalized",
        "_key_bundle",
        "shmac",
    )

    async def __init__(
        self,
        key: bytes,
        *,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
    ) -> "self":
        """
        Derives encryption keys & initializes a mutable buffer to
        automatically prepare plaintext given by the user with the
        necessary padding & resized to the blocksize of the `Chunky2048`
        cipher.

        ``key``: A 64-byte or greater entropic value that contains the
                user's desired entropy & cryptographic strength.
                Designed to be used as a longer-term user encryption /
                decryption key & is ideally a uniform value.

        ``salt``: An ephemeral, uniform 16-byte salt value. Automatically
                generated during encryption if not supplied. SHOULD BE
                USED ONLY ONCE for each encryption. Any repeats can harm
                anonymity & unnecessarily forces ciphertext security to rely
                on the salt reuse / misuse properties of the cipher. This
                value can be sent in the clear along with the ciphertext.

        ``aad``: An arbitrary bytes value that a user decides to
                categorize keystreams. It is authenticated as associated
                data & safely differentiates keystreams when it is
                unique for each permutation of `key`, `salt` & `iv`.
        """
        self._aad = aad
        self._byte_count = 0
        self._is_digesting = False
        self._is_finalized = False
        self._buffer = buffer = deque([Padding.start_padding()])
        self._key_bundle = key_bundle = await KeyAADBundle(
            key=key, salt=salt, aad=aad, allow_dangerous_determinism=True
        ).async_mode()
        self.shmac = shmac = StreamHMAC(key_bundle)._for_encryption()
        self._cipher = abytes_encipher(apopleft.root(buffer), shmac)

    @property
    def PACKETSIZE(self) -> int:
        """
        Returns the number of combined bytes each iteration of the
        stream will produce. Equal to 24 + 256; 24-bytes for the
        `block_id` & 256-bytes for the ciphertext block.
        """
        return chunky2048.PACKETSIZE

    @property
    def _iter_shortcuts(self) -> t.Tuple[
        t.Callable[..., bytes],
        t.Deque[bytes],
        t.Callable[[type(None)], bytes],
    ]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self.shmac.anext_block_id, self._buffer, self._cipher.asend

    @property
    def _buffer_shortcuts(self) -> t.Tuple[
        t.Deque[bytes], t.Callable[[bytes], None]
    ]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self._buffer, self._buffer.append

    @property
    def aad(self) -> bytes:
        """
        Returns the current value of the ``aad`` set by the user. This
        value may be updated to add different authentication contexts
        for blocks yet to be processed. **Requires synchonization!**
        """
        return self._aad

    @aad.setter
    def aad(self, value: bytes) -> None:
        """
        Sets a new current value of the ``aad``. This value may be
        updated to add different authentication contexts for blocks yet
        to be processed. **Requires synchonization!**
        """
        if value.__class__ is not bytes:
            raise Issue.value_must_be_type("aad", bytes)
        self._aad = value

    @property
    def salt(self) -> bytes:
        """
        Returns the ephemeral, uniform 16-byte salt value. Automatically
        generated during encryption if not supplied. SHOULD BE USED ONLY
        ONCE for each encryption. Any repeats reduce salt reuse / misuse
        security by 64 bits. It also harms anonymity. This value can be
        sent in the clear along with the ciphertext.
        """
        return self._key_bundle.salt

    @property
    def iv(self) -> bytes:
        """
        Returns the 16-byte ephemeral, uniform ``iv`` value, generated
        automatically & at random by the encryption algorithm. Helps
        ensure salt reuse / misue security even if the `key`, `salt` &
        `aad` are the same for ~2**64 messages. This value can be sent
        in the clear along with the ciphertext.
        """
        return self._key_bundle.iv

    async def __aiter__(self) -> t.AsyncGenerator[
        None, t.Tuple[bytes, bytes]
    ]:
        """
        Allows the object to be entered in for-loops an unlimited amount
        of times in the process of gathering data to buffer for the
        stream. This leads to a very pythonic API.
        """
        anext_block_id, buffer, cipher = self._iter_shortcuts
        while len(buffer) > MIN_STREAM_QUEUE:
            block = await cipher(None)
            yield await anext_block_id(block, aad=self._aad), block

    async def afinalize(self) -> t.AsyncGenerator[
        None, t.Tuple[bytes, bytes]
    ]:
        """
        Instructs the instance to finish receiving data into the buffer
        & to flush all ciphertext results out to the user.

         _____________________________________
        |                                     |
        |      Usage Example: Encryption      |
        |_____________________________________|


        for plaintext in session.upload.buffer(4 * stream.PACKETSIZE):
            await stream.abuffer(plaintext)
            async for block_id, ciphertext in stream:
                session.send_packet(block_id + ciphertext)

        async for block_id, ciphertext in stream.afinalize():  # <------
            session.send_packet(block_id + ciphertext)
        """
        self._is_finalized = True
        async for result in self:
            yield result
        self._buffer[-1] += await Padding.aend_padding(self._byte_count)
        block = await self._cipher.asend(None)
        yield await self.shmac.anext_block_id(block, aad=self._aad), block

    async def _adigest_data(
        self,
        data: t.Callable[[int], bytes],
        buffer: t.Deque[bytes],
        append: t.Callable[[bytes], None],
    ) -> None:
        """
        Prepares the input plaintext ``data`` for encryption by dividing
        it into blocksize chunks.
        """
        if buffer and len(buffer[-1]) != BLOCKSIZE:
            missing_bytes = BLOCKSIZE - len(buffer[-1])
            chunk = data(missing_bytes)
            buffer[-1] += chunk
            if len(chunk) != missing_bytes:
                return
        while True:
            await asleep()
            block = data(BLOCKSIZE)
            append(block)
            if len(block) != BLOCKSIZE:
                break

    async def abuffer(self, data: bytes) -> "self":
        """
        Prepares the input plaintext ``data`` for encryption by dividing
        it into blocksize chunks & taking plaintext measuremenets for
        automated message padding.

         _____________________________________
        |                                     |
        |      Usage Example: Encryption      |
        |_____________________________________|


        for plaintext in session.upload.buffer(4 * stream.PACKETSIZE):
            await stream.abuffer(plaintext)  # <------------------------
            async for block_id, ciphertext in stream:
                session.send_packet(block_id + ciphertext)

        async for block_id, ciphertext in stream.afinalize():
            session.send_packet(block_id + ciphertext)
        """
        if self._is_finalized:
            raise CipherStreamIssue.stream_has_been_closed()
        self._byte_count += len(data)
        data = io.BytesIO(data).read
        _buffer, append = self._buffer_shortcuts
        while self._is_digesting:
            await asleep(0.00001)
        try:
            self._is_digesting = True
            await self._adigest_data(data, _buffer, append)
        finally:
            self._is_digesting = False
        return self


class CipherStream:
    """
    A high-level public interface to the package's online, salt reuse /
    misuse resistant, tweakable AEAD cipher, `Chunky2048`.

    Since this class handles ciphertext validation automatically, all
    decrypted plaintexts are verified & can be released with ~1 / 2**96
    chance of block ID collisions.

    Pads, encrypts & authenticates bytes-type plaintext streams,
    converting them into `Chunky2048` ciphertext streams. The plaintext
    streams are processed in blocks of 256-bytes. Each block is
    prepended with their 24-byte `block_id` authentication tag. The
    total ciphertext length for each block is then 280-bytes & is
    referred to as a packet.

    Validation using `StreamHMAC` `block_id`'s provides robustness to
    communication channels. It does so by detecting forgeries & out-of-
    order messages without changing its internal state. If a tag fails
    to validate, the cipher stream can continue functioning once the
    authentic messages, in their correct order, begin coming in.
    --------
    HOWEVER: The more blocks that are allowed to fail without aborting,
    -------- the more chances an attacker has to spoof the 24-byte tag.

     _____________________________________
    |                                     |
    |      Usage Example: Encryption      |
    |_____________________________________|


    stream = CipherStream(key, aad=session.transcript)
    session.transmit(salt=stream.salt, iv=stream.iv)

    for plaintext in session.upload.buffer(4 * stream.PACKETSIZE):
        stream.buffer(plaintext)
        for block_id, ciphertext in stream:
            session.send_packet(block_id + ciphertext)

    for block_id, ciphertext in stream.finalize():
        session.send_packet(block_id + ciphertext)

    # Give option to check for further validity ------------------------
    # Cryptographically asserts stream is done. ------------------------
    session.transmit(shmac=stream.shmac.finalize())
    """

    __slots__ = (
        "_aad",
        "_buffer",
        "_byte_count",
        "_cipher",
        "_is_digesting",
        "_is_finalized",
        "_key_bundle",
        "shmac",
    )

    def __init__(
        self,
        key: bytes,
        *,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
    ) -> "self":
        """
        Derives encryption keys & initializes a mutable buffer to
        automatically prepare plaintext given by the user with the
        necessary padding & resized to the blocksize of the `Chunky2048`
        cipher.

        ``key``: A 64-byte or greater entropic value that contains the
                user's desired entropy & cryptographic strength.
                Designed to be used as a longer-term user encryption /
                decryption key & is ideally a uniform value.

        ``salt``: An ephemeral, uniform 16-byte salt value. Automatically
                generated during encryption if not supplied. SHOULD BE
                USED ONLY ONCE for each encryption. Any repeats can harm
                anonymity & unnecessarily forces ciphertext security to
                rely on the salt reuse / misuse properties of the cipher.
                This value can be sent in the clear along with the
                ciphertext.

        ``aad``: An arbitrary bytes value that a user decides to
                categorize keystreams. It is authenticated as associated
                data & safely differentiates keystreams when it is
                unique for each permutation of `key`, `salt` & `iv`.
        """
        self._aad = aad
        self._byte_count = 0
        self._is_digesting = False
        self._is_finalized = False
        self._buffer = buffer = deque([Padding.start_padding()])
        self._key_bundle = key_bundle = KeyAADBundle(
            key=key, salt=salt, aad=aad, allow_dangerous_determinism=True
        ).sync_mode()
        self.shmac = shmac = StreamHMAC(key_bundle)._for_encryption()
        self._cipher = bytes_encipher(popleft.root(buffer), shmac)

    @property
    def PACKETSIZE(self) -> int:
        """
        Returns the number of combined bytes each iteration of the
        stream will produce. Equal to 24 + 256; 24-bytes for the
        `block_id` & 256-bytes for the ciphertext block.
        """
        return chunky2048.PACKETSIZE

    @property
    def _iter_shortcuts(self) -> t.Tuple[
        t.Callable[..., bytes],
        t.Deque[bytes],
        t.Callable[[type(None)], bytes],
    ]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self.shmac.next_block_id, self._buffer, self._cipher.send

    @property
    def _buffer_shortcuts(self) -> t.Tuple[
        t.Deque[bytes], t.Callable[[bytes], None]
    ]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self._buffer, self._buffer.append

    @property
    def aad(self) -> bytes:
        """
        Returns the current value of the ``aad`` set by the user. This
        value may be updated to add different authentication contexts
        for blocks yet to be processed. **Requires synchonization!**
        """
        return self._aad

    @aad.setter
    def aad(self, value: bytes) -> None:
        """
        Sets a new current value of the ``aad``. This value may be
        updated to add different authentication contexts for blocks yet
        to be processed. **Requires synchonization!**
        """
        if value.__class__ is not bytes:
            raise Issue.value_must_be_type("aad", bytes)
        self._aad = value

    @property
    def salt(self) -> bytes:
        """
        Returns the ephemeral, uniform 16-byte salt value. Automatically
        generated during encryption if not supplied. SHOULD BE USED ONLY
        ONCE for each encryption. Any repeats reduce salt reuse / misuse
        security by 64 bits. It also harms anonymity. This value can be
        sent in the clear along with the ciphertext.
        """
        return self._key_bundle.salt

    @property
    def iv(self) -> bytes:
        """
        Returns the 16-byte ephemeral, uniform ``iv`` value, generated
        automatically & at random by the encryption algorithm. Helps
        ensure salt reuse / misue security even if the `key`, `salt` &
        `aad` are the same for ~2**64 messages. This value can be sent
        in the clear along with the ciphertext.
        """
        return self._key_bundle.iv

    def __iter__(self) -> t.Generator[
        None, t.Tuple[bytes, bytes], None
    ]:
        """
        Allows the object to be entered in for-loops an unlimited amount
        of times in the process of gathering data to buffer for the
        stream. This leads to a very pythonic API.
        """
        next_block_id, buffer, cipher = self._iter_shortcuts
        while len(buffer) > MIN_STREAM_QUEUE:
            block = cipher(None)
            yield next_block_id(block, aad=self._aad), block

    def finalize(self) -> t.Generator[
        None, t.Tuple[bytes, bytes], None
    ]:
        """
        Instructs the instance to finish receiving data into the buffer
        & to flush all ciphertext results out to the user.

         _____________________________________
        |                                     |
        |      Usage Example: Encryption      |
        |_____________________________________|


        for plaintext in session.upload.buffer(4 * stream.PACKETSIZE):
            stream.buffer(plaintext)
            for block_id, ciphertext in stream:
                session.send_packet(block_id + ciphertext)

        for block_id, ciphertext in stream.finalize():  # <-------------
            session.send_packet(block_id + ciphertext)
        """
        self._is_finalized = True
        for result in self:
            yield result
        self._buffer[-1] += Padding.end_padding(self._byte_count)
        block = self._cipher.send(None)
        yield self.shmac.next_block_id(block, aad=self._aad), block

    def _digest_data(
        self,
        data: t.Callable[[int], bytes],
        buffer: t.Deque[bytes],
        append: t.Callable[[bytes], None],
    ) -> None:
        """
        Prepares the input plaintext ``data`` for encryption by dividing
        it into blocksize chunks.
        """
        if buffer and len(buffer[-1]) != BLOCKSIZE:
            missing_bytes = BLOCKSIZE - len(buffer[-1])
            chunk = data(missing_bytes)
            buffer[-1] += chunk
            if len(chunk) != missing_bytes:
                return
        while True:
            block = data(BLOCKSIZE)
            append(block)
            if len(block) != BLOCKSIZE:
                break

    def buffer(self, data: bytes) -> "self":
        """
        Prepares the input plaintext ``data`` for encryption by dividing
        it into blocksize chunks & taking plaintext measuremenets for
        automated message padding.

         _____________________________________
        |                                     |
        |      Usage Example: Encryption      |
        |_____________________________________|


        for plaintext in session.upload.buffer(4 * stream.PACKETSIZE):
            stream.buffer(plaintext)  # <-------------------------------
            for block_id, ciphertext in stream:
                session.send_packet(block_id + ciphertext)

        for block_id, ciphertext in stream.finalize():
            session.send_packet(block_id + ciphertext)
        """
        if self._is_finalized:
            raise CipherStreamIssue.stream_has_been_closed()
        self._byte_count += len(data)
        data = io.BytesIO(data).read
        _buffer, append = self._buffer_shortcuts
        while self._is_digesting:
            asynchs.sleep(0.00001)
        try:
            self._is_digesting = True
            self._digest_data(data, _buffer, append)
        finally:
            self._is_digesting = False
        return self


class AsyncDecipherStream(metaclass=AsyncInit):
    """
    A high-level public interface to the package's online, salt reuse /
    misuse resistant, tweakable AEAD cipher, `Chunky2048`.

    Since this class handles ciphertext validation automatically, all
    decrypted plaintexts are verified & can be released with ~1 / 2**96
    chance of block ID collisions.

    Authenticates, decrypts & depads streams of `Chunky2048` ciphertext.
    The streams are processed in blocks of 280-bytes, where the first
    24-bytes of each block is its `block_id` authentication tag, & the
    remaining 256-bytes is encrypted plaintext.

    Validation using `StreamHMAC` `block_id`'s provides robustness to
    communication channels. It does so by detecting forgeries & out-of-
    order messages without changing its internal state. If a tag fails
    to validate, the cipher stream can continue functioning once the
    authentic messages, in their correct order, begin coming in.
    --------
    HOWEVER: The more blocks that are allowed to fail without aborting,
    -------- the more chances an attacker has to spoof the 24-byte tag.

     _____________________________________
    |                                     |
    |      Usage Example: Decryption      |
    |_____________________________________|


    stream = await AsyncDecipherStream(
        key, salt=session.salt, aad=session.transcript, iv=session.iv
    )
    for ciphertext in session.download.buffer(4 * stream.PACKETSIZE):
        await stream.abuffer(ciphertext)  # <--- raises InvalidBlockID if
        async for plaintext in stream:    # auth failure in last 4 packets
            yield plaintext

    async for plaintext in stream.afinalize():
        yield plaintext

    # An optional check for further validity ---------------------------
    # Cryptographically asserts stream is done. ------------------------
    shmac = await stream.shmac.afinalize()
    assert aiootp.bytes_are_equal(shmac, session.shmac)
    """

    __slots__ = (
        "_aad",
        "_buffer",
        "_cipher",
        "_is_digesting",
        "_is_finalized",
        "_is_streaming",
        "_key_bundle",
        "_result_queue",
        "_ttl",
        "shmac",
    )

    async def __init__(
        self,
        key: bytes,
        *,
        salt: bytes,
        aad: bytes = DEFAULT_AAD,
        iv: bytes,
        ttl: int = DEFAULT_TTL,
    ) -> "self":
        """
        Derives decryption keys & initializes mutable buffers to
        automatically prepare ciphertext & stage plaintext for retrival
        by the user. The plaintext produced is stripped of its padding,
        which was necessary during encryption for `Chunky2048` to be
        able to provide stronger salt reuse / misuse resistance.

        ``key``: A 64-byte or greater entropic value that contains the
                user's desired entropy & cryptographic strength.
                Designed to be used as a longer-term user encryption /
                decryption key & is ideally a uniform value.

        ``salt``: An ephemeral, uniform 16-byte salt value. Automatically
                generated during encryption if not supplied. SHOULD BE
                USED ONLY ONCE for each encryption. Any repeats can harm
                anonymity & unnecessarily forces ciphertext security to
                rely on the salt reuse / misuse properties of the cipher.
                This value can be sent in the clear along with the
                ciphertext.

        ``aad``: An arbitrary bytes value that a user decides to
                categorize keystreams. It is authenticated as associated
                data & safely differentiates keystreams when it is
                unique for each permutation of `key`, `salt` & `iv`.

        ``iv``: An ephemeral, uniform 16-byte value, generated
                automatically & at random by the encryption algorithm.
                Helps ensure salt reuse / misue security even if the
                `key`, `salt` & `aad` are the same for ~2**64 messages.
                This value can be sent in the clear along with the
                ciphertext.

        ``ttl``: An amount of seconds that dictate the allowable age of
                a ciphertext stream, but ONLY checks the time for expiry
                at the very start of a stream. Has no effect on how long
                a stream can continue to live for.
        """
        self._aad = aad
        self._ttl = ttl
        self._is_digesting = False
        self._is_streaming = False
        self._is_finalized = False
        self._result_queue = deque()
        self._buffer = buffer = deque()
        self._key_bundle = key_bundle = await KeyAADBundle(
            key=key, salt=salt, aad=aad, iv=iv,
        ).async_mode()
        self.shmac = shmac = StreamHMAC(key_bundle)._for_decryption()
        self._cipher = abytes_decipher(apopleft.root(buffer), shmac)

    @property
    def PACKETSIZE(self) -> int:
        """
        Returns the number of combined bytes each iteration of the
        stream will produce. Equal to 24 + 256; 24-bytes for the
        `block_id` & 256-bytes for the ciphertext block.
        """
        return chunky2048.PACKETSIZE

    @property
    def _iter_shortcuts(
        self
    ) -> t.Tuple[
        t.Deque[bytes], t.Callable[[], bytes]
    ]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self._result_queue, self._result_queue.popleft

    @property
    def _digest_data_shortcuts(self) -> t.Tuple[
        t.Callable[[type(None)], bytes], t.Callable[[bytes], None]
    ]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self._cipher.asend, self._result_queue.append

    @property
    def _buffer_shortcuts(self) -> t.Tuple[
        t.Callable[..., None], t.Callable[[bytes], None]
    ]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self.shmac.atest_next_block_id, self._buffer.append

    @property
    def aad(self) -> bytes:
        """
        Returns the current value of the ``aad`` set by the user. This
        value may be updated to add different authentication contexts
        for blocks yet to be processed. **Requires synchonization!**
        """
        return self._aad

    @aad.setter
    def aad(self, value: bytes) -> None:
        """
        Sets a new current value of the ``aad``. This value may be
        updated to add different authentication contexts for blocks yet
        to be processed. **Requires synchonization!**
        """
        if value.__class__ is not bytes:
            raise Issue.value_must_be_type("aad", bytes)
        self._aad = value

    @property
    def salt(self) -> bytes:
        """
        Returns the ephemeral, uniform 16-byte salt value. Automatically
        generated during encryption if not supplied. SHOULD BE USED ONLY
        ONCE for each encryption. Any repeats reduce salt reuse / misuse
        security by 64 bits. It also harms anonymity. This value can be
        sent in the clear along with the ciphertext.
        """
        return self._key_bundle.salt

    @property
    def iv(self) -> bytes:
        """
        Returns the 16-byte ephemeral, uniform ``iv`` value, generated
        automatically & at random by the encryption algorithm. Helps
        ensure salt reuse / misue security even if the `key`, `salt` &
        `aad` are the same for ~2**64 messages. This value can be sent
        in the clear along with the ciphertext.
        """
        return self._key_bundle.iv

    async def __aiter__(self) -> t.AsyncGenerator[None, bytes]:
        """
        Allows the object to be entered in for-loops an unlimited amount
        of times in the process of gathering data to buffer for the
        stream. This leads to a very pythonic API.
        """
        result_queue, pop_result = self._iter_shortcuts
        if not self._is_streaming:
            try:
                self._is_streaming = True
                timestamp = result_queue[0][TIMESTAMP_SLICE]
                await clock.atest_timestamp(timestamp, self._ttl)
            except TimeoutError as error:
                self._is_streaming = False
                raise error
            else:
                result_queue[0] = result_queue[0][INNER_BODY_SLICE]
        while len(result_queue) > MIN_STREAM_QUEUE:
            yield pop_result()
            await asleep()

    async def afinalize(self) -> t.AsyncGenerator[None, bytes]:
        """
        Instructs the instance to finish receiving data into the buffer
        & to flush all results out to the user with its plaintext
        padding removed.

         _____________________________________
        |                                     |
        |      Usage Example: Decryption      |
        |_____________________________________|


        for ciphertext in session.download.buffer(4 * stream.PACKETSIZE):
            await stream.abuffer(ciphertext)  # <--- raises InvalidBlockID if
            async for plaintext in stream:    # auth failure in last 4 packets
                yield plaintext

        async for plaintext in stream.afinalize():
            yield plaintext
        """
        self._is_finalized = True
        async for result in self:
            yield result
        block = self._result_queue.popleft()
        footer_index = Padding.depadding_end_index(block)
        yield block[:footer_index]

    async def _adigest_data(
        self,
        data: t.Callable[[int], bytes],
        atest_block_id: t.Callable[..., None],
        append: t.Callable[[bytes], None],
    ) -> None:
        """
        Prepares the input ciphertext ``data`` for decryption by
        dividing it into blocksize chunks & validating each packet's
        block ID.
        """
        cipher, queue_result = self._digest_data_shortcuts
        while True:
            block_id = data(BLOCK_ID_BYTES)
            if not block_id:
                break
            block = data(BLOCKSIZE)
            try:
                await atest_block_id(block_id, block, aad=self._aad)
            except InvalidBlockID as auth_fail:
                # Package the current state of buffering for the caller
                # to handle authentication failures & negotiation of
                # data retransmission if desired.
                auth_fail.failure_state = AuthFail(block_id, block, data)
                raise auth_fail
            append(block)
            queue_result(await cipher(None))

    async def abuffer(self, data: bytes) -> "self":
        """
        Prepares the input ciphertext ``data`` for decryption by
        dividing it into blocksize chunks & validating each packet's
        block ID.

         _____________________________________
        |                                     |
        |      Usage Example: Decryption      |
        |_____________________________________|


        for ciphertext in session.download.buffer(4 * stream.PACKETSIZE):
            await stream.abuffer(ciphertext)  # <--- raises InvalidBlockID if
            async for plaintext in stream:    # auth failure in last 4 packets
                yield plaintext

        async for plaintext in stream.afinalize():
            yield plaintext
        """
        if self._is_finalized:
            raise CipherStreamIssue.stream_has_been_closed()
        elif not data or len(data) % PACKETSIZE:
            raise CipherStreamIssue.invalid_buffer_size(len(data))
        data = io.BytesIO(data).read
        atest_block_id, append = self._buffer_shortcuts
        while self._is_digesting:
            await asleep(0.00001)
        try:
            self._is_digesting = True
            await self._adigest_data(data, atest_block_id, append)
        finally:
            self._is_digesting = False
        return self


class DecipherStream:
    """
    A high-level public interface to the package's online, salt reuse /
    misuse resistant, tweakable AEAD cipher, `Chunky2048`.

    Since this class handles ciphertext validation automatically, all
    decrypted plaintexts are verified & can be released with ~1 / 2**96
    chance of block ID collisions.

    Authenticates, decrypts & depads streams of `Chunky2048` ciphertext.
    The streams are processed in blocks of 280-bytes, where the first
    24-bytes of each block is its `block_id` authentication tag, & the
    remaining 256-bytes is encrypted plaintext.

    Validation using `StreamHMAC` `block_id`'s provides robustness to
    communication channels. It does so by detecting forgeries & out-of-
    order messages without changing its internal state. If a tag fails
    to validate, the cipher stream can continue functioning once the
    authentic messages, in their correct order, begin coming in.
    --------
    HOWEVER: The more blocks that are allowed to fail without aborting,
    -------- the more chances an attacker has to spoof the 24-byte tag.

     _____________________________________
    |                                     |
    |      Usage Example: Decryption      |
    |_____________________________________|


    stream = DecipherStream(
        key, salt=session.salt, aad=session.transcript, iv=session.iv
    )
    for ciphertext in session.download.buffer(4 * stream.PACKETSIZE):
        stream.buffer(ciphertext)   # <--- raises InvalidBlockID if
        for plaintext in stream:    # auth failure in last 4 packets
            yield plaintext

    for plaintext in stream.finalize():
        yield plaintext

    # An optional check for further validity ---------------------------
    # Cryptographically asserts stream is done. ------------------------
    assert aiootp.bytes_are_equal(stream.shmac.finalize(), session.shmac)
    """

    __slots__ = (
        "_aad",
        "_buffer",
        "_cipher",
        "_is_digesting",
        "_is_finalized",
        "_is_streaming",
        "_key_bundle",
        "_result_queue",
        "_ttl",
        "shmac",
    )

    def __init__(
        self,
        key: bytes,
        *,
        salt: bytes,
        aad: bytes = DEFAULT_AAD,
        iv: bytes,
        ttl: int = DEFAULT_TTL,
    ) -> "self":
        """
        Derives decryption keys & initializes mutable buffers to
        automatically prepare ciphertext & stage plaintext for retrival
        by the user. The plaintext produced is stripped of its padding,
        which was necessary during encryption for `Chunky2048` to be
        able to provide stronger salt reuse / misuse resistance.

        ``key``: A 64-byte or greater entropic value that contains the
                user's desired entropy & cryptographic strength.
                Designed to be used as a longer-term user encryption /
                decryption key & is ideally a uniform value.

        ``salt``: An ephemeral, uniform 16-byte salt value. Automatically
                generated during encryption if not supplied. SHOULD BE
                USED ONLY ONCE for each encryption. Any repeats can harm
                anonymity & unnecessarily forces ciphertext security to
                rely on the salt reuse / misuse properties of the cipher.
                This value can be sent in the clear along with the
                ciphertext.

        ``aad``: An arbitrary bytes value that a user decides to
                categorize keystreams. It is authenticated as associated
                data & safely differentiates keystreams when it is
                unique for each permutation of `key`, `salt` & `iv`.

        ``iv``: An ephemeral, uniform 16-byte value, generated
                automatically & at random by the encryption algorithm.
                Helps ensure salt reuse / misue security even if the
                `key`, `salt` & `aad` are the same for ~2**64 messages.
                This value can be sent in the clear along with the
                ciphertext.

        ``ttl``: An amount of seconds that dictate the allowable age of
                a ciphertext stream, but ONLY checks the time for expiry
                at the very start of a stream. Has no effect on how long
                a stream can continue to live for.
        """
        self._aad = aad
        self._ttl = ttl
        self._is_digesting = False
        self._is_streaming = False
        self._is_finalized = False
        self._result_queue = deque()
        self._buffer = buffer = deque()
        self._key_bundle = key_bundle = KeyAADBundle(
            key=key, salt=salt, aad=aad, iv=iv,
        ).sync_mode()
        self.shmac = shmac = StreamHMAC(key_bundle)._for_decryption()
        self._cipher = bytes_decipher(popleft.root(buffer), shmac)

    @property
    def PACKETSIZE(self) -> int:
        """
        Returns the number of combined bytes each iteration of the
        stream will produce. Equal to 24 + 256; 24-bytes for the
        `block_id` & 256-bytes for the ciphertext block.
        """
        return chunky2048.PACKETSIZE

    @property
    def _iter_shortcuts(self) -> t.Tuple[
        t.Deque[bytes], t.Callable[[], bytes]
    ]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self._result_queue, self._result_queue.popleft

    @property
    def _digest_data_shortcuts(self) -> t.Tuple[
        t.Callable[[type(None)], bytes], t.Callable[[bytes], None]
    ]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self._cipher.send, self._result_queue.append

    @property
    def _buffer_shortcuts(self) -> t.Tuple[
        t.Callable[..., None], t.Callable[[bytes], None]
    ]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self.shmac.test_next_block_id, self._buffer.append

    @property
    def aad(self) -> bytes:
        """
        Returns the current value of the ``aad`` set by the user. This
        value may be updated to add different authentication contexts
        for blocks yet to be processed. **Requires synchonization!**
        """
        return self._aad

    @aad.setter
    def aad(self, value: bytes) -> None:
        """
        Sets a new current value of the ``aad``. This value may be
        updated to add different authentication contexts for blocks yet
        to be processed. **Requires synchonization!**
        """
        if value.__class__ is not bytes:
            raise Issue.value_must_be_type("aad", bytes)
        self._aad = value

    @property
    def salt(self) -> bytes:
        """
        Returns the ephemeral, uniform 16-byte salt value. Automatically
        generated during encryption if not supplied. SHOULD BE USED ONLY
        ONCE for each encryption. Any repeats reduce salt reuse / misuse
        security by 64 bits. It also harms anonymity. This value can be
        sent in the clear along with the ciphertext.
        """
        return self._key_bundle.salt

    @property
    def iv(self) -> bytes:
        """
        Returns the 16-byte ephemeral, uniform ``iv`` value, generated
        automatically & at random by the encryption algorithm. Helps
        ensure salt reuse / misue security even if the `key`, `salt` &
        `aad` are the same for ~2**64 messages. This value can be sent
        in the clear along with the ciphertext.
        """
        return self._key_bundle.iv

    def __iter__(self) -> t.Generator[None, bytes, None]:
        """
        Allows the object to be entered in for-loops an unlimited amount
        of times in the process of gathering data to buffer for the
        stream. This leads to a very pythonic API.
        """
        result_queue, pop_result = self._iter_shortcuts
        if not self._is_streaming:
            try:
                self._is_streaming = True
                timestamp = result_queue[0][TIMESTAMP_SLICE]
                clock.test_timestamp(timestamp, self._ttl)
            except TimeoutError as error:
                self._is_streaming = False
                raise error
            else:
                result_queue[0] = result_queue[0][INNER_BODY_SLICE]
        while len(result_queue) > MIN_STREAM_QUEUE:
            yield pop_result()

    def finalize(self) -> t.Generator[None, bytes, None]:
        """
        Instructs the instance to finish receiving data into the buffer
        & to flush all results out to the user with its plaintext
        padding removed.

         _____________________________________
        |                                     |
        |      Usage Example: Decryption      |
        |_____________________________________|

        for ciphertext in source.download.buffer(4 * stream.PACKETSIZE):
            stream.buffer(ciphertext)   # <--- raises InvalidBlockID if
            for plaintext in stream:    # auth failure in last 4 packets
                yield plaintext
        for plaintext in stream.finalize():
            yield plaintext
        """
        self._is_finalized = True
        for result in self:
            yield result
        block = self._result_queue.popleft()
        footer_index = Padding.depadding_end_index(block)
        yield block[:footer_index]

    def _digest_data(
        self,
        data: t.Callable[[int], bytes],
        test_block_id: t.Callable[..., None],
        append: t.Callable[[bytes], None],
    ) -> None:
        """
        Prepares the input ciphertext ``data`` for decryption by
        dividing it into blocksize chunks & validating each packet's
        block ID.
        """
        cipher, queue_result = self._digest_data_shortcuts
        while True:
            block_id = data(BLOCK_ID_BYTES)
            if not block_id:
                break
            block = data(BLOCKSIZE)
            try:
                test_block_id(block_id, block, aad=self._aad)
            except InvalidBlockID as auth_fail:
                # Package the current state of buffering for the caller
                # to handle authentication failures & negotiation of
                # data retransmission if desired.
                auth_fail.failure_state = AuthFail(block_id, block, data)
                raise auth_fail
            append(block)
            queue_result(cipher(None))

    def buffer(self, data: bytes) -> "self":
        """
        Prepares the input ciphertext ``data`` for decryption by
        dividing it into blocksize chunks & validating each packet's
        block ID.

         _____________________________________
        |                                     |
        |      Usage Example: Decryption      |
        |_____________________________________|

        for ciphertext in source.download.buffer(4 * stream.PACKETSIZE):
            stream.buffer(ciphertext)   # <--- raises InvalidBlockID if
            for plaintext in stream:    # auth failure in last 4 packets
                yield plaintext
        for plaintext in stream.finalize():
            yield plaintext
        """
        if self._is_finalized:
            raise CipherStreamIssue.stream_has_been_closed()
        elif not data or len(data) % PACKETSIZE:
            raise CipherStreamIssue.invalid_buffer_size(len(data))
        data = io.BytesIO(data).read
        test_block_id, append = self._buffer_shortcuts
        while self._is_digesting:
            asynchs.sleep(0.00001)
        try:
            self._is_digesting = True
            self._digest_data(data, test_block_id, append)
        finally:
            self._is_digesting = False
        return self


def aplaintext_stream(data: bytes) -> t.AsyncGenerator[None, bytes]:
    """
     --------------------------------------------------------------
    | PRIVATE: Use high-level Chunky2048 or (Async)CipherStream    |
    |          instead!                                            |
     --------------------------------------------------------------

    Takes in plaintext bytes ``data``, then pads & yields it in 256-byte
    chunks per iteration. The plaintext padding is done in two separate
    ways:

    First, a 4-byte timestamp & 16-byte ephemeral SIV-key are prepended
    to the plaintext. This makes the first block, & the SIV which is
    derived from it, globally unique. This allows the cipher to be
    both online & be strongly salt reuse / misuse resistant, counter to
    findings in https://eprint.iacr.org/2015/189.pdf.

    Second, random padding bytes, & a single byte that encodes the
    padding size, are appended to make the resulting plaintext a
    multiple of the 256-byte blocksize. Further details can be found in
    the `Padding` class.
    """
    return adata.root(Padding.pad_plaintext(data), size=BLOCKSIZE)


def plaintext_stream(data: bytes) -> t.Generator[None, bytes, None]:
    """
     --------------------------------------------------------------
    | PRIVATE: Use high-level Chunky2048 or (Async)CipherStream    |
    |          instead!                                            |
     --------------------------------------------------------------

    Takes in plaintext bytes ``data``, then pads & yields it in 256-byte
    chunks per iteration. The plaintext padding is done in two separate
    ways:

    First, a 4-byte timestamp & 16-byte ephemeral SIV-key are prepended
    to the plaintext. This makes the first block, & the SIV which is
    derived from it, globally unique. This allows the cipher to be
    both online & be strongly salt reuse / misuse resistant, counter to
    findings in https://eprint.iacr.org/2015/189.pdf.

    Second, random padding bytes, & a single byte that encodes the
    padding size, are appended to make the resulting plaintext a
    multiple of the 256-byte blocksize. Further details can be found in
    the `Padding` class.
    """
    return _data.root(Padding.pad_plaintext(data), size=BLOCKSIZE)


async def abytes_encrypt(
    data: bytes,
    key: bytes,
    *,
    salt: t.Optional[bytes] = None,
    aad: bytes = DEFAULT_AAD,
) -> bytes:
    """
    A high-level public interface to the package's salt reuse / misuse
    resistant, tweakable AEAD cipher, `Chunky2048`.

    Returns the `Chunky2048` ciphertext of any bytes type ``data``. The
    returned bytes contain the 32-byte SHMAC authentication tag, the
    16-byte salt, & an ephemeral, uniform & random 16-byte IV.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.

    ``salt``: An ephemeral, uniform 16-byte salt value. Automatically
            generated during encryption if not supplied. SHOULD BE USED
            ONLY ONCE for each encryption. Any repeats can harm
            anonymity & unnecessarily forces ciphertext security to rely
            on the salt reuse / misuse properties of the cipher. This
            value can be sent in the clear along with the ciphertext.

    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of `key`, `salt` & `iv`.
    """
    key_bundle = await KeyAADBundle(
        key=key, salt=salt, aad=aad, allow_dangerous_determinism=True
    ).async_mode()
    shmac = StreamHMAC(key_bundle)._for_encryption()
    data = aplaintext_stream(data)
    ciphering = abytes_encipher(data, shmac)
    ciphertext = (
        b"".join([block async for block in ciphering]),
        key_bundle.iv,
        key_bundle.salt,
        await shmac.afinalize(),
    )
    return b"".join(ciphertext[::-1])


def bytes_encrypt(
    data: bytes,
    key: bytes,
    *,
    salt: t.Optional[bytes] = None,
    aad: bytes = DEFAULT_AAD,
) -> bytes:
    """
    A high-level public interface to the package's salt reuse / misuse
    resistant, tweakable AEAD cipher, `Chunky2048`.

    Returns the `Chunky2048` ciphertext of any bytes type ``data``. The
    returned bytes contain the 32-byte SHMAC authentication tag, the
    16-byte salt, & an ephemeral, uniform & random 16-byte IV.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.

    ``salt``: An ephemeral, uniform 16-byte salt value. Automatically
            generated during encryption if not supplied. SHOULD BE USED
            ONLY ONCE for each encryption. Any repeats can harm
            anonymity & unnecessarily forces ciphertext security to rely
            on the salt reuse / misuse properties of the cipher. This
            value can be sent in the clear along with the ciphertext.

    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of `key`, `salt` & `iv`.
    """
    key_bundle = KeyAADBundle(
        key=key, salt=salt, aad=aad, allow_dangerous_determinism=True
    ).sync_mode()
    shmac = StreamHMAC(key_bundle)._for_encryption()
    data = plaintext_stream(data)
    ciphertext = (
        b"".join(bytes_encipher(data, shmac)),
        key_bundle.iv,
        key_bundle.salt,
        shmac.finalize(),
    )
    return b"".join(ciphertext[::-1])


async def abytes_decrypt(
    data: bytes, key: bytes, *, aad: bytes = DEFAULT_AAD, ttl: int = 0
) -> bytes:
    """
    A high-level public interface to the package's salt reuse / misuse
    resistant, tweakable AEAD cipher, `Chunky2048`.

    Returns the plaintext bytes from the bytes ciphertext ``data``. The
    ``data`` bytes contain the 32-byte SHMAC authentication tag, the
    16-byte salt, & an ephemeral, uniform & random 16-byte IV.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.

    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of `key`, `salt` & `iv`.

    ``ttl``: An amount of seconds that dictate the allowable age of
            the decrypted message.
    """
    data = Ciphertext(data)
    key_bundle = KeyAADBundle(key=key, salt=data.salt, aad=aad, iv=data.iv)
    shmac = StreamHMAC(await key_bundle.async_mode())._for_decryption()
    ciphertext = adata.root(data.ciphertext, size=BLOCKSIZE)
    deciphering = abytes_decipher(ciphertext, shmac)
    plaintext = b"".join([block async for block in deciphering])
    await shmac.afinalize()
    await shmac.atest_shmac(data.shmac)
    return await Padding.adepad_plaintext(plaintext, ttl=ttl)


def bytes_decrypt(
    data: bytes, key: bytes, *, aad: bytes = DEFAULT_AAD, ttl: int = 0
) -> bytes:
    """
    A high-level public interface to the package's salt reuse / misuse
    resistant, tweakable AEAD cipher, `Chunky2048`.

    Returns the plaintext bytes from the bytes ciphertext ``data``. The
    ``data`` bytes contain the 32-byte SHMAC authentication tag, the
    16-byte salt, & an ephemeral, uniform & random 16-byte IV.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.

    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of `key`, `salt` & `iv`.

    ``ttl``: An amount of seconds that dictate the allowable age of
            the decrypted message.
    """
    data = Ciphertext(data)
    key_bundle = KeyAADBundle(key=key, salt=data.salt, aad=aad, iv=data.iv)
    shmac = StreamHMAC(key_bundle.sync_mode())._for_decryption()
    ciphertext = _data.root(data.ciphertext, size=BLOCKSIZE)
    plaintext = b"".join(bytes_decipher(ciphertext, shmac))
    shmac.finalize()
    shmac.test_shmac(data.shmac)
    return Padding.depad_plaintext(plaintext, ttl=ttl)


async def ajson_encrypt(
    data: t.JSONSerializable,
    key: bytes,
    *,
    salt: t.Optional[bytes] = None,
    aad: bytes = DEFAULT_AAD,
) -> bytes:
    """
    A high-level public interface to the package's salt reuse / misuse
    resistant, tweakable AEAD cipher, `Chunky2048`.

    Returns the `Chunky2048` ciphertext of any JSON serializable ``data``.
    The returned bytes contain the 32-byte SHMAC authentication tag, the
    16-byte salt, & an ephemeral, uniform & random 16-byte IV.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.

    ``salt``: An ephemeral, uniform 16-byte salt value. Automatically
            generated during encryption if not supplied. SHOULD BE USED
            ONLY ONCE for each encryption. Any repeats can harm
            anonymity & unnecessarily forces ciphertext security to rely
            on the salt reuse / misuse properties of the cipher. This
            value can be sent in the clear along with the ciphertext.

    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of `key`, `salt` & `iv`.
    """
    return await abytes_encrypt(
        json.dumps(data).encode(), key=key, salt=salt, aad=aad
    )


def json_encrypt(
    data: t.JSONSerializable,
    key: bytes,
    *,
    salt: t.Optional[bytes] = None,
    aad: bytes = DEFAULT_AAD,
) -> bytes:
    """
    A high-level public interface to the package's salt reuse / misuse
    resistant, tweakable AEAD cipher, `Chunky2048`.

    Returns the `Chunky2048` ciphertext of any JSON serializable ``data``.
    The returned bytes contain the 32-byte SHMAC authentication tag, the
    16-byte salt, & an ephemeral, uniform & random 16-byte IV.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.

    ``salt``: An ephemeral, uniform 16-byte salt value. Automatically
            generated during encryption if not supplied. SHOULD BE USED
            ONLY ONCE for each encryption. Any repeats can harm
            anonymity & unnecessarily forces ciphertext security to rely
            on the salt reuse / misuse properties of the cipher. This
            value can be sent in the clear along with the ciphertext.

    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of `key`, `salt` & `iv`.
    """
    return bytes_encrypt(
        json.dumps(data).encode(), key=key, salt=salt, aad=aad
    )


async def ajson_decrypt(
    data: bytes, key: bytes, *, aad: bytes = DEFAULT_AAD, ttl: int = 0
) -> t.JSONSerializable:
    """
    A high-level public interface to the package's salt reuse / misuse
    resistant, tweakable AEAD cipher, `Chunky2048`.

    Returns the loaded plaintext JSON deserializable value from the
    bytes ciphertext ``data``.  The ``data`` bytes contain the 32-byte
    SHMAC authentication tag, the 16-byte salt, & an ephemeral, uniform
    & random 16-byte IV.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.

    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of `key`, `salt` & `iv`.

    ``ttl``: An amount of seconds that dictate the allowable age of
            the decrypted message.
    """
    return json.loads(await abytes_decrypt(data, key=key, aad=aad, ttl=ttl))


def json_decrypt(
    data: bytes, key: bytes, *, aad: bytes = DEFAULT_AAD, ttl: int = 0
) -> t.JSONSerializable:
    """
    A high-level public interface to the package's salt reuse / misuse
    resistant, tweakable AEAD cipher, `Chunky2048`.

    Returns the loaded plaintext JSON deserializable value from the
    bytes ciphertext ``data``.  The ``data`` bytes contain the 32-byte
    SHMAC authentication tag, the 16-byte salt, & an ephemeral, uniform
    & random 16-byte IV.

    ``key``: A 64-byte or greater entropic value that contains the
            user's desired entropy & cryptographic strength. Designed to
            be used as a longer-term user encryption / decryption key &
            is ideally a uniform value.

    ``aad``: An arbitrary bytes value that a user decides to categorize
            keystreams. It is authenticated as associated data & safely
            differentiates keystreams when it is unique for each
            permutation of `key`, `salt` & `iv`.

    ``ttl``: An amount of seconds that dictate the allowable age of
            the decrypted message.
    """
    return json.loads(bytes_decrypt(data, key=key, aad=aad, ttl=ttl))


class Chunky2048:
    r"""
    An efficient high-level public interface to the package's online,
    salt reuse / misuse resistant, tweakable AEAD pseudo one-time pad
    cipher implementation. This implementation is built primarily out of
    async & sync generators as data processing pipelines & communication
    coroutines.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    key = aiootp.generate_key()
    cipher = aiootp.Chunky2048(key)

    ciphertext = cipher.bytes_encrypt(b"binary data")
    assert isinstance(ciphertext, bytes)
    plaintext = cipher.bytes_decrypt(ciphertext)
    assert plaintext == b"binary data"

    ciphertext = cipher.json_encrypt({"any": "JSON serializable object"})
    assert isinstance(ciphertext, bytes)
    plaintext = cipher.json_decrypt(ciphertext)
    assert plaintext == {"any": "JSON serializable object"}

    # Encrypted & authenticated urlsafe tokens can be created too ->
    token = cipher.make_token(b"binary data")
    print(token)
    b'''RAJE5RxTUY_NmMwvkbv3xGl-hPgLbcWUfCKCBR4wCLxH598ee7qk22DvKZVF417k
    nZAtj6Xud4yxz189V28FaQboFuq6yxeFRpWt6FzfDZwSUM_lBBSCB44xmufC9T5w1kiE
    5x6R340aCQW5LX6J3lyAuLLo7qlTT7tADWnw1TNrIGjEsMzPRykkMjozU2KDn2KBzJWq
    -b-3A-6HxY1NaJ-SItywKf601ebCe2mB3VbuLPlVligGTB1PH3QUhnKQ9VdSaOxtRezs
    0PXqFt44QQVaV-krZsiRZpxieVHzWpLl5apqnESYehriv28lmbnv1KXlbxPxwMQNXAqI
    6ae-RU_nESmjRKPnt9NGQPwpcvnKQztLkCk6PjaH74zsMUALAklWzE0ats4yDAZ1ACZk
    YmaEup0q2keiesd5Qmgcao8%3D'''
    assert b"binary data" == cipher.read_token(token)

     _____________________________________
    |                                     |
    |     Algorithm Pseudocode: Init      |
    |_____________________________________|

    e = a canonical, domain-specified encoding / padding function
    S = seed_kdf = shake_128(e(SALT_S, key, salt, aad, iv, METADATA))
    L = left_kdf = shake_128(e(SALT_L, key, salt, aad, iv, METADATA))
    R = right_kdf = shake_128(e(SALT_R, key, salt, aad, iv, METADATA))
    V = shmac_mac = shake_128(e(SALT_V, key, salt, aad, iv, METADATA))
    P = 256-byte plaintext block
    C = 256-byte ciphertext block
    S_L, S_R = the two 168-byte seed_kdf outputs for the left & right kdfs
    K_L, K_R = the two 128-byte left & right kdf outputs

    Each block, except for the first (see `SyntheticIV`),
    is processed as such:

     _____________________________________
    |                                     |
    |    Algorithm Diagram: Encryption    |
    |_____________________________________|
                                               ___ ___
                                                |   |
                                -----           |   |
                       S_L --->|  L  |--->K_L---⊕-->|
                      /         -----           |   |
     -----      -----/                          |   |     -----      ---
    |  V  |--->|  S  |                          P   C--->|  V  |--->|  S
     -----      -----\                          |   |     -----      ---
                      \         -----           |   |
                       S_R --->|  R  |--->K_R---⊕-->|
                                -----           |   |
                                                |   |
                                               _|_ _|_

     _____________________________________
    |                                     |
    |    Algorithm Diagram: Decryption    |
    |_____________________________________|
                                               ___ ___
                                                |   |
                                -----           |   |
                       S_L --->|  L  |--->K_L---⊕-->|
                      /         -----           |   |
     -----      -----/                          |   |     -----      ---
    |  V  |--->|  S  |                          C   P    |  V  |--->|  S
     -----      -----\                          |   |     -----      ---
                      \         -----           |   |       ^
                       S_R --->|  R  |--->K_R---⊕-->|       |
                                -----           |   |       |
                                                |   |       |
                                               _|_ _|_      |
                                                |           |
                                                -------------
    """

    __slots__ = ("_key",)

    InvalidSHMAC = InvalidSHMAC
    TimestampExpired = TimestampExpired

    def __init__(self, key: bytes) -> "self":
        """
        Creates an efficient object which manages a main encryption
        ``key`` for use in the `Chunky2048` cipher.
        """
        if len(key) < MIN_KEY_BYTES:
            raise KeyAADIssue.invalid_key()
        self._key = key

    async def abytes_encrypt(
        self,
        data: bytes,
        *,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        Returns the `Chunky2048` ciphertext of any bytes type ``data``.
        The returned bytes contain the 32-byte SHMAC authentication tag,
        the 16-byte salt, & an ephemeral, uniform & random 16-byte IV.

        ``salt``: An ephemeral, uniform 16-byte salt value. Automatically
                generated during encryption if not supplied. SHOULD BE
                USED ONLY ONCE for each encryption. Any repeats can harm
                anonymity & unnecessarily forces ciphertext security to rely
                on the salt reuse / misuse properties of the cipher. This
                value can be sent in the clear along with the ciphertext.

        ``aad``: An arbitrary bytes value that a user decides to categorize
                keystreams. It is authenticated as associated data & safely
                differentiates keystreams when it is unique for each
                permutation of `key`, `salt` & `iv`.
        """
        return await abytes_encrypt(data, key=self._key, salt=salt, aad=aad)

    def bytes_encrypt(
        self,
        data: bytes,
        *,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        A high-level public interface to the package's salt reuse /
        misuse resistant, tweakable AEAD cipher, `Chunky2048`.

        Returns the `Chunky2048` ciphertext of any bytes type ``data``.
        The returned bytes contain the 32-byte SHMAC authentication tag,
        the 16-byte salt, & an ephemeral, uniform & random 16-byte IV.

        ``salt``: An ephemeral, uniform 16-byte salt value. Automatically
                generated during encryption if not supplied. SHOULD BE
                USED ONLY ONCE for each encryption. Any repeats can harm
                anonymity & unnecessarily forces ciphertext security to rely
                on the salt reuse / misuse properties of the cipher. This
                value can be sent in the clear along with the ciphertext.

        ``aad``: An arbitrary bytes value that a user decides to categorize
                keystreams. It is authenticated as associated data & safely
                differentiates keystreams when it is unique for each
                permutation of `key`, `salt` & `iv`.
        """
        return bytes_encrypt(data, key=self._key, salt=salt, aad=aad)

    async def abytes_decrypt(
        self, data: bytes, *, aad: bytes = DEFAULT_AAD, ttl: int = 0
    ) -> bytes:
        """
        A high-level public interface to the package's salt reuse /
        misuse resistant, tweakable AEAD cipher, `Chunky2048`.

        Returns the plaintext bytes from the bytes ciphertext ``data``.
        The ``data`` bytes contain the 32-byte SHMAC authentication tag,
        the 16-byte salt, & an ephemeral, uniform & random 16-byte IV.

        ``aad``: An arbitrary bytes value that a user decides to categorize
                keystreams. It is authenticated as associated data & safely
                differentiates keystreams when it is unique for each
                permutation of `key`, `salt` & `iv`.

        ``ttl``: An amount of seconds that dictate the allowable age of
                the decrypted message.
        """
        return await abytes_decrypt(data, key=self._key, aad=aad, ttl=ttl)

    def bytes_decrypt(
        self, data: bytes, *, aad: bytes = DEFAULT_AAD, ttl: int = 0
    ) -> bytes:
        """
        A high-level public interface to the package's salt reuse /
        misuse resistant, tweakable AEAD cipher, `Chunky2048`.

        Returns the plaintext bytes from the bytes ciphertext ``data``.
        The ``data`` bytes contain the 32-byte SHMAC authentication tag,
        the 16-byte salt, & an ephemeral, uniform & random 16-byte IV.

        ``aad``: An arbitrary bytes value that a user decides to categorize
                keystreams. It is authenticated as associated data & safely
                differentiates keystreams when it is unique for each
                permutation of `key`, `salt` & `iv`.

        ``ttl``: An amount of seconds that dictate the allowable age of
                the decrypted message.
        """
        return bytes_decrypt(data, key=self._key, aad=aad, ttl=ttl)

    async def ajson_encrypt(
        self,
        data: t.JSONSerializable,
        *,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        A high-level public interface to the package's salt reuse /
        misuse resistant, tweakable AEAD cipher, `Chunky2048`.

        Returns the `Chunky2048` ciphertext of any JSON serializable
        ``data``. The returned bytes contain the 32-byte SHMAC
        authentication tag, the 16-byte salt, & an ephemeral, uniform &
        random 16-byte IV.

        ``salt``: An ephemeral, uniform 16-byte salt value. Automatically
                generated during encryption if not supplied. SHOULD BE
                USED ONLY ONCE for each encryption. Any repeats can harm
                anonymity & unnecessarily forces ciphertext security to rely
                on the salt reuse / misuse properties of the cipher. This
                value can be sent in the clear along with the ciphertext.

        ``aad``: An arbitrary bytes value that a user decides to categorize
                keystreams. It is authenticated as associated data & safely
                differentiates keystreams when it is unique for each
                permutation of `key`, `salt` & `iv`.
        """
        return await ajson_encrypt(data, key=self._key, salt=salt, aad=aad)

    def json_encrypt(
        self,
        data: t.JSONSerializable,
        *,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
    ) -> bytes:
        """
        A high-level public interface to the package's salt reuse /
        misuse resistant, tweakable AEAD cipher, `Chunky2048`.

        Returns the `Chunky2048` ciphertext of any JSON serializable
        ``data``. The returned bytes contain the 32-byte SHMAC
        authentication tag, the 16-byte salt, & an ephemeral, uniform &
        random 16-byte IV.

        ``salt``: An ephemeral, uniform 16-byte salt value. Automatically
                generated during encryption if not supplied. SHOULD BE
                USED ONLY ONCE for each encryption. Any repeats can harm
                anonymity & unnecessarily forces ciphertext security to rely
                on the salt reuse / misuse properties of the cipher. This
                value can be sent in the clear along with the ciphertext.

        ``aad``: An arbitrary bytes value that a user decides to categorize
                keystreams. It is authenticated as associated data & safely
                differentiates keystreams when it is unique for each
                permutation of `key`, `salt` & `iv`.
        """
        return json_encrypt(data, key=self._key, salt=salt, aad=aad)

    async def ajson_decrypt(
        self, data: bytes, *, aad: bytes = DEFAULT_AAD, ttl: int = 0
    ) -> t.JSONSerializable:
        """
        A high-level public interface to the package's salt reuse /
        misuse resistant, tweakable AEAD cipher, `Chunky2048`.

        Returns the loaded plaintext JSON deserializable value from the
        bytes ciphertext ``data``.  The ``data`` bytes contain the 32-
        byte SHMAC authentication tag, the 16-byte salt, & an ephemeral,
        uniform & random 16-byte IV.

        ``aad``: An arbitrary bytes value that a user decides to categorize
                keystreams. It is authenticated as associated data & safely
                differentiates keystreams when it is unique for each
                permutation of `key`, `salt` & `iv`.

        ``ttl``: An amount of seconds that dictate the allowable age of
                the decrypted message.
        """
        return await ajson_decrypt(data, key=self._key, aad=aad, ttl=ttl)

    def json_decrypt(
        self, data: bytes, *, aad: bytes = DEFAULT_AAD, ttl: int = 0
    ) -> t.JSONSerializable:
        """
        A high-level public interface to the package's salt reuse /
        misuse resistant, tweakable AEAD cipher, `Chunky2048`.

        Returns the loaded plaintext JSON deserializable value from the
        bytes ciphertext ``data``.  The ``data`` bytes contain the 32-
        byte SHMAC authentication tag, the 16-byte salt, & an ephemeral,
        uniform & random 16-byte IV.

        ``aad``: An arbitrary bytes value that a user decides to categorize
                keystreams. It is authenticated as associated data & safely
                differentiates keystreams when it is unique for each
                permutation of `key`, `salt` & `iv`.

        ``ttl``: An amount of seconds that dictate the allowable age of
                the decrypted message.
        """
        return json_decrypt(data, key=self._key, aad=aad, ttl=ttl)

    async def amake_token(
        self, data: bytes, *, aad: bytes = DEFAULT_AAD
    ) -> bytes:
        """
        A high-level public interface to the package's salt reuse /
        misuse resistant, tweakable AEAD cipher, `Chunky2048`.

        Encrypts the bytes-type ``data`` with the instance key & returns
        a urlsafe encoded ciphertext token. The ``token`` bytes contain
        the 32-byte SHMAC authentication tag, the 16-byte salt, & an
        ephemeral, uniform & random 16-byte IV.

        ``aad``: An arbitrary bytes value that a user decides to categorize
                keystreams. It is authenticated as associated data & safely
                differentiates keystreams when it is unique for each
                permutation of `key`, `salt` & `iv`.
        """
        if data.__class__ is not bytes:
            raise Issue.value_must_be_type("token data", bytes)
        ciphertext = await self.abytes_encrypt(data, aad=aad)
        return await BytesIO.abytes_to_urlsafe(ciphertext)

    def make_token(self, data: bytes, *, aad: bytes = DEFAULT_AAD) -> bytes:
        """
        A high-level public interface to the package's salt reuse /
        misuse resistant, tweakable AEAD cipher, `Chunky2048`.

        Encrypts the bytes-type ``data`` with the instance key & returns
        a urlsafe encoded ciphertext token. The ``token`` bytes contain
        the 32-byte SHMAC authentication tag, the 16-byte salt, & an
        ephemeral, uniform & random 16-byte IV.

        ``aad``: An arbitrary bytes value that a user decides to categorize
                keystreams. It is authenticated as associated data & safely
                differentiates keystreams when it is unique for each
                permutation of `key`, `salt` & `iv`.
        """
        if data.__class__ is not bytes:
            raise Issue.value_must_be_type("token data", bytes)
        ciphertext = self.bytes_encrypt(data, aad=aad)
        return BytesIO.bytes_to_urlsafe(ciphertext)

    async def aread_token(
        self,
        token: t.Base64URLSafe,
        *,
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
    ) -> bytes:
        """
        A high-level public interface to the package's salt reuse /
        misuse resistant, tweakable AEAD cipher, `Chunky2048`.

        Decodes a ciphertext ``token`` & returns the decrypted token
        data. The ``token`` bytes contain the 32-byte SHMAC authentication
        tag, the 16-byte salt, & an ephemeral, uniform & random 16-byte
        IV.

        ``aad``: An arbitrary bytes value that a user decides to categorize
                keystreams. It is authenticated as associated data & safely
                differentiates keystreams when it is unique for each
                permutation of `key`, `salt` & `iv`.

        ``ttl``: An amount of seconds that dictate the allowable age of
                the decrypted message.
        """
        if token.__class__ is not bytes:
            token = token.encode()
        ciphertext = await BytesIO.aurlsafe_to_bytes(token)
        return await self.abytes_decrypt(ciphertext, aad=aad, ttl=ttl)

    def read_token(
        self,
        token: t.Base64URLSafe,
        *,
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
    ) -> bytes:
        """
        A high-level public interface to the package's salt reuse /
        misuse resistant, tweakable AEAD cipher, `Chunky2048`.

        Decodes a ciphertext ``token`` & returns the decrypted token
        data. The ``token`` bytes contain the 32-byte SHMAC authentication
        tag, the 16-byte salt, & an ephemeral, uniform & random 16-byte
        IV.

        ``aad``: An arbitrary bytes value that a user decides to categorize
                keystreams. It is authenticated as associated data & safely
                differentiates keystreams when it is unique for each
                permutation of `key`, `salt` & `iv`.

        ``ttl``: An amount of seconds that dictate the allowable age of
                the decrypted message.
        """
        if token.__class__ is not bytes:
            token = token.encode()
        ciphertext = BytesIO.urlsafe_to_bytes(token)
        return self.bytes_decrypt(ciphertext, aad=aad, ttl=ttl)


extras = dict(
    _StreamHMAC=StreamHMAC,
    _SyntheticIV=SyntheticIV,
    AsyncCipherStream=AsyncCipherStream,
    AsyncDecipherStream=AsyncDecipherStream,
    ChaCha20Poly1305=ChaCha20Poly1305,
    Chunky2048=Chunky2048,
    CipherStream=CipherStream,
    DecipherStream=DecipherStream,
    __doc__=__doc__,
    __package__=__package__,
    _abytes_decipher=abytes_decipher,
    _abytes_encipher=abytes_encipher,
    _aplaintext_stream=aplaintext_stream,
    _bytes_decipher=bytes_decipher,
    _bytes_encipher=bytes_encipher,
    _plaintext_stream=plaintext_stream,
    abytes_decrypt=abytes_decrypt,
    abytes_encrypt=abytes_encrypt,
    ajson_decrypt=ajson_decrypt,
    ajson_encrypt=ajson_encrypt,
    bytes_decrypt=bytes_decrypt,
    bytes_encrypt=bytes_encrypt,
    json_decrypt=json_decrypt,
    json_encrypt=json_encrypt,
)


ciphers = make_module("ciphers", mapping=extras)

