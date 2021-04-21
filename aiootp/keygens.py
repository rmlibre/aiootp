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
    "keygens",
    "Ropake",
    "X25519",
    "Ed25519",
    "AsyncKeys",
    "Keys",
    "amnemonic",
    "mnemonic",
]


__doc__ = (
    "A collection of high-level tools for creating & managing symmetric "
    "& 25519 elliptic curve asymmetric keys."
)


from collections import deque
import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey, X25519PrivateKey
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey, Ed25519PrivateKey
)
from hashlib import sha3_256, sha3_512
from .asynchs import *
from .commons import *
from commons import *  # import the module's constants
from .randoms import csprbg, acsprbg
from .randoms import csprng, acsprng
from .randoms import random_256, arandom_256
from .randoms import random_512, arandom_512
from .randoms import token_hash, atoken_hash
from .randoms import generate_salt, agenerate_salt
from .ciphers import Database
from .ciphers import DomainKDF
from .ciphers import Passcrypt
from .ciphers import AsyncDatabase
from .ciphers import keys, akeys
from .ciphers import passcrypt, apasscrypt
from .ciphers import bytes_keys, abytes_keys
from .ciphers import padding_key, apadding_key
from .ciphers import json_encrypt, ajson_encrypt
from .ciphers import json_decrypt, ajson_decrypt
from .ciphers import keypair_ratchets, akeypair_ratchets
from .ciphers import test_key_and_salt, atest_key_and_salt
from .generics import azip
from .generics import Hasher
from .generics import arange
from .generics import Domains
from .generics import is_iterable
from .generics import comprehension
from .generics import sha_256, asha_256
from .generics import sha_512, asha_512
from .generics import bytes_range, abytes_range
from .generics import sha_256_hmac, asha_256_hmac
from .generics import sha_512_hmac, asha_512_hmac
from .generics import convert_static_method_to_member
from .generics import time_safe_equality, atime_safe_equality


@comprehension()
async def atable_keystream(key=None, table=ASCII_TABLE):
    """
    This table based key generator function converts any key string
    containing an arbitrary set of characters, into another key string
    containing the set of characters provided by the table argument.
    This is an infinite generator that produces key material at about
    128 bytes per iteration.

    The ASCII_TABLE that's provided as a default, is a comprehensive set
    of ascii characters that are legible, unique, and have single octet
    byte representations. It contains 95 unique characters.

    This generator function provides either deterministic keys from a
    user key, or generates a random 512-bit hash and derives a random
    key with the desired table elements from this hash. The result is a
    random, normal distribution of characters from among the items
    within the table.

    Usage Examples:

    key = "hotdiggitydog_thischowisyummy"
    async with atable_keystream(key=key) as generator:
        new_key = await generator()
        assert new_key != await generator()
    print(new_key)
    >>> Hx`4^ej;u&/]qOF21Ea2~(6f"smp'DvMk[(wy'lME%CpCo|1ZWt> &tu=Mw_
    """
    if not key:
        key = await acsprng()
    size = len(table)
    keystream = abytes_keys(key, salt=key).abytes_to_int()
    async for key_portion in keystream.ato_base(size, table):
        yield key_portion


@comprehension()
def table_keystream(key=None, table=ASCII_TABLE):
    """
    This table based key generator function converts any key string
    containing an arbitrary set of characters, into another key string
    containing the set of characters provided by the table argument.
    This is an infinite generator that produces key material at about
    128 bytes per iteration.

    The ASCII_TABLE that's provided as a default, is a comprehensive set
    of ascii characters that are legible, unique, and have single octet
    byte representations. It contains 95 unique characters.

    This generator function provides either deterministic keys from a
    user key, or generates a random 512-bit hash and derives a random
    key with the desired table elements from this hash. The result is a
    random, normal distribution of characters from among the items
    within the table.

    Usage Example:

    key = "hotdiggitydog_thischowisyummy"
    with table_keystream(key=key) as generator:
        new_key = generator()
        assert new_key != generator()
    print(new_key)
    >>> Hx`4^ej;u&/]qOF21Ea2~(6f"smp'DvMk[(wy'lME%CpCo|1ZWt> &tu=Mw_
    """
    if not key:
        key = csprng()
    size = len(table)
    keystream = bytes_keys(key, salt=key).bytes_to_int()
    for key_portion in keystream.to_base(size, table):
        yield key_portion


async def atable_key(key=None, table=ASCII_TABLE, size=64):
    """
    This table based key function converts any key string containing
    any arbitrary set of characters, into another key string containing
    the set of items provided by the table argument.

    The ASCII_TABLE that's provided as a default, is a comprehensive set
    of ascii characters that are all legible, with unique, single octet
    byte representations. It contains 95 unique characters.

    This generator function provides either deterministic keys from a
    user key, or generates a random 512-bit hash and derives a random
    key with the desired table elements from this hash. The result is a
    random, normal distribution of characters from among the items
    within the table.

    The size parameter determines the number of bytes/elements the
    output will contain.


    Usage Examples:

    key = "smellycaaaat, smelly caaaaat!"
    new_key = table_key(key=key, table="0123456789abcdef")
    print(new_key)
    >>> 4f271c61b0e615a7d3e9ac0161497034d047d4ecddc650ae054f829b3416818c

    new_key = table_key(key=key, size=len(key))
    print(new_key)
    >>> #mE)bOQD@lY%]Qwpb9Zi^32]jteVg
    """
    async with atable_keystream(key=key, table=table) as generator:
        new_key = await generator()
        while len(new_key) < size:
            new_key += await generator()
        return new_key[:size]


def table_key(key=None, table=ASCII_TABLE, size=64):
    """
    This table based key function converts any key string containing
    any arbitrary set of characters, into another key string containing
    the set of items provided by the table argument.

    The ASCII_TABLE that's provided as a default, is a comprehensive set
    of ascii characters that are all legible, with unique, single octet
    byte representations. It contains 95 unique characters.

    This generator function provides either deterministic keys from a
    user key, or generates a random 512-bit hash and derives a random
    key with the desired table elements from this hash. The result is a
    random, normal distribution of characters from among the items
    within the table.

    The size parameter determines the number of bytes/elements the
    output will contain.


    Usage Examples:
    key = "smellycaaaat, smelly caaaaat!"
    new_key = table_key(key=key, table="0123456789abcdef")
    print(new_key)
    >>> 4f271c61b0e615a7d3e9ac0161497034d047d4ecddc650ae054f829b3416818c

    new_key = table_key(key=key, size=len(key))
    print(new_key)
    >>> #mE)bOQD@lY%]Qwpb9Zi^32]jteVg
    """
    with table_keystream(key=key, table=table) as generator:
        new_key = generator()
        while len(new_key) < size:
            new_key += generator()
        return new_key[:size]


@comprehension()
async def amnemonic(
    key,
    *,
    salt=None,
    words=None,
    kb=Passcrypt._DEFAULT_KB,
    cpu=Passcrypt._DEFAULT_CPU,
    hardness=Passcrypt._DEFAULT_HARDNESS,
):
    """
    Creates a stream of words for a mnemonic key from a user password
    ``key`` & random salt. If a salt isn't passed, then a random salt is
    generated & is available by calling ``result(exit=True)`` on the
    generator object. The ``words`` used for the mnemonic can be passed
    in, but by default are a 2048 word list of unique, all lowercase
    english words.
    """
    keystream_shift = None
    words = words if words else WORD_LIST
    length = len(words)
    salt = salt if salt else await agenerate_salt()
    key = await apasscrypt(key, salt, kb=kb, cpu=cpu, hardness=hardness)
    keystream = abytes_keys(key, salt=salt, pid=key)
    async with keystream.abytes_to_int().arelay(salt) as indexes:
        while True:
            if keystream_shift:
                await keystream.gen.asend(keystream_shift)
            keystream_shift = yield words[await indexes() % length]


@comprehension()
def mnemonic(
    key,
    *,
    salt=None,
    words=None,
    kb=Passcrypt._DEFAULT_KB,
    cpu=Passcrypt._DEFAULT_CPU,
    hardness=Passcrypt._DEFAULT_HARDNESS,
):
    """
    Creates a stream of words for a mnemonic key from a user password
    ``key`` & random salt. If a salt isn't passed, then a random salt is
    generated & is available by calling ``result(exit=True)`` on the
    generator object. The ``words`` used for the mnemonic can be passed
    in, but by default are a 2048 word list of unique, all lowercase
    english words.
    """
    keystream_shift = None
    words = words if words else WORD_LIST
    length = len(words)
    salt = salt if salt else generate_salt()
    key = passcrypt(key, salt, kb=kb, cpu=cpu, hardness=hardness)
    keystream = bytes_keys(key, salt=salt, pid=key)
    with keystream.bytes_to_int().relay(salt) as indexes:
        while True:
            if keystream_shift:
                keystream.gen.send(keystream_shift)
            keystream_shift = yield words[indexes() % length]


async def ainsert_keygens(self, key=None, *, automate_key_use=True):
    """
    A generic __init__ function that can be copied into abitrary class
    or instance dictionaries to give those objects access to stateful
    & ephemeral key material generators.
    """
    key = key if key else await acsprng()
    self.keygen = Keys(key=key, automate_key_use=automate_key_use)
    self.akeygen = AsyncKeys(key=key, automate_key_use=automate_key_use)


def insert_keygens(self, key=None, *, automate_key_use=True):
    """
    A generic __init__ function that can be copied into abitrary class
    or instance dictionaries to give those objects access to stateful
    & ephemeral key material generators.
    """
    key = key if key else csprng()
    self.keygen = Keys(key=key, automate_key_use=automate_key_use)
    self.akeygen = AsyncKeys(key=key, automate_key_use=automate_key_use)


async def asingle_use_key(key=None, *, salt=None, pid=0):
    """
    Returns a mapping containing a unique combination of a ``key``,
    ``salt`` & ``pid`` whose use is limited TO A SINGLE encryption /
    decryption round. The reuse of the same permutation of ``key``,
    ``salt`` & ``pid`` for multiple different messages **completely**
    breaks the security of the encryption algorithm if the correct
    padding, available from the `Padding` class, on the plaintext is not
    used.

    Both new ``key`` & ``salt`` values are returned in the mapping
    if neither are specified. The returned ``pid`` defaults to ``0``,
    as it does across the package.
    """
    if key and salt:
        raise PermissionError(UNSAFE_KEY_REUSE)
    key = key if key else await acsprng()
    salt = salt if salt else await agenerate_salt()
    await atest_key_and_salt(key, salt)
    return Namespace(key=key, salt=salt, pid=pid)


def single_use_key(key=None, *, salt=None, pid=0):
    """
    Returns a mapping containing a unique combination of a ``key``,
    ``salt`` & ``pid`` whose use is limited TO A SINGLE encryption /
    decryption round. The reuse of the same permutation of ``key``,
    ``salt`` & ``pid`` for multiple different messages **completely**
    breaks the security of the encryption algorithm if the correct
    padding, available from the `Padding` class, on the plaintext is not
    used.

    Both new ``key`` & ``salt`` values are returned in the mapping
    if neither are specified. The returned ``pid`` defaults to ``0``,
    as it does across the package.
    """
    if key and salt:
        raise PermissionError(UNSAFE_KEY_REUSE)
    key = key if key else csprng()
    salt = salt if salt else generate_salt()
    test_key_and_salt(key, salt)
    return Namespace(key=key, salt=salt, pid=pid)


class AsyncKeys:
    """
    This simple class coordinates and manages a symmetric key to create
    pseudo-one-time-pad key material streams, key derivation functions,
    as well as HMAC creation & HMAC validation of data. The class also
    contains static methods & key generators that function independantly
    from instance states.
    """
    instance_methods = {
        akeys,
        abytes_keys,
        amnemonic,
        atable_key,
        atable_keystream,
        asingle_use_key,
    }

    DomainKDF = DomainKDF
    akeys = staticmethod(akeys)
    acsprbg = staticmethod(acsprbg)
    acsprng = staticmethod(acsprng)
    amnemonic = staticmethod(amnemonic)
    apasscrypt = staticmethod(apasscrypt)
    atable_key = staticmethod(atable_key)
    arandom_256 = staticmethod(arandom_256)
    arandom_512 = staticmethod(arandom_512)
    abytes_keys = staticmethod(abytes_keys)
    apadding_key = staticmethod(apadding_key)
    agenerate_salt = staticmethod(agenerate_salt)
    asingle_use_key = staticmethod(asingle_use_key)
    atable_keystream = staticmethod(atable_keystream)
    akeypair_ratchets = staticmethod(akeypair_ratchets)
    _atest_key_and_salt = staticmethod(atest_key_and_salt)
    _atime_safe_equality = staticmethod(atime_safe_equality)

    def __init__(self, key=None, *, automate_key_use=True):
        """
        Stores a key in the instance used to create deterministic
        streams of key material &, create & validate HMAC codes. If a
        ``key`` argument is not passed then a new 512-bit random key is
        created.
        """
        self._reset(key=key, automate_key_use=automate_key_use)
        self.apasscrypt = self._apasscrypt

    @property
    def key(self):
        """
        Returns the instance's main symmetric key.
        """
        return self._key

    async def ahmac(
        self, data, *, key=None, hasher=asha_256_hmac
    ):
        """
        Creates an HMAC code of ``data`` using ``key``  or the
        instance's ``self.key`` if it's not supplied & the hashing
        function ``hasher``.
        """
        return await hasher(data, key=key if key else self.key)

    async def atime_safe_equality(
        self, value_0=None, value_1=None, *, key=None
    ):
        """
        Tests if ``value_0`` is equal to ``value_1`` with a randomized-
        time comparison. Each value is prepended with a salt, a ``key``
        & is hashed prior to the comparison. This algorithm reveals no
        meaningful information, even though compared in non-constant
        time, since an adversary wouldn't have access to these values.
        If ``key`` isn't supplied then the instance's `self.key` is used
        for the task. This scheme is easier to implement correctly than
        a constant-time algorithm, & it's easier to prove infeasibility
        guarantees regarding timing attacks.
        """
        key = key if key else self.key
        return await self._atime_safe_equality(value_0, value_1, key=key)

    async def atest_hmac(
        self, data, *, hmac=None, key=None, hasher=asha_256_hmac
    ):
        """
        Tests if the given ``hmac`` of some ``data`` is valid with a
        non-constant time comparison on the hash of each the supplied &
        derived HMACs, appended with a salt prior to hashing. The
        algorithm prepends the instance's ``self.key`` if ``key`` is not
        supplied to further make the tested outputs undeterminable to an
        attacker. The random salt & key allow the hashes to be compared
        normally in non-constant time, without revealing meaningful
        information, since an attacker wouldn't have access to either.
        This scheme is easier to implement correctly & is easier to
        prove guarantees of the infeasibility of timing attacks. Any
        async ``hasher`` function can be specified as the HMAC function,
        which is by default ``asha_256_hmac``.
        """
        if not hmac:
            raise ValueError(MISSING_HMAC)
        key = key if key else self.key
        true_hmac = await self.ahmac(data=data, key=key, hasher=hasher)
        if await self.atime_safe_equality(hmac, true_hmac, key=key):
            return True
        else:
            raise ValueError(INVALID_HMAC)

    def _reset(self, key=None, *, automate_key_use=True):
        """
        Replaces the stored instance key used to create deterministic
        streams of key material &, create & validate HMAC codes.
        """
        self._key = key if key else csprng()
        if automate_key_use:
            for method in self.instance_methods:
                convert_static_method_to_member(
                    self, method.__name__, method, key=self.key,
                )

    async def areset(self, key=None, *, automate_key_use=True):
        """
        Replaces the stored instance key used to create deterministic
        streams of key material &, create & validate HMAC codes.
        """
        self._key = key if key else await acsprng()
        if automate_key_use:
            for method in self.instance_methods:
                convert_static_method_to_member(
                    self, method.__name__, method, key=self.key
                )
                await asleep(0)

    async def _apasscrypt(
        self,
        password,
        salt,
        *,
        kb=Passcrypt._DEFAULT_KB,
        cpu=Passcrypt._DEFAULT_CPU,
        hardness=Passcrypt._DEFAULT_HARDNESS,
    ):
        """
        A tunably memory & cpu hard method which returns a key from a
        user password & salt. This method also protects the passwords
        it processes with the instance's key, which forces attackers to
        also find a way to retrieve it in order to crack the passwords.
        """
        Passcrypt._check_inputs(password, salt)
        salted_password = await self.ahmac((password, salt))
        return await apasscrypt(
            salted_password, salt, kb=kb, cpu=cpu, hardness=hardness
        )


class Keys:
    """
    This simple class coordinates and manages a symmetric key to create
    pseudo-one-time-pad key material streams, key derivation functions,
    as well as HMAC creation & HMAC validation of data. The class also
    contains static methods & key generators that function independantly
    from instance states.
    """
    instance_methods = {
        keys,
        bytes_keys,
        mnemonic,
        table_key,
        table_keystream,
        single_use_key,
    }

    DomainKDF = DomainKDF
    keys = staticmethod(keys)
    csprbg = staticmethod(csprbg)
    csprng = staticmethod(csprng)
    mnemonic = staticmethod(mnemonic)
    passcrypt = staticmethod(passcrypt)
    table_key = staticmethod(table_key)
    random_256 = staticmethod(random_256)
    random_512 = staticmethod(random_512)
    bytes_keys = staticmethod(bytes_keys)
    padding_key = staticmethod(padding_key)
    generate_salt = staticmethod(generate_salt)
    single_use_key = staticmethod(single_use_key)
    table_keystream = staticmethod(table_keystream)
    keypair_ratchets = staticmethod(keypair_ratchets)
    _test_key_and_salt = staticmethod(test_key_and_salt)
    _time_safe_equality = staticmethod(time_safe_equality)

    def __init__(self, key=None, *, automate_key_use=True):
        """
        Stores a key in the instance used to create deterministic
        streams of key material &, create & validate HMAC codes. If a
        ``key`` argument is not passed then a new 512-bit random key is
        created.
        """
        self.reset(key, automate_key_use=automate_key_use)
        self.passcrypt = self._passcrypt

    @property
    def key(self):
        """
        Returns the instance's main symmetric key.
        """
        return self._key

    def hmac(self, data, *, key=None, hasher=sha_256_hmac):
        """
        Creates an HMAC code of ``data`` using ``key``  or the
        instance's ``self.key`` if it's not supplied & the hashing
        function ``hasher``.
        """
        return hasher(data, key=key if key else self.key)

    def time_safe_equality(self, value_0=None, value_1=None, *, key=None):
        """
        Tests if ``value_0`` is equal to ``value_1`` with a randomized-
        time comparison. Each value is prepended with a salt, a ``key``
        & is hashed prior to the comparison. This algorithm reveals no
        meaningful information, even though compared in non-constant
        time, since an adversary wouldn't have access to these values.
        If ``key`` isn't supplied then the instance's `self.key` is used
        for the task. This scheme is easier to implement correctly than
        a constant-time algorithm, & it's easier to prove infeasibility
        guarantees regarding timing attacks.
        """
        key = key if key else self.key
        return self._time_safe_equality(value_0, value_1, key=key)

    def test_hmac(
        self, data, *, hmac=None, key=None, hasher=sha_256_hmac
    ):
        """
        Tests if the given ``hmac`` of some ``data`` is valid with a
        non-constant time comparison on the hash of each the supplied &
        derived HMACs, appended with a salt prior to hashing. The
        algorithm prepends the instance's ``self.key`` if ``key`` is not
        supplied to further make the tested outputs undeterminable to an
        attacker. The random salt & key allow the hashes to be compared
        normally in non-constant time, without revealing meaningful
        information, since an attacker wouldn't have access to either.
        This scheme is easier to implement correctly & is easier to
        prove guarantees of the infeasibility of timing attacks. Any
        sync ``hasher`` function can be specified as the HMAC function,
        which is by default ``sha_256_hmac``.
        """
        if not hmac:
            raise ValueError(MISSING_HMAC)
        key = key if key else self.key
        true_hmac = self.hmac(data=data, key=key, hasher=hasher)
        if self.time_safe_equality(hmac, true_hmac, key=key):
            return True
        else:
            raise ValueError(INVALID_HMAC)

    def reset(self, key=None, *, automate_key_use=True):
        """
        Replaces the stored instance key used to create deterministic
        streams of key material &, create & validate HMAC codes.
        """
        self._key = key if key else csprng()
        if automate_key_use:
            for method in self.instance_methods:
                convert_static_method_to_member(
                    self, method.__name__, method, key=self.key,
                )

    def _passcrypt(
        self,
        password,
        salt,
        *,
        kb=Passcrypt._DEFAULT_KB,
        cpu=Passcrypt._DEFAULT_CPU,
        hardness=Passcrypt._DEFAULT_HARDNESS,
    ):
        """
        A tunably memory & cpu hard method which returns a key from a
        user password & salt. This method also protects the passwords
        it processes with the instance's key, which forces attackers to
        also find a way to retrieve it in order to crack the passwords.
        """
        Passcrypt._check_inputs(password, salt)
        salted_password = self.hmac((password, salt))
        return passcrypt(
            salted_password, salt, kb=kb, cpu=cpu, hardness=hardness
        )


class Asymmetric25519:
    """
    Contains a collection of class methods & values that simplify the
    usage of the cryptography library, as well as pointers to values in
    the cryptography library.
    """

    cryptography = cryptography
    hazmat = cryptography.hazmat
    serialization = serialization
    exceptions = cryptography.exceptions
    X25519PublicKey = X25519PublicKey
    X25519PrivateKey = X25519PrivateKey
    Ed25519PublicKey = Ed25519PublicKey
    Ed25519PrivateKey = Ed25519PrivateKey
    _PUBLIC_BYTES_ENUM = {
        "encoding": serialization.Encoding.Raw,
        "format": serialization.PublicFormat.Raw,
    }
    _PRIVATE_BYTES_ENUM = {
        "encoding": serialization.Encoding.Raw,
        "format": serialization.PrivateFormat.Raw,
        "encryption_algorithm": serialization.NoEncryption(),
    }

    @staticmethod
    async def aed25519_key():
        """
        Returns an ``Ed25519PrivateKey`` from the cryptography package
        used to make elliptic curve signatures of data.
        """
        await asleep(0)
        return Ed25519PrivateKey.generate()

    @staticmethod
    def ed25519_key():
        """
        Returns an ``Ed25519PrivateKey`` from the cryptography package
        used to make elliptic curve signatures of data.
        """
        return Ed25519PrivateKey.generate()

    @staticmethod
    async def ax25519_key():
        """
        Returns a ``X25519PrivateKey`` from the cryptography package for
        use in an elliptic curve diffie-hellman exchange.
        """
        await asleep(0)
        return X25519PrivateKey.generate()

    @staticmethod
    def x25519_key():
        """
        Returns a ``X25519PrivateKey`` from the cryptography package for
        use in an elliptic curve diffie-hellman exchange.
        """
        return X25519PrivateKey.generate()

    @classmethod
    async def apublic_bytes(cls, secret_key, *, hex=False):
        """
        Returns the public key bytes of either an ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` from the cryptography package for an
        elliptic curve diffie-hellman exchange or signature verification
        key. If ``hex`` is truthy, then a hex string of the public key
        is returned instead of bytes.
        """
        await asleep(0)
        if hasattr(secret_key, "public_key"):
            public_key = secret_key.public_key()
        else:
            public_key = secret_key

        public_bytes = public_key.public_bytes(**cls._PUBLIC_BYTES_ENUM)
        if hex:
            return public_bytes.hex()
        else:
            return public_bytes

    @classmethod
    def public_bytes(cls, secret_key, *, hex=False):
        """
        Returns the public key bytes of either an ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` from the cryptography package for an
        elliptic curve diffie-hellman exchange or signature verification
        key. If ``hex`` is truthy, then a hex string of the public key
        is returned instead of bytes.
        """
        if hasattr(secret_key, "public_key"):
            public_key = secret_key.public_key()
        else:
            public_key = secret_key

        public_bytes = public_key.public_bytes(**cls._PUBLIC_BYTES_ENUM)
        if hex:
            return public_bytes.hex()
        else:
            return public_bytes

    @classmethod
    async def asecret_bytes(cls, secret_key, *, hex=False):
        """
        Returns the secret key bytes of either an ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` from the cryptography package for an
        elliptic curve diffie-hellman exchange or signature creation
        key. If ``hex`` is truthy, then a hex string of the secret key
        is returned instead of bytes.
        """
        await asleep(0)
        secret_bytes = secret_key.private_bytes(**cls._PRIVATE_BYTES_ENUM)
        if hex:
            return secret_bytes.hex()
        else:
            return secret_bytes

    @classmethod
    def secret_bytes(cls, secret_key, *, hex=False):
        """
        Returns the secret key bytes of either an ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` from the cryptography package for an
        elliptic curve diffie-hellman exchange or signature creation
        key. If ``hex`` is truthy, then a hex string of the secret key
        is returned instead of bytes.
        """
        secret_bytes = secret_key.private_bytes(**cls._PRIVATE_BYTES_ENUM)
        if hex:
            return secret_bytes.hex()
        else:
            return secret_bytes

    @staticmethod
    async def aexchange(secret_key: X25519PrivateKey, public_key: bytes):
        """
        Returns the shared key bytes derived from an elliptic curve key
        exchange with the user's ``secret_key`` key, & their communicating
        peer's ``public_key`` public key's bytes or hex value.
        """
        await asleep(0)
        if not isinstance(public_key, bytes):
            public_key = bytes.fromhex(public_key)
        return secret_key.exchange(
            X25519PublicKey.from_public_bytes(public_key)
        )

    @staticmethod
    def exchange(secret_key: X25519PrivateKey, public_key: bytes):
        """
        Returns the shared key bytes derived from an elliptic curve key
        exchange with the user's ``secret_key`` key, & their communicating
        peer's ``public_key`` public key's bytes or hex value.
        """
        if not isinstance(public_key, bytes):
            public_key = bytes.fromhex(public_key)
        return secret_key.exchange(
            X25519PublicKey.from_public_bytes(public_key)
        )

    @classmethod
    @comprehension()
    async def adh2_client(cls):
        """
        Generates an ephemeral ``X25519`` secret key which is used to
        start a 2DH client key exchange. This key is yielded as public
        key bytes. Then the server's two public keys should be sent into
        this coroutine when they're received. When this coroutine
        reaches the raise statement, a primed ``sha3_512`` kdf object
        will be accessible from the ``aresult`` method of this generator.

        Usage Example:

        from aiootp import X25519

        async with X25519.protocols.adh2_client() as exchange:
            client_hello = await exchange()
            response = internet.post(client_hello)
            await exchange(response)

        shared_key_kdf = await exchange.aresult()
        """
        domain = Domains.DH2
        my_ephemeral_key = await X25519().agenerate()
        my_public_ephemeral_key = my_ephemeral_key.public_bytes
        peer_identity_key, peer_ephemeral_key = yield (
            my_public_ephemeral_key
        )
        shared_key_ad = await my_ephemeral_key.aexchange(peer_identity_key)
        shared_key_cd = await my_ephemeral_key.aexchange(peer_ephemeral_key)
        raise UserWarning(sha3_512(domain + shared_key_ad + shared_key_cd))

    @classmethod
    @comprehension()
    def dh2_client(cls):
        """
        Generates an ephemeral ``X25519`` secret key which is used to
        start a 2DH client key exchange. This key is yielded as public
        key bytes. Then the server's two public keys should be sent into
        this coroutine when they're received. When this coroutine
        reaches the return statement, a primed ``sha3_512`` kdf object
        will be accessible from the ``result`` method of this generator.

        Usage Example:

        from aiootp import X25519

        with X25519.protocols.dh2_client() as exchange:
            client_hello = exchange()
            response = internet.post(client_hello)
            exchange(response)

        shared_key_kdf = exchange.result()
        """
        domain = Domains.DH2
        my_ephemeral_key = X25519().generate()
        my_public_ephemeral_key = my_ephemeral_key.public_bytes
        peer_identity_key, peer_ephemeral_key = yield (
            my_public_ephemeral_key
        )
        shared_key_ad = my_ephemeral_key.exchange(peer_identity_key)
        shared_key_cd = my_ephemeral_key.exchange(peer_ephemeral_key)
        return sha3_512(domain + shared_key_ad + shared_key_cd)

    @classmethod
    @comprehension()
    async def adh2_server(
        cls, *, my_identity_key, peer_ephemeral_key: bytes
    ):
        """
        Takes in the user's ``X25519`` secret key & a peer's public key
        bytes to enact a 2DH key exchange. This yields the user's two
        public keys as bytes, one from the secret key which was passed
        in as an argument, one which is ephemeral. When this coroutine
        reaches the raise statement, a primed ``sha3_512`` kdf object
        will be accessible from the ``aresult`` method of this generator.

        Usage Example:

        from aiootp import X25519

        # This key may be used again as an identity for this protocol
        ecdhe_key = await X25519().agenerate()

        pkD = client_public_key = internet.receive()

        async with ecdhe_key.adh2_server(peer_ephemeral_key=pkD) as exchange:
            internet.send(await exchange.aexhaust())

        shared_key_kdf = await exchange.aresult()
        """
        domain = Domains.DH2
        my_ephemeral_key = await X25519().agenerate()
        yield my_identity_key.public_bytes, my_ephemeral_key.public_bytes
        shared_key_ad = await my_identity_key.aexchange(peer_ephemeral_key)
        shared_key_cd = await my_ephemeral_key.aexchange(peer_ephemeral_key)
        raise UserWarning(sha3_512(domain + shared_key_ad + shared_key_cd))

    @classmethod
    @comprehension()
    def dh2_server(cls, *, my_identity_key, peer_ephemeral_key: bytes):
        """
        Takes in the user's ``X25519`` secret key & a peer's public key
        bytes to enact a 2DH key exchange. This yields the user's two
        public keys as bytes, one from the secret key which was passed
        in as an argument, one which is ephemeral. When this coroutine
        reaches the return statement, a primed ``sha3_512`` kdf object
        will be accessible from the ``result`` method of this generator.

        Usage Example:

        from aiootp import X25519

        # This key may be used again as an identity for this protocol
        ecdhe_key = X25519().generate()

        pkD = client_public_key = internet.receive()

        with ecdhe_key.dh2_server(peer_ephemeral_key=pkD) as exchange:
            internet.send(exchange.exhaust())

        shared_key_kdf = exchange.result()
        """
        domain = Domains.DH2
        my_ephemeral_key = X25519().generate()
        yield my_identity_key.public_bytes, my_ephemeral_key.public_bytes
        shared_key_ad = my_identity_key.exchange(peer_ephemeral_key)
        shared_key_cd = my_ephemeral_key.exchange(peer_ephemeral_key)
        return sha3_512(domain + shared_key_ad + shared_key_cd)

    @classmethod
    @comprehension()
    async def adh3_client(cls, *, my_identity_key):
        """
        Takes in the user's ``X25519`` secret key to enact a 3DH key
        exchange with a peer. This yields the user's two public keys as
        bytes, one from the secret key which was passed in as an
        argument, one which is ephemeral. When this coroutine reaches
        the raise statement, a primed ``sha3_512`` kdf object will be
        accessible from the ``aresult`` method of this generator.

        Usage Example:

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
        my_ephemeral_key = await X25519().agenerate()
        peer_identity_key, peer_ephemeral_key = yield (
            my_identity_key.public_bytes,
            my_ephemeral_key.public_bytes,
        )
        shared_key_ad = await my_ephemeral_key.aexchange(peer_identity_key)
        shared_key_bc = await my_identity_key.aexchange(peer_ephemeral_key)
        shared_key_cd = await my_ephemeral_key.aexchange(peer_ephemeral_key)
        raise UserWarning(
            sha3_512(domain + shared_key_ad + shared_key_bc + shared_key_cd)
        )

    @classmethod
    @comprehension()
    def dh3_client(cls, *, my_identity_key):
        """
        Takes in the user's ``X25519`` secret key to enact a 3DH key
        exchange with a peer. This yields the user's two public keys as
        bytes, one from the secret key which was passed in as an
        argument, one which is ephemeral. When this coroutine reaches
        the return statement, a primed ``sha3_512`` kdf object will be
        accessible from the ``result`` method of this generator.

        Usage Example:

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
        my_ephemeral_key = X25519().generate()
        peer_identity_key, peer_ephemeral_key = yield (
            my_identity_key.public_bytes,
            my_ephemeral_key.public_bytes,
        )
        shared_key_ad = my_ephemeral_key.exchange(peer_identity_key)
        shared_key_bc = my_identity_key.exchange(peer_ephemeral_key)
        shared_key_cd = my_ephemeral_key.exchange(peer_ephemeral_key)
        return sha3_512(
            domain + shared_key_ad + shared_key_bc + shared_key_cd
        )

    @classmethod
    @comprehension()
    async def adh3_server(
        cls,
        *,
        my_identity_key,
        peer_identity_key: bytes,
        peer_ephemeral_key: bytes,
    ):
        """
        Takes in the user's ``X25519`` secret key & two of a peer's
        public keys bytes to enact a 3DH deniable key exchange. This
        yields the user's two public keys as bytes, one from the secret
        key which was passed in as an argument, one which is ephemeral.
        When this coroutine reaches the raise statement, a primed
        ``sha3_512`` kdf object will be accessible from the ``aresult``
        method of this generator.

        Usage Example:

        from aiootp import X25519

        # This key may be used again as an identity for this protocol
        ecdhe_key = await X25519().agenerate()

        pkB, pkD = client_public_keys = internet.receive()

        server = ecdhe_key.adh3_server(
            peer_identity_key=pkB, peer_ephemeral_key=pkD
        )
        async with server as exchange:
            internet.send(await exchange.aexhaust())

        shared_key_kdf = await exchange.aresult()
        """
        domain = Domains.DH3
        my_ephemeral_key = await X25519().agenerate()
        yield my_identity_key.public_bytes, my_ephemeral_key.public_bytes
        shared_key_ad = await my_identity_key.aexchange(peer_ephemeral_key)
        shared_key_bc = await my_ephemeral_key.aexchange(peer_identity_key)
        shared_key_cd = await my_ephemeral_key.aexchange(peer_ephemeral_key)
        raise UserWarning(
            sha3_512(domain + shared_key_ad + shared_key_bc + shared_key_cd)
        )

    @classmethod
    @comprehension()
    def dh3_server(
        cls,
        *,
        my_identity_key,
        peer_identity_key: bytes,
        peer_ephemeral_key: bytes,
    ):
        """
        Takes in the user's ``X25519`` secret key & two of a peer's
        public keys bytes to enact a 3DH deniable key exchange. This
        yields the user's two public keys as bytes, one from the secret
        key which was passed in as an argument, one which is ephemeral.
        When this coroutine reaches the raise statement, a primed
        ``sha3_512`` kdf object will be accessible from the ``result``
        method of this generator.

        Usage Example:

        from aiootp import X25519

        # This key may be used again as an identity for this protocol
        ecdhe_key = X25519().generate()

        pkB, pkD = client_public_keys = internet.receive()

        server = ecdhe_key.dh3_server(
            peer_identity_key=pkB, peer_ephemeral_key=pkD
        )
        with server as exchange:
            internet.send(exchange.exhaust())

        shared_key_kdf = exchange.result()
        """
        domain = Domains.DH3
        my_ephemeral_key = X25519().generate()
        yield my_identity_key.public_bytes, my_ephemeral_key.public_bytes
        shared_key_ad = my_identity_key.exchange(peer_ephemeral_key)
        shared_key_bc = my_ephemeral_key.exchange(peer_identity_key)
        shared_key_cd = my_ephemeral_key.exchange(peer_ephemeral_key)
        return sha3_512(
            domain + shared_key_ad + shared_key_bc + shared_key_cd
        )


class BaseEllipticCurve:
    """
    Collects the shared functionality between the ``X25519`` & ``Ed25519``
    classes.
    """

    PublicKey = None
    SecretKey = None
    _asymmetric = Asymmetric25519
    _exceptions = _asymmetric.exceptions

    @classmethod
    def _preprocess_key(cls, key_material):
        """
        Converts to bytes if ``key_material`` is hex, otherwise returns
        it unaltered only if is truthy.
        """
        if not key_material:
            raise ValueError("No key material or object given.")
        elif issubclass(key_material.__class__, str):
            key_material = bytes.fromhex(key_material)
            return key_material
        else:
            return key_material

    @classmethod
    def _process_public_key(cls, public_key):
        """
        Accepts a ``public_key`` in either hex, bytes, ``X25519PublicKey``,
        ``X25519PrivateKey``, ``Ed25519PublicKey`` or ``Ed25519PrivateKey``
        format. Returns an instantiaed public key associated with the
        subclass inhereting this method.
        """
        public_key = cls._preprocess_key(public_key)
        if issubclass(public_key.__class__, bytes):
            return cls.PublicKey.from_public_bytes(public_key)
        else:
            public_key = cls._asymmetric.public_bytes(public_key)
            return cls.PublicKey.from_public_bytes(public_key)

    @classmethod
    def _process_secret_key(cls, secret_key):
        """
        Accepts a ``secret_key`` in either hex, bytes, ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` format. Returns an instantiaed secret
        key associated with the subclass inhereting this method.
        """
        secret_key = cls._preprocess_key(secret_key)
        if issubclass(secret_key.__class__, bytes):
            return cls.SecretKey.from_private_bytes(secret_key)
        else:
            secret_key = cls._asymmetric.secret_bytes(secret_key)
            return cls.SecretKey.from_private_bytes(secret_key)

    def __init__(self):
        """
        Create a instance specific object of the ``Asymmetric25519``
        class.
        """
        self._asymmetric = self._asymmetric()

    async def aimport_public_key(self, public_key):
        """
        Populates an instance from the received ``public_key`` that is
        of either hex, bytes, ``X25519PublicKey``, ``X25519PrivateKey``,
        ``Ed25519PublicKey`` or ``Ed25519PrivateKey`` type.
        """
        await asleep(0)
        self._public_key = self._process_public_key(public_key)
        return self

    def import_public_key(self, public_key):
        """
        Populates an instance from the received ``public_key`` that is
        of either hex, bytes, ``X25519PublicKey``, ``X25519PrivateKey``,
        ``Ed25519PublicKey`` or ``Ed25519PrivateKey`` type.
        """
        self._public_key = self._process_public_key(public_key)
        return self

    async def aimport_secret_key(self, secret_key):
        """
        Populates an instance from the received ``secret_key`` that is
        of either hex, bytes, ``X25519PrivateKey`` or ``Ed25519PrivateKey``
        type.
        """
        await asleep(0)
        if hasattr(self, "_secret_key"):
            raise PermissionError("This instance is already initialized.")
        self._secret_key = self._process_secret_key(secret_key)
        self._public_key = self.PublicKey.from_public_bytes(
            await self._asymmetric.apublic_bytes(self._secret_key)
        )
        return self

    def import_secret_key(self, secret_key):
        """
        Populates an instance from the received ``secret_key`` that is
        of either hex, bytes, ``X25519PrivateKey`` or ``Ed25519PrivateKey``
        type.
        """
        if hasattr(self, "_secret_key"):
            raise PermissionError("This instance is already initialized.")
        self._secret_key = self._process_secret_key(secret_key)
        self._public_key = self.PublicKey.from_public_bytes(
            self._asymmetric.public_bytes(self._secret_key)
        )
        return self

    @property
    def secret_key(self):
        """
        Returns the instantiated & populated SecretKey of the associated
        sublass inhereting this method.
        """
        return self._secret_key

    @property
    def public_key(self):
        """
        Returns the instantiated & populated PublicKey of the associated
        sublass inhereting this method.
        """
        return self._public_key

    @property
    def secret_bytes(self):
        """
        Returns the secret bytes of the instance's instantiated &
        populated SecretKey of the associated sublass inhereting this
        method.
        """
        return self._asymmetric.secret_bytes(self._secret_key)

    @property
    def public_bytes(self):
        """
        Returns the public bytes of the instance's instantiated &
        populated PublicKey of the associated sublass inhereting this
        method.
        """
        return self._asymmetric.public_bytes(self._public_key)


class Ed25519(BaseEllipticCurve):
    """
    This class is used to create stateful objects that simplify usage of
    the cryptography library's ed25519 protocol.

    Usage Example:

    from aiootp import Ed25519

    # In a land, long ago ->
    user_alice = Ed25519().generate()
    internet.send(user_alice.public_bytes.hex())

    # Alice wants to sign a document so that Bob can prove she wrote it.
    # So, Alice sends her public key bytes of the key she wants to
    # associate with her identity, the document & the signature ->
    document = b"DesignDocument.cad"
    signed_document = user_alice.sign(document)
    message = {
        "document": document,
        "signature": signed_document,
        "public_key": user_alice.public_bytes.hex(),
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
    PublicKey = BaseEllipticCurve._asymmetric.Ed25519PublicKey
    SecretKey = BaseEllipticCurve._asymmetric.Ed25519PrivateKey
    InvalidSignature = BaseEllipticCurve._exceptions.InvalidSignature

    async def agenerate(self):
        """
        Generates a new secret key used for signing bytes data &
        populates the instance with it & its associated public key. This
        method returns the instance for convenience in instantiating a
        stateful object with await Ed25519().agenerate().
        """
        key = await self._asymmetric.aed25519_key()
        await self.aimport_secret_key(key)
        return self

    def generate(self):
        """
        Generates a new secret key used for signing bytes data &
        populates the instance with it & its associated public key. This
        method returns the instance for convenience in instantiating a
        stateful object with Ed25519().generate().
        """
        key = self._asymmetric.ed25519_key()
        self.import_secret_key(key)
        return self

    async def asign(self, data):
        """
        Signs some bytes ``data`` with the instance's secret key.
        """
        await asleep(0)
        return self.secret_key.sign(data)

    def sign(self, data):
        """
        Signs some bytes ``data`` with the instance's secret key.
        """
        return self.secret_key.sign(data)

    async def averify(self, signature, data, *, public_key=None):
        """
        Receives a ``signature`` to verify data with the instance's
        public key. If the ``public_key`` keyword-only argument is
        used, then that key is used instead of the instance key to run
        the verification.
        """
        if public_key:
            await asleep(0)
            public_key = self._process_public_key(public_key)
        else:
            public_key = self.public_key
        await asleep(0)
        public_key.verify(signature, data)

    def verify(self, signature, data, *, public_key=None):
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


class X25519(BaseEllipticCurve):
    """
    This class is used to create stateful objects that simplify usage of
    the cryptography library's x25519 protocol.

    Usage Example:

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
    PublicKey = BaseEllipticCurve._asymmetric.X25519PublicKey
    SecretKey = BaseEllipticCurve._asymmetric.X25519PrivateKey

    _client_indentity_protocols = Namespace(
        adh3_client=Asymmetric25519.adh3_client,
        dh3_client=Asymmetric25519.dh3_client,
    )
    _client_no_indentity_protocols = Namespace(
        adh2_client=Asymmetric25519.adh2_client,
        dh2_client=Asymmetric25519.dh2_client,
    )
    _client_protocols = Namespace(
        **_client_indentity_protocols, **_client_no_indentity_protocols
    )
    _server_protocols = Namespace(
        adh2_server=Asymmetric25519.adh2_server,
        dh2_server=Asymmetric25519.dh2_server,
        adh3_server=Asymmetric25519.adh3_server,
        dh3_server=Asymmetric25519.dh3_server,
    )
    protocols = Namespace(**_server_protocols, **_client_protocols)

    async def _ainsert_identity_key_into_protocols(self):
        """
        Creates instance method versions of the protocols in
        self.protocols. Those methods automatically pass the instance's
        secret key as a keyword argument to streamline their usage in
        the package's ready-made elliptic curve diffie-hellman exchange
        protocols.
        """
        for name, protocol in self._server_protocols:
            await asleep(0)
            convert_static_method_to_member(
                self, name, protocol, my_identity_key=self
            )
        for name, protocol in self._client_indentity_protocols:
            await asleep(0)
            convert_static_method_to_member(
                self, name, protocol, my_identity_key=self
            )

    def _insert_identity_key_into_protocols(self):
        """
        Creates instance method versions of the protocols in
        self.protocols. Those methods automatically pass the instance's
        secret key as a keyword argument to streamline their usage in
        the package's ready-made elliptic curve diffie-hellman exchange
        protocols.
        """
        for name, protocol in self._server_protocols:
            convert_static_method_to_member(
                self, name, protocol, my_identity_key=self
            )
        for name, protocol in self._client_indentity_protocols:
            convert_static_method_to_member(
                self, name, protocol, my_identity_key=self
            )

    async def aimport_secret_key(self, secret_key):
        """
        Populates an instance from the received ``secret_key`` that is
        of either hex, bytes or a ``X25519PrivateKey`` type. Creates
        instance method versions of the protocols in self.protocols.
        Those methods automatically pass the instance's secret key as a
        keyword argument to streamline their usage in the package's
        ready-made elliptic curve diffie-hellman exchange protocols.
        """
        await super().aimport_secret_key(secret_key)
        await self._ainsert_identity_key_into_protocols()
        return self

    def import_secret_key(self, secret_key):
        """
        Populates an instance from the received ``secret_key`` that is
        of either hex, bytes or a ``X25519PrivateKey`` type. Creates
        instance method versions of the protocols in self.protocols.
        Those methods automatically pass the instance's secret key as a
        keyword argument to streamline their usage in the package's
        ready-made elliptic curve diffie-hellman exchange protocols.
        """
        super().import_secret_key(secret_key)
        self._insert_identity_key_into_protocols()
        return self

    async def agenerate(self):
        """
        Generates a new secret key used for a single elliptic curve
        diffie-hellman exchange, or as an argument to one of the 3dh or
        2dh generators in X25519.protocols. This populates the instance
        with the secret key & its associated public key. This method
        returns the instance for convenience in instantiating a stateful
        object with await X25519().agenerate().
        """
        key = await self._asymmetric.ax25519_key()
        await self.aimport_secret_key(key)
        return self

    def generate(self):
        """
        Generates a new secret key used for a single elliptic curve
        diffie-hellman exchange, or as an argument to one of the 3dh or
        2dh generators in X25519.protocols. This populates the instance
        with the secret key & its associated public key. This method
        returns the instance for convenience in instantiating a stateful
        object with await X25519().generate().
        """
        key = self._asymmetric.x25519_key()
        self.import_secret_key(key)
        return self

    async def aexchange(self, public_key):
        """
        Takes in a public key from a communicating party & uses the
        instance's secret key to do an elliptic curve diffie-hellman
        exchange & returns the resulting secret shared bytes.
        """
        await asleep(0)
        public_key = self._process_public_key(public_key)
        return await self._asymmetric.aexchange(
            self._secret_key,
            await self._asymmetric.apublic_bytes(public_key),
        )

    def exchange(self, public_key):
        """
        Takes in a public key from a communicating party & uses the
        instance's secret key to do an elliptic curve diffie-hellman
        exchange & returns the resulting secret shared bytes.
        """
        public_key = self._process_public_key(public_key)
        return self._asymmetric.exchange(
            self._secret_key, self._asymmetric.public_bytes(public_key)
        )


class Ropake:
    """
    Ratcheting Opaque Password Authenticated Key Exchange

    An implementation of a password-authenticated key exchange protocol
    for servers to securely authenticate users & users to authenticate
    servers. User passwords aren't disclosed to the servers. They are
    used to build persistently secure connection keys which are made
    future & forward secure with a new elliptic curve diffie-hellman
    shared key being used for every authentication & mixed with keys
    established from past authentications. The protocol requires that
    the client & server are able to securely store cryptographic
    material, & by default this module's ``AsyncDatabase`` & ``Database``
    classes are intended to be used for this purpose.

    Usage Examples:

    import aiootp
    from aiootp import Ropake

    new_account = True
    # The arguments must contain at least one unique element for each
    # service the client wants to authenticate with. Using unique
    # cryptographically secure keys would be better, but this is a good
    # alternative ->
    tokens = aiootp.Database.generate_profile_tokens(
        server_url,     # An unlimited number of arguments can be passed
        email_address,  # here as additional, optional credentials.
        username=username,
        password=password,
        salt=optional_salt_keyword_argument,
    )
    db = await aiootp.AsyncDatabase.agenerate_profile(tokens)

    if new_account:
        client = Ropake.client_registration(db)
    else:
        client = Ropake.client(db)
    client_hello = client()
    internet.send(client_hello)

    server_db = aiootp.Database("some_cryptographic_key")
    client_hello = internet.receive()
    if Ropake.is_registering(client_hello):
        server = Ropake.server_registration(client_hello, server_db)
    else:
        server = Ropake.server(client_hello, server_db)
    server_hello = server()
    internet.send(server_hello)
    try:
        server()
    except StopIteration:
        shared_keys = server.result()

        # The user's KEY_ID for storing account data in the server
        # database does not need to remain secret
        key_id = shared_keys[Ropake.KEY_ID]

        # The key used during the user's next login authentication
        server_db[key_id][Ropake.KEY] == shared_keys[Ropake.KEY]

        # The key used to encrypt communication for the current session
        server_db[key_id][Ropake.SESSION_KEY] == shared_keys[Ropake.SESSION_KEY]

        # A user is authenticated if they can decrypt messages encrypted
        # with the session key & again proves themselves on the next
        # authentication attempt by encrypting the hello message with
        # the Ropake.KEY & successfully reproducing the keyed password
        # from a stored secret 512-bit salt.

    server_hello = internet.receive()
    try:
        client(server_hello)
    except StopIteration:
        shared_keys = client.result()
        # These shared keys will be the same as the one's the server
        # derived if the registration / authentication was successful.
    """

    PUB = PUB
    KEY = KEY
    SALT = SALT
    KEY_ID = KEY_ID
    SECRET = SECRET
    CIPHERTEXT = CIPHERTEXT
    SHARED_KEY = SHARED_KEY
    TIMEOUT = ROPAKE_TIMEOUT
    SESSION_KEY = SESSION_KEY
    SESSION_SALT = SESSION_SALT
    REGISTRATION = REGISTRATION
    SHARED_SECRET = SHARED_SECRET
    PASSWORD_SALT = PASSWORD_SALT
    AUTHENTICATION = AUTHENTICATION
    KEYED_PASSWORD = KEYED_PASSWORD
    NEXT_PASSWORD_SALT = NEXT_PASSWORD_SALT
    NEXT_KEYED_PASSWORD = NEXT_KEYED_PASSWORD
    X25519 = X25519
    Ed25519 = Ed25519
    generate_salt = staticmethod(csprng)
    agenerate_salt = staticmethod(acsprng)

    _KEYED_PASSWORD_TUTORIAL = f"""\
    ``database`` needs a {KEYED_PASSWORD} entry.
    tokens = Database.generate_profile_tokens(
        server_url,     # An unlimited number of arguments can be passed
        email_address,  # here as additional, optional credentials.
        username=username,
        password=password,
        salt=optional_salt_value,
    )
    db = Database.generate_profile(tokens)
    db[Ropake.PASSWORD_SALT] = salt = Ropake.generate_salt()
    db[Ropake.KEYED_PASSWORD] = Ropake._make_commit(db._root_key, salt)
    db[Ropake.NEXT_PASSWORD_SALT] = next_salt = Ropake.generate_salt()
    db[Ropake.NEXT_KEYED_PASSWORD] = Ropake._make_commit(db._root_key, next_salt)
    # client sends keyed_password to server during registration & sends
    # Ropake._id(salt) to the server during authentication, as well as
    # the next keyed_password to be used during the next authentication.
    """

    @classmethod
    def is_registering(cls, client_hello=None):
        """
        Takes a ``client_hello`` protocol packet & returns ``"Maybe""``
        if it contains neither a KEY_ID or CIPHERTEXT element signifying
        it may be a registration packet instead of an authentication
        packet. Returns ``False`` if either a KEY_ID or CIPHERTEXT
        element is present, meaning it's definitely not a compatible
        registration packet.
        """
        if not isinstance(client_hello, dict) or not client_hello:
            return False
        elif (
            cls.KEY_ID not in client_hello
            and cls.CIPHERTEXT not in client_hello
        ):
            return "Maybe"
        else:
            return False

    @classmethod
    def is_authenticating(cls, client_hello=None):
        """
        Takes a ``client_hello`` protocol packet & returns ``"Maybe"``
        if it does contain a KEY_ID & CIPHERTEXT element, signifying
        that it may be an authentication packet instead of registration
        packet. Returns ``False`` if the KEY_ID or CIPHERTEXT element
        isn't present, meaning that it's definitely not a compatible
        authentication packet.
        """
        if not isinstance(client_hello, dict) or not client_hello:
            return False
        elif cls.KEY_ID in client_hello and cls.CIPHERTEXT in client_hello:
            return "Maybe"
        else:
            return False

    @staticmethod
    async def _aid(key=None):
        """
        Returns a deterministic hmac of any arbitrary key material. This
        is typically used to identify a particular connection between a
        server & client which avoids personal or device identfiable
        information being needed for authenticating parties to identify
        each other.
        """
        return await asha_512_hmac(key, key=key)

    @staticmethod
    def _id(key=None):
        """
        Returns a deterministic hmac of any arbitrary key material. This
        is typically used to identify a particular connection between a
        server & client which avoids personal or device identfiable
        information being needed for authenticating parties to identify
        each other.
        """
        return sha_512_hmac(key, key=key)

    @staticmethod
    async def _aclient_message_key(key, *, label="client_hello"):
        """
        Hashes a ROPAKE protocol authentication ``key`` with a ``label``
        converting it into a one-time client_hello message key. This
        prevents replay attacks on the messages between the client &
        server if a unique label is used per distinct key. Since the key
        already ratchets in a future & foward secure way after each
        authentication, the label doesn't need to change during default
        usage of this method.
        """
        if key:
            prekey = ("client", label, key)
            return await asha_512_hmac(prekey, key=prekey)
        else:
            raise ValueError(
                "Must provide ``key`` material to mix with ``label``."
            )

    @staticmethod
    def _client_message_key(key, *, label="client_hello"):
        """
        Hashes a ROPAKE protocol authentication ``key`` with a ``label``
        converting it into a one-time client_hello message key. This
        prevents replay attacks on the messages between the client &
        server if a unique label is used per distinct key. Since the key
        already ratchets in a future & foward secure way after each
        authentication, the label doesn't need to change during default
        usage of this method.
        """
        if key:
            prekey = ("client", label, key)
            return sha_512_hmac(prekey, key=prekey)
        else:
            raise ValueError(
                "Must provide ``key`` material to mix with ``label``."
            )

    @staticmethod
    async def _aserver_message_key(key, *, label="server_hello"):
        """
        Hashes a ROPAKE protocol authentication ``key`` with a ``label``
        converting it into a one-time server_hello message key. This
        prevents replay attacks on the messages between the client &
        server if a unique label is used per distinct key. Since the key
        already ratchets in a future & foward secure way after each
        authentication, the label doesn't need to change during default
        usage of this method.
        """
        if key:
            prekey = ("server", label, key)
            return await asha_512_hmac(prekey, key=prekey)
        else:
            raise ValueError(
                "Must provide ``key`` material to mix with ``label``."
            )

    @staticmethod
    def _server_message_key(key, *, label="server_hello"):
        """
        Hashes a ROPAKE protocol authentication ``key`` with a ``label``
        converting it into a one-time server_hello message key. This
        prevents replay attacks on the messages between the client &
        server if a unique label is used per distinct key. Since the key
        already ratchets in a future & foward secure way after each
        authentication, the label doesn't need to change during default
        usage of this method.
        """
        if key:
            prekey = ("server", label, key)
            return sha_512_hmac(prekey, key=prekey)
        else:
            raise ValueError(
                "Must provide ``key`` material to mix with ``label``."
            )

    @classmethod
    async def _aencrypt(cls, *, message_key, key_id=None, **plaintext):
        """
        A flexible pseudo-one-time-pad encryption method which turns the
        keyword arguments passed as ``**plaintext`` into a dictionary
        which is encrypted as a json object with the ``message_key``
        value. If a ``key_id`` is specified, then a registration has
        already established a shared key between the client & server,
        so the key_id is attached to the outside of the ciphertext so
        the other party knows which user/server is attempting to
        communicate with them.
        """
        message = await ajson_encrypt(plaintext, key=message_key)
        if key_id:
            return {cls.KEY_ID: key_id, **message}
        else:
            return message

    @classmethod
    def _encrypt(cls, *, message_key, key_id=None, **plaintext):
        """
        A flexible pseudo-one-time-pad encryption method which turns the
        keyword arguments passed as ``**plaintext`` into a dictionary
        which is encrypted as a json object with the ``message_key``
        value. If a ``key_id`` is specified, then a registration has
        already established a shared key between the client & server,
        so the key_id is attached to the outside of the ciphertext so
        the other party knows which user/server is attempting to
        communicate with them.
        """
        message = json_encrypt(plaintext, key=message_key)
        if key_id:
            return {cls.KEY_ID: key_id, **message}
        else:
            return message

    @classmethod
    async def _adecrypt(cls, *, message_key, ciphertext, ttl=0):
        """
        Decrypts a pseudo-one-time-pad ``ciphertext`` of json data with
        the ``message_key`` & returns the plaintext as well as the
        key_id in a dictionary if it was attached to the ciphertext.
        ``ttl`` determines the amount of seconds that the decrypted
        message is allowed to be aged.
        """
        if ciphertext.get(cls.KEY_ID):
            key_id = ciphertext.pop(cls.KEY_ID)
            message = await ajson_decrypt(
                data=ciphertext,
                key=message_key,
                ttl=ttl if ttl else cls.TIMEOUT,
            )
            return {cls.KEY_ID: key_id, **message}
        else:
            return await ajson_decrypt(
                data=ciphertext,
                key=message_key,
                ttl=ttl if ttl else cls.TIMEOUT,
            )

    @classmethod
    def _decrypt(cls, *, message_key, ciphertext, ttl=0):
        """
        Decrypts a pseudo-one-time-pad ``ciphertext`` of json data with
        the ``message_key`` & returns the plaintext as well as the
        key_id in a dictionary if it was attached to the ciphertext.
        ``ttl`` determines the amount of seconds that the decrypted
        message is allowed to be aged.
        """
        if ciphertext.get(cls.KEY_ID):
            key_id = ciphertext.pop(cls.KEY_ID)
            message = json_decrypt(
                data=ciphertext,
                key=message_key,
                ttl=ttl if ttl else cls.TIMEOUT,
            )
            return {cls.KEY_ID: key_id, **message}
        else:
            return json_decrypt(
                data=ciphertext,
                key=message_key,
                ttl=ttl if ttl else cls.TIMEOUT,
            )

    @classmethod
    async def _amake_commit(cls, password_hash, salt):
        """
        Takes in a hashed password string & a secret salt then returns
        a number which functions as a commit message between the client
        & server during the ROPAKE protocol. This commit message is
        shared with the server, then on the subsequent authentication
        with the server, the client will send the hash of the secret
        salt. This allows both parties to arrive at a common value
        without the server ever learning brute-forceable information
        about the password hash (if the secret salt is >= 256 bits).
        """
        return int(await cls._aid((password_hash, salt)), 16) ^ int(
            await cls._aid(salt), 16
        )

    @classmethod
    def _make_commit(cls, password_hash, salt):
        """
        Takes in a hashed password string & a secret salt then returns
        a number which functions as a commit message between the client
        & server during the ROPAKE protocol. This commit message is
        shared with the server, then on the subsequent authentication
        with the server, the client will send the hash of the secret
        salt. This allows both parties to arrive at a common value
        without the server ever learning brute-forceable information
        about the password hash (if the secret salt is >= 256 bits).
        """
        return int(cls._id((password_hash, salt)), 16) ^ int(
            cls._id(salt), 16
        )

    @classmethod
    async def _apopulate_database(cls, database: AsyncDatabase):
        """
        Inserts session values into a client database for their use in
        the registration & authentication processes.
        """
        db = database
        if not db[cls.KEY]:
            password_salt = db[cls.SALT] = await cls.agenerate_salt()
            db[cls.KEYED_PASSWORD] = await cls._amake_commit(
                db._root_key, password_salt
            )
        else:
            password_salt = db[cls.SALT]
            db[cls.KEYED_PASSWORD] = await cls._amake_commit(
                db._root_key, password_salt
            )
            password_salt = db[cls.NEXT_PASSWORD_SALT] = cls.generate_salt()
            db[cls.NEXT_KEYED_PASSWORD] = await cls._amake_commit(
                db._root_key, password_salt
            )

    @classmethod
    def _populate_database(cls, database: Database):
        """
        Inserts session values into a client database for their use in
        the registration & authentication processes.
        """
        db = database
        if not db[cls.KEY]:
            password_salt = db[cls.SALT] = cls.generate_salt()
            db[cls.KEYED_PASSWORD] = cls._make_commit(
                db._root_key, password_salt
            )
        else:
            password_salt = db[cls.SALT]
            db[cls.KEYED_PASSWORD] = cls._make_commit(
                db._root_key, password_salt
            )
            password_salt = db[cls.NEXT_PASSWORD_SALT] = cls.generate_salt()
            db[cls.NEXT_KEYED_PASSWORD] = cls._make_commit(
                db._root_key, password_salt
            )

    @classmethod
    async def _ainit_protocol(cls):
        """
        Instatiates a ``Namespace`` object with the generic values used
        to execute the ``Ropake`` registration & authentication protocols
        for both the server & client, then returns it.
        """
        values = Namespace()
        values.salt = await cls.agenerate_salt()
        values.session_salt = await cls.agenerate_salt()
        values.ecdhe_key = await X25519().agenerate()
        values.pub = values.ecdhe_key.public_bytes
        return values

    @classmethod
    def _init_protocol(cls):
        """
        Instatiates a ``Namespace`` object with the generic values used
        to execute the ``Ropake`` registration & authentication protocols
        for both the server & client, then returns it.
        """
        values = Namespace()
        values.salt = cls.generate_salt()
        values.session_salt = cls.generate_salt()
        values.ecdhe_key = X25519().generate()
        values.pub = values.ecdhe_key.public_bytes
        return values

    @classmethod
    async def _aunpack_client_hello(
        cls, client_hello: dict, key=None, *, ttl=0
    ):
        """
        Allows a server to quickly decrypt or unpack the client's hello
        data into a ``Namespace`` object for efficient & more readable
        processing of the data for authentication & registration.
        """
        if key:
            client_hello = await cls._adecrypt(
                ciphertext=client_hello,
                message_key=await cls._aclient_message_key(key),
                ttl=ttl if ttl else cls.TIMEOUT,
            )
        return Namespace(client_hello)

    @classmethod
    def _unpack_client_hello(cls, client_hello: dict, key=None, *, ttl=0):
        """
        Allows a server to quickly decrypt or unpack the client's hello
        data into a ``Namespace`` object for efficient & more readable
        processing of the data for authentication & registration.
        """
        if key:
            client_hello = cls._decrypt(
                ciphertext=client_hello,
                message_key=cls._client_message_key(key),
                ttl=ttl if ttl else cls.TIMEOUT,
            )
        return Namespace(client_hello)

    @classmethod
    async def _afinalize(
        cls, key: any, shared_key: any, shared_secret: any
    ):
        """
        Combines the current sessions' derived keys, with the keys
        derived during the last session & the current session encryption
        key into brand new key for the next authentication, & a new
        session key which updates the current session's encryption key.
        Returns a ``Namespace`` object containing these new keys.
        """
        key = await asha_512_hmac((key, shared_key), key=shared_secret)
        session_key = await asha_512(key, shared_key, shared_secret)
        return Namespace(
            mapping={cls.KEY: key, cls.SESSION_KEY: session_key}
        )

    @classmethod
    def _finalize(cls, key: any, shared_key: any, shared_secret: any):
        """
        Combines the current sessions' derived keys, with the keys
        derived during the last session & the current session encryption
        key into brand new key for the next authentication, & a new
        session key which updates the current session's encryption key.
        Returns a ``Namespace`` object containing these new keys.
        """
        key = sha_512_hmac((key, shared_key), key=shared_secret)
        session_key = sha_512(key, shared_key, shared_secret)
        return Namespace(
            mapping={cls.KEY: key, cls.SESSION_KEY: session_key}
        )

    @classmethod
    async def _aintegrate_salts(
        cls, results: Namespace, client_session_salt, server_session_salt
    ):
        """
        Mixes in random session salts to the shared key generation
        results of the Ropake protocol & returns the mutated results.
        """
        salt = results.session_salt = await asha_512(
            results.session_key, client_session_salt, server_session_salt
        )
        results.key = await asha_512(salt, results.key)
        results.session_key = await asha_512(salt, results.session_key)
        results.key_id = await cls._aid(results.key)
        return results

    @classmethod
    def _integrate_salts(
        cls, results: Namespace, client_session_salt, server_session_salt
    ):
        """
        Mixes in random session salts to the shared key generation
        results of the Ropake protocol & returns the mutated results.
        """
        salt = results.session_salt = sha_512(
            results.session_key, client_session_salt, server_session_salt
        )
        results.key = sha_512(salt, results.key)
        results.session_key = sha_512(salt, results.session_key)
        results.key_id = cls._id(results.key)
        return results

    @classmethod
    @comprehension()
    async def aclient_registration(cls, database: AsyncDatabase = None):
        """
        This is an oblivious, one-message async password authenticated
        key exchange registration protocol. Takes in a user database
        opened using unique credentials for a particular service. The
        database persists cryptographic material on the client's
        filesystem for establishing a ratcheting verification system.

        The user password is never transmitted to the server, instead
        it's processed through the ``passcrypt`` function & the
        database key initializer, before being hashed with a random
        secret salt. The secret salt is stored on the user filesystem in
        an encrypted database. The hash of the salt is xor'd with the
        hash of the concatenated password plus salt, which is called a
        keyed password, and is send to the server. The hash of the
        secret is shared with the server during the next authentication
        so a common set of keys can derived without revealing any brute-
        forceable data to the server. Every subsequent authentication is
        encrypted with & modified by the key produced by the prior
        exchange in a ratcheting protocol which is resistent to man-in-
        the-middle attacks if any prior exchange was not man-in-the-
        middled.

        Usage Example:

        # The arguments must contain at least one unique element for
        # each service the client wants to authenticate with. Using
        # unique cryptographically secure keys would be better, but this
        # is a good alternative ->

        tokens = await aiootp.AsyncDatabase.agenerate_profile_tokens(
            server_url,     # An unlimited number of arguments can be passed
            email_address,  # here as additional, optional credentials.
            username=username,
            password=password,
            salt=optional_salt_keyword_argument,
        )
        db = await aiootp.AsyncDatabase.agenerate_profile(tokens)

        async with Ropake.aclient_registration(db) as client:
            client_hello = await client()
            internet.send(client_hello)
            server_hello = internet.receive()
            await client(server_hello)

        shared_keys = await client.aresult()
        """
        db = database
        await cls._apopulate_database(db)
        values = await cls._ainit_protocol()
        response = yield {
            cls.PUB: values.pub.hex(),
            cls.SALT: values.salt,
            cls.SESSION_SALT: values.session_salt,
            cls.KEYED_PASSWORD: await db.apop(cls.KEYED_PASSWORD),
        }
        shared_key = await values.ecdhe_key.aexchange(response[cls.PUB])
        results = await cls._afinalize(
            values.salt, response[cls.SALT], shared_key
        )
        await cls._aintegrate_salts(
            results, values.session_salt, response[cls.SESSION_SALT]
        )
        db[cls.KEY] = results.key
        await db.asave()
        raise UserWarning(
            Namespace(
                key=results.key,
                key_id=results.key_id,
                session_key=results.session_key,
            )
        )

    @classmethod
    @comprehension()
    def client_registration(cls, database: Database = None):
        """
        This is an oblivious, one-message sync password authenticated
        key exchange registration protocol. Takes in a user database
        opened using unique credentials for a particular service. The
        database persists cryptographic material on the client's
        filesystem for establishing a ratcheting verification system.

        The user password is never transmitted to the server, instead
        it's processed through the database key initializer before being
        hashed with a random secret salt. The secret salt is stored on
        the user filesystem in the encrypted database. The hash of the
        salt is xor'd with the hash of the concatenated password & salt
        then sent to the server as a keyed password verifier. The salt
        hash is shared with the server during the next authentication so
        a common set of authenticated keys can be derived during a ecdhe
        without revealing any brute-forceable data to the server. Every
        subsequent authentication is encrypted with & modified by an
        auth key produced by the prior exchange in a ratcheting protocol
        which is resistent to man-in-the-middle attacks.

        Usage Example:

        # The arguments must contain at least one unique element for
        # each service the client wants to authenticate with. Using
        # unique cryptographically secure keys would be better, but this
        # is a good alternative ->

        tokens = aiootp.Database.generate_profile_tokens(
            server_url,     # An unlimited number of arguments can be passed
            email_address,  # here as additional, optional credentials.
            username=username,
            password=password,
            salt=optional_salt_keyword_argument,
        )
        db = aiootp.Database.generate_profile(tokens)

        with Ropake.client_registration(db) as client:
            client_hello = client()
            internet.send(client_hello)
            server_hello = internet.receive()
            client(server_hello)

        shared_keys = client.result()
        """
        db = database
        cls._populate_database(db)
        values = cls._init_protocol()
        response = yield {
            cls.PUB: values.pub.hex(),
            cls.SALT: values.salt,
            cls.SESSION_SALT: values.session_salt,
            cls.KEYED_PASSWORD: db.pop(cls.KEYED_PASSWORD),
        }
        shared_key = values.ecdhe_key.exchange(response[cls.PUB])
        results = cls._finalize(values.salt, response[cls.SALT], shared_key)
        cls._integrate_salts(
            results, values.session_salt, response[cls.SESSION_SALT]
        )
        db[cls.KEY] = results.key
        db.save()
        return Namespace(
            key=results.key,
            key_id=results.key_id,
            session_key=results.session_key,
        )

    @classmethod
    @comprehension()
    async def aserver_registration(cls, client_hello=None, database=None):
        """
        This is an oblivious, one-message async password authenticated
        key exchange registration protocol. It takes in a client's
        hello protocol message, & an encrypted server database, to
        retrieve & store the cryptographic values used to augment a
        elliptic curve diffie-hellman exchange to provide authentication.

        The user password is never transmitted to the server, instead
        it's processed through the database key initializer before being
        hashed with a random secret salt. The secret salt is stored on
        the user filesystem in the encrypted database. The hash of the
        salt is xor'd with the hash of the concatenated password & salt
        then sent to the server as a keyed password verifier. The salt
        hash is shared with the server during the next authentication so
        a common set of authenticated keys can be derived during a ecdhe
        without revealing any brute-forceable data to the server. Every
        subsequent authentication is encrypted with & modified by an
        auth key produced by the prior exchange in a ratcheting protocol
        which is resistent to man-in-the-middle attacks.

        Usage Example:

        db = await AsyncDatabase("server_database_key")
        client_hello = internet.receive()

        async with Ropake.aserver_registration(client_hello, db) as server:
            server_hello = await server()
            internet.send(server_hello)
            await server()

        shared_keys = await server.aresult()
        """
        values = await cls._ainit_protocol()
        client = await cls._aunpack_client_hello(client_hello)
        shared_key = await values.ecdhe_key.aexchange(client.pub)
        results = await cls._afinalize(client.salt, values.salt, shared_key)
        await cls._aintegrate_salts(
            results, client.session_salt, values.session_salt
        )
        database[results.key_id] = {
            cls.KEY: results.key,
            cls.KEYED_PASSWORD: client.keyed_password,
        }
        yield {
            cls.PUB: values.pub,
            cls.SALT: values.salt,
            cls.SESSION_SALT: values.session_salt,
        }
        raise UserWarning(
            Namespace(
                key=results.key,
                key_id=results.key_id,
                session_key=results.session_key,
            )
        )

    @classmethod
    @comprehension()
    def server_registration(cls, client_hello=None, database=None):
        """
        This is a one-message, ratcheting, oblivious, password
        authenticated key exchange registration protocol. It takes in
        a client's hello protocol message, & an encrypted server
        database, to retrieve & store the cryptographic values used in
        the exchange.

        The user password is never transmitted to the server, instead
        it's processed through the database key initializer before being
        hashed with a random secret salt. The secret salt is stored on
        the user filesystem in the encrypted database. The hash of the
        salt is xor'd with the hash of the concatenated password & salt
        then sent to the server as a keyed password verifier. The salt
        hash is shared with the server during the next authentication so
        a common set of authenticated keys can be derived during a ecdhe
        without revealing any brute-forceable data to the server. Every
        subsequent authentication is encrypted with & modified by an
        auth key produced by the prior exchange in a ratcheting protocol
        which is resistent to man-in-the-middle attacks.

        Usage Example:

        server_db = Database("server_database_key")
        client_hello = internet.receive()

        with Ropake.server_registration(client_hello, server_db) as server:
            server_hello = server()
            internet.send(server_hello)
            server()

        shared_keys = server.result()
        """
        values = cls._init_protocol()
        client = cls._unpack_client_hello(client_hello)
        shared_key = values.ecdhe_key.exchange(client.pub)
        results = cls._finalize(client.salt, values.salt, shared_key)
        cls._integrate_salts(
            results, client.session_salt, values.session_salt
        )
        database[results.key_id] = {
            cls.KEY: results.key,
            cls.KEYED_PASSWORD: client.keyed_password,
        }
        yield {
            cls.PUB: values.pub,
            cls.SALT: values.salt,
            cls.SESSION_SALT: values.session_salt,
        }
        return Namespace(
            key=results.key,
            key_id=results.key_id,
            session_key=results.session_key,
        )

    @classmethod
    @comprehension()
    async def aclient(cls, database: AsyncDatabase = None, *, ttl=0):
        """
        This is an oblivious, one-message async password authenticated
        key exchange authentication protocol. Takes in a user database
        opened using unique credentials for a particular service. The
        database persists cryptographic material on the client's
        filesystem for establishing a ratcheting verification system.

        The user password is never transmitted to the server, instead
        it's processed through the database key initializer before being
        hashed with a random secret salt. The secret salt is stored on
        the user filesystem in the encrypted database. The hash of the
        salt is xor'd with the hash of the concatenated password & salt
        then sent to the server as a keyed password verifier. The salt
        hash is shared with the server during the next authentication so
        a common set of authenticated keys can be derived during a ecdhe
        without revealing any brute-forceable data to the server. Every
        subsequent authentication is encrypted with & modified by an
        auth key produced by the prior exchange in a ratcheting protocol
        which is resistent to man-in-the-middle attacks.

        Usage Example:

        # The arguments must contain at least one unique element for
        # each service the client wants to authenticate with. Using
        # unique cryptographically secure keys would be better, but this
        # is a good alternative ->

        tokens = await aiootp.AsyncDatabase.agenerate_profile_tokens(
            server_url,     # An unlimited number of arguments can be passed
            email_address,  # here as additional, optional credentials.
            username=username,
            password=password,
            salt=optional_salt_keyword_argument,
        )
        db = await aiootp.AsyncDatabase.agenerate_profile(tokens)

        async with Ropake.aclient(db) as client:
            client_hello = await client()
            server_hello = internet.post(client_hello)
            await client(server_hello)

        shared_keys = await client.aresult()
        """
        db = database
        await cls._apopulate_database(db)
        key = db[cls.KEY]
        key_id = await cls._aid(key)
        values = await cls._ainit_protocol()
        password_salt = await cls._aid(db[cls.SALT])
        encrypted_response = yield await cls._aencrypt(
            key_id=key_id,
            message_key=await cls._aclient_message_key(key),
            salt=values.salt,
            pub=values.pub.hex(),
            password_salt=password_salt,
            session_salt=values.session_salt,
            keyed_password=await db.apop(cls.NEXT_KEYED_PASSWORD),
        )
        response = await ajson_decrypt(
            encrypted_response,
            key=await cls._aserver_message_key(key),
            ttl=ttl if ttl else cls.TIMEOUT,
        )
        shared_key = await values.ecdhe_key.aexchange(response[cls.PUB])
        shared_secret = await asha_512(
            key,
            shared_key,
            values.salt,
            response[cls.SALT],
            await db.apop(cls.KEYED_PASSWORD) ^ int(password_salt, 16),
        )
        db[cls.SALT] = await db.apop(cls.NEXT_PASSWORD_SALT)
        results = await cls._afinalize(key, shared_key, shared_secret)
        await cls._aintegrate_salts(
            results, values.session_salt, response[cls.SESSION_SALT]
        )
        db[cls.KEY] = results.key
        await db.asave()
        raise UserWarning(
            Namespace(
                key=results.key,
                key_id=results.key_id,
                session_key=results.session_key,
            )
        )

    @classmethod
    @comprehension()
    def client(cls, database: Database = None, *, ttl=0):
        """
        This is an oblivious, one-message sync password authenticated
        key exchange authentication protocol. Takes in a user database
        opened using unique credentials for a particular service. The
        database persists cryptographic material on the client's
        filesystem for establishing a ratcheting verification system.

        The user password is never transmitted to the server, instead
        it's processed through the database key initializer before being
        hashed with a random secret salt. The secret salt is stored on
        the user filesystem in the encrypted database. The hash of the
        salt is xor'd with the hash of the concatenated password & salt
        then sent to the server as a keyed password verifier. The salt
        hash is shared with the server during the next authentication so
        a common set of authenticated keys can be derived during a ecdhe
        without revealing any brute-forceable data to the server. Every
        subsequent authentication is encrypted with & modified by an
        auth key produced by the prior exchange in a ratcheting protocol
        which is resistent to man-in-the-middle attacks.

        Usage Example:

        # The arguments must contain at least one unique element for
        # each service the client wants to authenticate with. Using
        # unique cryptographically secure keys would be better, but this
        # is a good alternative ->

        tokens = aiootp.Database.generate_profile_tokens(
            server_url,     # An unlimited number of arguments can be passed
            email_address,  # here as additional, optional credentials.
            username=username,
            password=password,
            salt=optional_salt_keyword_argument,
        )
        db = aiootp.Database.generate_profile(tokens)

        with Ropake.client(db) as client:
            client_hello = client()
            internet.send(client_hello)
            server_hello = internet.receive()
            client(server_hello)

        shared_keys = client.result()
        """
        db = database
        cls._populate_database(db)
        key = db[cls.KEY]
        key_id = cls._id(key)
        values = cls._init_protocol()
        password_salt = cls._id(db[cls.SALT])
        encrypted_response = yield cls._encrypt(
            key_id=key_id,
            message_key=cls._client_message_key(key),
            salt=values.salt,
            pub=values.pub.hex(),
            password_salt=password_salt,
            session_salt=values.session_salt,
            keyed_password=db.pop(cls.NEXT_KEYED_PASSWORD),
        )
        response = json_decrypt(
            encrypted_response,
            key=cls._server_message_key(key),
            ttl=ttl if ttl else cls.TIMEOUT,
        )
        shared_key = values.ecdhe_key.exchange(response[cls.PUB])
        shared_secret = sha_512(
            key,
            shared_key,
            values.salt,
            response[cls.SALT],
            db.pop(cls.KEYED_PASSWORD) ^ int(password_salt, 16),
        )
        db[cls.SALT] = db.pop(cls.NEXT_PASSWORD_SALT)
        results = cls._finalize(key, shared_key, shared_secret)
        cls._integrate_salts(
            results, values.session_salt, response[cls.SESSION_SALT]
        )
        db[cls.KEY] = results.key
        db.save()
        return Namespace(
            key=results.key,
            key_id=results.key_id,
            session_key=results.session_key,
        )

    @classmethod
    @comprehension()
    async def aserver(cls, client_hello=None, database=None, *, ttl=0):
        """
        This is a one-message, ratcheting, oblivious, password
        authenticated key exchange authentication protocol. It takes in
        a client's hello protocol message, & an encrypted server
        database, to retrieve & store the cryptographic values used in
        the exchange.

        The user password is never transmitted to the server, instead
        it's processed through the database key initializer before being
        hashed with a random secret salt. The secret salt is stored on
        the user filesystem in the encrypted database. The hash of the
        salt is xor'd with the hash of the concatenated password & salt
        then sent to the server as a keyed password verifier. The salt
        hash is shared with the server during the next authentication so
        a common set of authenticated keys can be derived during a ecdhe
        without revealing any brute-forceable data to the server. Every
        subsequent authentication is encrypted with & modified by an
        auth key produced by the prior exchange in a ratcheting protocol
        which is resistent to man-in-the-middle attacks.

        Usage Example:

        server_db = await AsyncDatabase("server_database_key")
        client_hello = internet.receive()

        async with Ropake.aserver(client_hello, server_db) as server:
            server_hello = await server()
            internet.send(server_hello)
            await server()

        shared_keys = await server.aresult()
        """
        key = database[client_hello[cls.KEY_ID]][cls.KEY]
        values = await cls._ainit_protocol()
        client = await cls._aunpack_client_hello(
            client_hello, key=key, ttl=ttl
        )
        shared_key = await values.ecdhe_key.aexchange(client.pub)
        keyed_password = database[client.key_id][cls.KEYED_PASSWORD]
        shared_secret = await asha_512(
            key,
            shared_key,
            client.salt,
            values.salt,
            keyed_password ^ int(client.password_salt, 16),
        )
        results = await cls._afinalize(key, shared_key, shared_secret)
        await cls._aintegrate_salts(
            results, client.session_salt, values.session_salt
        )
        database[results.key_id] = {
            cls.KEY: results.key,
            cls.KEYED_PASSWORD: client.keyed_password,
        }
        del database[client.key_id]
        yield await cls._aencrypt(
            message_key=await cls._aserver_message_key(key),
            salt=values.salt,
            pub=values.pub.hex(),
            session_salt=values.session_salt,
        )
        raise UserWarning(
            Namespace(
                key=results.key,
                key_id=results.key_id,
                session_key=results.session_key,
            )
        )

    @classmethod
    @comprehension()
    def server(cls, client_hello=None, database=None, *, ttl=0):
        """
        This is a one-message, ratcheting, oblivious, password
        authenticated key exchange authentication protocol. It takes in
        a client's hello protocol message, & an encrypted server
        database, to retrieve & store the cryptographic values used in
        the exchange.

        The user password is never transmitted to the server, instead
        it's processed through the database key initializer before being
        hashed with a random secret salt. The secret salt is stored on
        the user filesystem in the encrypted database. The hash of the
        salt is xor'd with the hash of the concatenated password & salt
        then sent to the server as a keyed password verifier. The salt
        hash is shared with the server during the next authentication so
        a common set of authenticated keys can be derived during a ecdhe
        without revealing any brute-forceable data to the server. Every
        subsequent authentication is encrypted with & modified by an
        auth key produced by the prior exchange in a ratcheting protocol
        which is resistent to man-in-the-middle attacks.

        Usage Example:

        server_db = Database("server_database_key")
        client_hello = internet.receive()

        with Ropake.server(client_hello, server_db) as server:
            server_hello = server()
            internet.send(server_hello)
            server()

        shared_keys = server.result()
        """
        key = database[client_hello[cls.KEY_ID]][cls.KEY]
        values = cls._init_protocol()
        client = cls._unpack_client_hello(client_hello, key=key, ttl=ttl)
        shared_key = values.ecdhe_key.exchange(client.pub)
        keyed_password = database[client.key_id][cls.KEYED_PASSWORD]
        shared_secret = sha_512(
            key,
            shared_key,
            client.salt,
            values.salt,
            keyed_password ^ int(client.password_salt, 16),
        )
        results = cls._finalize(key, shared_key, shared_secret)
        cls._integrate_salts(
            results, client.session_salt, values.session_salt
        )
        database[results.key_id] = {
            cls.KEY: results.key,
            cls.KEYED_PASSWORD: client.keyed_password,
        }
        del database[client.key_id]
        yield cls._encrypt(
            message_key=cls._server_message_key(key),
            salt=values.salt,
            pub=values.pub.hex(),
            session_salt=values.session_salt,
        )
        return Namespace(
            key=results.key,
            key_id=results.key_id,
            session_key=results.session_key,
        )


__extras = {
    "Asymmetric25519": Asymmetric25519,
    "BaseEllipticCurve": BaseEllipticCurve,
    "Ed25519": Ed25519,
    "X25519": X25519,
    "Ropake": Ropake,
    "DomainKDF": DomainKDF,
    "Passcrypt": Passcrypt,
    "AsyncKeys": AsyncKeys,
    "Keys": Keys,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "_ainsert_keygens": ainsert_keygens,
    "_insert_keygens": insert_keygens,
    "agenerate_salt": agenerate_salt,
    "generate_salt": generate_salt,
    "acsprng": acsprng,
    "csprng": csprng,
    "acsprbg": acsprbg,
    "csprbg": csprbg,
    "akeys": akeys,
    "keys": keys,
    "abytes_keys": abytes_keys,
    "bytes_keys": bytes_keys,
    "amnemonic": amnemonic,
    "mnemonic": mnemonic,
    "apasscrypt": apasscrypt,
    "passcrypt": passcrypt,
    "akeypair_ratchets": akeypair_ratchets,
    "keypair_ratchets": keypair_ratchets,
    "apadding_key": apadding_key,
    "padding_key": padding_key,
    "protocols": X25519.protocols,
    "atable_key": atable_key,
    "table_key": table_key,
    "atable_keystream": atable_keystream,
    "table_keystream": table_keystream,
    "arandom_256": arandom_256,
    "random_256": random_256,
    "arandom_512": arandom_512,
    "random_512": random_512,
}


keygens = Namespace.make_module("keygens", mapping=__extras)

