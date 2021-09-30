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
    "keygens",
    "AsyncKeys",
    "Ed25519",
    "Keys",
    "KeyAADBundle",
    "PackageSigner",
    "PackageVerifier",
    "X25519",
    "amnemonic",
    "mnemonic",
]


__doc__ = (
    "A collection of high-level tools for creating & managing symmetric"
    " & 25519 elliptic curve asymmetric keys."
)


import json
import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey, X25519PrivateKey
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey, Ed25519PrivateKey
)
from hashlib import sha512, sha3_256, sha3_512
from ._exceptions import *
from ._typing import Typing
from ._containers import PackageSignerFiles, PackageSignerScope
from .asynchs import *
from .asynchs import asleep
from .commons import *
from .commons import ropake_constants
from commons import *  # import the module's constants
from .generics import Domains
from .generics import azip
from .generics import comprehension
from .generics import sha3__256, asha3__256
from .generics import sha3__512, asha3__512
from .generics import sha3__256_hmac, asha3__256_hmac
from .generics import sha3__512_hmac, asha3__512_hmac
from .generics import bytes_are_equal, abytes_are_equal
from .randoms import csprng, acsprng
from .randoms import random_256, arandom_256
from .randoms import random_512, arandom_512
from .randoms import generate_salt, agenerate_salt
from .ciphers import Database
from .ciphers import DomainKDF
from .ciphers import Passcrypt
from .ciphers import KeyAADBundle
from .ciphers import bytes_keys, abytes_keys


@comprehension()
async def atable_keystream(
    key: Typing.Optional[bytes] = None,
    *,
    table: Typing.Sequence[Typing.AnyStr] = Tables.ASCII_95,
):
    """
    This is an infinite key generator function that pseudo-randomly
    yields a single element from a supplied `table` on each iteration.
    The pseudo-random function used to make element choices is the
    Chunky2048 cipher's keystream algorithm. This keystream is either
    derived from a user-supplied `key`, or a random 64-byte key that's
    automatically generated.

    The ASCII_95 table that's provided as a default, is the set of ascii
    characters with ordinal values in set(range(32, 127)). It contains
    95 unique, printable characters.

    Usage Example:

    key = b"smellycaaaat, smelly caaaaat!"

    await atable_keystream(key)[:32].ajoin()
    >>> J=Gci8WMpRR9SQlN8t0~oj95ZK<k+&HW
    """
    table_size = len(table)
    if table_size > 256:
        raise Issue.value_must("table", "contain at most 256 elements")
    elif not key:
        key = await acsprng()
    keystream = abytes_keys.root(await KeyAADBundle.aunsafe(key, key))
    if table_size % 256:
        async for key in keystream:
            for byte in key:
                if byte < table_size:
                    yield table[byte]
    else:
        async for key in keystream:
            for byte in key:
                yield table[byte % table_size]


@comprehension()
def table_keystream(
    key: Typing.Optional[bytes] = None,
    *,
    table: Typing.Sequence[Typing.AnyStr] = Tables.ASCII_95,
):
    """
    This is an infinite key generator function that pseudo-randomly
    yields a single element from a supplied `table` on each iteration.
    The pseudo-random function used to make element choices is the
    Chunky2048 cipher's keystream algorithm. This keystream is either
    derived from a user-supplied `key`, or a random 64-byte key that's
    automatically generated.

    The ASCII_95 table that's provided as a default, is the set of ascii
    characters with ordinal values in set(range(32, 127)). It contains
    95 unique, printable characters.

    Usage Example:

    key = b"smellycaaaat, smelly caaaaat!"

    "".join(table_keystream(key)[:32])
    >>> J=Gci8WMpRR9SQlN8t0~oj95ZK<k+&HW
    """
    table_size = len(table)
    if table_size > 256:
        raise Issue.value_must("table", "contain at most 256 elements")
    elif not key:
        key = csprng()
    keystream = bytes_keys.root(KeyAADBundle.unsafe(key, key))
    if table_size % 256:
        for key in keystream:
            yield from (table[byte] for byte in key if byte < table_size)
    else:
        for key in keystream:
            yield from (table[byte % table_size] for byte in key)


async def atable_key(
    key: Typing.Optional[bytes] = None,
    *,
    table: Typing.Sequence[Typing.AnyStr] = Tables.ASCII_95,
    size: int = 64,
):
    """
    This is an key generation function that builds keys pseudo-randomly
    from elements in a supplied `table`. The pseudo-random function used
    to make element choices is the Chunky2048 cipher's keystream
    algorithm. This keystream is either derived from a user-supplied
    `key`, or a random 64-byte key that's automatically generated.

    The ASCII_95 table that's provided as a default, is the set of ascii
    characters with ordinal values in set(range(32, 127)). It contains
    95 unique, printable characters.

    The size parameter determines the number of elements the output key
    will contain.

    Usage Example:

    key = b"smellycaaaat, smelly caaaaat!"

    table_key(key=key, table="0123456789abcdef")
    >>> b6558225d702851463a7c9b82d23365d20e28a9b7020fa83c03b0140decdc225

    table_key(key, size=32)
    >>> J=Gci8WMpRR9SQlN8t0~oj95ZK<k+&HW
    """
    on = table[0][:0]
    stream = atable_keystream.root(key=key, table=table)
    return on.join(
        [char async for _, char in azip.root(range(size), stream)]
    )


def table_key(
    key: Typing.Optional[bytes] = None,
    *,
    table: Typing.Sequence[Typing.AnyStr] = Tables.ASCII_95,
    size: int = 64,
):
    """
    This is an key generation function that builds keys pseudo-randomly
    from elements in a supplied `table`. The pseudo-random function used
    to make element choices is the Chunky2048 cipher's keystream
    algorithm. This keystream is either derived from a user-supplied
    `key`, or a random 64-byte key that's automatically generated.

    The ASCII_95 table that's provided as a default, is the set of ascii
    characters with ordinal values in set(range(32, 127)). It contains
    95 unique, printable characters.

    The size parameter determines the number of elements the output key
    will contain.

    Usage Example:

    key = b"smellycaaaat, smelly caaaaat!"

    table_key(key, table="0123456789abcdef")
    >>> b6558225d702851463a7c9b82d23365d20e28a9b7020fa83c03b0140decdc225

    table_key(key, size=32)
    >>> J=Gci8WMpRR9SQlN8t0~oj95ZK<k+&HW
    """
    on = table[0][:0]
    stream = table_keystream.root(key=key, table=table)
    return on.join(char for _, char in zip(range(size), stream))


@comprehension()
async def amnemonic(
    key: bytes,
    *,
    salt: Typing.Optional[bytes] = None,
    words: Typing.Optional[Typing.Sequence[Typing.Any]] = None,
    **passcrypt_settings,
):
    """
    Creates a stream of words for a mnemonic key from a user passphrase
    ``key`` & random salt. If a salt isn't passed, then a random salt is
    generated & is available by calling ``result(exit=True)`` on the
    generator object. The ``words`` used for the mnemonic can be passed
    in, but by default are a 2048 word list of unique, all lowercase
    english words.
    """
    keystream_shift = None
    words = words if words else WORD_LIST
    length = len(words)
    salt = salt if salt else await agenerate_salt(size=32)
    key = await Passcrypt.anew(key, salt, **passcrypt_settings)
    keystream = abytes_keys(await KeyAADBundle.aunsafe(key, salt, key))
    async with keystream.abytes_to_int().arelay(salt) as indexes:
        while True:
            if keystream_shift:
                await keystream.asend(keystream_shift)
            keystream_shift = yield words[await indexes() % length]


@comprehension()
def mnemonic(
    key: bytes,
    *,
    salt: Typing.Optional[bytes] = None,
    words: Typing.Optional[Typing.Sequence[Typing.Any]] = None,
    **passcrypt_settings,
):
    """
    Creates a stream of words for a mnemonic key from a user passphrase
    ``key`` & random salt. If a salt isn't passed, then a random salt is
    generated & is available by calling ``result(exit=True)`` on the
    generator object. The ``words`` used for the mnemonic can be passed
    in, but by default are a 2048 word list of unique, all lowercase
    english words.
    """
    keystream_shift = None
    words = words if words else WORD_LIST
    length = len(words)
    salt = salt if salt else generate_salt(size=32)
    key = Passcrypt.new(key, salt, **passcrypt_settings)
    keystream = bytes_keys(KeyAADBundle.unsafe(key, salt, key))
    with keystream.bytes_to_int().relay(salt) as indexes:
        while True:
            if keystream_shift:
                keystream.send(keystream_shift)
            keystream_shift = yield words[indexes() % length]


class AsyncKeys:
    """
    This simple class is a high-level interface for symmetric key
    creation, derivation & HMAC validation of data.
    """

    __slots__ = []

    DomainKDF = DomainKDF
    Passcrypt = Passcrypt
    KeyAADBundle = KeyAADBundle

    abytes_keys = staticmethod(abytes_keys)
    acsprng = staticmethod(acsprng)
    agenerate_salt = staticmethod(agenerate_salt)
    amnemonic = staticmethod(amnemonic)
    arandom_256 = staticmethod(arandom_256)
    arandom_512 = staticmethod(arandom_512)
    atable_key = staticmethod(atable_key)
    atable_keystream = staticmethod(atable_keystream)

    @staticmethod
    async def amake_hmac(
        data: Typing.DeterministicRepr,
        *,
        key: bytes,
        hasher: Typing.Callable = asha3__256_hmac,
    ):
        """
        Creates an HMAC code of ``data`` using the supplied ``key`` &
        the hashing function ``hasher``. Any async ``hasher`` function
        can be specified as the HMAC function, which is by default
        SHA3_256_HMAC.
        """
        return await hasher(data, key=key, hex=False)

    @classmethod
    async def atest_hmac(
        cls,
        data: Typing.DeterministicRepr,
        untrusted_hmac: bytes,
        *,
        key: bytes,
        hasher: Typing.Callable = asha3__256_hmac,
    ):
        """
        Tests if the given ``hmac`` of some ``data`` is valid with a
        time-safe comparison with a derived HMAC. Any async ``hasher``
        function can be specified as the HMAC function, which is by
        default SHA3_256_HMAC.
        """
        if not untrusted_hmac:
            raise Issue.no_value_specified("hmac")
        true_hmac = await cls.amake_hmac(data, key=key, hasher=hasher)
        if await abytes_are_equal(untrusted_hmac, true_hmac):
            return True
        else:
            raise Issue.invalid_value("HMAC of data stream")


class Keys:
    """
    This simple class is a high-level interface for symmetric key
    creation, derivation & HMAC validation of data.
    """

    __slots__ = []

    DomainKDF = DomainKDF
    Passcrypt = Passcrypt
    KeyAADBundle = KeyAADBundle

    bytes_keys = staticmethod(bytes_keys)
    csprng = staticmethod(csprng)
    generate_salt = staticmethod(generate_salt)
    mnemonic = staticmethod(mnemonic)
    random_256 = staticmethod(random_256)
    random_512 = staticmethod(random_512)
    table_key = staticmethod(table_key)
    table_keystream = staticmethod(table_keystream)

    @staticmethod
    def make_hmac(
        data: Typing.DeterministicRepr,
        *,
        key: bytes,
        hasher: Typing.Callable = sha3__256_hmac,
    ):
        """
        Creates an HMAC code of ``data`` using the supplied ``key`` &
        the hashing function ``hasher``. Any sync ``hasher`` function
        can be specified as the HMAC function, which is by default
        SHA3_256_HMAC.
        """
        return hasher(data, key=key, hex=False)

    @classmethod
    def test_hmac(
        cls,
        data: Typing.DeterministicRepr,
        untrusted_hmac: bytes,
        *,
        key: bytes,
        hasher: Typing.Callable = sha3__256_hmac,
    ):
        """
        Tests if the given ``hmac`` of some ``data`` is valid with a
        time-safe comparison with a derived HMAC. Any sync ``hasher``
        function can be specified as the HMAC function, which is by
        default SHA3_256_HMAC.
        """
        if not untrusted_hmac:
            raise Issue.no_value_specified("hmac")
        true_hmac = cls.make_hmac(data, key=key, hasher=hasher)
        if bytes_are_equal(untrusted_hmac, true_hmac):
            return True
        else:
            raise Issue.invalid_value("HMAC of data stream")


class Curve25519:
    """
    Contains a collection of class methods & values that simplify the
    usage of the cryptography library, as well as pointers to values in
    the cryptography library.
    """

    __slots__ = []

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
    async def aed25519_key():
        """
        Returns an ``Ed25519PrivateKey`` from the cryptography package
        used to make elliptic curve signatures of data.
        """
        await asleep()
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
        await asleep()
        return X25519PrivateKey.generate()

    @staticmethod
    def x25519_key():
        """
        Returns a ``X25519PrivateKey`` from the cryptography package for
        use in an elliptic curve diffie-hellman exchange.
        """
        return X25519PrivateKey.generate()

    @classmethod
    async def apublic_bytes(cls, key):
        """
        Returns the public key bytes of either an ``X25519PrivateKey``,
        ``X25519PublicKey``, ``Ed25519PublicKey`` or ``Ed25519PrivateKey``
        object from the cryptography package.
        """
        await asleep()
        if hasattr(key, "public_key"):
            public_key = key.public_key()
        else:
            public_key = key
        return public_key.public_bytes(**cls._PUBLIC_BYTES_ENUM)

    @classmethod
    def public_bytes(cls, key):
        """
        Returns the public key bytes of either an ``X25519PrivateKey``,
        ``X25519PublicKey``, ``Ed25519PublicKey`` or ``Ed25519PrivateKey``
        object from the cryptography package.
        """
        if hasattr(key, "public_key"):
            public_key = key.public_key()
        else:
            public_key = key
        return public_key.public_bytes(**cls._PUBLIC_BYTES_ENUM)

    @classmethod
    async def asecret_bytes(cls, secret_key):
        """
        Returns the secret key bytes of either an ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` from the cryptography package.
        """
        await asleep()
        return secret_key.private_bytes(**cls._PRIVATE_BYTES_ENUM)

    @classmethod
    def secret_bytes(cls, secret_key):
        """
        Returns the secret key bytes of either an ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` from the cryptography package.
        """
        return secret_key.private_bytes(**cls._PRIVATE_BYTES_ENUM)

    @staticmethod
    async def aexchange(secret_key, public_key: Typing.AnyStr):
        """
        Returns the shared key bytes derived from an elliptic curve key
        exchange with the user's ``secret_key`` key, & their communicating
        peer's ``public_key`` public key's bytes or hex value.
        """
        await asleep()
        if public_key.__class__ is not bytes:
            public_key = bytes.fromhex(public_key)
        return secret_key.exchange(
            X25519PublicKey.from_public_bytes(public_key)
        )

    @staticmethod
    def exchange(secret_key, public_key: Typing.AnyStr):
        """
        Returns the shared key bytes derived from an elliptic curve key
        exchange with the user's ``secret_key`` key, & their communicating
        peer's ``public_key`` public key's bytes or hex value.
        """
        if public_key.__class__ is not bytes:
            public_key = bytes.fromhex(public_key)
        return secret_key.exchange(
            X25519PublicKey.from_public_bytes(public_key)
        )


class Base25519:
    """
    Collects the shared functionality between the ``X25519`` & ``Ed25519``
    classes.
    """

    __slots__ = ["_public_key", "_secret_key"]

    _Curve25519 = Curve25519

    _exceptions = Curve25519.exceptions

    PublicKey = None
    SecretKey = None

    @classmethod
    def _preprocess_key(cls, key_material):
        """
        Converts to bytes if ``key_material`` is hex, otherwise returns
        it unaltered only if is truthy.
        """
        if not key_material:
            raise Issue.no_value_specified("key material")
        elif key_material.__class__ is str:
            key_material = bytes.fromhex(key_material)
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
        if public_key.__class__ is not bytes:
            public_key = cls._Curve25519.public_bytes(public_key)
        return cls.PublicKey.from_public_bytes(public_key)

    @classmethod
    def _process_secret_key(cls, secret_key):
        """
        Accepts a ``secret_key`` in either hex, bytes, ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` format. Returns an instantiaed secret
        key associated with the subclass inhereting this method.
        """
        secret_key = cls._preprocess_key(secret_key)
        if secret_key.__class__ is not bytes:
            secret_key = cls._Curve25519.secret_bytes(secret_key)
        return cls.SecretKey.from_private_bytes(secret_key)

    async def aimport_public_key(self, public_key):
        """
        Populates an instance from the received ``public_key`` that is
        of either hex, bytes, ``X25519PublicKey``, ``X25519PrivateKey``,
        ``Ed25519PublicKey`` or ``Ed25519PrivateKey`` type.
        """
        await asleep()
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
        await asleep()
        if hasattr(self, "_secret_key"):
            cls = self.__class__.__qualname__
            raise Issue.value_already_set(f"{cls} instance key")
        self._secret_key = self._process_secret_key(secret_key)
        self._public_key = self.PublicKey.from_public_bytes(
            await self._Curve25519.apublic_bytes(self._secret_key)
        )
        return self

    def import_secret_key(self, secret_key):
        """
        Populates an instance from the received ``secret_key`` that is
        of either hex, bytes, ``X25519PrivateKey`` or ``Ed25519PrivateKey``
        type.
        """
        if hasattr(self, "_secret_key"):
            cls = self.__class__.__qualname__
            raise Issue.value_already_set(f"{cls} instance key")
        self._secret_key = self._process_secret_key(secret_key)
        self._public_key = self.PublicKey.from_public_bytes(
            self._Curve25519.public_bytes(self._secret_key)
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
        return self._Curve25519.secret_bytes(self._secret_key)

    @property
    def public_bytes(self):
        """
        Returns the public bytes of the instance's instantiated &
        populated PublicKey of the associated sublass inhereting this
        method.
        """
        return self._Curve25519.public_bytes(self._public_key)

    def is_secret_key(self):
        """
        Returns a boolean of whether the instance contains a secret key.
        """
        return hasattr(self, "_secret_key")

    def is_public_key(self):
        """
        Returns a boolean of whether the instance contains a public key.
        """
        return hasattr(self, "_public_key")


class Ed25519(Base25519):
    """
    This class is used to create stateful objects that simplify usage of
    the cryptography library's ed25519 protocol.

    Usage Example:

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

    __slots__ = ["_public_key", "_secret_key"]

    InvalidSignature = Base25519._exceptions.InvalidSignature
    PublicKey = Curve25519.Ed25519PublicKey
    SecretKey = Curve25519.Ed25519PrivateKey

    async def agenerate(self):
        """
        Generates a new secret key used for signing bytes data &
        populates the instance with it & its associated public key. This
        method returns the instance for convenience in instantiating a
        stateful object with await Ed25519().agenerate().
        """
        key = await self._Curve25519.aed25519_key()
        await self.aimport_secret_key(key)
        return self

    def generate(self):
        """
        Generates a new secret key used for signing bytes data &
        populates the instance with it & its associated public key. This
        method returns the instance for convenience in instantiating a
        stateful object with Ed25519().generate().
        """
        key = self._Curve25519.ed25519_key()
        self.import_secret_key(key)
        return self

    async def asign(self, data: bytes):
        """
        Signs some bytes ``data`` with the instance's secret key.
        """
        await asleep()
        return self.secret_key.sign(data)

    def sign(self, data: bytes):
        """
        Signs some bytes ``data`` with the instance's secret key.
        """
        return self.secret_key.sign(data)

    async def averify(
        self, signature: bytes, data: bytes, *, public_key=None
    ):
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

    def verify(self, signature: bytes, data: bytes, *, public_key=None):
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

    __slots__ = ["_public_key", "_secret_key"]

    PublicKey = Curve25519.X25519PublicKey
    SecretKey = Curve25519.X25519PrivateKey

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
        key = await self._Curve25519.ax25519_key()
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
        key = self._Curve25519.x25519_key()
        self.import_secret_key(key)
        return self

    async def aexchange(self, public_key):
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

    def exchange(self, public_key):
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
        peer_identity_key, peer_ephemeral_key = yield (
            my_ephemeral_key.public_bytes
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
        peer_identity_key, peer_ephemeral_key = yield (
            my_ephemeral_key.public_bytes
        )
        shared_key_ad = my_ephemeral_key.exchange(peer_identity_key)
        shared_key_cd = my_ephemeral_key.exchange(peer_ephemeral_key)
        return sha3_512(domain + shared_key_ad + shared_key_cd)

    @comprehension()
    async def adh2_server(self, peer_ephemeral_key: bytes):
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

        client_ephemeral_key = internet.receive()

        async with ecdhe_key.adh2_server(client_ephemeral_key) as exchange:
            internet.send(await exchange.aexhaust())

        shared_key_kdf = await exchange.aresult()
        """
        domain = Domains.DH2
        my_identity_key = self
        my_ephemeral_key = await X25519().agenerate()
        yield my_identity_key.public_bytes, my_ephemeral_key.public_bytes
        shared_key_ad = await my_identity_key.aexchange(peer_ephemeral_key)
        shared_key_cd = await my_ephemeral_key.aexchange(peer_ephemeral_key)
        raise UserWarning(sha3_512(domain + shared_key_ad + shared_key_cd))

    @comprehension()
    def dh2_server(self, peer_ephemeral_key: bytes):
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

        client_ephemeral_key = internet.receive()

        with ecdhe_key.dh2_server(client_ephemeral_key) as exchange:
            internet.send(exchange.exhaust())

        shared_key_kdf = exchange.result()
        """
        domain = Domains.DH2
        my_identity_key = self
        my_ephemeral_key = X25519().generate()
        yield my_identity_key.public_bytes, my_ephemeral_key.public_bytes
        shared_key_ad = my_identity_key.exchange(peer_ephemeral_key)
        shared_key_cd = my_ephemeral_key.exchange(peer_ephemeral_key)
        return sha3_512(domain + shared_key_ad + shared_key_cd)

    @comprehension()
    async def adh3_client(self):
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
        my_identity_key = self
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

    @comprehension()
    def dh3_client(self):
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
        my_identity_key = self
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

    @comprehension()
    async def adh3_server(
        self, peer_identity_key: bytes, peer_ephemeral_key: bytes
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

        identity_key, ephemeral_key = client_keys = internet.receive()

        server = ecdhe_key.adh3_server(identity_key, ephemeral_key)
        async with server as exchange:
            internet.send(await exchange.aexhaust())

        shared_key_kdf = await exchange.aresult()
        """
        domain = Domains.DH3
        my_identity_key = self
        my_ephemeral_key = await X25519().agenerate()
        yield my_identity_key.public_bytes, my_ephemeral_key.public_bytes
        shared_key_ad = await my_identity_key.aexchange(peer_ephemeral_key)
        shared_key_bc = await my_ephemeral_key.aexchange(peer_identity_key)
        shared_key_cd = await my_ephemeral_key.aexchange(peer_ephemeral_key)
        raise UserWarning(
            sha3_512(domain + shared_key_ad + shared_key_bc + shared_key_cd)
        )

    @comprehension()
    def dh3_server(
        self, peer_identity_key: bytes, peer_ephemeral_key: bytes
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

        identity_key, ephemeral_key = client_keys = internet.receive()

        server = ecdhe_key.dh3_server(identity_key, ephemeral_key)
        with server as exchange:
            internet.send(exchange.exhaust())

        shared_key_kdf = exchange.result()
        """
        domain = Domains.DH3
        my_identity_key = self
        my_ephemeral_key = X25519().generate()
        yield my_identity_key.public_bytes, my_ephemeral_key.public_bytes
        shared_key_ad = my_identity_key.exchange(peer_ephemeral_key)
        shared_key_bc = my_ephemeral_key.exchange(peer_identity_key)
        shared_key_cd = my_ephemeral_key.exchange(peer_ephemeral_key)
        return sha3_512(
            domain + shared_key_ad + shared_key_bc + shared_key_cd
        )


class PackageSigner:
    """
    Provides an intuitive API for users to sign their own packages.

    Usage Example:

    import getpass
    import json
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
        directory=getpass("secure directory:\n"),
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

    __slots__ = ["_db", "_scope", "files"]

    _Hasher = sha512
    _InvalidSignature = Ed25519._exceptions.InvalidSignature
    _Signer = Ed25519

    _CHECKSUM = CHECKSUM
    _CHECKSUMS = CHECKSUMS
    _CLASS = "PackageSigner"
    _PUBLIC_CREDENTIALS = PUBLIC_CREDENTIALS
    _SCOPE = SCOPE
    _SIGNATURE = SIGNATURE
    _SIGNING_KEY = SIGNING_KEY
    _VERSIONS = VERSIONS

    @classmethod
    def _database_template(cls):
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
    def generate_signing_key(cls):
        """
        Generates a new `Ed25519` secret signing key object.
        """
        return cls._Signer().generate()

    def __init__(
        self,
        package: str,
        version: str,
        date: Typing.Optional[int] = None,
        **scopes: Typing.Dict[str, Typing.JSONSerializable],
    ):
        """
        Sets the instance's package scope attributes & default file
        checksums container.
        """
        self.files = PackageSignerFiles()
        self._scope = PackageSignerScope(
            package=package,
            version=version,
            date=date if date else asynchs.this_day(),
            **scopes,
        )

    @property
    def _public_credentials(self):
        """
        Returns public credentials from the instance's secure database.
        """
        return self.db[self._scope.package][self._PUBLIC_CREDENTIALS]

    @property
    def signing_key(self):
        """
        Returns the package's secret signing key from the instance's
        encrypted database in an `Ed25519` object.
        """
        encrypted_key = self.db[self._scope.package][self._SIGNING_KEY]
        if not encrypted_key:
            raise PackageSignerIssue.signing_key_hasnt_been_set()
        key = self.db.read_token(encrypted_key)
        return Ed25519().import_secret_key(key)

    @property
    def db(self):
        """
        Returns the instance's database object, or alerts the user to
        connect to a secure database if it isn't yet set.
        """
        try:
            return self._db
        except AttributeError:
            raise PackageSignerIssue.must_connect_to_secure_database()

    @property
    def _checksums(self):
        """
        Returns the instance's package filenames & their hexdigests in
        a json ready dictionary.
        """
        return {
            filename: hasher.hexdigest()
            for filename, hasher in sorted(self.files.items())
        }

    @property
    def _summary(self):
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
                name: value
                for name, value in sorted(self._scope.items())
            },
            self._SIGNING_KEY: self.signing_key.public_bytes.hex(),
        }

    @property
    def _checksum(self):
        """
        Returns the digest of the current package summary.
        """
        return self._Hasher(json.dumps(self._summary).encode()).digest()

    @property
    def _signature(self):
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
        *secret_credentials: Typing.Iterable[Typing.Any],
        passphrase: Typing.Any,
        salt: Typing.Any = None,
        username: Typing.Any = None,
        directory: Typing.OptionalPathStr = None,
        **passcrypt_settings: Typing.Dict[str, int],
    ):
        """
        Opens an encrypted database connection using the Passcrypt
        passphrase-based key derivation function, a ``passphrase`` & any
        available additional credentials a user may have. If a database
        doesn't already exist, then a new one is created with default
        values.
        """
        tokens = Database.generate_profile_tokens(
            self._CLASS,
            *secret_credentials,
            username=username,
            passphrase=passphrase,
            salt=salt,
            **passcrypt_settings,
        )
        self._db = Database.generate_profile(
            tokens,
            directory=directory if directory else Database.directory,
        )
        try:
            self.db.query_tag(self._scope.package, cache=True)
        except LookupError:
            self.db[self._scope.package] = self._database_template()

    def update_scope(self, **scopes):
        """
        Updates the package scopes to qualify the package signature of
        the current package version within the instance.
        """
        self._scope.namespace.update(scopes)

    def update_public_credentials(
        self, **credentials: Typing.Dict[str, Typing.JSONSerializable]
    ):
        """
        Updates the public credentials to be associated with the package
        signature & stores them in the instance's database cache. The
        database must be saved separately to save them to disk.
        """
        package = self._scope.package
        self.db[package][self._PUBLIC_CREDENTIALS].update(credentials)

    def update_signing_key(self, signing_key: bytes):
        """
        Updates the package's secret signing key as an encrypted token
        within the instance's database cache. The database must be saved
        separately to save the encrypted signing key to disk.
        """
        if signing_key.__class__ is not bytes:
            raise Issue.value_must_be_type("signing_key", bytes)
        package = self._scope.package
        self.db[package][self._SIGNING_KEY] = self.db.make_token(
            signing_key
        ).decode()

    def add_file(self, filename: str, file_data: bytes):
        """
        Stores a ``filename`` & the hash object of the file's bytes type
        contents in the instance's `files` attribute mapping.
        """
        self.files[filename] = self._Hasher(file_data)

    def sign_package(self):
        """
        Signs the package summary checksum & stores it in the instance's
        secure database cache. The database must be saved separately to
        save the signature to disk.
        """
        checksum = self._checksum
        self.db[self._scope.package][self._VERSIONS].update(
            {self._scope.version: self.signing_key.sign(checksum).hex()}
        )

    def summarize(self):
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
        except self._InvalidSignature:
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

    Usage Example:

    from aiootp import PackageVerifier

    verifier = PackageVerifier(public_signing_key)
    verifier.verify_summary(package_signature_summary)
    """

    __slots__ = [
        "_checksum", "_signature", "_signing_key", "_summary_dictionary"
    ]

    _Hasher = sha512
    _InvalidSignature = Ed25519._exceptions.InvalidSignature
    _Signer = Ed25519

    _CHECKSUM = CHECKSUM
    _SIGNATURE = SIGNATURE
    _SIGNING_KEY = SIGNING_KEY

    def __init__(self, public_signing_key: bytes):
        """
        Receives the bytes type public signing key a user expects a
        package to be signed by, & stores it within the instance.
        """
        if public_signing_key.__class__ is not bytes:
            raise Issue.value_must_be_type("public signing key", bytes)
        self._signing_key = Ed25519().import_public_key(public_signing_key)

    @property
    def _summary_bytes(self):
        """
        Returns the UTF-8 encoded JSON package signature summary sans
        the package checksum & signature for hashing.
        """
        return json.dumps(self._summary_dictionary).encode()

    def _import_summary(
        self, summary: Typing.Dict[str, Typing.JSONSerializable]
    ):
        """
        Verifies the package summary checksum & stores its values within
        the instance.
        """
        summary = self._summary_dictionary = {**summary}
        self._checksum = bytes.fromhex(summary.pop(self._CHECKSUM))
        self._signature = bytes.fromhex(summary.pop(self._SIGNATURE))
        if self._Hasher(self._summary_bytes).digest() != self._checksum:
            raise Issue.invalid_value("package summary checksum")

    def verify_summary(
        self,
        summary: Typing.Union[
            Typing.Dict[str, Typing.JSONSerializable],
            Typing.JSONDeserializable,
        ],
    ):
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
        try:
            self._signing_key.verify(self._signature, self._checksum)
        except self._InvalidSignature:
            raise Issue.invalid_value("package summary signature")


extras = dict(
    AsyncKeys=AsyncKeys,
    Curve25519=Curve25519,
    DomainKDF=DomainKDF,
    Ed25519=Ed25519,
    KeyAADBundle=KeyAADBundle,
    Keys=Keys,
    PackageSigner=PackageSigner,
    PackageVerifier=PackageVerifier,
    Passcrypt=Passcrypt,
    X25519=X25519,
    __doc__=__doc__,
    __main_exports__=__all__,
    __package__=__package__,
    abytes_keys=abytes_keys,
    acsprng=acsprng,
    agenerate_salt=agenerate_salt,
    amnemonic=amnemonic,
    arandom_256=arandom_256,
    arandom_512=arandom_512,
    atable_key=atable_key,
    atable_keystream=atable_keystream,
    bytes_keys=bytes_keys,
    csprng=csprng,
    generate_salt=generate_salt,
    mnemonic=mnemonic,
    random_256=random_256,
    random_512=random_512,
    table_key=table_key,
    table_keystream=table_keystream,
)


keygens = commons.make_module("keygens", mapping=extras)

