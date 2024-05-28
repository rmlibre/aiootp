# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2024 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["Curve25519"]


__doc__ = (
    "An adapter to Curve25519 operations from the `cryptography` package."
)


import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey, X25519PrivateKey
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey, Ed25519PrivateKey
)

from aiootp._typing import Typing as t
from aiootp._exceptions import Issue
from aiootp.asynchs import asleep


class Curve25519:
    """
    Contains a collection of class methods & values that simplify the
    usage of the cryptography library, as well as pointers to values in
    the cryptography library.
    """

    __slots__ = ()

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
        Returns an `Ed25519PrivateKey` from the cryptography package
        used to make elliptic curve signatures of data.
        """
        await asleep()
        return Ed25519PrivateKey.generate()

    @staticmethod
    def ed25519_key() -> Ed25519PrivateKey:
        """
        Returns an `Ed25519PrivateKey` from the cryptography package
        used to make elliptic curve signatures of data.
        """
        return Ed25519PrivateKey.generate()

    @staticmethod
    async def ax25519_key() -> X25519PrivateKey:
        """
        Returns a `X25519PrivateKey` from the cryptography package for
        use in an elliptic curve diffie-hellman exchange.
        """
        await asleep()
        return X25519PrivateKey.generate()

    @staticmethod
    def x25519_key() -> X25519PrivateKey:
        """
        Returns a `X25519PrivateKey` from the cryptography package for
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
        Returns the public key bytes of either an `X25519PrivateKey`,
        `X25519PublicKey`, `Ed25519PublicKey` or `Ed25519PrivateKey`
        object from the cryptography package.
        """
        await asleep()
        return cls.public_bytes(key)

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
        Returns the public key bytes of either an `X25519PrivateKey`,
        `X25519PublicKey`, `Ed25519PublicKey` or `Ed25519PrivateKey`
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
            return key.public_key().public_bytes_raw()
        else:
            return key.public_bytes_raw()

    @classmethod
    async def asecret_bytes(
        cls, secret_key: t.Union[X25519PrivateKey, Ed25519PrivateKey]
    ) -> bytes:
        """
        Returns the secret key bytes of either an `X25519PrivateKey`
        or `Ed25519PrivateKey` from the cryptography package.
        """
        await asleep()
        return cls.secret_bytes(secret_key)

    @classmethod
    def secret_bytes(
        cls, secret_key: t.Union[X25519PrivateKey, Ed25519PrivateKey]
    ) -> bytes:
        """
        Returns the secret key bytes of either an `X25519PrivateKey`
        or `Ed25519PrivateKey` from the cryptography package.
        """
        key_types = (X25519PrivateKey, Ed25519PrivateKey)
        if not issubclass(secret_key.__class__, key_types):
            raise Issue.value_must_be_type("secret_key", key_types)
        else:
            return secret_key.private_bytes_raw()

    @classmethod
    async def aexchange(
        cls, secret_key: X25519PrivateKey, public_key: bytes
    ) -> bytes:
        """
        Returns the shared key bytes derived from an elliptic curve key
        exchange with the user's `secret_key` key, & their communicating
        peer's `public_key` bytes.
        """
        await asleep()
        return cls.exchange(secret_key=secret_key, public_key=public_key)

    @classmethod
    def exchange(
        cls, secret_key: X25519PrivateKey, public_key: bytes
    ) -> bytes:
        """
        Returns the shared key bytes derived from an elliptic curve key
        exchange with the user's `secret_key` key, & their communicating
        peer's `public_key` bytes.
        """
        return secret_key.exchange(
            X25519PublicKey.from_public_bytes(public_key)
        )


module_api = dict(
    Curve25519=t.add_type(Curve25519),
    Ed25519PublicKey=t.add_type(Ed25519PublicKey),
    Ed25519PrivateKey=t.add_type(Ed25519PrivateKey),
    X25519PublicKey=t.add_type(X25519PublicKey),
    X25519PrivateKey=t.add_type(X25519PrivateKey),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

