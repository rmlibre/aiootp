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


__all__ = ["Base25519"]


__doc__ = (
    "A general type defining an interface to Curve25519 operations."
)


from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey, X25519PrivateKey
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey, Ed25519PrivateKey
)

from aiootp._typing import Typing as t
from aiootp._exceptions import Issue
from aiootp.asynchs import asleep
from aiootp.commons import FrozenInstance


class Base25519(FrozenInstance):
    """
    Collects the shared functionality between the `X25519` & `Ed25519`
    classes.
    """

    __slots__ = ("_public_key", "_secret_key")

    PublicKey: type = None
    SecretKey: type = None

    def __init__(self) -> None:
        self._secret_key = None
        self._public_key = None

    def _process_secret_key(
        self, secret_key: t.Union[bytes, t.SecretKeyType]
    ) -> t.SecretKeyType:
        """
        If `secret_key` is either of `bytes` or `self.SecretKey` type,
        returns an instance of `self.SecretKey`. Otherwise raises
        `TypeError`.
        """
        cls = secret_key.__class__
        if cls is bytes:
            return self.SecretKey.from_private_bytes(secret_key)
        elif issubclass(cls, self.SecretKey):
            return secret_key
        else:
            raise Issue.value_must_be_type("secret_key", "valid key type")

    def _process_public_key(
        self, public_key: t.Union[bytes, t.PublicKeyType]
    ) -> t.PublicKeyType:
        """
        If `public_key` is either of `bytes` or `self.PublicKey` type,
        returns an instance of `self.PublicKey`. Otherwise raises
        `TypeError`.
        """
        cls = public_key.__class__
        if cls is bytes:
            return self.PublicKey.from_public_bytes(public_key)
        elif issubclass(cls, self.PublicKey):
            return public_key
        else:
            raise Issue.value_must_be_type("public_key", "valid key type")

    async def aimport_secret_key(
        self, secret_key: t.Union[bytes, t.SecretKeyType]
    ) -> t.Self:
        """
        Populates an instance from the received `secret_key` that is
        of either `bytes` or `self.SecretKey` type.
        """
        await asleep()
        return self.import_secret_key(secret_key)

    def import_secret_key(
        self, secret_key: t.Union[bytes, t.SecretKeyType]
    ) -> t.Self:
        """
        Populates an instance from the received `secret_key` that is
        of either `bytes` or `self.SecretKey` type.
        """
        if self.has_public_key():
            raise Issue.cant_reassign_attribute("public_key")
        insert = object.__setattr__
        insert(self, "_secret_key", self._process_secret_key(secret_key))
        insert(self, "_public_key", self._secret_key.public_key())
        return self

    async def aimport_public_key(
        self, public_key: t.Union[bytes, t.PublicKeyType]
    ) -> t.Self:
        """
        Populates an instance from the received `public_key` that is
        of either `bytes` or `self.PublicKey` type.
        """
        await asleep()
        return self.import_public_key(public_key)

    def import_public_key(
        self, public_key: t.Union[bytes, t.PublicKeyType]
    ) -> t.Self:
        """
        Populates an instance from the received `public_key` that is
        of either `bytes` or `self.PublicKey` type.
        """
        if self.has_public_key():
            raise Issue.cant_reassign_attribute("public_key")
        insert = object.__setattr__
        insert(self, "_secret_key", None)
        insert(self, "_public_key", self._process_public_key(public_key))
        return self

    async def agenerate(self) -> t.Self:
        """
        Populates the instance with a newly generated secret key.
        """
        return await self.aimport_secret_key(self.SecretKey.generate())

    def generate(self) -> t.Self:
        """
        Populates the instance with a newly generated secret key.
        """
        return self.import_secret_key(self.SecretKey.generate())

    @property
    def secret_key(self) -> t.Optional[t.SecretKeyType]:
        """
        Returns the instance's secret key object.
        """
        return self._secret_key

    @property
    def public_key(self) -> t.Optional[t.PublicKeyType]:
        """
        Returns the instance's public key object.
        """
        return self._public_key

    @property
    def secret_bytes(self) -> bytes:
        """
        Returns the secret bytes of the instance's secret key.
        """
        return self._secret_key.private_bytes_raw()

    @property
    def public_bytes(self) -> bytes:
        """
        Returns the public bytes of the instance's public key.
        """
        return self._public_key.public_bytes_raw()

    def has_secret_key(self) -> bool:
        """
        Returns a boolean of whether the instance contains a secret key.
        """
        return self._secret_key is not None

    def has_public_key(self) -> bool:
        """
        Returns a boolean of whether the instance contains a public key.
        """
        return self._public_key is not None


module_api = dict(
    Base25519=t.add_type(Base25519),
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

