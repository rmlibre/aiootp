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


from aiootp._typing import Typing as t
from aiootp._exceptions import Issue
from aiootp.asynchs import asleep
from aiootp.commons import FrozenInstance

from .adapter import Curve25519


class Base25519(FrozenInstance):
    """
    Collects the shared functionality between the `X25519` & `Ed25519`
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
            bytes,
            t.X25519PrivateKey,
            t.Ed25519PrivateKey,
            t.X25519PublicKey,
            t.Ed25519PublicKey,
        ],
    ) -> t.Union[t.X25519PublicKey, t.Ed25519PublicKey]:
        """
        Accepts a `public_key` in either bytes, `X25519PublicKey`,
        `X25519PrivateKey`, `Ed25519PublicKey` or `Ed25519PrivateKey`
        format. Returns an instantiaed public key associated with the
        subclass inheriting this method.
        """
        if issubclass(
            public_key.__class__,
            (self.PublicKey, self.SecretKey, self.__class__)
        ):
            public_key = self._Curve25519.public_bytes(public_key)
            return self.PublicKey.from_public_bytes(public_key)
        elif public_key.__class__ is bytes:
            return self.PublicKey.from_public_bytes(public_key)
        else:
            raise Issue.value_must_be_type("public_key", "valid key type")

    def _process_secret_key(
        self,
        secret_key: t.Union[bytes, t.X25519PrivateKey, t.Ed25519PrivateKey],
    ) -> t.Union[t.Ed25519PrivateKey, t.X25519PrivateKey]:
        """
        Accepts a `secret_key` in either bytes, `X25519PrivateKey`
        or `Ed25519PrivateKey` format. Returns an instantiaed secret
        key associated with the subclass inheriting this method.
        """
        if issubclass(
            secret_key.__class__, (self.SecretKey, self.__class__)
        ):
            secret_key = self._Curve25519.secret_bytes(secret_key)
            return self.SecretKey.from_private_bytes(secret_key)
        elif secret_key.__class__ is bytes:
            return self.SecretKey.from_private_bytes(secret_key)
        else:
            raise Issue.value_must_be_type("secret_key", "valid key type")

    async def aimport_public_key(
        self,
        public_key: t.Union[
            bytes,
            t.X25519PrivateKey,
            t.Ed25519PrivateKey,
            t.X25519PublicKey,
            t.Ed25519PublicKey,
        ],
    ) -> t.Self:
        """
        Populates an instance from the received `public_key` that is
        of either bytes, `X25519PublicKey`, `X25519PrivateKey`,
        `Ed25519PublicKey` or `Ed25519PrivateKey` type.
        """
        await asleep()
        return self.import_public_key(public_key)

    def import_public_key(
        self,
        public_key: t.Union[
            bytes,
            t.X25519PrivateKey,
            t.Ed25519PrivateKey,
            t.X25519PublicKey,
            t.Ed25519PublicKey,
        ],
    ) -> t.Self:
        """
        Populates an instance from the received `public_key` that is
        of either bytes, `X25519PublicKey`, `X25519PrivateKey`,
        `Ed25519PublicKey` or `Ed25519PrivateKey` type.
        """
        if hasattr(self, "_public_key"):
            raise Issue.value_already_set("public key", "the instance")
        self._secret_key = None
        self._public_key = self._process_public_key(public_key)
        return self

    async def aimport_secret_key(
        self,
        secret_key: t.Union[bytes, t.X25519PrivateKey, t.Ed25519PrivateKey],
    ) -> t.Self:
        """
        Populates an instance from the received `secret_key` that is
        of either bytes, `X25519PrivateKey` or `Ed25519PrivateKey`
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
        secret_key: t.Union[bytes, t.X25519PrivateKey, t.Ed25519PrivateKey],
    ) -> t.Self:
        """
        Populates an instance from the received `secret_key` that is
        of either bytes, `X25519PrivateKey` or `Ed25519PrivateKey`
        type.
        """
        if hasattr(self, "_public_key") or hasattr(self, "_secret_key"):
            raise Issue.value_already_set(f"key", "the instance")
        self._secret_key = self._process_secret_key(secret_key)
        self._public_key = self.PublicKey.from_public_bytes(
            self._Curve25519.public_bytes(self._secret_key)
        )
        return self

    async def agenerate(self) -> t.Self:
        """
        Populates the instance with a newly generated private key.
        """
        await self.aimport_secret_key(self.SecretKey.generate())
        return self

    def generate(self) -> t.Self:
        """
        Populates the instance with a newly generated private key.
        """
        self.import_secret_key(self.SecretKey.generate())
        return self

    @property
    def secret_key(self) -> t.Union[t.X25519PrivateKey, t.Ed25519PrivateKey]:
        """
        Returns the instantiated & populated SecretKey of the associated
        subclass inheriting this method.
        """
        return self._secret_key

    @property
    def public_key(self) -> t.Union[t.X25519PublicKey, t.Ed25519PublicKey]:
        """
        Returns the instantiated & populated PublicKey of the associated
        subclass inheriting this method.
        """
        return self._public_key

    @property
    def secret_bytes(self) -> bytes:
        """
        Returns the secret bytes of the instance's instantiated &
        populated SecretKey of the associated subclass inheriting this
        method.
        """
        return self._Curve25519.secret_bytes(self._secret_key)

    @property
    def public_bytes(self) -> bytes:
        """
        Returns the public bytes of the instance's instantiated &
        populated PublicKey of the associated subclass inheriting this
        method.
        """
        return self._Curve25519.public_bytes(self._public_key)

    def has_secret_key(self) -> bool:
        """
        Returns a boolean of whether the instance contains a secret key.
        """
        return getattr(self, "_secret_key", None) is not None

    def has_public_key(self) -> bool:
        """
        Returns a boolean of whether the instance contains a public key.
        """
        return hasattr(self, "_public_key")


module_api = dict(
    Base25519=t.add_type(Base25519),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

