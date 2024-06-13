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


__all__ = [
    "AsymmetricKeyType",
    "DomainKDFType",
    "KeyExchangeType",
    "PublicSignerType",
    "SecretSignerType",
    "SignerType",
]


__doc__ = (
    "Dependency inversion & documentation support for types relevant to "
    "the `keygens` subpackage."
)


from .interface import Typing as t


@t.runtime_checkable
class DomainKDFType(t.Protocol):

    def copy(self) -> t.Cls:
        pass  # pragma: no cover

    async def aupdate(self, *data: bytes) -> t.Self:
        pass  # pragma: no cover

    def update(self, *data: bytes) -> t.Self:
        pass  # pragma: no cover

    async def asha3_256(self, *data: bytes, aad: bytes) -> bytes:
        pass  # pragma: no cover

    def sha3_256(self, *data: bytes, aad: bytes) -> bytes:
        pass  # pragma: no cover

    async def asha3_512(self, *data: bytes, aad: bytes) -> bytes:
        pass  # pragma: no cover

    def sha3_512(self, *data: bytes, aad: bytes) -> bytes:
        pass  # pragma: no cover

    async def ashake_128(
        self, *data: bytes, size: int, aad: bytes
    ) -> bytes:
        pass  # pragma: no cover

    def shake_128(self, *data: bytes, size: int, aad: bytes) -> bytes:
        pass  # pragma: no cover

    async def ashake_256(
        self, *data: bytes, size: int, aad: bytes
    ) -> bytes:
        pass  # pragma: no cover

    def shake_256(self, *data: bytes, size: int, aad: bytes) -> bytes:
        pass  # pragma: no cover


@t.runtime_checkable
class PublicSignerType(t.Protocol):

    def public_bytes(self, encoding, format) -> bytes:
        pass  # pragma: no cover

    def public_bytes_raw(self) -> bytes:
        pass  # pragma: no cover

    def verify(self, signature: bytes, data: bytes) -> None:
        pass  # pragma: no cover


@t.runtime_checkable
class SecretSignerType(t.Protocol):

    def public_key(self) -> PublicSignerType:
        pass  # pragma: no cover

    def private_bytes(self, encoding, format) -> bytes:
        pass  # pragma: no cover

    def private_bytes_raw(self) -> bytes:
        pass  # pragma: no cover

    def sign(self, data: bytes) -> bytes:
        pass  # pragma: no cover


@t.runtime_checkable
class AsymmetricKeyType(t.Protocol):

    async def aimport_public_key(
        self,
        public_key: t.Union[bytes, PublicSignerType, SecretSignerType],
    ) -> t.Self:
        pass  # pragma: no cover

    def import_public_key(
        self,
        public_key: t.Union[bytes, PublicSignerType, SecretSignerType],
    ) -> t.Self:
        pass  # pragma: no cover

    async def aimport_secret_key(
        self,
        secret_key: t.Union[bytes, SecretSignerType],
    ) -> t.Self:
        pass  # pragma: no cover

    def import_secret_key(
        self,
        secret_key: t.Union[bytes, SecretSignerType],
    ) -> t.Self:
        pass  # pragma: no cover

    @property
    def secret_key(self) -> t.Union[SecretSignerType]:
        pass  # pragma: no cover

    @property
    def public_key(self) -> t.Union[PublicSignerType]:
        pass  # pragma: no cover

    @property
    def secret_bytes(self) -> bytes:
        pass  # pragma: no cover

    @property
    def public_bytes(self) -> bytes:
        pass  # pragma: no cover

    def has_secret_key(self) -> bool:
        pass  # pragma: no cover

    def has_public_key(self) -> bool:
        pass  # pragma: no cover

    async def agenerate(self) -> t.Self:
        pass  # pragma: no cover

    def generate(self) -> t.Self:
        pass  # pragma: no cover


class SignerType(AsymmetricKeyType):

    async def asign(self, data: bytes) -> bytes:
        pass  # pragma: no cover

    def sign(self, data: bytes) -> bytes:
        pass  # pragma: no cover

    async def averify(
        self,
        signature: bytes,
        data: bytes,
        *,
        public_key: t.Union[None, bytes, PublicSignerType],
    ) -> None:
        pass  # pragma: no cover

    def verify(
        self,
        signature: bytes,
        data: bytes,
        *,
        public_key: t.Union[None, bytes, PublicSignerType],
    ) -> None:
        pass  # pragma: no cover


class KeyExchangeType(AsymmetricKeyType):

    @classmethod
    async def adh2_client(cls, peer_identity_key: bytes) -> None:  # TODO: return type & classes
        pass  # pragma: no cover

    @classmethod
    def dh2_client(cls, peer_identity_key: bytes) -> None:  # TODO: return type & classes
        pass  # pragma: no cover

    async def adh2_server(
        self, peer_identity_key: bytes, peer_ephemeral_key: bytes
    ) -> None:
        pass  # pragma: no cover

    def dh2_server(
        self, peer_identity_key: bytes, peer_ephemeral_key: bytes
    ) -> None:
        pass  # pragma: no cover

    async def adh3_client(self, peer_identity_key: bytes) -> None:  # TODO: return type & classes
        pass  # pragma: no cover

    def dh3_client(self, peer_identity_key: bytes) -> None:  # TODO: return type & classes
        pass  # pragma: no cover

    async def adh3_server(
        self, peer_identity_key: bytes, peer_ephemeral_key: bytes
    ) -> None:
        pass  # pragma: no cover

    def dh3_server(
        self, peer_identity_key: bytes, peer_ephemeral_key: bytes
    ) -> None:
        pass  # pragma: no cover


module_api = dict(
    AsymmetricKeyType=t.add_type(AsymmetricKeyType),
    DomainKDFType=t.add_type(DomainKDFType),
    KeyExchangeType=t.add_type(KeyExchangeType),
    PublicSignerType=t.add_type(PublicSignerType),
    SecretSignerType=t.add_type(SecretSignerType),
    SignerType=t.add_type(SignerType),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
