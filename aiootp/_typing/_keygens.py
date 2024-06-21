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
    "KeyExchangeProtocolType",
    "KeyExchangeType",
    "PublicKeyType",
    "SecretKeyType",
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
class PublicKeyType(t.Protocol):

    def public_bytes(self, encoding, format) -> bytes:
        pass  # pragma: no cover

    def public_bytes_raw(self) -> bytes:
        pass  # pragma: no cover


@t.runtime_checkable
class SecretKeyType(t.Protocol):

    def private_bytes(self, encoding, format) -> bytes:
        pass  # pragma: no cover

    def private_bytes_raw(self) -> bytes:
        pass  # pragma: no cover

    def public_key(self) -> PublicKeyType:
        pass  # pragma: no cover


@t.runtime_checkable
class AsymmetricKeyType(t.Protocol):

    async def aimport_secret_key(
        self, secret_key: t.Union[bytes, SecretKeyType]
    ) -> t.Self:
        pass  # pragma: no cover

    def import_secret_key(
        self, secret_key: t.Union[bytes, SecretKeyType]
    ) -> t.Self:
        pass  # pragma: no cover

    async def aimport_public_key(
        self, public_key: t.Union[bytes, PublicKeyType]
    ) -> t.Self:
        pass  # pragma: no cover

    def import_public_key(
        self, public_key: t.Union[bytes, PublicKeyType]
    ) -> t.Self:
        pass  # pragma: no cover

    async def agenerate(self) -> t.Self:
        pass  # pragma: no cover

    def generate(self) -> t.Self:
        pass  # pragma: no cover

    def has_secret_key(self) -> bool:
        pass  # pragma: no cover

    def has_public_key(self) -> bool:
        pass  # pragma: no cover


@t.runtime_checkable
class SignerType(AsymmetricKeyType, t.Protocol):

    async def asign(self, data: bytes) -> bytes:
        pass  # pragma: no cover

    def sign(self, data: bytes) -> bytes:
        pass  # pragma: no cover

    async def averify(
        self,
        signature: bytes,
        data: bytes,
        *,
        public_key: t.Union[None, bytes, PublicKeyType],
    ) -> None:
        pass  # pragma: no cover

    def verify(
        self,
        signature: bytes,
        data: bytes,
        *,
        public_key: t.Union[None, bytes, PublicKeyType],
    ) -> None:
        pass  # pragma: no cover


@t.runtime_checkable
class KeyExchangeProtocolType(t.Protocol):

    async def asend(self, *keys: bytes) -> t.Union[t.Tuple[bytes], bytes]:
        pass  # pragma: no cover

    def send(self, *keys: bytes) -> t.Union[t.Tuple[bytes], bytes]:
        pass  # pragma: no cover

    async def areceive(self, *keys: bytes) -> DomainKDFType:
        pass  # pragma: no cover

    def receive(self, *keys: bytes) -> DomainKDFType:
        pass  # pragma: no cover


@t.runtime_checkable
class KeyExchangeType(AsymmetricKeyType, t.Protocol):

    async def aexchange(
        self, public_key: t.Union[PublicKeyType, bytes]
    ) -> bytes:
        pass  # pragma: no cover

    def exchange(
        self, public_key: t.Union[PublicKeyType, bytes]
    ) -> bytes:
        pass  # pragma: no cover

    @classmethod
    def dh2_client(cls) -> KeyExchangeProtocolType:
        pass  # pragma: no cover

    def dh2_server(self) -> KeyExchangeProtocolType:
        pass  # pragma: no cover

    def dh3_client(self) -> KeyExchangeProtocolType:
        pass  # pragma: no cover

    def dh3_server(self) -> KeyExchangeProtocolType:
        pass  # pragma: no cover


module_api = dict(
    AsymmetricKeyType=t.add_type(AsymmetricKeyType),
    DomainKDFType=t.add_type(DomainKDFType),
    KeyExchangeProtocolType=t.add_type(KeyExchangeProtocolType),
    KeyExchangeType=t.add_type(KeyExchangeType),
    PublicKeyType=t.add_type(PublicKeyType),
    SecretKeyType=t.add_type(SecretKeyType),
    SignerType=t.add_type(SignerType),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

