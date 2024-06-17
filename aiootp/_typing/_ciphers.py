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
    "AsyncCipherStreamingType",
    "AsyncDatastream",
    "AsyncKeystream",
    "AsyncOrSyncDatastream",
    "AsyncOrSyncKeystream",
    "CipherInterfaceType",
    "CipherStreamingType",
    "Datastream",
    "Keystream",
    "PaddingType",
    "StreamHMACType",
    "SyntheticIVType",
]


__doc__ = (
    "Dependency inversion & documentation support for types relevant to "
    "the `ciphers` subpackage."
)


from .interface import Typing as t


Keystream = t.Keystream = t.NewType(
    "Keystream", t.Generator[bytes, bytes, None]
)
AsyncKeystream = t.AsyncKeystream = t.NewType(
    "AsyncKeystream", t.AsyncGenerator[bytes, bytes]
)
AsyncOrSyncKeystream = t.AsyncOrSyncKeystream = t.NewType(
    "AsyncOrSyncKeystream", t.Union[AsyncKeystream, Keystream]
)


Datastream = t.Datastream = t.NewType("Datastream", t.Iterable[bytes])
AsyncDatastream = t.AsyncDatastream = t.NewType(
    "AsyncDatastream", t.AsyncIterable[bytes]
)
AsyncOrSyncDatastream = t.AsyncOrSyncDatastream = t.NewType(
    "AsyncOrSyncDatastream", t.Union[AsyncDatastream, Datastream]
)


@t.runtime_checkable
class PaddingType(t.Protocol):

    async def astart_padding(self) -> bytes:
        pass  # pragma: no cover

    def start_padding(self) -> bytes:
        pass  # pragma: no cover

    async def aend_padding(self, size: int) -> bytes:
        pass  # pragma: no cover

    def end_padding(self, size: int) -> bytes:
        pass  # pragma: no cover

    async def apad_plaintext(self, data: bytes) -> bytes:
        pass  # pragma: no cover

    def pad_plaintext(self, data: bytes) -> bytes:
        pass  # pragma: no cover

    async def adepadding_start_index(self) -> int:
        pass  # pragma: no cover

    def depadding_start_index(self) -> int:
        pass  # pragma: no cover

    async def adepadding_end_index(self, data: bytes) -> int:
        pass  # pragma: no cover

    def depadding_end_index(self, data: bytes) -> int:
        pass  # pragma: no cover

    async def adepad_plaintext(self, data: bytes, *, ttl: int) -> bytes:
        pass  # pragma: no cover

    def depad_plaintext(self, data: bytes, *, ttl: int) -> bytes:
        pass  # pragma: no cover


@t.runtime_checkable
class StreamHMACType(t.Protocol):

    @property
    def config(self) -> t.ConfigType:
        pass  # pragma: no cover

    @property
    def mode(self) -> str:
        pass  # pragma: no cover

    async def anext_block_id(
        self, next_block: bytes, *, size: t.Optional[int], aad: bytes
    ) -> bytes:
        pass  # pragma: no cover

    def next_block_id(
        self, next_block: bytes, *, size: t.Optional[int], aad: bytes
    ) -> bytes:
        pass  # pragma: no cover

    async def afinalize(self) -> bytes:
        pass  # pragma: no cover

    def finalize(self) -> bytes:
        pass  # pragma: no cover

    async def aresult(self) -> bytes:
        pass  # pragma: no cover

    def result(self) -> bytes:
        pass  # pragma: no cover

    async def atest_next_block_id(
        self, untrusted_block_id: bytes, next_block: bytes, aad: bytes
    ) -> None:
        pass  # pragma: no cover

    def test_next_block_id(
        self, untrusted_block_id: bytes, next_block: bytes, aad: bytes
    ) -> None:
        pass  # pragma: no cover

    async def atest_shmac(self, untrusted_shmac: bytes) -> None:
        pass  # pragma: no cover

    def test_shmac(self, untrusted_shmac: bytes) -> None:
        pass  # pragma: no cover


@t.runtime_checkable
class SyntheticIVType(t.Protocol):

    @classmethod
    async def avalidated_transform(
        cls, datastream: AsyncDatastream, shmac: StreamHMACType, **kw
    ) -> bytes:
        pass  # pragma: no cover

    @classmethod
    def validated_transform(
        cls, datastream: Datastream, shmac: StreamHMACType, **kw
    ) -> bytes:
        pass  # pragma: no cover


@t.runtime_checkable
class AsyncCipherStreamingType(t.Protocol):

    @property
    def salt(self) -> bytes:
        pass  # pragma: no cover

    @property
    def aad(self) -> bytes:
        pass  # pragma: no cover

    @property
    def iv(self) -> bytes:
        pass  # pragma: no cover

    @property
    def shmac(self) -> StreamHMACType:
        pass  # pragma: no cover

    async def __aiter__(
        self
    ) -> t.AsyncGenerator[t.Tuple[bytes, bytes], None]:
        pass  # pragma: no cover

    async def abuffer(self, data: bytes) -> t.Self:
        pass  # pragma: no cover

    async def afinalize(self) -> t.Self:
        pass  # pragma: no cover


@t.runtime_checkable
class CipherStreamingType(t.Protocol):

    @property
    def salt(self) -> bytes:
        pass  # pragma: no cover

    @property
    def aad(self) -> bytes:
        pass  # pragma: no cover

    @property
    def iv(self) -> bytes:
        pass  # pragma: no cover

    @property
    def shmac(self) -> StreamHMACType:
        pass  # pragma: no cover

    def __iter__(
        self
    ) -> t.Generator[t.Tuple[bytes, bytes], None, None]:
        pass  # pragma: no cover

    def buffer(self, data: bytes) -> t.Self:
        pass  # pragma: no cover

    def finalize(self) -> t.Self:
        pass  # pragma: no cover


@t.runtime_checkable
class CipherInterfaceType(t.Protocol):

    async def abytes_encrypt(
        self,
        data: bytes,
        *,
        salt: t.Optional[bytes],
        aad: bytes,
    ) -> bytes:
        pass  # pragma: no cover

    def bytes_encrypt(
        self,
        data: bytes,
        *,
        salt: t.Optional[bytes],
        aad: bytes,
    ) -> bytes:
        pass  # pragma: no cover

    async def abytes_decrypt(
        self, data: bytes, *, aad: bytes, ttl: int
    ) -> bytes:
        pass  # pragma: no cover

    def bytes_decrypt(self, data: bytes, *, aad: bytes, ttl: int) -> bytes:
        pass  # pragma: no cover

    async def ajson_encrypt(
        self,
        data: t.JSONSerializable,
        *,
        salt: t.Optional[bytes],
        aad: bytes,
    ) -> bytes:
        pass  # pragma: no cover

    def json_encrypt(
        self,
        data: t.JSONSerializable,
        *,
        salt: t.Optional[bytes],
        aad: bytes,
    ) -> bytes:
        pass  # pragma: no cover

    async def ajson_decrypt(
        self, data: bytes, *, aad: bytes, ttl: int
    ) -> t.JSONSerializable:
        pass  # pragma: no cover

    def json_decrypt(
        self, data: bytes, *, aad: bytes, ttl: int
    ) -> t.JSONSerializable:
        pass  # pragma: no cover

    async def amake_token(self, data: bytes, *, aad: bytes) -> bytes:
        pass  # pragma: no cover

    def make_token(self, data: bytes, *, aad: bytes) -> bytes:
        pass  # pragma: no cover

    async def aread_token(
        self, token: t.Base64URLSafe, *, aad: bytes, ttl: int
    ) -> bytes:
        pass  # pragma: no cover

    def read_token(
        self, token: t.Base64URLSafe, *, aad: bytes, ttl: int
    ) -> bytes:
        pass  # pragma: no cover

    async def astream_encrypt(
        self, *, salt: t.Optional[bytes], aad: bytes
    ):
        pass  # pragma: no cover

    def stream_encrypt(
        self, *, salt: t.Optional[bytes], aad: bytes
    ):
        pass  # pragma: no cover

    async def astream_decrypt(
        self, *, salt: bytes, aad: bytes, iv: bytes, ttl: int
    ):
        pass  # pragma: no cover

    def stream_decrypt(
        self, *, salt: bytes, aad: bytes, iv: bytes, ttl: int
    ):
        pass  # pragma: no cover


module_api = dict(
    AsyncCipherStreamingType=t.add_type(AsyncCipherStreamingType),
    AsyncDatastream=AsyncDatastream,
    AsyncKeystream=AsyncKeystream,
    AsyncOrSyncDatastream=AsyncOrSyncDatastream,
    AsyncOrSyncKeystream=AsyncOrSyncKeystream,
    CipherInterfaceType=t.add_type(CipherInterfaceType),
    CipherStreamingType=t.add_type(CipherStreamingType),
    Datastream=Datastream,
    Keystream=Keystream,
    PaddingType=t.add_type(PaddingType),
    StreamHMACType=t.add_type(StreamHMACType),
    SyntheticIVType=t.add_type(SyntheticIVType),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

