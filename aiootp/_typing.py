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


__all__ = ["Typing"]


__doc__ = "A type-hinting utility for the package."


import types
import typing
import pathlib
from typing import NewType


try:
    import typing_extensions
except ModuleNotFoundError:  # pragma: no cover
    typing_extensions = typing  # pragma: no cover


try:
    Protocol = typing.Protocol
except AttributeError:  # pragma: no cover
    Protocol = typing_extensions.Protocol  # pragma: no cover


try:
    Self = typing.Self
except AttributeError:  # pragma: no cover
    Self = typing_extensions.Self  # pragma: no cover


Cls = NewType("Cls", Self)


Base64URLSafe = NewType("Base64URLSafe", typing.Union[str, bytes])


Path = pathlib.Path
PathStr = NewType("PathStr", typing.Union[Path, str])
OptionalPath = NewType("OptionalPath", typing.Optional[Path])
OptionalPathStr = NewType("OptionalPathStr", typing.Optional[PathStr])


Number = NewType("Number", typing.Union[int, float, complex])
OptionalNumber = NewType("OptionalNumber", typing.Optional[Number])
RealNumber = NewType("RealNumber", typing.Union[int, float])
PositiveRealNumber = NewType("PositiveRealNumber", typing.Union[int, float])
OptionalRealNumber = NewType("OptionalRealNumber", typing.Optional[RealNumber])


_JSONSerializableNonContainerTypes = NewType(
    "_JSONSerializableNonContainerTypes",
    typing.Union[str, float, int, bool, None],
)
_JSONSerializableBaseTypes = NewType(
    "_JSONSerializableBaseTypes",
    typing.Union[dict, list, _JSONSerializableNonContainerTypes],
)
JSONArray = NewType("JSONArray", typing.List[_JSONSerializableBaseTypes])
JSONObject = NewType(
    "JSONObject", typing.Dict[str, _JSONSerializableBaseTypes]
)
JSONSerializable = NewType(
    "JSONSerializable",
    typing.Union[JSONObject, JSONArray, _JSONSerializableNonContainerTypes],
)
JSONDeserializable = NewType(
    "JSONDeserializable", typing.Union[str, bytes, bytearray]
)


Keystream = NewType(
    "Keystream", typing.Generator[bytes, typing.Optional[bytes], None]
)
AsyncKeystream = NewType(
    "AsyncKeystream", typing.AsyncGenerator[bytes, typing.Optional[bytes]]
)
AsyncOrSyncKeystream = NewType(
    "AsyncOrSyncKeystream", typing.Union[AsyncKeystream, Keystream]
)


Datastream = NewType("Datastream", typing.Iterable[bytes])
AsyncDatastream = NewType("AsyncDatastream", typing.AsyncIterable[bytes])
AsyncOrSyncDatastream = NewType(
    "AsyncOrSyncDatastream", typing.Union[AsyncDatastream, Datastream]
)


class _AsyncOrSyncIterableMeta(type):
    """
    Allows bracketed choices of types to be given to the `Iterable` &
    `AsyncIterable` type hinters for the `AsyncOrSyncIterable` subclass.
    """

    def __getitem__(cls, obj: typing.Any):
        return typing.Union[typing.Iterable[obj], typing.AsyncIterable[obj]]


class AsyncOrSyncIterable(metaclass=_AsyncOrSyncIterableMeta):
    """
    Allows bracketed choices of types to be given to the `Iterable` &
    `AsyncIterable` type hinters.
    """


@typing.runtime_checkable
class SupportsPopleft(Protocol):

    def popleft(self) -> typing.Any:
        pass  # pragma: no cover


@typing.runtime_checkable
class IgnoreType(Protocol):

    @property
    def ignored_exceptions(self) -> typing.Tuple[Exception]:
        pass  # pragma: no cover

    @property
    def except_code(self) -> typing.Callable[..., bool]:
        pass  # pragma: no cover

    @property
    def else_code(self) -> typing.Callable[..., typing.Any]:
        pass  # pragma: no cover

    @property
    def finally_code(self) -> typing.Callable[..., typing.Any]:
        pass  # pragma: no cover

    @property
    def bus(self) -> typing.Mapping[typing.Hashable, typing.Any]:
        pass  # pragma: no cover

    @property
    def error(self) -> typing.Optional[Exception]:
        pass  # pragma: no cover

    @property
    def traceback(self) -> typing.Optional[types.TracebackType]:
        pass  # pragma: no cover

    async def __aenter__(self) -> Self:
        pass  # pragma: no cover

    def __enter__(self) -> Self:
        pass  # pragma: no cover

    async def __aexit__(
        self,
        exc_type: typing.Optional[type] = None,
        exc_value: typing.Optional[Exception] = None,
        traceback: typing.Optional[types.TracebackType] = None,
    ) -> bool:
        pass  # pragma: no cover

    def __exit__(
        self,
        exc_type: typing.Optional[type] = None,
        exc_value: typing.Optional[Exception] = None,
        traceback: typing.Optional[types.TracebackType] = None,
    ) -> bool:
        pass  # pragma: no cover


@typing.runtime_checkable
class PoolExecutorType(Protocol):

    def map(
        self,
        fn: typing.Callable[..., typing.Any],
        *iterables: typing.Any,
        timeout: typing.Optional[PositiveRealNumber],
        chunksize: int,
    ) -> typing.Iterator[typing.Any]:
        pass  # pragma: no cover

    def shutdown(self, wait: bool) -> None:
        pass  # pragma: no cover

    def submit(
        self,
        fn: typing.Callable[..., typing.Any],
        /,
        *args: typing.Any,
        **kwargs: typing.Any,
    ) -> typing.Any:
        pass  # pragma: no cover


@typing.runtime_checkable
class ConfigType(Protocol):

    @property
    def config_id(self) -> typing.Hashable:
        pass  # pragma: no cover

    @property
    def slots_types(self) -> typing.Mapping[str, type]:
        pass  # pragma: no cover

    def set_config_id(self, config_id: typing.Hashable) -> None:
        pass  # pragma: no cover

    def keys(self) -> typing.Generator[None, typing.Any, None]:
        pass  # pragma: no cover

    def values(self) -> typing.Generator[None, typing.Any, None]:
        pass  # pragma: no cover

    def items(
        self
    ) -> typing.Generator[None, typing.Tuple[typing.Any, typing.Any], None]:
        pass  # pragma: no cover


@typing.runtime_checkable
class HasherType(Protocol):

    @property
    def name(self) -> str:
        pass  # pragma: no cover

    @property
    def block_size(self) -> int:
        pass  # pragma: no cover

    @property
    def digest_size(self) -> int:
        pass  # pragma: no cover

    def copy(self, /) -> "HasherType":
        pass  # pragma: no cover

    def update(self, data: bytes, /) -> None:
        pass  # pragma: no cover

    def digest(self, /) -> bytes:
        pass  # pragma: no cover

    def hexdigest(self, /) -> str:
        pass  # pragma: no cover


@typing.runtime_checkable
class XOFType(Protocol):

    @property
    def name(self) -> str:
        pass  # pragma: no cover

    @property
    def block_size(self) -> int:
        pass  # pragma: no cover

    @property
    def digest_size(self) -> int:
        return 0  # pragma: no cover

    def copy(self, /) -> "XOFType":
        pass  # pragma: no cover

    def update(self, data: bytes, /) -> None:
        pass  # pragma: no cover

    def digest(self, size: int, /) -> bytes:
        pass  # pragma: no cover

    def hexdigest(self, size: int, /) -> str:
        pass  # pragma: no cover


class EntropyHashingType(XOFType):

    async def ahash(self, *data: bytes, size: int) -> bytes:
        pass  # pragma: no cover

    def hash(self, *data: bytes, size: int) -> bytes:
        pass  # pragma: no cover


@typing.runtime_checkable
class DomainKDFType(Protocol):

    def copy(self) -> Cls:
        pass  # pragma: no cover

    async def aupdate(self, *data: bytes) -> Self:
        pass  # pragma: no cover

    def update(self, *data: bytes) -> Self:
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


@typing.runtime_checkable
class ClockType(Protocol):

    async def atime(self) -> int:
        pass  # pragma: no cover

    def time(self) -> int:
        pass  # pragma: no cover

    async def amake_timestamp(self, *, size: int, byte_order: str) -> bytes:
        pass  # pragma: no cover

    def make_timestamp(self, *, size: int, byte_order: str) -> bytes:
        pass  # pragma: no cover

    async def atest_timestamp(
        self, timestamp: bytes, ttl: int, *, byte_order: str
    ) -> None:
        pass  # pragma: no cover

    def test_timestamp(
        self, timestamp: bytes, ttl: int, *, byte_order: str
    ) -> None:
        pass  # pragma: no cover


@typing.runtime_checkable
class PaddingType(Protocol):

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


@typing.runtime_checkable
class PermutationType(Protocol):

    @classmethod
    def key_size(cls, config_id: typing.Hashable) -> int:
        pass  # pragma: no cover

    def permute(self, value: int) -> int:
        pass  # pragma: no cover

    def invert(self, value: int) -> int:
        pass  # pragma: no cover


@typing.runtime_checkable
class StreamHMACType(Protocol):

    @property
    def config(self) -> ConfigType:
        pass  # pragma: no cover

    @property
    def mode(self) -> str:
        pass  # pragma: no cover

    async def anext_block_id(
        self, next_block: bytes, *, size: typing.Optional[int], aad: bytes
    ) -> bytes:
        pass  # pragma: no cover

    def next_block_id(
        self, next_block: bytes, *, size: typing.Optional[int], aad: bytes
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


@typing.runtime_checkable
class SyntheticIVType(Protocol):

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


@typing.runtime_checkable
class AsyncCipherStreamingType(Protocol):

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
    ) -> typing.AsyncGenerator[None, typing.Tuple[bytes, bytes]]:
        pass  # pragma: no cover

    async def abuffer(self, data: bytes) -> Self:
        pass  # pragma: no cover

    async def afinalize(self) -> Self:
        pass  # pragma: no cover


@typing.runtime_checkable
class CipherStreamingType(Protocol):

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
    ) -> typing.Generator[None, typing.Tuple[bytes, bytes], None]:
        pass  # pragma: no cover

    def buffer(self, data: bytes) -> Self:
        pass  # pragma: no cover

    def finalize(self) -> Self:
        pass  # pragma: no cover


@typing.runtime_checkable
class CipherInterfaceType(Protocol):

    async def abytes_encrypt(
        self,
        data: bytes,
        *,
        salt: typing.Optional[bytes],
        aad: bytes,
    ) -> bytes:
        pass  # pragma: no cover

    def bytes_encrypt(
        self,
        data: bytes,
        *,
        salt: typing.Optional[bytes],
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
        data: JSONSerializable,
        *,
        salt: typing.Optional[bytes],
        aad: bytes,
    ) -> bytes:
        pass  # pragma: no cover

    def json_encrypt(
        self,
        data: JSONSerializable,
        *,
        salt: typing.Optional[bytes],
        aad: bytes,
    ) -> bytes:
        pass  # pragma: no cover

    async def ajson_decrypt(
        self, data: bytes, *, aad: bytes, ttl: int
    ) -> JSONSerializable:
        pass  # pragma: no cover

    def json_decrypt(
        self, data: bytes, *, aad: bytes, ttl: int
    ) -> JSONSerializable:
        pass  # pragma: no cover

    async def amake_token(self, data: bytes, *, aad: bytes) -> bytes:
        pass  # pragma: no cover

    def make_token(self, data: bytes, *, aad: bytes) -> bytes:
        pass  # pragma: no cover

    async def aread_token(
        self, token: Base64URLSafe, *, aad: bytes, ttl: int
    ) -> bytes:
        pass  # pragma: no cover

    def read_token(
        self, token: Base64URLSafe, *, aad: bytes, ttl: int
    ) -> bytes:
        pass  # pragma: no cover

    async def astream_encrypt(
        self, *, salt: typing.Optional[bytes], aad: bytes
    ):
        pass  # pragma: no cover

    def stream_encrypt(
        self, *, salt: typing.Optional[bytes], aad: bytes
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


@typing.runtime_checkable
class PublicSignerType(Protocol):

    def public_bytes(self, encoding, format) -> bytes:
        pass  # pragma: no cover

    def public_bytes_raw(self) -> bytes:
        pass  # pragma: no cover

    def verify(self, signature: bytes, data: bytes) -> None:
        pass  # pragma: no cover


@typing.runtime_checkable
class SecretSignerType(Protocol):

    def public_key(self) -> PublicSignerType:
        pass  # pragma: no cover

    def private_bytes(self, encoding, format) -> bytes:
        pass  # pragma: no cover

    def private_bytes_raw(self) -> bytes:
        pass  # pragma: no cover

    def sign(self, data: bytes) -> bytes:
        pass  # pragma: no cover


@typing.runtime_checkable
class AsymmetricKeyType(Protocol):

    async def aimport_public_key(
        self,
        public_key: typing.Union[bytes, PublicSignerType, SecretSignerType],
    ) -> Self:
        pass  # pragma: no cover

    def import_public_key(
        self,
        public_key: typing.Union[bytes, PublicSignerType, SecretSignerType],
    ) -> Self:
        pass  # pragma: no cover

    async def aimport_secret_key(
        self,
        secret_key: typing.Union[bytes, SecretSignerType],
    ) -> Self:
        pass  # pragma: no cover

    def import_secret_key(
        self,
        secret_key: typing.Union[bytes, SecretSignerType],
    ) -> Self:
        pass  # pragma: no cover

    @property
    def secret_key(self) -> typing.Union[SecretSignerType]:
        pass  # pragma: no cover

    @property
    def public_key(self) -> typing.Union[PublicSignerType]:
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

    async def agenerate(self) -> Self:
        pass  # pragma: no cover

    def generate(self) -> Self:
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
        public_key: typing.Union[None, bytes, PublicSignerType],
    ) -> None:
        pass  # pragma: no cover

    def verify(
        self,
        signature: bytes,
        data: bytes,
        *,
        public_key: typing.Union[None, bytes, PublicSignerType],
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


@typing.runtime_checkable
class AsyncDatabaseType(Protocol):

    async def aload_tags(self, *, silent: bool) -> Self:
        pass  # pragma: no cover

    async def aload_metatags(
        self, *, preload: bool, silent: bool
    ) -> Self:
        pass  # pragma: no cover

    async def aload_database(
        self,
        *,
        manifest: bool,
        silent: bool,
        preload: bool,
    ) -> Self:
        pass  # pragma: no cover

    async def afilename(self, tag: str) -> str:
        pass  # pragma: no cover

    async def aset_tag(
        self, tag: str, data: JSONSerializable, *, cache: bool
    ) -> Self:
        pass  # pragma: no cover

    async def aquery_tag(
        self, tag: str, *, silent: bool, cache: bool
    ) -> typing.Union[bytes, JSONSerializable]:
        pass  # pragma: no cover

    async def apop_tag(
        self, tag: str, *, silent: bool
    ) -> typing.Union[bytes, JSONSerializable]:
        pass  # pragma: no cover

    async def arollback_tag(
        self, tag: str, *, cache: bool
    ) -> Self:
        pass  # pragma: no cover

    async def aclear_cache(self, *, metatags: bool) -> Self:
        pass  # pragma: no cover

    async def ametatag(
        self, tag: str, *, preload: bool, silent: bool
    ) -> Cls:
        pass  # pragma: no cover

    async def adelete_metatag(self, tag: str) -> Self:
        pass # pragma: no cover

    async def adelete_database(self) -> None:
        pass  # pragma: no cover

    async def asave_tag(
        self, tag: str, *, admin: bool, drop_cache: bool
    ) -> Self:
        pass  # pragma: no cover


@typing.runtime_checkable
class DatabaseType(Protocol):

    def load_tags(self, *, silent: bool) -> Self:
        pass  # pragma: no cover

    def load_metatags(
        self, *, preload: bool, silent: bool
    ) -> Self:
        pass  # pragma: no cover

    def load_database(
        self,
        *,
        manifest: bool,
        silent: bool,
        preload: bool,
    ) -> Self:
        pass  # pragma: no cover

    def filename(self, tag: str) -> str:
        pass  # pragma: no cover

    def set_tag(
        self, tag: str, data: JSONSerializable, *, cache: bool
    ) -> Self:
        pass  # pragma: no cover

    def query_tag(
        self, tag: str, *, silent: bool, cache: bool
    ) -> typing.Union[bytes, JSONSerializable]:
        pass  # pragma: no cover

    def pop_tag(
        self, tag: str, *, silent: bool
    ) -> typing.Union[bytes, JSONSerializable]:
        pass  # pragma: no cover

    def rollback_tag(
        self, tag: str, *, cache: bool
    ) -> Self:
        pass  # pragma: no cover

    def clear_cache(self, *, metatags: bool) -> Self:
        pass  # pragma: no cover

    def metatag(
        self, tag: str, *, preload: bool, silent: bool
    ) -> Cls:
        pass  # pragma: no cover

    def delete_metatag(self, tag: str) -> Self:
        pass # pragma: no cover

    def delete_database(self) -> None:
        pass  # pragma: no cover

    def save_tag(
        self, tag: str, *, admin: bool, drop_cache: bool
    ) -> Self:
        pass  # pragma: no cover


def _transpose_this_modules_types(
    class_dict: typing.Dict[str, typing.Any]
):
    """
    Inserts the types from this module's global namespace.
    """
    this_modules_types = {
        name: value for name, value in globals().items()
        if name[0].isupper()
    }
    class_dict.update(this_modules_types)


def _transpose_types_modules_types(
    class_dict: typing.Dict[str, typing.Any]
) -> None:
    """
    Inserts the types from the standard library's `types` module.
    """
    for name in types.__all__:
        if name[0].isupper():
            class_dict[name] = getattr(types, name)


def _transpose_typing_modules_types(
    class_dict: typing.Dict[str, typing.Any]
) -> None:
    """
    Inserts the types from the standard library's `typing` module.
    """
    for name in typing.__all__:
        if name[0].isupper():
            class_dict[name] = getattr(typing, name)
    if typing is not typing_extensions:
        for name in typing_extensions.__all__:
            if name[0].isupper():
                class_dict[name] = getattr(typing_extensions, name)


class Typing:
    """
    A container for type-hinting variables.
    """

    __slots__ = ()

    _transpose_this_modules_types(class_dict=vars())
    _transpose_types_modules_types(class_dict=vars())
    _transpose_typing_modules_types(class_dict=vars())

    AnyStr = typing.AnyStr
    OptionalAnyStr = typing.Optional[AnyStr]

    overload = typing.overload
    if hasattr(typing, "TypedDict"):
        extensions = typing
    else:
        extensions = typing_extensions  # pragma: no cover
    runtime_checkable = typing.runtime_checkable

    @classmethod
    def _test_type_name(cls, name: str) -> None:
        """
        Assures new type additions to the class are unique & title or
        capital-cased identifiers.
        """
        attribute_already_defined = name in cls.__dict__
        is_mixed_case = "_" in name
        is_capitalized = name[0].isupper()

        if not name.isidentifier():
            raise ValueError(f"Invalid type name {repr(name)}.")
        elif attribute_already_defined:
            raise AttributeError(f"{repr(name)} is already defined.")
        elif is_mixed_case or not is_capitalized:
            raise ValueError(f"{repr(name)} must be title or capital-cased")

    @classmethod
    def _test_type(cls, new_type: type) -> None:
        """
        Throws `TypeError` if `new_type` doesn't have class-type
        attributes.
        """
        has_type_attributes = (
            hasattr(new_type, "mro")
            and hasattr(new_type, "__mro__")
            and hasattr(new_type, "__bases__")
            and hasattr(new_type, "__prepare__")
        )
        if not has_type_attributes:
            raise TypeError(f"{repr(new_type)} is not a type.")  # pragma: no cover

    @classmethod
    def add_type(cls, new_type: type) -> type:
        """
        Adds a new typing type to the class dictionary.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        class MessageType(bytes):
            pass

        Typing.add_type(MessageType)
        message: Typing.MessageType = b"Hello, World!"
        """
        name = new_type.__qualname__
        cls._test_type_name(name)
        cls._test_type(new_type)
        setattr(cls, name, new_type)
        return new_type


module_api = dict(
    Typing=Typing,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

