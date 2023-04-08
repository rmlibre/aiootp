# This file is part of aiootp, an asynchronous crypto and anonymity
# library. Home of the Chunky2048 psuedo one-time pad stream cipher.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["Typing"]


__doc__ = (
    "Describes the package's data structures & functionality by explici"
    "tly declaring their type-hinting types."
)


import types
import typing
import pathlib
from hashlib import sha3_256, sha3_512


try:
    import typing_extensions
except ModuleNotFoundError:
    typing_extensions = typing


try:
    Protocol = typing.Protocol
except AttributeError:
    Protocol = typing_extensions.Protocol  # type: ignore


class SupportsAppend(Protocol):
    def appendleft(self, value: typing.Any) -> None:
        ...


class SupportsAppendleft(Protocol):
    def appendleft(self, value: typing.Any) -> None:
        ...


class SupportsPop(Protocol):
    def pop(self) -> typing.Any:
        ...


class SupportsPopleft(Protocol):
    def popleft(self) -> typing.Any:
        ...


class SupportsContains(Protocol):
    def __contains__(self, value: typing.Any) -> bool:
        ...


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


Index = typing.Union[int, slice]
OptionalIndex = typing.Union[int, slice, None]


Base64URLSafe = typing.Union[str, bytes]


Path = pathlib.Path
PathStr = typing.Union[Path, str]
OptionalPath = typing.Optional[Path]
OptionalPathStr = typing.Optional[PathStr]


Number = typing.Union[int, float, complex]
OptionalNumber = typing.Optional[Number]
RealNumber = typing.Union[int, float]
PositiveRealNumber = typing.Union[int, float]
OptionalRealNumber = typing.Optional[RealNumber]


DeterministicRepr = typing.Union[
    str,
    bytes,
    bytearray,
    int,
    float,
    list,
    tuple,
    bool,
    None,
    typing.Any,
]


_JSONSerializableNonContainerTypes = typing.Union[
    str, float, int, bool, None
]
_JSONSerializableBaseTypes = typing.Union[
    dict, list, _JSONSerializableNonContainerTypes
]
JSONArray = typing.List[_JSONSerializableBaseTypes]
JSONObject = typing.Dict[str, _JSONSerializableBaseTypes]
JSONSerializable = typing.Union[
    JSONObject, JSONArray, _JSONSerializableNonContainerTypes
]
JSONDeserializable = typing.Union[str, bytes, bytearray]


class DictCiphertext(typing_extensions.TypedDict):
    shmac: str
    salt: str
    iv: str
    ciphertext: typing.List[str]


JSONCiphertext = typing.Union[DictCiphertext, JSONDeserializable]


Keystream = typing.Generator[bytes, typing.Optional[bytes], None]
AsyncKeystream = typing.AsyncGenerator[bytes, typing.Optional[bytes]]
AsyncOrSyncKeystream = typing.Union[AsyncKeystream, Keystream]


Datastream = typing.Iterable[bytes]
AsyncDatastream = typing.AsyncIterable[bytes]
AsyncOrSyncDatastream = typing.Union[AsyncDatastream, Datastream]


class PasscryptNewSettingsType(typing_extensions.TypedDict):
    mb: int
    cpu: int
    cores: int
    tag_size: int


class PasscryptKWsNew(typing_extensions.TypedDict):
    aad: bytes
    mb: int
    cpu: int
    cores: int
    tag_size: int


class PasscryptHashSettingsType(typing_extensions.TypedDict):
    mb: int
    cpu: int
    cores: int
    tag_size: int
    salt_size: int


class PasscryptKWsHash(typing_extensions.TypedDict):
    aad: bytes
    mb: int
    cpu: int
    cores: int
    tag_size: int
    salt_size: int


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
    types_modules_types = {
        name: getattr(types, name) for name in types.__all__
        if name[0].isupper()
    }
    class_dict.update(types_modules_types)


def _transpose_typing_modules_types(
    class_dict: typing.Dict[str, typing.Any]
) -> None:
    """
    Inserts the types from the standard library's `typing` module.
    """
    typing_types = {
        name: value for name, value in typing.__dict__.items()
        if (
            ("typing." in str(value) or "collections.abc." in str(value))
            and name[0].isupper()
        )
    }
    class_dict.update(typing_types)


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
        extensions = typing_extensions

    @classmethod
    def _test_type_name(cls, name: str) -> None:
        """
        Assures new type additions to the class are unique & title or
        capital-cased.
        """
        attribute_already_defined = name in cls.__dict__
        is_mixed_case = "_" in name
        is_capitalized = name[0].isupper()

        if not name.isidentifier():
            raise ValueError(f"Invalid variable name {repr(name)}.")
        elif attribute_already_defined:
            raise AttributeError(f"{repr(name)} is already defined.")
        elif is_mixed_case or not is_capitalized:
            raise ValueError(f"{repr(name)} must be title or capital-cased")

    @classmethod
    def add_type(cls, name: str, new_type: typing.Any) -> None:
        """
        Adds a new typing type to the class dictionary.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        Typing.add_type("Message", Union[str, bytes, None])
        message: Typing.Message = b"Hello, World!"

        Typing.add_type("ID", str)
        user_id: Typing.ID = "U009813"
        """
        cls._test_type_name(name)
        setattr(cls, name, new_type)

