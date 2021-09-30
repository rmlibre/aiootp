# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
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
from ._exceptions import Issue as _Issue


try:
    import typing_extensions
except ModuleNotFoundError:
    typing_extensions = typing


try:
    Protocol = typing.Protocol
except AttributeError:
    Protocol = typing_extensions.Protocol  # type: ignore


class SupportsPop(Protocol):
    def pop(self) -> typing.Any:
        ...


class SupportsPopleft(Protocol):
    def popleft(self) -> typing.Any:
        ...


class SupportsContains(Protocol):
    def __contains__(self, value: typing.Any) -> typing.Any:
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
_JSONArray = typing.List[_JSONSerializableBaseTypes]
_JSONObject = typing.Dict[str, _JSONSerializableBaseTypes]
JSONSerializable = typing.Union[
    _JSONObject, _JSONArray, _JSONSerializableNonContainerTypes
]
JSONDeserializable = typing.Union[str, bytes, bytearray]


class DictCiphertext(typing_extensions.TypedDict):
    hmac: str
    salt: str
    siv: str
    ciphertext: typing.List[int]


JSONCiphertext = typing.Union[DictCiphertext, JSONDeserializable]


Keystream = typing.Generator[bytes, typing.Optional[bytes], None]
AsyncKeystream = typing.AsyncGenerator[bytes, typing.Optional[bytes]]
AsyncOrSyncKeystream = typing.Union[AsyncKeystream, AsyncKeystream]


Datastream = typing.Iterable[bytes]
AsyncDatastream = typing.AsyncIterable[bytes]
AsyncOrSyncDatastream = typing.Union[Datastream, AsyncDatastream]


def _transpose_this_modules_types(class_dict: typing.Dict):
    """
    Inserts the types from this module's global namespace.
    """
    this_modules_types = {
        name: value for name, value in globals().items()
        if name[0].isupper()
    }
    class_dict.update(this_modules_types)


def _transpose_types_modules_types(class_dict: typing.Dict):
    """
    Inserts the types from the standard library's `types` module.
    """
    types_modules_types = {
        name: getattr(types, name) for name in types.__all__
        if name[0].isupper()
    }
    class_dict.update(types_modules_types)


def _transpose_typing_modules_types(class_dict: typing.Dict):
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

    __slots__ = []

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
    def _test_type_name(cls, name: str):
        """
        Assures new type additions to the class are unique & title or
        capital-cased.
        """
        attribute_already_defined = name in cls.__dict__
        is_mixed_case = "_" in name
        is_capitalized = name[0].isupper()

        if not name.isidentifier():
            raise _Issue.invalid_value(f"variable name {repr(name)}")
        elif attribute_already_defined:
            raise _Issue.cant_overwrite_existing_attribute(repr(name))
        elif is_mixed_case or not is_capitalized:
            raise _Issue.value_must(repr(name), "be title or capital-cased")

    @classmethod
    def add_type(cls, name: str, new_type: typing.Any):
        """
        Adds a new typing type to the class dictionary.

        Usage Example:

        Typing.add_type("Message", Union[str, bytes, None])
        message: Typing.Message = b"Hello, World!"

        Typing.add_type("ID", str)
        user_id: Typing.ID = "U009813"
        """
        cls._test_type_name(name)
        setattr(cls, name, new_type)

