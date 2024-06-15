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
    "Base64URLSafe",
    "HasherType",
    "JSONArray",
    "JSONDeserializable",
    "JSONObject",
    "JSONSerializable",
    "Number",
    "PositiveRealNumber",
    "RealNumber",
    "SupportsAppendPop",
    "SupportsPopleft",
    "XOFType",
]


__doc__ = (
    "Dependency inversion & documentation support for types relevant to "
    "the `generics` subpackage."
)


from .interface import Typing as t


Base64URLSafe = t.Base64URLSafe = t.NewType(
    "Base64URLSafe", t.Union[str, bytes]
)


Number = t.Number = t.NewType("Number", t.Union[int, float, complex])
RealNumber = t.RealNumber = t.NewType("RealNumber", t.Union[int, float])
PositiveRealNumber = t.PositiveRealNumber = t.NewType(
    "PositiveRealNumber", t.Union[int, float]
)


_JSONSerializableNonContainerTypes = t.NewType(
    "_JSONSerializableNonContainerTypes",
    t.Union[str, float, int, bool, None],
)
_JSONSerializableBaseTypes = t.NewType(
    "_JSONSerializableBaseTypes",
    t.Union[dict, list, _JSONSerializableNonContainerTypes],
)
JSONArray = t.JSONArray = t.NewType(
    "JSONArray", t.List[_JSONSerializableBaseTypes]
)
JSONObject = t.JSONObject = t.NewType(
    "JSONObject", t.Dict[str, _JSONSerializableBaseTypes]
)
JSONSerializable = t.JSONSerializable = t.NewType(
    "JSONSerializable",
    t.Union[JSONObject, JSONArray, _JSONSerializableNonContainerTypes],
)
JSONDeserializable = t.JSONDeserializable = t.NewType(
    "JSONDeserializable", t.Union[str, bytes, bytearray]
)


@t.runtime_checkable
class SupportsPopleft(t.Protocol):

    def popleft(self) -> t.Any:
        pass  # pragma: no cover


@t.runtime_checkable
class SupportsAppendPop(t.Protocol):

    def append(self, obj: t.Any, /) -> None:
        pass  # pragma: no cover

    def pop(self, index: int = -1, /) -> t.Any:
        pass  # pragma: no cover


@t.runtime_checkable
class HasherType(t.Protocol):

    @property
    def name(self) -> str:
        pass  # pragma: no cover

    @property
    def block_size(self) -> int:
        pass  # pragma: no cover

    @property
    def digest_size(self) -> int:
        pass  # pragma: no cover

    def copy(self, /) -> t.Self:
        pass  # pragma: no cover

    def update(self, data: bytes, /) -> None:
        pass  # pragma: no cover

    def digest(self, /) -> bytes:
        pass  # pragma: no cover

    def hexdigest(self, /) -> str:
        pass  # pragma: no cover


class XOFType(HasherType):

    @property
    def digest_size(self) -> int:
        return 0  # pragma: no cover

    def digest(self, size: int, /) -> bytes:
        pass  # pragma: no cover

    def hexdigest(self, size: int, /) -> str:
        pass  # pragma: no cover


module_api = dict(
    Base64URLSafe=Base64URLSafe,
    HasherType=t.add_type(HasherType),
    JSONArray=JSONArray,
    JSONDeserializable=JSONDeserializable,
    JSONObject=JSONObject,
    JSONSerializable=JSONSerializable,
    Number=Number,
    PositiveRealNumber=PositiveRealNumber,
    RealNumber=RealNumber,
    SupportsAppendPop=t.add_type(SupportsAppendPop),
    SupportsPopleft=t.add_type(SupportsPopleft),
    XOFType=t.add_type(XOFType),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

