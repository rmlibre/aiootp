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
from typing import NewType


try:
    Self = typing.Self
except AttributeError:              # pragma: no cover
    Self = NewType("Self", "Self")  # pragma: no cover
    # TODO: Remove when Python 3.11 is oldest supported version.


Cls = NewType("Cls", Self)


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


class Typing:
    """
    A container for type-hinting variables.
    """

    __slots__ = ()

    _transpose_this_modules_types(class_dict=vars())
    _transpose_types_modules_types(class_dict=vars())
    _transpose_typing_modules_types(class_dict=vars())

    overload = typing.overload
    runtime_checkable = typing.runtime_checkable

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
            raise TypeError(f"{repr(new_type)} is not a type.")

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
        cls._test_type(new_type)
        cls._test_type_name(name)
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

