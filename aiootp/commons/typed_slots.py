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
    "FrozenTypedSlots",
    "OpenFrozenTypedSlots",
    "OpenTypedSlots",
    "TypedSlots",
]


__doc__ = (
    "Classes using a `slots_types` mapping to enforce variable-type "
    "associations on the variables named in their `__slots__`."
)


from aiootp._typing import Typing as t
from aiootp._exceptions import Issue, TypeUncheckableAtRuntime
from aiootp._exceptions import MissingDeclaredVariables

from .slots import Slots, OpenFrozenSlots


class TypedSlots(Slots):
    """
    Allows subclasses to define a `slots_types` mapping that enforces
    variable-type associations on the variables named in `__slots__`."

    Masked repr.
    Mutable instance.
    """

    __slots__ = ()

    slots_types: t.Mapping[str, t.Any] = dict()

    @classmethod
    def _copy_acceptable_type_declarations(
        cls, /, base: type, slots_types: t.Mapping[str, t.Any]
    ) -> None:
        """
        Traverses the method resolution order, testing & collecting the
        available slots types declarations.
        """
        if not issubclass(base, TypedSlots):
            return
        for name, value in base.slots_types.items():
            try:
                isinstance(value, value)
                issubclass(value, value)
            except TypeError as error:
                raise TypeUncheckableAtRuntime(name, value)
            if name not in cls.__slots__:
                raise MissingDeclaredVariables(
                    name, found_in="slots_types", missed="__slots__"
                )
            elif name != "__dict__":
                slots_types[name] = value

    @classmethod
    def _make_frozen_class_slots_types_container(
        cls, slots_types: t.Mapping[str, type], /
    ) -> OpenFrozenSlots:
        """
        Creates a class-specific type to govern type correctness.
        """
        cls_name = f"{cls.__qualname__}SlotsTypes"
        cls_dict = dict(
            __slots__=tuple(slots_types),
            __module__=__name__,
        )
        container = type(cls_name, (OpenFrozenSlots,), cls_dict)
        return container(**slots_types)

    @classmethod
    def _make_frozen_class_slots_types(cls, /) -> OpenFrozenSlots:
        """
        Creates & populates a class-specific type to govern type
        correctness.
        """
        slots_types = {}
        for base in reversed(cls.__mro__):
            cls._copy_acceptable_type_declarations(base, slots_types)
        diff = set(
            cls.__slots__
        ).difference({"__dict__"}).symmetric_difference(slots_types)
        if diff:
            raise MissingDeclaredVariables(
                *diff, found_in="__slots__", missed="slots_types"
            )
        return cls._make_frozen_class_slots_types_container(slots_types)

    def __init_subclass__(cls, /, *a: t.Any, **kw: t.Any) -> None:
        """
        Installs a prepared an class-specific type to govern type
        correctness to all subclasses.
        """
        super().__init_subclass__(*a, **kw)
        cls.slots_types = cls._make_frozen_class_slots_types()

    def _validate_type(self, name: str, value: t.Any, /) -> None:
        """
        Validates the type of the `value` based on the class' type
        definition of the `name` attribute.
        """
        if name not in self.slots_types:
            return

        value_type = self.slots_types[name]
        if not isinstance(value, value_type):
            raise Issue.value_must_be_type(name, value_type)

    def __setitem__(self, name: str, value: t.Any, /) -> None:
        """
        Transforms bracket lookup into dotted access on the instance.
        Sets the attribute if the type is correct.
        """
        self._validate_type(name, value)
        if name.__class__ is str:
            object.__setattr__(self, name, value)
        else:
            self.__dict__[name] = value


class OpenTypedSlots(TypedSlots):
    """
    Allows subclasses to define a `slots_types` mapping that enforces
    variable-type associations on the variables named in `__slots__`."

    Unmasked repr.
    Mutable instance.
    """

    __slots__ = ()

    slots_types: t.Mapping[str, t.Any] = dict()

    def __repr__(self, /, *, mask: bool = False) -> str:
        """
        Pretty displays the instance & its attributes.
        """
        return super().__repr__(mask=mask)


class FrozenTypedSlots(TypedSlots):
    """
    Allows subclasses to define a `slots_types` mapping that enforces
    variable-type associations on the variables named in `__slots__`."

    Masked repr.
    Immutable instance. (set once)
    """

    __slots__ = ()

    slots_types: t.Mapping[str, t.Any] = dict()

    def __setitem__(self, name: str, value: t.Any, /) -> None:
        """
        Denies setting attributes after they have already been set.
        """
        if name in self:
            raise Issue.cant_reassign_attribute(name)

        self._validate_type(name, value)
        if name.__class__ is str:
            object.__setattr__(self, name, value)
        else:
            self.__dict__[name] = value

    def __delitem__(self, name: str, /) -> None:
        """
        Denies deleting attributes.
        """
        raise Issue.cant_deassign_attribute(name)


class OpenFrozenTypedSlots(FrozenTypedSlots):
    """
    Allows subclasses to define a `slots_types` mapping that enforces
    variable-type associations on the variables named in `__slots__`."

    Unmasked repr.
    Immutable instance. (set once)
    """

    __slots__ = ()

    slots_types: t.Mapping[str, t.Any] = dict()

    def __repr__(self, /, *, mask: bool = False) -> str:
        """
        Pretty displays the instance & its attributes.
        """
        return super().__repr__(mask=mask)


module_api = dict(
    FrozenTypedSlots=t.add_type(FrozenTypedSlots),
    OpenFrozenTypedSlots=t.add_type(OpenFrozenTypedSlots),
    OpenTypedSlots=t.add_type(OpenTypedSlots),
    TypedSlots=t.add_type(TypedSlots),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

