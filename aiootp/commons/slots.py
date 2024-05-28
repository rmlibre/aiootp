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
    "FrozenInstance",
    "FrozenSlots",
    "OpenFrozenSlots",
    "OpenSlots",
    "Slots",
]


__doc__ = (
    "Definitions for mapping classes that expect subclasses to define "
    "instance attributes in __slots__."
)


import asyncio
from os import linesep as sep

from aiootp._typing import Typing as t
from aiootp._constants import OMITTED
from aiootp._debug_control import DebugControl
from aiootp._exceptions import Issue


class Slots:
    """
    A base class which allow subclasses to create very efficient
    instances, with explicitly declared attributes in their `__slots__`.
    """

    __slots__ = ()

    _MAPPED_ATTRIBUTES: t.Iterable[str] = ()
    _UNMAPPED_ATTRIBUTES: t.Iterable[str] = (
        "_UNMAPPED_ATTRIBUTES",
        "_is_mapped_attribute",
        "keys",
        "values",
        "items",
    )

    def __init__(
        self, mapping: t.Mapping[t.Hashable, t.Any] = {}, **kwargs
    ) -> None:
        """
        Maps the user-defined kwargs to the instance attributes. If a
        subclass defines a `__slots__` list, then only variables with
        names in the list can be admitted to the instance. Defining
        classes with __slots__ can greatly increase memory efficiency if
        a system instantiates many objects of the class.
        """
        for name, value in {**mapping, **kwargs}.items():
            setattr(self, name, value)

    def __dir__(self) -> t.List[t.Hashable]:
        """
        Returns the instance directory.
        """
        directory = set(object.__dir__(self)).difference(
            self._UNMAPPED_ATTRIBUTES
        )
        return [*directory]

    def __bool__(self) -> bool:
        """
        If the instance is empty then return False, otherwise True.
        """
        return any(1 for name in self)

    def __len__(self) -> int:
        """
        Returns the number of elements in the instance.
        """
        return sum(1 for name in self)

    def __contains__(self, name: str) -> bool:
        """
        Returns a bool of `name`'s membership in the instance.
        """
        return hasattr(self, name)

    def __setitem__(self, name: str, value: t.Any) -> None:
        """
        Transforms bracket item assignment into dotted assignment on the
        instance.
        """
        if name.__class__ is str:
            setattr(self, name, value)
        else:
            self.__dict__[name] = value

    def __getitem__(self, name: str) -> t.Any:
        """
        Transforms bracket lookup into dotted access on the instance.
        """
        if name.__class__ is str:
            return getattr(self, name)
        else:
            return self.__dict__[name]

    def __delitem__(self, name: str) -> None:
        """
        Deletes the item `name` from the instance.
        """
        if name.__class__ is str:
            delattr(self, name)
        else:
            del self.__dict__[name]

    def __repr__(self, *, mask: bool = True) -> str:
        """
        Pretty displays the instance & its attributes.
        """
        cls = self.__class__
        if mask and not DebugControl.is_debugging():
            show = lambda value: f"{OMITTED}{value.__class__}"
        else:
            show = lambda value: repr(value)
        on = f",{sep}    " if self else ", "
        start = f"{sep}    " if self else ""
        body = on.join(
            f"{name}={show(value)}"
            for name, value in cls.items(self)
            if str(name)[0] != "_"
        )
        end = f",{sep}" if self else ""
        return f"{cls.__qualname__}({start}{body}{end})"

    def _is_mapped_attribute(self, name: str) -> bool:
        """
        Allows the class to define criteria which include an instance
        attribute within the mapping unpacking interface.
        """
        return (
            hasattr(self, name)
            and (
                (name in self._MAPPED_ATTRIBUTES)
                or (name not in self._UNMAPPED_ATTRIBUTES)
            )
        )

    async def __aiter__(self) -> t.AsyncGenerator[None, t.Any]:
        """
        Unpacks instance variable names with with async iteration.
        """
        for cls in self.__class__.__mro__:
            for slot in getattr(cls, "__slots__", ()):
                if self._is_mapped_attribute(slot):
                    await asyncio.sleep(0)
                    yield slot

    def __iter__(self) -> t.Generator[None, t.Any, None]:
        """
        Unpacks instance variable names with with sync iteration.
        """
        for cls in self.__class__.__mro__:
            for slot in getattr(cls, "__slots__", ()):
                if self._is_mapped_attribute(slot):
                    yield slot

    def keys(self) -> t.Iterable[str]:
        """
        Yields the names of all items in the instance.
        """
        yield from self

    def values(self) -> t.Iterable[t.Any]:
        """
        Yields the values of all items in the instance.
        """
        yield from (getattr(self, name) for name in self)

    def items(self) -> t.Iterable[t.Tuple[str, t.Any]]:
        """
        Yields the name, value pairs of all items in the instance.
        """
        yield from ((name, getattr(self, name)) for name in self)


class OpenSlots(Slots):
    """
    A version of the `Slots` class which doesn't mask instance
    `__repr__`'s by default.
    """

    __slots__ = ()

    def __repr__(self, mask: bool = False) -> str:
        """
        Denies setting attributes after they have already been set.
        """
        return super().__repr__(mask=mask)


class FrozenSlots(Slots):
    """
    A version of the `Slots` class which enables instances of subclasses
    to have attributes that are frozen once they're set.
    """

    __slots__ = ()

    def __setattr__(self, name: str, value: t.Any) -> None:
        """
        Denies setting attributes after they have already been set.
        """
        if hasattr(self, name):
            raise Issue.cant_reassign_attribute(name)
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """
        Denies deleting attributes.
        """
        raise Issue.cant_deassign_attribute(name)


class OpenFrozenSlots(FrozenSlots):
    """
    A version of the `FrozenSlots` class which doesn't mask instance
    `__repr__`'s by default.
    """

    __slots__ = ()

    def __repr__(self, mask: bool = False) -> str:
        """
        Denies setting attributes after they have already been set.
        """
        return super().__repr__(mask=mask)


class FrozenInstance:
    """
    A class which supports frozen instances of subclasses to act as
    proper types with behavior instead of just being efficient wrappers
    around data in their `__slots__` (like `Slots` subclasses). This
    could help with safety by explicitly discouraging mutable state
    where it isn't explicity imposed.
    """

    __slots__ = ()

    def __init__(
        self, mapping: t.Mapping[t.Hashable, t.Any] = {}, **kwargs
    ) -> None:
        """
        Maps the user-defined kwargs to the instance attributes. If a
        subclass defines a `__slots__` list, then only variables with
        names in the list can be admitted to the instance. Defining
        classes with `__slots__` can greatly increase memory efficiency
        if a system instantiates many objects of the class.
        """
        for name, value in {**mapping, **kwargs}.items():
            setattr(self, name, value)

    def __repr__(self) -> str:
        """
        Pretty displays the instance & its attributes.
        """
        has = lambda name: hasattr(self, name)
        get = lambda name: getattr(self, name).__class__
        body = f",{sep}    ".join(
            f"{name}={f'<set>{get(name)}' if has(name) else '<unset>'}"
            for cls in self.__class__.__mro__
            for name in getattr(cls, "__slots__", ())
            if str(name[0]) != "_"
        )
        start = f"{sep}    " if body else ""
        end = f",{sep}" if body else ""
        return f"{self.__class__.__qualname__}({start}{body}{end})"

    def __setattr__(self, name: str, value: t.Any) -> None:
        """
        Denies setting attributes after they have already been set.
        """
        if hasattr(self, name):
            raise Issue.cant_reassign_attribute(name)
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """
        Denies deleting attributes.
        """
        raise Issue.cant_deassign_attribute(name)


module_api = dict(
    FrozenInstance=t.add_type(FrozenInstance),
    FrozenSlots=t.add_type(FrozenSlots),
    OpenFrozenSlots=t.add_type(OpenFrozenSlots),
    OpenSlots=t.add_type(OpenSlots),
    Slots=t.add_type(Slots),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

