# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2026 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


"""
Definitions for mapping classes that expect subclasses to define
instance attributes in __slots__.
"""

__all__ = ["FrozenSlots", "OpenFrozenSlots", "OpenSlots", "Slots"]


import asyncio
from os import linesep as sep

from aiootp._typing import Typing as t
from aiootp._constants import OMITTED
from aiootp._debug_control import DebugControl
from aiootp._exceptions import Issue
from aiootp._gentools import collate


DICT: str = "__dict__"
SLOTS: str = "__slots__"
UNMAPPED_ATTRIBUTES: str = "_UNMAPPED_ATTRIBUTES"
DIRLESS_ATTRIBUTES: str = "_DIRLESS_ATTRIBUTES"
RESTRICTED_ATTRIBUTES: str = "_RESTRICTED_ATTRIBUTES"


class Slots:
    """
    A base class which allow subclasses to create very efficient
    instances, with explicitly declared attributes in their `__slots__`.

    Masked repr.
    Mutable instance.

     _____________________________________
    |                                     |
    |   Stability of Assignment Styles:   |
    |_____________________________________|


    from aiootp.commons.slots import Slots

    class HybridNamespace(Slots):
        __slots__ = ("attr", "__dict__")

    hybrid = HybridNamespace()

    ✔ hybrid.attr = "value"                # supported
    ✔ hybrid["attr"] = "value"             # supported
    ✔ setattr(hybrid, "attr", "value")     # supported

    ❌ hybrid.__dict__["attr"] = "value"    # unsupported


    # See: https://github.com/rmlibre/aiootp/pull/11
    """

    __slots__ = ()

    # fmt: off
    _UNMAPPED_ATTRIBUTES: frozenset[str] = frozenset({DICT})
    _DIRLESS_ATTRIBUTES: frozenset[str] = frozenset({
        UNMAPPED_ATTRIBUTES,
        DIRLESS_ATTRIBUTES,
        RESTRICTED_ATTRIBUTES,
        "keys",
        "values",
        "items",
        "update",
        "clear",
    })
    _RESTRICTED_ATTRIBUTES: frozenset[str] = frozenset({
        "keys",
        "values",
        "items",
        "update",
        "clear",
    })
    # fmt: on

    def __init_subclass__(cls, /, *a: t.Any, **kw: t.Any) -> None:
        """
        Brings slots declarations from subclasses up the class hierarchy.
        """
        super().__init_subclass__(*a, **kw)
        # Preserve original declaration order & enforce uniqueness
        # fmt: off
        for collection_type, collection in (
            (tuple, SLOTS),
            (frozenset, UNMAPPED_ATTRIBUTES),
            (frozenset, DIRLESS_ATTRIBUTES),
            (frozenset, RESTRICTED_ATTRIBUTES),
        ):
            attrs = collection_type({
                name: None
                for subcls in cls.__mro__
                for name in getattr(subcls, collection, ())
            })
            setattr(cls, collection, attrs)

        conflicts = cls._RESTRICTED_ATTRIBUTES.intersection(cls.__slots__)
        if conflicts:
            raise Issue.slots_conflicts_with_class_variables((*conflicts,))
        # fmt: on
        cls._slots_set = frozenset(cls.__slots__)

    def __init__(
        self, mapping: t.Mapping[t.Hashable, t.Any] = {}, /, **kw: t.Any
    ) -> None:
        """
        Maps user-defined kwargs to instance attributes. If a subclass
        defines a `__slots__`, then only the names declared within can
        be admitted to the instance. Unless `"__dict__"` is also added.
        Defining classes with slots improves a system's memory efficiency,
        especially when many instances are created. Having an instance
        dictionary offers flexibility, though the interplay with slots
        can cause problems. This initializer avoids setting the names
        declared in `__slots__` within a potential instance dict.

        This is a general & flexible initializer. Subclasses can improve
        their performance & documentation by being more specific, ie:

        def __init__(self, a: int, b: int) -> None:
            self.a = a
            self.b = b
        """
        self.update(mapping, **kw)

    def __dir__(self, /) -> list[t.Hashable]:
        """
        Returns the instance directory.
        """
        dirless_attributes = self._DIRLESS_ATTRIBUTES
        return [
            name
            for name in object.__dir__(self)
            if name not in dirless_attributes
        ]

    def __bool__(self, /) -> bool:
        """
        If the instance is empty then return False, otherwise True.
        """
        return any(1 for name in self)

    def __len__(self, /) -> int:
        """
        Returns the number of elements in the instance.
        """
        return sum(1 for name in self)

    def __contains__(self, name: t.Hashable, /) -> bool:
        """
        Returns a bool of `name`'s membership in the instance.
        """
        in_slots = name in self._slots_set
        in_dict = name in getattr(self, DICT, ())
        return (in_slots and hasattr(self, name)) or in_dict

    def __setattr__(self, name: str, value: t.Any, /) -> None:
        """
        Delegates attr assignment logic to the `__getitem__` interface.
        This allows more consistency for subclasses with custom behavior
        since changes can be applied in one place. That interface also
        allows for non-string attribute names, better supporting those
        subclasses which define `__dict__`.

         _____________________________________
        |                                     |
        |   Stability of Assignment Styles:   |
        |_____________________________________|


        from aiootp.commons.slots import Slots

        class HybridNamespace(Slots):
            __slots__ = ("attr", "__dict__")

        hybrid = HybridNamespace()

        ✔ hybrid.attr = "value"                # supported
        ✔ hybrid["attr"] = "value"             # supported
        ✔ setattr(hybrid, "attr", "value")     # supported

        ❌ hybrid.__dict__["attr"] = "value"    # unsupported


        # See: https://github.com/rmlibre/aiootp/pull/11
        """
        self[name] = value

    def __delattr__(self, name: str, /) -> None:
        """
        Delegates attr deletion logic to the `__detitem__` interface.
        This allows more consistency for subclasses with custom behavior
        since changes can be applied in one place. That interface also
        allows for non-string attribute names, better supporting those
        subclasses which define `__dict__`.
        """
        del self[name]

    def __setitem__(self, name: str, value: t.Any, /) -> None:
        """
        Transforms bracket item assignment into dotted assignment on the
        instance.
        """
        if name in self._RESTRICTED_ATTRIBUTES:
            raise Issue.cant_reassign_attribute(name)
        elif name.__class__ is str:
            object.__setattr__(self, name, value)
        else:
            self.__dict__[name] = value

    def __getitem__(self, name: str, /) -> t.Any:
        """
        Transforms bracket lookup into dotted access on the instance.
        """
        if name.__class__ is str:
            return getattr(self, name)
        else:
            return self.__dict__[name]

    def __delitem__(self, name: str, /) -> None:
        """
        Deletes the item `name` from the instance.
        """
        if name.__class__ is str:
            object.__delattr__(self, name)
        else:
            del self.__dict__[name]

    def __repr__(self, /, *, mask: bool = True) -> str:
        """
        Pretty displays the instance & its attributes.
        """
        cls = self.__class__
        if mask and not DebugControl.is_debugging():

            def show(value: t.Any) -> str:
                return f"{OMITTED}{value.__class__}"
        else:

            def show(value: t.Any) -> str:
                return repr(value)

        start = f"{sep}    " if self else ""
        on = f",{sep}    " if self else ", "
        body = on.join(
            f"{name}={show(value)}"
            for name, value in self.items()
            if str(name)[0] != "_"
        )
        end = f",{sep}" if self else ""
        return f"{cls.__qualname__}({start}{body}{end})"

    async def __aiter__(self, /) -> t.AsyncGenerator[t.Any, None]:
        """
        Unpacks instance variable names with with async iteration.
        """
        for name in self:
            await asyncio.sleep(0)
            yield name

    def __iter__(self, /) -> t.Generator[t.Any, None, None]:
        """
        Unpacks instance variable names with with sync iteration.
        """
        unmapped_attributes = self._UNMAPPED_ATTRIBUTES
        for name in collate(self.__slots__, getattr(self, DICT, ())):
            if name in self and name not in unmapped_attributes:
                yield name

    def keys(self, /) -> t.Iterable[t.Hashable]:
        """
        Yields the names of all items in the instance.
        """
        yield from self

    def values(self, /) -> t.Iterable[t.Any]:
        """
        Yields the values of all items in the instance.
        """
        for name in self:
            yield self[name]

    def items(self, /) -> t.Iterable[tuple[t.Hashable, t.Any]]:
        """
        Yields the name, value pairs of all items in the instance.
        """
        for name in self:
            yield name, self[name]

    def update(
        self, mapping: t.Mapping[t.Hashable, t.Any] = {}, /, **kw: t.Any
    ) -> None:
        """
        Updates the instance with new key-values from a mapping.

        The defualt ``__init__`` relies on this method. This method
        shouldn't be overloaded in subclasses without care given to how
        it will change initialization as well.

        See: https://github.com/rmlibre/aiootp/pull/15
        """
        for name, value in {**dict(mapping), **kw}.items():
            self[name] = value

    def clear(self, /) -> None:
        """
        Deletes the instance's attribute references from its slots & dict.
        """
        getattr(self, DICT, []).clear()
        for name in self.__slots__:
            if hasattr(self, name):
                del self[name]


class OpenSlots(Slots):
    """
    A version of the `Slots` class which doesn't mask instance
    `__repr__`'s by default.

    Unmasked repr.
    Mutable instance.
    """

    __slots__ = ()

    def __repr__(self, /, *, mask: bool = False) -> str:
        """
        Denies setting attributes after they have already been set.
        """
        return super().__repr__(mask=mask)


class FrozenSlots(Slots):
    """
    A version of the `Slots` class which enables instances of subclasses
    to have attributes that are frozen once they're set.

    Masked repr.
    Immutable instance. (set once)
    """

    __slots__ = ()

    def __setitem__(self, name: str, value: t.Any, /) -> None:
        """
        Denies setting attributes after they have already been set.
        """
        if name in self:
            raise Issue.cant_reassign_attribute(name)

        super().__setitem__(name, value)

    def __delitem__(self, name: str, /) -> None:
        """
        Denies deleting attributes.
        """
        raise Issue.cant_deassign_attribute(name)


class OpenFrozenSlots(FrozenSlots):
    """
    A version of the `FrozenSlots` class which doesn't mask instance
    `__repr__`'s by default.

    Unmasked repr.
    Immutable instance. (set once)
    """

    __slots__ = ()

    def __repr__(self, /, *, mask: bool = False) -> str:
        """
        Denies setting attributes after they have already been set.
        """
        return super().__repr__(mask=mask)


module_api = dict(
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
