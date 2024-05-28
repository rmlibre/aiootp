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
    "FrozenNamespace", "Namespace", "OpenFrozenNamespace", "OpenNamespace"
]


__doc__ = "Definitions for mapping classes."


import asyncio

from aiootp._typing import Typing as t
from aiootp._exceptions import Issue

from .slots import Slots


class Namespace(Slots):
    """
    A simple wrapper for turning mappings into Namespace objects that
    allow dotted lookup and assignment on those mappings.
    """

    __slots__ = ("__dict__",)

    _UNMAPPED_ATTRIBUTES = (
        "_UNMAPPED_ATTRIBUTES",
        "_is_mapped_attribute",
        "keys",
        "values",
        "items",
        "update",
    )

    def __init__(
        self, mapping: t.Mapping[t.Hashable, t.Any] = {}, **kwargs
    ) -> None:
        """
        Maps the user-defined mapping & kwargs to the Namespace's
        instance dictionary.
        """
        self.__dict__.update(mapping) if mapping else 0
        self.__dict__.update(kwargs) if kwargs else 0

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
        If the namespace is empty then return False, otherwise True.
        """
        return bool(self.__dict__)

    def __len__(self) -> int:
        """
        Returns the number of elements in the Namespace's mapping.
        """
        return len(self.__dict__)

    def __contains__(self, name: t.Hashable) -> bool:
        """
        Returns a bool of `variable`'s membership in the instance
        dictionary.
        """
        return name in self.__dict__

    async def __aiter__(self) -> t.AsyncGenerator[None, t.Hashable]:
        """
        Unpacks instance variable names with with async iteration.
        """
        for name in self.__dict__:
            await asyncio.sleep(0)
            if self._is_mapped_attribute(name):
                yield name

    def __iter__(self) -> t.Generator[None, t.Hashable, None]:
        """
        Unpacks instance variable names with with sync iteration.
        """
        for name in self.__dict__:
            if self._is_mapped_attribute(name):
                yield name

    def _is_mapped_attribute(self, name: t.Hashable) -> bool:
        """
        Allows the class to define criteria which include an instance
        attribute within the mapping unpacking interface.
        """
        return name in self.__dict__

    def keys(self) -> t.Iterable[t.Hashable]:
        """
        Yields the names of all items in the instance.
        """
        yield from self.__dict__

    def values(self) -> t.Iterable[t.Any]:
        """
        Yields the values of all items in the instance.
        """
        yield from self.__dict__.values()

    def items(self) -> t.Iterable[t.Tuple[t.Hashable, t.Any]]:
        """
        Yields the name, value pairs of all items in the instance.
        """
        yield from self.__dict__.items()

    def update(self, mapping: t.Mapping[t.Hashable, t.Any]) -> None:
        """
        Updates the instance with new key-values from a mapping.
        """
        self.__dict__.update(mapping)


class OpenNamespace(Namespace):
    """
    A version of the `Namespace` class which doesn't omit instance
    repr's by default.
    """

    def __repr__(self, mask: bool = False) -> str:
        """
        Pretty displays the instance & its attributes.
        """
        return super().__repr__(mask=mask)


class FrozenNamespace(Namespace):
    """
    A simple wrapper for turning mappings into Namespace objects that
    allow dotted lookup and assignment on those mappings. Also, provides
    utilities for copying mappings into other containers, & turning
    mappings into stand-alone, first-class modules.
    """

    @property
    def __all__(self) -> t.List[str]:
        """
        Allows users that have turned their namespace into a Module
        object to do a `from namespace import *` on the contents of
        the namespace's mapping. This method excludes exporting private
        methods & attributes.
        """
        return [var for var in self.__dict__ if str(var)[0] != "_"]

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


class OpenFrozenNamespace(FrozenNamespace):
    """
    A version of the `FrozenNamespace` class which doesn't omit instance
    repr's by default.
    """

    def __repr__(self, mask: bool = False) -> str:
        """
        Pretty displays the instance & its attributes.
        """
        return super().__repr__(mask=mask)


module_api = dict(
    FrozenNamespace=t.add_type(FrozenNamespace),
    Namespace=t.add_type(Namespace),
    OpenFrozenNamespace=t.add_type(OpenFrozenNamespace),
    OpenNamespace=t.add_type(OpenNamespace),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

