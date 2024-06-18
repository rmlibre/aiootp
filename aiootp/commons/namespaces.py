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

    _UNMAPPED_ATTRIBUTES: t.Tuple[str] = (
        "__dict__", *Slots._UNMAPPED_ATTRIBUTES
    )

    def __init__(
        self, mapping: t.Mapping[t.Hashable, t.Any] = {}, /, **kw: t.Any
    ) -> None:
        """
        Maps the user-defined mapping & kwargs to the Namespace's
        instance dictionary.
        """
        self.__dict__.update(mapping) if mapping else 0
        self.__dict__.update(kw) if kw else 0


class OpenNamespace(Namespace):
    """
    A version of the `Namespace` class which doesn't omit instance
    repr's by default.
    """

    def __repr__(self, /, *, mask: bool = False) -> str:
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
    def __all__(self, /) -> t.List[str]:
        """
        Allows users that have turned their namespace into a Module
        object to do a `from namespace import *` on the contents of
        the namespace's mapping. This method excludes exporting private
        methods & attributes.
        """
        return [var for var in self if str(var)[0] != "_"]

    def __setattr__(self, name: str, value: t.Any, /) -> None:
        """
        Denies setting attributes after they have already been set.
        """
        if name in self:
            raise Issue.cant_reassign_attribute(name)
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str, /) -> None:
        """
        Denies deleting attributes.
        """
        raise Issue.cant_deassign_attribute(name)

    def __setitem__(self, name: str, value: t.Any, /) -> None:
        """
        Denies setting attributes after they have already been set.
        """
        if name in self:
            raise Issue.cant_reassign_attribute(name)
        elif name.__class__ is str:
            object.__setattr__(self, name, value)
        else:
            self.__dict__[name] = value

    def __delitem__(self, name: str, /) -> None:
        """
        Denies deleting attributes.
        """
        raise Issue.cant_deassign_attribute(name)


class OpenFrozenNamespace(FrozenNamespace):
    """
    A version of the `FrozenNamespace` class which doesn't omit instance
    repr's by default.
    """

    def __repr__(self, /, *, mask: bool = False) -> str:
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

