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


__all__ = ["FrozenInstance"]


__doc__ = (
    "General classes that expect subclasses to define attributes in "
    "`__slots__`."
)


from os import linesep as sep

from aiootp._typing import Typing as t
from aiootp._exceptions import Issue


class FrozenInstance:
    """
    A non-mapping base class which enables subclasses to define frozen
    instances with proper behavior & efficient `__slots__` declarations.
    This could help with safety by explicitly discouraging mutable state
    where it isn't explicity imposed.
    """

    __slots__ = ()

    def __init__(
        self, mapping: t.Mapping[t.Hashable, t.Any] = {}, /, **kw: t.Any
    ) -> None:
        """
        Populates instance attributes with user-defined kwargs which
        have been declared in the class' `__slots__`.
        """
        for name, value in {**mapping, **kw}.items():
            setattr(self, name, value)

    def __repr__(self, /) -> str:
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

    def __setattr__(self, name: str, value: t.Any, /) -> None:
        """
        Denies setting attributes after they have already been set.
        """
        if hasattr(self, name):
            raise Issue.cant_reassign_attribute(name)
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str, /) -> None:
        """
        Denies deleting attributes.
        """
        raise Issue.cant_deassign_attribute(name)


module_api = dict(
    FrozenInstance=t.add_type(FrozenInstance),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

