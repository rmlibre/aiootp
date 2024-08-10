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


"""
Definitions for mapping classes.
"""

__all__ = [
    "FrozenNamespace",
    "Namespace",
    "OpenFrozenNamespace",
    "OpenNamespace",
]


from aiootp._typing import Typing as t
from aiootp._exceptions import Issue

from .slots import Slots


class Namespace(Slots):
    """
    A simple wrapper for turning mappings into Namespace objects that
    allow dotted lookup and assignment on those mappings.

    Masked repr.
    Mutable instance.

     _____________________________________
    |                                     |
    |   Stability of Assignment Styles:   |
    |_____________________________________|


    from aiootp.commons.namespaces import Namespace

    class HybridNamespace(Namespace):
        __slots__ = ("attr",)

    hybrid = HybridNamespace()

    ✔ hybrid.attr = "value"                # supported
    ✔ hybrid["attr"] = "value"             # supported
    ✔ setattr(hybrid, "attr", "value")     # supported

    ❌ hybrid.__dict__["attr"] = "value"    # unsupported


    # See: https://github.com/rmlibre/aiootp/pull/11
    """

    __slots__ = ("__dict__",)


class OpenNamespace(Namespace):
    """
    A version of the `Namespace` class which doesn't omit instance
    repr's by default.

    Unmasked repr.
    Mutable instance.
    """

    __slots__ = ()

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


class OpenFrozenNamespace(FrozenNamespace):
    """
    A version of the `FrozenNamespace` class which doesn't omit instance
    repr's by default.

    Unmasked repr.
    Immutable instance. (set once)
    """

    __slots__ = ()

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
