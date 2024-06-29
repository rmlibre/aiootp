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


__all__ = ["make_module", "remake_module", "remake_subpackage"]


__doc__ = "Standardization utilities for Python packaging."


import sys

from aiootp._typing import Typing as t

from .namespaces import FrozenNamespace


def make_module(name: str, *, mapping: dict) -> FrozenNamespace:
    """
    Turns a mapping into a module object version of a Namespace which is
    importable using normal python syntax.
    """
    module = t.ModuleType(name)
    module.__dict__.update(mapping)
    sys.modules[name] = module
    return FrozenNamespace(module.__dict__)


def remake_module(module: t.ModuleType, /) -> FrozenNamespace:
    """
    The interface for overwriting the package's modules consistently,
    applying the changes which specify the UI/UX of each.
    """
    api = module.module_api
    name = api["__name__"]  # .split(".")[-1]  # <- Uncomment for access to
                            # private variables & package debugging using
                            # from aiootp.<module> import <private_variable>
    return make_module(name=name, mapping=api)


def remake_subpackage(package: t.ModuleType, /) -> FrozenNamespace:
    """
    Applies the `remake_module` recursively to a subpackage's modules &
    the subpackage itself.
    """
    for name, subpackage in getattr(package, "subpackages", {}).items():
        package.module_api[name] = remake_subpackage(subpackage)
    for name, module in getattr(package, "modules", {}).items():
        package.module_api[name] = remake_module(module)
    return remake_module(package)


module_api = dict(
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    make_module=make_module,
    remake_module=remake_module,
    remake_subpackage=remake_subpackage,
)

