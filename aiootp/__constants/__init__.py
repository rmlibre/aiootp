# This file is part of aiootp:
# an application agnostic — async-compatible — anonymity & cryptography
# library, providing access to high-level Pythonic utilities to simplify
# the tasks of secure data processing, communication & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__doc__ = (
    "A sub-package to better organize the package's constants."
)


import types
import typing


class SimpleNamespace(types.SimpleNamespace):
    def __getitem__(self, name: str) -> typing.Any:
        try:
            return self.__dict__[name]
        except KeyError:
            return getattr(self, name)

    def __setitem__(self, name: str, value: typing.Any) -> None:
        self.__dict__[name] = value

    def __iter__(self) -> typing.Hashable:
        yield from self.__dict__

    def keys(self) -> typing.Hashable:
        yield from self.__dict__

    def values(self) -> typing.Any:
        yield from self.__dict__.values()

    def items(self) -> typing.Tuple[typing.Hashable, typing.Any]:
        yield from self.__dict__.items()


from .misc import *
from .datasets import *
from .passcrypt import *
from .slick256 import *
from .chunky2048 import *  # Chunky2048 consts get namespace priority


__all__ = [
    "misc",
    "datasets",
    "passcrypt",
    "slick256",
    "chunky2048",
    *(n for n in globals() if n[0].isupper()),
]


misc = SimpleNamespace(**misc)
datasets = SimpleNamespace(**datasets)
passcrypt = SimpleNamespace(**passcrypt)
slick256 = SimpleNamespace(**slick256)
chunky2048 = SimpleNamespace(**chunky2048)

