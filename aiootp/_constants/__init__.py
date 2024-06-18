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


__all__ = []


__doc__ = "A sub-package to better organize the package's constants."


import asyncio

from aiootp._typing import Typing as t


class NamespaceMapping(t.SimpleNamespace):
    def __init__(
        self, mapping: t.Mapping[str, t.Any] = {}, **kwargs
    ) -> None:
        super().__init__(**kwargs)
        self.__dict__.update(mapping)

    def __getitem__(self, name: str) -> t.Any:
        return self.__dict__[name]

    def __setitem__(self, name: str, value: t.Any) -> None:
        self.__dict__[name] = value

    def __delitem__(self, name: str) -> None:
        del self.__dict__[name]

    def __contains__(self, name: str) -> bool:
        return name in self.__dict__

    def __len__(self) -> int:
        return len(self.__dict__)

    async def __aiter__(self) -> str:
        for name in self.__dict__:
            await asyncio.sleep(0)
            yield name

    def __iter__(self) -> str:
        yield from self.__dict__

    def keys(self) -> t.Iterable[t.Hashable]:
        yield from self.__dict__

    def values(self) -> t.Iterable[t.Any]:
        yield from self.__dict__.values()

    def items(self) -> t.Iterable[t.Tuple[t.Hashable, t.Any]]:
        yield from self.__dict__.items()

    def update(self, mapping: t.Mapping[str, t.Any] = {}, /, **kw) -> None:
        self.__dict__.update(mapping, **kw)


def collect_non_private_constants(
    mapping: t.Mapping[str, t.Any]
) -> t.Mapping[str, t.Any]:
    """
    Selectively moves uppercase, non-private declarations within a
    `mapping` to a returned dictionary.
    """
    return {
        name: value
        for name, value in mapping.items()
        if (name.isupper() and not name.startswith("_"))
    }


from .misc import *
from .datasets import *


modules = dict(misc=misc, datasets=datasets)


module_api = dict(
    NamespaceMapping=t.add_type(NamespaceMapping),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

