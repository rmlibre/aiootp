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
Wraps file operations from the `os` module in a decorator that runs
those methods in an async executor. This was adapted from the
`aiofiles` package:

https://github.com/Tinche/aiofiles/blob/master/aiofiles/os.py

Whose license is Apache License 2.0, available here:

http://www.apache.org/licenses/LICENSE-2.0
"""

__all__ = [
    "chmod",
    "chown",
    "makedirs",
    "mkdir",
    "rename",
    "remove",
    "rmdir",
    "sendfile",
    "stat",
]


import os
import warnings

from aiootp._typing import Typing as t

from .loops import asleep, wrap_in_executor


def _not_implemented_placeholder(
    name: str,
) -> t.Coroutine[t.Any, t.Any, t.Any]:
    async def function_not_implemented(*_: t.Any, **__: t.Any) -> None:
        await asleep()
        message = f"`{name}` function not supported by OS."
        warnings.warn(message)

    return function_not_implemented


defs = {}


for name in __all__:
    if hasattr(os, name):
        defs[name] = wrap_in_executor(getattr(os, name))
    else:
        defs[name] = _not_implemented_placeholder(name)  # pragma: no cover


globals().update(defs)


module_api = dict(
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    _not_implemented_placeholder=_not_implemented_placeholder,
    **defs,
)
