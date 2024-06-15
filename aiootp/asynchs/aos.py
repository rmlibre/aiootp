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


__doc__ = (
    """
    Wraps file operations from the `os` module in a decorator that runs
    those methods in an async executor. This was adapted from the
    `aiofiles` package:

    https://github.com/Tinche/aiofiles/blob/master/aiofiles/os.py

    Whose license is Apache License 2.0, available here:

    http://www.apache.org/licenses/LICENSE-2.0
    """
)


import os
import warnings

from aiootp._typing import Typing as t

from .loops import asleep, wrap_in_executor


async def not_implemented_placeholder(*a: t.Any, **kw: t.Any) -> None:
    await asleep()                                      # pragma: no cover
    warnings.warn("Function not supported by OS.")      # pragma: no cover


for name in __all__:
    if hasattr(os, name):
        globals()[name] = wrap_in_executor(getattr(os, name))
    else:
        globals()[name] = not_implemented_placeholder   # pragma: no cover


module_api = dict(
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    chmod=chmod,
    chown=chown,
    makedirs=makedirs,
    mkdir=mkdir,
    rename=rename,
    remove=remove,
    rmdir=rmdir,
    sendfile=sendfile,
    stat=stat,
)

