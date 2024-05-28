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
    "wrap_in_executor",
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
from functools import wraps, partial

from aiootp._typing import Typing as t

from .loops import event_loop


def wrap_in_executor(function) -> t.Coroutine[t.Any, t.Any, t.Any]:
    """
    A decorator that wraps synchronous blocking IO functions so they
    will run in an executor.
    """

    @wraps(function)
    async def runner(*args, **kwargs):
        partial_function = partial(function, *args, **kwargs)
        return await event_loop().run_in_executor(
            executor=None, func=partial_function
        )

    return runner


chmod = wrap_in_executor(os.chmod)
chown = wrap_in_executor(os.chown)
makedirs = wrap_in_executor(os.makedirs)
mkdir = wrap_in_executor(os.mkdir)
rename = wrap_in_executor(os.rename)
remove = wrap_in_executor(os.remove)
rmdir = wrap_in_executor(os.rmdir)
sendfile = wrap_in_executor(os.sendfile)
stat = wrap_in_executor(os.stat)


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
    wrap_in_executor=wrap_in_executor,
)

