# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2026 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


"""
A type to manage common IO-related database operations.
"""

__all__ = ["DatabaseIO"]


from pathlib import Path

from aiootp._typing import Typing as t
from aiootp._paths import DatabasePath
from aiootp.generics import ByteIO


class DatabaseIO(ByteIO):
    """
    Manages IO operations for the `AsyncDatabase` & `Database` types.
    """

    __slots__ = ("path",)

    _Path: type = Path

    _path: _Path = DatabasePath()

    slots_types = dict(path=_Path)

    def initialize_root_path(self, path: _Path | str | None, /) -> None:
        """
        Sets a `pathlib.Path` object to the user-specified `path` if
        given, else returns a copy of the default database directory
        `Path` object.
        """
        if path is None:
            self.path = self._Path(self._path)
        else:
            self.path = self._Path(path)

    def __init__(self, path: _Path | str | None = None, /) -> None:
        """
        Prepare a container for IO operations relative to a user-defined
        `path`, or a default path if none is provided.
        """
        self.initialize_root_path(path)


module_api = dict(
    DatabaseIO=t.add_type(DatabaseIO),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
