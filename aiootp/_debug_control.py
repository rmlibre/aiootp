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


__all__ = ["DebugControl"]


__doc__ = "A controller for toggling debug mode."


import warnings

from ._typing import Typing as t


class DebugControl:
    """
    WARNING: Enabling debugging reveals potentially sensitive values,
    -------- such as cryptographic keys, in object repr's that are
    omitted by default. Also turns on asyncio's debugging.
    """

    __slots__ = ()

    _DEBUG_MODE: bool = False

    _switches: t.List[t.Callable[[bool], t.Any]] = []

    @classmethod
    def is_debugging(cls, /):
        return cls._DEBUG_MODE

    @classmethod
    def enable_debugging(cls, /, *, silence_warnings: bool = False) -> None:
        """
        WARNING: This will reveal potentially sensitive values, such as
        cryptographic keys, in object repr's that are omitted by default.
        """
        if not silence_warnings:
            warnings.warn(cls.__doc__)  # pragma: no cover
        if not cls._DEBUG_MODE:
            cls._DEBUG_MODE = True
            for toggle in cls._switches:
                toggle()

    @classmethod
    def disable_debugging(cls, /) -> None:
        if cls._DEBUG_MODE:
            cls._DEBUG_MODE = False
            for toggle in cls._switches:
                toggle()


module_api = dict(
    DebugControl=DebugControl,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

