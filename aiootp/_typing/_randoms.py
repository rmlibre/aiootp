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


__all__ = ["EntropyHashingType"]


__doc__ = (
    "Dependency inversion & documentation support for types relevant to "
    "the `randoms` subpackage."
)


from .interface import Typing as t


class EntropyHashingType(t.XOFType):

    async def ahash(self, *data: bytes, size: int) -> bytes:
        pass  # pragma: no cover

    def hash(self, *data: bytes, size: int) -> bytes:
        pass  # pragma: no cover


module_api = dict(
    EntropyHashingType=t.add_type(EntropyHashingType),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

