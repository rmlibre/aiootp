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


__all__ = ["PermutationType"]


__doc__ = (
    "Dependency inversion & documentation support for types relevant to "
    "the `_permutations` subpackage."
)


from .interface import Typing as t


@t.runtime_checkable
class PermutationType(t.Protocol):

    @classmethod
    def key_size(cls, config_id: t.Hashable) -> int:
        pass  # pragma: no cover

    async def apermute(self, value: int) -> int:
        pass  # pragma: no cover

    def permute(self, value: int) -> int:
        pass  # pragma: no cover

    async def ainvert(self, value: int) -> int:
        pass  # pragma: no cover

    def invert(self, value: int) -> int:
        pass  # pragma: no cover


module_api = dict(
    PermutationType=t.add_type(PermutationType),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

