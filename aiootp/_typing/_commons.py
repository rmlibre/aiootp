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
Dependency inversion & documentation support for types relevant to
the `commons` subpackage.
"""

__all__ = ["ConfigType"]


from .interface import Typing as t


@t.runtime_checkable
class ConfigType(t.Protocol):
    def set_config_id(self, config_id: t.Hashable) -> None:
        pass  # pragma: no cover

    def keys(self) -> t.Generator[str, None, None]:
        pass  # pragma: no cover

    def values(self) -> t.Generator[t.Any, None, None]:
        pass  # pragma: no cover

    def items(self) -> t.Generator[t.Tuple[str, t.Any], None, None]:
        pass  # pragma: no cover

    def update(
        self, mapping: t.Mapping[t.Hashable, t.Any], /, **kw: t.Any
    ) -> None:
        pass  # pragma: no cover


module_api = dict(
    ConfigType=t.add_type(ConfigType),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
