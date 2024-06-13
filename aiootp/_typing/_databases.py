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


__all__ = ["AsyncDatabaseType", "DatabaseType"]


__doc__ = (
    "Dependency inversion & documentation support for types relevant to "
    "the `databases` subpackage."
)


from .interface import Typing as t


@t.runtime_checkable
class AsyncDatabaseType(t.Protocol):

    async def aload_tags(self, *, silent: bool) -> t.Self:
        pass  # pragma: no cover

    async def aload_metatags(
        self, *, preload: bool, silent: bool
    ) -> t.Self:
        pass  # pragma: no cover

    async def aload_database(
        self,
        *,
        manifest: bool,
        silent: bool,
        preload: bool,
    ) -> t.Self:
        pass  # pragma: no cover

    async def afilename(self, tag: str) -> str:
        pass  # pragma: no cover

    async def aset_tag(
        self, tag: str, data: t.JSONSerializable, *, cache: bool
    ) -> t.Self:
        pass  # pragma: no cover

    async def aquery_tag(
        self, tag: str, *, silent: bool, cache: bool
    ) -> t.Union[bytes, t.JSONSerializable]:
        pass  # pragma: no cover

    async def apop_tag(
        self, tag: str, *, silent: bool
    ) -> t.Union[bytes, t.JSONSerializable]:
        pass  # pragma: no cover

    async def arollback_tag(
        self, tag: str, *, cache: bool
    ) -> t.Self:
        pass  # pragma: no cover

    async def aclear_cache(self, *, metatags: bool) -> t.Self:
        pass  # pragma: no cover

    async def ametatag(
        self, tag: str, *, preload: bool, silent: bool
    ) -> t.Cls:
        pass  # pragma: no cover

    async def adelete_metatag(self, tag: str) -> t.Self:
        pass # pragma: no cover

    async def adelete_database(self) -> None:
        pass  # pragma: no cover

    async def asave_tag(
        self, tag: str, *, admin: bool, drop_cache: bool
    ) -> t.Self:
        pass  # pragma: no cover


@t.runtime_checkable
class DatabaseType(t.Protocol):

    def load_tags(self, *, silent: bool) -> t.Self:
        pass  # pragma: no cover

    def load_metatags(
        self, *, preload: bool, silent: bool
    ) -> t.Self:
        pass  # pragma: no cover

    def load_database(
        self,
        *,
        manifest: bool,
        silent: bool,
        preload: bool,
    ) -> t.Self:
        pass  # pragma: no cover

    def filename(self, tag: str) -> str:
        pass  # pragma: no cover

    def set_tag(
        self, tag: str, data: t.JSONSerializable, *, cache: bool
    ) -> t.Self:
        pass  # pragma: no cover

    def query_tag(
        self, tag: str, *, silent: bool, cache: bool
    ) -> t.Union[bytes, t.JSONSerializable]:
        pass  # pragma: no cover

    def pop_tag(
        self, tag: str, *, silent: bool
    ) -> t.Union[bytes, t.JSONSerializable]:
        pass  # pragma: no cover

    def rollback_tag(
        self, tag: str, *, cache: bool
    ) -> t.Self:
        pass  # pragma: no cover

    def clear_cache(self, *, metatags: bool) -> t.Self:
        pass  # pragma: no cover

    def metatag(
        self, tag: str, *, preload: bool, silent: bool
    ) -> t.Cls:
        pass  # pragma: no cover

    def delete_metatag(self, tag: str) -> t.Self:
        pass # pragma: no cover

    def delete_database(self) -> None:
        pass  # pragma: no cover

    def save_tag(
        self, tag: str, *, admin: bool, drop_cache: bool
    ) -> t.Self:
        pass  # pragma: no cover


module_api = dict(
    AsyncDatabaseType=t.add_type(AsyncDatabaseType),
    DatabaseType=t.add_type(DatabaseType),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

