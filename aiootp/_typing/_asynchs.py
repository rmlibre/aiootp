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


__all__ = ["AsyncOrSyncIterable", "ClockType", "Future", "PoolExecutorType"]


__doc__ = (
    "Dependency inversion & documentation support for types relevant to "
    "the `asynchs` subpackage."
)


from concurrent.futures._base import Future

from .interface import Typing as t


class _AsyncOrSyncIterableMeta(type):
    """
    Allows bracketed choices of types to be given to the `Iterable` &
    `AsyncIterable` type hinters for the `AsyncOrSyncIterable` subclass.
    """

    def __getitem__(cls, obj: t.Any):
        return t.Union[t.Iterable[obj], t.AsyncIterable[obj]]


class AsyncOrSyncIterable(metaclass=_AsyncOrSyncIterableMeta):
    """
    Allows bracketed choices of types to be given to the `Iterable` &
    `AsyncIterable` type hinters.
    """


@t.runtime_checkable
class PoolExecutorType(t.Protocol):

    def map(
        self,
        fn: t.Callable[..., t.Any],
        *iterables: t.Any,
        timeout: t.Optional[t.PositiveRealNumber],
        chunksize: int,
    ) -> t.Iterator[t.Any]:
        pass  # pragma: no cover

    def shutdown(self, wait: bool) -> None:
        pass  # pragma: no cover

    def submit(
        self,
        fn: t.Callable[..., t.Any],
        /,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> Future:
        pass  # pragma: no cover


@t.runtime_checkable
class ClockType(t.Protocol):

    async def atime(self) -> int:
        pass  # pragma: no cover

    def time(self) -> int:
        pass  # pragma: no cover

    async def amake_timestamp(self, *, size: int, byte_order: str) -> bytes:
        pass  # pragma: no cover

    def make_timestamp(self, *, size: int, byte_order: str) -> bytes:
        pass  # pragma: no cover

    async def atest_timestamp(
        self, timestamp: bytes, ttl: int, *, byte_order: str
    ) -> None:
        pass  # pragma: no cover

    def test_timestamp(
        self, timestamp: bytes, ttl: int, *, byte_order: str
    ) -> None:
        pass  # pragma: no cover


module_api = dict(
    AsyncOrSyncIterable=t.add_type(AsyncOrSyncIterable),
    ClockType=t.add_type(ClockType),
    Future=t.add_type(Future),
    PoolExecutorType=t.add_type(PoolExecutorType),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

