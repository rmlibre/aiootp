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
Dependency inversion & documentation support for types relevant to
the `asynchs` subpackage.
"""

__all__ = [
    "AsyncOrSyncIterable",
    "ClockType",
    "ConcurrencyGuardType",
    "ConcurrencyGuardPolicy",
    "Future",
    "MultiConcurrencyGaurdType",
    "PoolExecutorType",
    "QueueType",
]


from concurrent.futures._base import Future

from .interface import Typing as t


class _AsyncOrSyncIterableMeta(type):
    """
    Allows bracketed choices of types to be given to the `Iterable` &
    `AsyncIterable` type hinters for the `AsyncOrSyncIterable` subclass.
    """

    def __getitem__(cls, obj: t.Any) -> t.Union:
        return t.Union[
            t.Iterable[obj], t.AsyncIterable[obj]
        ]  # pragma: no cover


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
        timeout: t.PositiveRealNumber | None,
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
class QueueType(t.Protocol):
    def get(self, block: bool, timeout: int | None) -> t.Any:
        pass  # pragma: no cover

    def get_nowait(self) -> t.Any:
        pass  # pragma: no cover

    def put(self, item: t.Any, block: bool, timeout: int | None) -> None:
        pass  # pragma: no cover

    def put_nowait(self, item: t.Any) -> None:
        pass  # pragma: no cover

    def empty(self) -> bool:
        pass  # pragma: no cover

    def full(self) -> bool:
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
        self, timestamp: bytes, ttl: int | None, *, byte_order: str
    ) -> None:
        pass  # pragma: no cover

    def test_timestamp(
        self, timestamp: bytes, ttl: int | None, *, byte_order: str
    ) -> None:
        pass  # pragma: no cover


@t.runtime_checkable
class ConcurrencyGuardType(t.Protocol):
    async def __aenter__(self, /) -> t.Self:
        pass  # pragma: no cover

    def __enter__(self, /) -> t.Self:
        pass  # pragma: no cover

    async def __aexit__(
        self,
        /,
        exc_type: type | None = None,
        exc_value: Exception | None = None,
        traceback: t.TracebackType | None = None,
    ) -> bool:
        pass  # pragma: no cover

    def __exit__(
        self,
        /,
        exc_type: type | None = None,
        exc_value: Exception | None = None,
        traceback: t.TracebackType | None = None,
    ) -> bool:
        pass  # pragma: no cover


@t.runtime_checkable
class ConcurrencyGuardPolicy(t.Protocol):
    def is_exclusive(self, /) -> bool:
        pass  # pragma: no cover

    def use(self, /, guard: ConcurrencyGuardType) -> None:
        pass  # pragma: no cover

    def get_in_queue(self, /, guard: ConcurrencyGuardType) -> None:
        pass  # pragma: no cover

    def get_off_queue(self, /, guard: ConcurrencyGuardType) -> None:
        pass  # pragma: no cover

    def notify_on(self, /, guard: ConcurrencyGuardType) -> None:
        pass  # pragma: no cover

    def notify_off(self, /, guard: ConcurrencyGuardType) -> None:
        pass  # pragma: no cover

    def is_free_to_run(self, /, guard: ConcurrencyGuardType) -> bool:
        pass  # pragma: no cover


@t.runtime_checkable
class MultiConcurrencyGaurdType(t.Protocol):
    def guard(
        self,
        /,
        target: t.Hashable,
        *,
        policy: ConcurrencyGuardPolicy | None = None,
        probe_delay: t.PositiveRealNumber | None = None,
        token: bytes | None = None,
    ) -> ConcurrencyGuardType:
        pass  # pragma: no cover

    def monitor(
        self,
        /,
        target: t.Hashable,
        *,
        policy: ConcurrencyGuardPolicy | None = None,
        probe_delay: t.PositiveRealNumber | None = None,
        token: bytes | None = None,
    ) -> ConcurrencyGuardType:
        pass  # pragma: no cover


module_api = dict(
    AsyncOrSyncIterable=t.add_type(AsyncOrSyncIterable),
    ClockType=t.add_type(ClockType),
    ConcurrencyGuardPolicy=t.add_type(ConcurrencyGuardPolicy),
    ConcurrencyGuardType=t.add_type(ConcurrencyGuardType),
    Future=t.add_type(Future),
    MultiConcurrencyGaurdType=t.add_type(MultiConcurrencyGaurdType),
    PoolExecutorType=t.add_type(PoolExecutorType),
    QueueType=t.add_type(QueueType),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
