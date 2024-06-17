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


__all__ = ["RawGUIDConfig", "RawGUIDContainer"]


__doc__ = "A configuration type for `RawGUID`."


import io
import warnings
from secrets import token_bytes

from aiootp._typing import Typing as t
from aiootp._constants import NANOSECONDS, BIG
from aiootp._exceptions import Issue
from aiootp.commons import Config, OpenFrozenSlots
from aiootp.asynchs import Clock


if not Clock(NANOSECONDS).has_adequate_resolution():
    warnings.warn(  # pragma: no cover
        f"\nBEWARE: Nanosecond clocks require better time resolution than "
        f"what's available from the system's time resolution of "
        f"{Clock._SYSTEM_TIME_RESOLUTION} seconds/tick. \nSeveral of the "
        f"package's tools, such as GUIDs, need fine resolution to function "
        f"correctly & satisfy their stated guarantees."
    )


class RawGUIDConfig(Config):
    """
    A configuration type for `RawGUID`.
    """

    __slots__ = (
        "TIMESTAMP_BYTES",
        "PRF_BYTES",
        "NODE_ID_BYTES",
        "TICKER_BYTES",
        "TICK_DOMAIN",
        "SIZE",
        "clock",
        "prf",
    )

    slots_types: t.Mapping[str, type] = dict(
        TIMESTAMP_BYTES=int,
        PRF_BYTES=int,
        NODE_ID_BYTES=int,
        TICKER_BYTES=int,
        TICK_DOMAIN=int,
        SIZE=int,
        clock=t.ClockType,
        prf=t.Callable,
    )

    def _process_size(self, size: int) -> int:
        """
        Ensures the specified raw guid size matches the combined length
        of its components.
        """
        if size != (
            self.TIMESTAMP_BYTES
            + self.PRF_BYTES
            + self.NODE_ID_BYTES
            + self.TICKER_BYTES
        ):
            raise Issue.invalid_length("stated guid size", size)
        return size

    def _process_clock(self, clock: t.Optional[type]) -> type:
        """
        Returns a default clock if one isn't provided.
        """
        if clock is None:
            return Clock(NANOSECONDS)
        else:
            return clock

    def __init__(
        self,
        *,
        timestamp_bytes: int,
        prf_bytes: int,
        node_id_bytes: int,
        ticker_bytes: int,
        size: int,
        clock: t.Optional[t.ClockType] = None,
        prf: t.Callable[[int], bytes] = token_bytes,
    ) -> None:
        self.TIMESTAMP_BYTES = timestamp_bytes
        self.PRF_BYTES = prf_bytes
        self.NODE_ID_BYTES = node_id_bytes
        self.TICKER_BYTES = ticker_bytes
        self.TICK_DOMAIN = int(self.TICKER_BYTES * "ff", 16)
        self.SIZE = self._process_size(size)
        self.clock = self._process_clock(clock)
        self.prf = prf


class RawGUIDContainer(OpenFrozenSlots):
    """
    Parses `RawGUID` bytes values into instance attributes.
    """

    __slots__ = ("timestamp", "token", "node_id", "ticker")

    _MAPPED_ATTRIBUTES: t.Tuple[str] = __slots__

    def __init__(self, guid: bytes, *, config: RawGUIDConfig) -> None:
        if not len(guid) == config.SIZE:
            raise Issue.invalid_length("raw guid", config.SIZE)
        reader = io.BytesIO(guid).read
        self.timestamp = reader(config.TIMESTAMP_BYTES)
        self.token = reader(config.PRF_BYTES)
        self.node_id = reader(config.NODE_ID_BYTES)
        self.ticker = reader(config.TICKER_BYTES)

    def __iter__(self) -> t.Generator[str, None, None]:
        yield from self._MAPPED_ATTRIBUTES

    def __hash__(self) -> int:
        return int.from_bytes(self.sort_key, BIG)

    def __eq__(self, other: "cls") -> bool:
        return self.sort_key == other.sort_key

    def __gt__(self, other: "cls") -> bool:
        return self.sort_key > other.sort_key

    def __lt__(self, other: "cls") -> bool:
        return self.sort_key < other.sort_key

    @property
    def sort_key(self) -> bytes:
        return (
            self.timestamp + self.node_id + self.ticker + self.token
        )


module_api = dict(
    RawGUIDConfig=t.add_type(RawGUIDConfig),
    RawGUIDContainer=t.add_type(RawGUIDContainer),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

