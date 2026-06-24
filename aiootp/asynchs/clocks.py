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
Time & timestamping tools.
"""

__all__ = ["Clock", "ns_counter", "s_counter"]


from time import time_ns, get_clock_info
from time import perf_counter as s_counter
from time import perf_counter_ns as ns_counter

from aiootp._typing import Typing as t
from aiootp._constants import EPOCH_NS, BIG
from aiootp._constants import (
    YEARS,
    MONTHS,
    DAYS,
    HOURS,
    MINUTES,
    SECONDS,
    DECISECONDS,
    CENTISECONDS,
    MILLISECONDS,
    MICROSECONDS,
    NANOSECONDS,
)
from aiootp._constants import SAFE_TIMESTAMP_BYTES
from aiootp._exceptions import Issue, TimestampExpired
from aiootp.commons import FrozenNamespace, FrozenTypedSlots

from .loops import asleep


_YEAR_WITH_LEAP_DAYS: float = 365.24225


class TimeUnit:
    """
    Utility classes to produce clock timings representing different
    units of time.
    """

    __slots__ = ()

    name: str
    as_ns: int | float  # time-unit as nanoseconds
    per_s: int | float  # time-units per second

    @classmethod
    def time(unit, /, epoch: int = 0) -> int:
        """
        Returns the current time in the class' units with respect to the
        supplied `epoch`. The `epoch` is always measured in nanoseconds
        since the UNIX epoch of 0.
        """
        return int((time_ns() - epoch) / unit.as_ns)


class Nanoseconds(TimeUnit):
    __slots__ = ()

    name: str = NANOSECONDS
    as_ns: int | float = 1
    per_s: int | float = 1_000_000_000


class Microseconds(TimeUnit):
    __slots__ = ()

    name: str = MICROSECONDS
    as_ns: int | float = Nanoseconds.as_ns * 1_000
    per_s: int | float = Nanoseconds.per_s // 1_000


class Milliseconds(TimeUnit):
    __slots__ = ()

    name: str = MILLISECONDS
    as_ns: int | float = Microseconds.as_ns * 1_000
    per_s: int | float = Microseconds.per_s // 1_000


class Centiseconds(TimeUnit):
    __slots__ = ()

    name: str = CENTISECONDS
    as_ns: int | float = Milliseconds.as_ns * 10
    per_s: int | float = Milliseconds.per_s // 10


class Deciseconds(TimeUnit):
    __slots__ = ()

    name: str = DECISECONDS
    as_ns: int | float = Centiseconds.as_ns * 10
    per_s: int | float = Centiseconds.per_s // 10


class Seconds(TimeUnit):
    __slots__ = ()

    name: str = SECONDS
    as_ns: int | float = Deciseconds.as_ns * 10
    per_s: int | float = Deciseconds.per_s // 10


class Minutes(TimeUnit):
    __slots__ = ()

    name: str = MINUTES
    as_ns: int | float = Seconds.as_ns * 60
    per_s: int | float = Seconds.per_s / 60


class Hours(TimeUnit):
    __slots__ = ()

    name: str = HOURS
    as_ns: int | float = Minutes.as_ns * 60
    per_s: int | float = Minutes.per_s / 60


class Days(TimeUnit):
    __slots__ = ()

    name: str = DAYS
    as_ns: int | float = Hours.as_ns * 24
    per_s: int | float = Hours.per_s / 24


class Months(TimeUnit):
    __slots__ = ()

    name: str = MONTHS
    as_ns: int | float = Days.as_ns * (_YEAR_WITH_LEAP_DAYS / 12)
    per_s: int | float = Days.per_s / (_YEAR_WITH_LEAP_DAYS / 12)


class Years(TimeUnit):
    __slots__ = ()

    name: str = YEARS
    as_ns: int | float = Days.as_ns * _YEAR_WITH_LEAP_DAYS
    per_s: int | float = Days.per_s / _YEAR_WITH_LEAP_DAYS


class Clock(FrozenTypedSlots):
    """
    A class whose objects are used for creating & measuring bytes-type
    timestamps, with configurable time units & epoch of measure.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp.asynchs import Clock

    # Create an object with specified units & epoch ->
    ns_clock = Clock(Clock.NANOSECONDS, epoch=0)

    # Create a bytes-type timestamp of the object's current time in
    # nanoseconds from its epoch ->
    timestamp = ns_clock.make_timestamp(size=8)

    # Retrieve the elapsed time from the object's current time & a given
    # timestamp ->
    while ns_clock.delta(timestamp) < 2_000_000_000: # wait two seconds
        await do_something_else()

    # Throw a `TimestampExpired` error if a given timestamp is older
    # than `ttl` units from the object's current time ->
    try:
        ns_clock.test_timestamp(timestamp, ttl=1_000_000_000)
    except ns_clock.TimestampExpired as e:
        print(f"Timestamp expired by {e.expired_by} # of {e.units}.")
        'Timestamp expired by 287491003983 # of nanoseconds.'

    # These are the supported units ->
    year_clock = Clock(Clock.YEARS)
    month_clock = Clock(Clock.MONTHS)
    day_clock = Clock(Clock.DAYS)
    hour_clock = Clock(Clock.HOURS)
    minute_clock = Clock(Clock.MINUTES)
    second_clock = Clock(Clock.SECONDS)
    ds_clock = Clock(Clock.DECISECONDS)
    cs_clock = Clock(Clock.CENTISECONDS)
    ms_clock = Clock(Clock.MILLISECONDS)
    µs_clock = Clock(Clock.MICROSECONDS)
    ns_clock = Clock(Clock.NANOSECONDS)

    # The `epoch` is always measured in nanoseconds from the UNIX epoch of 0
    hour_clock = Clock("hours", epoch=9000)  # time starts 9000 nanoseconds
                                             # after the UNIX epoch
    # The default epoch for the package is 1672531200000000000,
    # Sun, 01 Jan 2023 00:00:00 UTC
    """

    __slots__ = (
        "_epoch",
        "_resolution_needed",
        "_time",
        "unit",
    )

    _UNMAPPED_ATTRIBUTES: frozenset = frozenset({
        "_epoch",
        "_resolution_needed",
        "_time",
    })  # fmt: skip
    _DIRLESS_ATTRIBUTES: frozenset = frozenset({
        "YEARS",
        "MONTHS",
        "DAYS",
        "HOURS",
        "MINUTES",
        "SECONDS",
        "DECISECONDS",
        "CENTISECONDS",
        "MILLISECONDS",
        "MICROSECONDS",
        "NANOSECONDS",
    })  # fmt: skip
    _SYSTEM_TIME_RESOLUTION: t.PositiveRealNumber = get_clock_info(
        "time",
    ).resolution

    _times: FrozenNamespace = FrozenNamespace({
        YEARS: Years,
        MONTHS: Months,
        DAYS: Days,
        HOURS: Hours,
        MINUTES: Minutes,
        SECONDS: Seconds,
        DECISECONDS: Deciseconds,
        CENTISECONDS: Centiseconds,
        MILLISECONDS: Milliseconds,
        MICROSECONDS: Microseconds,
        NANOSECONDS: Nanoseconds,
    })  # fmt: skip

    YEARS: str = YEARS
    MONTHS: str = MONTHS
    DAYS: str = DAYS
    HOURS: str = HOURS
    MINUTES: str = MINUTES
    SECONDS: str = SECONDS
    DECISECONDS: str = DECISECONDS
    CENTISECONDS: str = CENTISECONDS
    MILLISECONDS: str = MILLISECONDS
    MICROSECONDS: str = MICROSECONDS
    NANOSECONDS: str = NANOSECONDS

    TimestampExpired: type = TimestampExpired

    slots_types = dict(
        _epoch=int,
        _resolution_needed=(float, int),
        _time=t.Callable,
        unit=t.TimeUnitType,
    )

    def __init__(
        self,
        /,
        units: str = SECONDS,
        *,
        epoch: int = EPOCH_NS,
    ) -> None:
        """
        Create an object which can create & measure bytes-type
        timestamps, with configurable units & epoch of measure.
        """
        if units not in self._times:
            raise Issue.invalid_value("time units", units)
        self.unit = self._times[units]()
        self._time = self.unit.time
        self._resolution_needed = self.unit.as_ns * 1e-09
        self._epoch = epoch

    def __repr__(self, /) -> str:
        """
        Displays the class & state of the instance.
        """
        return (
            f"{self.__class__.__qualname__}("
            f"{self.unit.name!r}, epoch={self._epoch})"
        )

    def has_adequate_resolution(self, /) -> bool:
        """
        Reports on whether the system's time resolution in fine enough
        to accurately work with the requested time units.
        """
        return self._resolution_needed >= self._SYSTEM_TIME_RESOLUTION

    async def atime(self, /) -> int:
        """
        Returns the instance's conception of the current time as an
        integer, which is the number of time units since the instance's
        epoch.
        """
        await asleep()
        return self._time(self._epoch)

    def time(self, /) -> int:
        """
        Returns the instance's conception of the current time as an
        integer, which is the number of time units since the instance's
        epoch.
        """
        return self._time(self._epoch)

    async def amake_timestamp(
        self,
        /,
        *,
        size: int = SAFE_TIMESTAMP_BYTES,
        byte_order: str = BIG,
    ) -> bytes:
        """
        Returns a `size`-byte `byte_order`-endian representation of
        the instance's conception of the current time.
        """
        return (await self.atime()).to_bytes(size, byte_order)

    def make_timestamp(
        self,
        /,
        *,
        size: int = SAFE_TIMESTAMP_BYTES,
        byte_order: str = BIG,
    ) -> bytes:
        """
        Returns a `size`-byte `byte_order`-endian representation of
        the instance's conception of the current time.
        """
        return self.time().to_bytes(size, byte_order)

    async def aread_timestamp(
        self,
        /,
        timestamp: bytes,
        *,
        byte_order: str = BIG,
    ) -> int:
        """
        Returns the integer representation of the `byte_order`-endian
        bytes-type `timestamp`.
        """
        await asleep()
        return int.from_bytes(timestamp, byte_order)

    def read_timestamp(
        self,
        /,
        timestamp: bytes,
        *,
        byte_order: str = BIG,
    ) -> int:
        """
        Returns the integer representation of the `byte_order`-endian
        bytes-type `timestamp`.
        """
        return int.from_bytes(timestamp, byte_order)

    async def adelta(
        self,
        /,
        timestamp: bytes,
        *,
        byte_order: str = BIG,
    ) -> int:
        """
        Takes a `timestamp` & returns the integer difference between
        the instance's conception of the current time & the timestamp.
        """
        stamp = await self.aread_timestamp(timestamp, byte_order=byte_order)
        return await self.atime() - stamp

    def delta(self, /, timestamp: bytes, *, byte_order: str = BIG) -> int:
        """
        Takes a `timestamp` & returns the integer difference between
        the instance's conception of the current time & the timestamp.
        """
        stamp = self.read_timestamp(timestamp, byte_order=byte_order)
        return self.time() - stamp

    async def atest_timestamp(
        self,
        /,
        timestamp: bytes,
        ttl: int | None,
        *,
        byte_order: str = BIG,
    ) -> None:
        """
        Raises `TimestampExpired` if `timestamp` is more than
        `ttl` time units old from the instance's conception of the
        current time.
        """
        if ttl is None:
            return
        delta = await self.adelta(timestamp, byte_order=byte_order)
        timestamp_is_expired = delta > ttl
        expired_by = delta - ttl
        if timestamp_is_expired:
            raise self.TimestampExpired(self.unit.name, expired_by)

    def test_timestamp(
        self,
        /,
        timestamp: bytes,
        ttl: int | None,
        *,
        byte_order: str = BIG,
    ) -> None:
        """
        Raises `TimestampExpired` if `timestamp` is more than
        `ttl` time units old from the instance's conception of the
        current time.
        """
        if ttl is None:
            return
        delta = self.delta(timestamp, byte_order=byte_order)
        timestamp_is_expired = delta > ttl
        expired_by = delta - ttl
        if timestamp_is_expired:
            raise self.TimestampExpired(self.unit.name, expired_by)


module_api = dict(
    Clock=t.add_type(Clock),
    TimeUnit=t.add_type(TimeUnit),
    Nanoseconds=t.add_type(Nanoseconds),
    Microseconds=t.add_type(Microseconds),
    Milliseconds=t.add_type(Milliseconds),
    Centiseconds=t.add_type(Centiseconds),
    Deciseconds=t.add_type(Deciseconds),
    Seconds=t.add_type(Seconds),
    Minutes=t.add_type(Minutes),
    Hours=t.add_type(Hours),
    Days=t.add_type(Days),
    Months=t.add_type(Months),
    Years=t.add_type(Years),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    ns_counter=ns_counter,
    s_counter=s_counter,
)
