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


__all__ = [
    "Clock",
    "ns_counter",
    "s_counter",
    "this_nanosecond",
    "this_microsecond",
    "this_millisecond",
    "this_second",
    "this_minute",
    "this_hour",
    "this_day",
    "this_month",
    "this_year",
]


__doc__ = "Time & timestamping tools."


from time import time_ns, get_clock_info
from time import perf_counter as s_counter
from time import perf_counter_ns as ns_counter

from aiootp._typing import Typing as t
from aiootp._constants import SAFE_TIMESTAMP_BYTES, SECONDS, EPOCH_NS, BIG
from aiootp._exceptions import Issue, TimestampExpired
from aiootp.commons import FrozenNamespace, FrozenInstance

from .loops import asleep


_YEAR_WITH_LEAP_DAYS: float = 365.24225
_ONE_NANOSECOND: int = 1
_ONE_MICROSECOND: int = 1_000
_ONE_MILLISECOND: int = 1_000_000
_ONE_SECOND: int = 1_000_000_000
_ONE_MINUTE: int = 60 * _ONE_SECOND
_ONE_HOUR: int = 60 * _ONE_MINUTE
_ONE_DAY: int = 24 * _ONE_HOUR
_ONE_MONTH: float = (_YEAR_WITH_LEAP_DAYS * _ONE_DAY) / 12
_ONE_YEAR: float = _YEAR_WITH_LEAP_DAYS * _ONE_DAY


def this_nanosecond(epoch: int = 0) -> int:
    return time_ns() - epoch


def this_microsecond(epoch: int = 0) -> int:
    return this_nanosecond(epoch) // _ONE_MICROSECOND


def this_millisecond(epoch: int = 0) -> int:
    return this_nanosecond(epoch) // _ONE_MILLISECOND


def this_second(epoch: int = 0) -> int:
    return this_nanosecond(epoch) // _ONE_SECOND


def this_minute(epoch: int = 0) -> int:
    return this_nanosecond(epoch) // _ONE_MINUTE


def this_hour(epoch: int = 0) -> int:
    return this_nanosecond(epoch) // _ONE_HOUR


def this_day(epoch: int = 0) -> int:
    return this_nanosecond(epoch) // _ONE_DAY


def this_month(epoch: int = 0) -> int:
    return int(this_nanosecond(epoch) / _ONE_MONTH)


def this_year(epoch: int = 0) -> int:
    return int(this_nanosecond(epoch) / _ONE_YEAR)


class Clock(FrozenInstance):
    """
    A class whose objects are used for creating & measuring bytes-type
    timestamps, with configurable time units & epoch of measure.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp.asynchs import Clock

    # Create an object with specified units & epoch ->
    ns_clock = Clock("nanoseconds", epoch=0)

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
    year_clock = Clock("years")
    month_clock = Clock("months")
    day_clock = Clock("days")
    hour_clock = Clock("hours")
    minute_clock = Clock("minutes")
    second_clock = Clock("seconds")
    ms_clock = Clock("milliseconds")
    µs_clock = Clock("microseconds")
    ns_clock = Clock("nanoseconds")

    # The `epoch` is always measured in nanoseconds from the UNIX epoch of 0
    hour_clock = Clock("hours", epoch=9000)  # time starts 9000 nanoseconds
                                             # after the UNIX epoch
    # The default epoch for the package is 1672531200000000000,
    # Sun, 01 Jan 2023 00:00:00 UTC
    """

    __slots__ = ("_epoch", "_resolution_needed", "_time", "_units")

    _SYSTEM_TIME_RESOLUTION: t.PositiveRealNumber = get_clock_info(
        "time"
    ).resolution

    _times: FrozenNamespace = FrozenNamespace(
        years=(this_year, _ONE_YEAR / _ONE_SECOND),
        months=(this_month, _ONE_MONTH / _ONE_SECOND),
        days=(this_day, 24 * 60 * 60),
        hours=(this_hour, 60 * 60),
        minutes=(this_minute, 60),
        seconds=(this_second, 1),
        milliseconds=(this_millisecond, 1e-3),
        microseconds=(this_microsecond, 1e-6),
        nanoseconds=(this_nanosecond, 1e-9),
    )

    TimestampExpired: type = TimestampExpired

    def __init__(
        self, units: str = SECONDS, *, epoch: int = EPOCH_NS
    ) -> None:
        """
        Create an object which can create & measure bytes-type
        timestamps, with configurable units & epoch of measure.
        """
        if units not in self._times:
            raise Issue.invalid_value("time units", units)
        self._epoch = epoch
        self._time, self._resolution_needed = self._times[units]
        self._units = units

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__qualname__}("
            f"{repr(self._units)}, epoch={self._epoch})"
        )

    def has_adequate_resolution(self) -> bool:
        """
        Reports on whether the system's time resolution in fine enough
        to accurately work with the requested time units.
        """
        return self._resolution_needed >= self._SYSTEM_TIME_RESOLUTION

    async def atime(self) -> int:
        """
        Returns the instance's conception of the current time as an
        integer, which is the number of time units since the instance's
        epoch.
        """
        await asleep()
        return self._time(self._epoch)

    def time(self) -> int:
        """
        Returns the instance's conception of the current time as an
        integer, which is the number of time units since the instance's
        epoch.
        """
        return self._time(self._epoch)

    async def amake_timestamp(
        self,
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
        self, timestamp: bytes, *, byte_order: str = BIG
    ) -> int:
        """
        Returns the integer representation of the `byte_order`-endian
        bytes-type `timestamp`.
        """
        await asleep()
        return int.from_bytes(timestamp, byte_order)

    def read_timestamp(
        self, timestamp: bytes, *, byte_order: str = BIG
    ) -> int:
        """
        Returns the integer representation of the `byte_order`-endian
        bytes-type `timestamp`.
        """
        return int.from_bytes(timestamp, byte_order)

    async def adelta(
        self, timestamp: bytes, *, byte_order: str = BIG
    ) -> int:
        """
        Takes a `timestamp` & returns the integer difference between
        the instance's conception of the current time & the timestamp.
        """
        return await self.atime() - await self.aread_timestamp(timestamp)

    def delta(
        self, timestamp: bytes, *, byte_order: str = BIG
    ) -> int:
        """
        Takes a `timestamp` & returns the integer difference between
        the instance's conception of the current time & the timestamp.
        """
        return self.time() - self.read_timestamp(timestamp)

    async def atest_timestamp(
        self, timestamp: bytes, ttl: int, *, byte_order: str = BIG
    ) -> None:
        """
        Raises `TimestampExpired` if `timestamp` is more than
        `ttl` time units old from the instance's conception of the
        current time.
        """
        delta = await self.adelta(timestamp, byte_order=byte_order)
        timestamp_is_expired = delta > ttl
        expired_by = delta - ttl
        if ttl and timestamp_is_expired:
            raise self.TimestampExpired(self._units, expired_by)

    def test_timestamp(
        self, timestamp: bytes, ttl: int, *, byte_order: str = BIG
    ) -> None:
        """
        Raises `TimestampExpired` if `timestamp` is more than
        `ttl` time units old from the instance's conception of the
        current time.
        """
        delta = self.delta(timestamp, byte_order=byte_order)
        timestamp_is_expired = delta > ttl
        expired_by = delta - ttl
        if ttl and timestamp_is_expired:
            raise self.TimestampExpired(self._units, expired_by)


module_api = dict(
    Clock=t.add_type(Clock),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    ns_counter=ns_counter,
    s_counter=s_counter,
    this_nanosecond=this_nanosecond,
    this_microsecond=this_microsecond,
    this_millisecond=this_millisecond,
    this_second=this_second,
    this_minute=this_minute,
    this_hour=this_hour,
    this_day=this_day,
    this_month=this_month,
    this_year=this_year,
)

