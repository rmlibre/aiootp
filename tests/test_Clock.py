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


import math
import time
import warnings

from aiootp.asynchs.clocks import TimeUnit

from conftest import *


TIME_RESOLUTION = time.get_clock_info("time").resolution
TIME_VARIANCE = math.ceil(TIME_RESOLUTION / 1e-09)

YEAR_WITH_LEAP_DAYS = 365.24225


class EpochType:
    seconds: int
    nanoseconds: int


class UnixEpoch(EpochType):
    seconds: int = 0
    nanoseconds: int = 0


class PackageEpoch(EpochType):
    seconds: int = EPOCH
    nanoseconds: int = EPOCH_NS


EPOCHS_TESTED = [UnixEpoch, PackageEpoch]


class ExaminedTimeUnit(TimeUnit):
    @classmethod
    def conversion(
        unit,
        /,
        control_time: int | float,
        epoch: EpochType,
    ) -> int:
        shifted_control_time = control_time - epoch.seconds
        return int(shifted_control_time * unit.per_s)


TIME_UNITS: tuple[ExaminedTimeUnit] = tuple(
    type(
        time_unit.__name__,
        (ExaminedTimeUnit,),
        time_unit.__dict__.copy(),
    )
    for time_unit in Clock._times.values()
)


class EqualTimingExperiment:
    __slots__ = ("early_control", "experiment", "late_control", "epoch")

    def __init__(
        self,
        control_timer: t.Callable[[], t.PositiveRealNumber],
        experiment_timer: t.Callable[[], int],
        epoch: EpochType,
    ) -> None:
        self.epoch = epoch
        self.early_control, self.experiment, self.late_control = (
            control_timer(),
            experiment_timer(),
            control_timer(),
        )

    def correct_range(
        self,
        control_conversion: t.Callable[[int | float, EpochType], int],
    ) -> range:
        return range(
            control_conversion(self.early_control, epoch=self.epoch) - 1,
            control_conversion(self.late_control, epoch=self.epoch) + 2,
        )


class TestAPlatformCounter:
    def test_is_monotonic(self) -> None:
        assert time.get_clock_info("perf_counter").monotonic is True

    def test_is_nanosecond_precise(self) -> None:
        problem = (  # fmt: skip
            "Platform perf counter doesn't have nanosecond resolution."
        )
        resolution_warning = lambda _: warnings.warn(problem) or True
        with Ignore(AssertionError, if_except=resolution_warning):
            assert time.get_clock_info("perf_counter").resolution <= 1e-09
        assert time.get_clock_info("perf_counter").resolution <= 1e-07


class TestAPlatformTime:
    def test_is_at_least_millisecond_precise(self) -> None:
        problem = (  # fmt: skip
            "Platform time doesn't have at least millisecond resolution."
        )
        resolution_warning = lambda _: warnings.warn(problem) or True
        with Ignore(AssertionError, if_except=resolution_warning):
            assert time.get_clock_info("time").resolution <= 1e-03
        assert time.get_clock_info("time").resolution <= 1 / 64


class TestClockConversions:
    def test_package_epoch_starts_year_2023(self) -> None:
        info = time.gmtime(Clock(SECONDS, epoch=0).time())
        year_difference = info.tm_year - 2023
        assert year_difference >= 0
        package_info = time.gmtime(Clock(SECONDS).time())
        assert package_info.tm_year - 1970 == year_difference

    def test_epoch_representations_are_equivalent(self) -> None:
        assert EPOCH == (EPOCH_NS // 1_000_000_000)

    def test_nanoseconds_are_always_unique_and_incrementing(self) -> None:
        number_of_tests = 1024
        iterations = tuple(range(number_of_tests))
        right_now = Clock(NANOSECONDS).time
        tests = [right_now() for test in iterations]
        if TIME_RESOLUTION <= 1e-07:
            assert number_of_tests == len(set(tests))
        elif TIME_RESOLUTION <= 1e-03:
            assert number_of_tests <= 12 * len(set(tests))
        assert tests == sorted(tests)

    @pytest.mark.parametrize("epoch", EPOCHS_TESTED)
    @pytest.mark.parametrize("unit", TIME_UNITS)
    def test_time_unit_clock_correctness(
        self,
        epoch: EpochType,
        unit: ExaminedTimeUnit,
    ) -> None:
        clock = Clock(unit.name, epoch=epoch.nanoseconds)
        test = EqualTimingExperiment(
            control_timer=time.time,
            experiment_timer=clock.time,
            epoch=epoch,
        )
        expected_span = test.correct_range(unit.conversion)
        if TIME_RESOLUTION <= 1 / unit.per_s:
            assert test.experiment in expected_span
        else:
            variance = int(TIME_VARIANCE * unit.as_ns)
            assert test.experiment in range(
                expected_span.start - variance,
                expected_span.stop + variance,
            )


class TestClock:
    async def test_invalid_unit_throws_error(self) -> None:
        problem = (  # fmt: skip
            "An invalid time unit successfully initialized an instance."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            Clock("attoseconds")

    async def test_instance_repr(self) -> None:
        units = SECONDS
        epoch = EPOCH_NS
        string = repr(Clock(units, epoch=epoch))
        assert str(units) in string
        assert str(epoch) in string

    @pytest.mark.parametrize("delta", [1, 2, 32])
    @pytest.mark.parametrize(
        "units,min_resolution,timestamp_bytes",
        [
            (NANOSECONDS, 2 * 10**8, [8, 9, 10, 11]),
            (MICROSECONDS, 2 * 10**5, [7, 8, 9, 10]),
            (MILLISECONDS, 2 * 10**2, [6, 7, 8, 9]),
            (CENTISECONDS, 2 * 10**1, [5, 6, 7, 8]),
            (DECISECONDS, 2, [5, 6, 7, 8]),
            (SECONDS, 1, [4, 5, 6, 7, 8]),
            (MINUTES, 1, [4, 5, 6, 7, 8]),
            (HOURS, 1, [3, 5, 6, 8]),
            (DAYS, 1, [2, 3, 4, 8]),
            (MONTHS, 1, [2, 3, 4, 8]),
            (YEARS, 1, [1, 2, 4, 8]),
        ],
    )
    async def test_delta_less_than_equal_to_ttl_passes(
        self,
        units: str,
        min_resolution: int,
        timestamp_bytes: list[int],
        delta: int,
    ) -> None:
        clock = Clock(units)
        for size in timestamp_bytes:
            now = clock.make_timestamp(size=size)
            assert len(now) == size
            await clock.atest_timestamp(now, ttl=min_resolution * delta)
            clock.test_timestamp(now, ttl=min_resolution * delta)

    @pytest.mark.parametrize("ttl", [0, 1, 2, 32])
    @pytest.mark.parametrize(
        "units,timestamp_bytes",
        [
            (NANOSECONDS, [8, 9, 10, 11]),
            (MICROSECONDS, [7, 8, 9, 10]),
            (MILLISECONDS, [6, 7, 8, 9]),
            (CENTISECONDS, [5, 6, 7, 8]),
            (DECISECONDS, [5, 6, 7, 8]),
            (SECONDS, [4, 5, 6, 7, 8]),
            (MINUTES, [4, 5, 6, 7, 8]),
            (HOURS, [3, 5, 6, 8]),
            (DAYS, [2, 3, 4, 8]),
            (MONTHS, [2, 3, 4, 8]),
            (YEARS, [1, 2, 4, 8]),
        ],
    )
    async def test_delta_greater_than_ttl_fails(
        self,
        units: str,
        timestamp_bytes: list[int],
        ttl: int,
    ) -> None:
        clock = Clock(units)
        past_time = max(0, clock.time() - ttl - 1)

        if ttl - past_time >= 0:
            ttl = past_time - 1

        for size in timestamp_bytes:
            past = past_time.to_bytes(size, BIG)

            problem = (  # fmt: skip
                f"Expired {clock=} timestamp of {size=} with {ttl=} was "
                "not caught."
            )
            with Ignore(TimestampExpired, if_else=violation(problem)) as r:
                await clock.atest_timestamp(past, ttl=ttl)
            assert r.error.expired_by >= 1

            with Ignore(TimestampExpired, if_else=violation(problem)) as r:
                clock.test_timestamp(past, ttl=ttl)
            assert r.error.expired_by >= 1


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
