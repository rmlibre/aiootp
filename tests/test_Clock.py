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


import math
import time
import warnings

from conftest import *


TIME_RESOLUTION = time.get_clock_info("time").resolution
TIME_VARIANCE = math.ceil(TIME_RESOLUTION / 1e-09)

YEAR_WITH_LEAP_DAYS = 365.24225

EPOCHS_TESTED = (
    OpenNamespace(seconds=0, nanoseconds=0),
    OpenNamespace(seconds=EPOCH, nanoseconds=EPOCH_NS),
)


class EqualTimingExperiment:
    __slots__ = ("early_control", "experiment", "late_control", "epoch")

    def __init__(
        self,
        control_timer: t.Callable[[], t.PositiveRealNumber],
        experiment_timer: t.Callable[[], int],
        epoch: int,
    ) -> None:
        self.epoch = epoch
        self.early_control, self.experiment, self.late_control = (
            control_timer(),
            experiment_timer(),
            control_timer(),
        )

    def correct_range(
        self,
        *,
        control_conversion: t.Callable[[t.PositiveRealNumber], int],
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
    seconds_to_nanoseconds = staticmethod(
        lambda control, epoch: int(
            (control - epoch.seconds) * 1_000_000_000
        )
    )
    seconds_to_microseconds = staticmethod(
        lambda control, epoch: int((control - epoch.seconds) * 1_000_000)
    )
    seconds_to_milliseconds = staticmethod(
        lambda control, epoch: int((control - epoch.seconds) * 1_000)
    )
    seconds_to_centiseconds = staticmethod(
        lambda control, epoch: int((control - epoch.seconds) * 100)
    )
    seconds_to_deciseconds = staticmethod(
        lambda control, epoch: int((control - epoch.seconds) * 10)
    )
    seconds_to_seconds = staticmethod(
        lambda control, epoch: int(control - epoch.seconds)
    )
    seconds_to_minutes = staticmethod(
        lambda control, epoch: int((control - epoch.seconds) / 60)
    )
    seconds_to_hours = staticmethod(
        lambda control, epoch: int((control - epoch.seconds) / (60 * 60))
    )
    seconds_to_days = staticmethod(
        lambda control, epoch: int(
            (control - epoch.seconds) / (60 * 60 * 24)
        )
    )
    seconds_to_months = staticmethod(
        lambda control, epoch: int(
            (control - epoch.seconds)
            / (60 * 60 * 24 * YEAR_WITH_LEAP_DAYS / 12)
        )
    )
    seconds_to_years = staticmethod(
        lambda control, epoch: int(
            (control - epoch.seconds) / (60 * 60 * 24 * YEAR_WITH_LEAP_DAYS)
        )
    )

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
            assert number_of_tests <= 10 * len(set(tests))
        assert tests == sorted(tests)

    def test_nanoseconds_correctness(self) -> None:
        for epoch in EPOCHS_TESTED:
            clock = Clock(NANOSECONDS, epoch=epoch.nanoseconds)
            test = EqualTimingExperiment(
                control_timer=time.time,
                experiment_timer=clock.time,
                epoch=epoch,
            )
            span = test.correct_range(
                control_conversion=self.seconds_to_nanoseconds
            )
            if TIME_RESOLUTION <= 1e-09:
                assert test.experiment in span
            else:
                assert test.experiment in range(
                    span.start - TIME_VARIANCE,
                    span.stop + TIME_VARIANCE,
                )

    def test_microseconds_correctness(self) -> None:
        for epoch in EPOCHS_TESTED:
            clock = Clock(MICROSECONDS, epoch=epoch.nanoseconds)
            test = EqualTimingExperiment(
                control_timer=time.time,
                experiment_timer=clock.time,
                epoch=epoch,
            )
            span = test.correct_range(
                control_conversion=self.seconds_to_microseconds
            )
            if TIME_RESOLUTION <= 1e-09:
                assert test.experiment in span
            else:
                assert test.experiment in range(
                    span.start - (TIME_VARIANCE // 1_000),
                    span.stop + (TIME_VARIANCE // 1_000),
                )

    def test_milliseconds_correctness(self) -> None:
        for epoch in EPOCHS_TESTED:
            clock = Clock(MILLISECONDS, epoch=epoch.nanoseconds)
            test = EqualTimingExperiment(
                control_timer=time.time,
                experiment_timer=clock.time,
                epoch=epoch,
            )
            span = test.correct_range(
                control_conversion=self.seconds_to_milliseconds
            )
            if TIME_RESOLUTION <= 1e-09:
                assert test.experiment in span
            else:
                assert test.experiment in range(
                    span.start - (TIME_VARIANCE // 1_000_000),
                    span.stop + (TIME_VARIANCE // 1_000_000),
                )

    def test_centiseconds_correctness(self) -> None:
        for epoch in EPOCHS_TESTED:
            clock = Clock(CENTISECONDS, epoch=epoch.nanoseconds)
            test = EqualTimingExperiment(
                control_timer=time.time,
                experiment_timer=clock.time,
                epoch=epoch,
            )
            span = test.correct_range(
                control_conversion=self.seconds_to_centiseconds
            )
            if TIME_RESOLUTION <= 1e-09:
                assert test.experiment in span
            else:
                assert test.experiment in range(
                    span.start - (TIME_VARIANCE // 10_000_000),
                    span.stop + (TIME_VARIANCE // 10_000_000),
                )

    def test_deciseconds_correctness(self) -> None:
        for epoch in EPOCHS_TESTED:
            clock = Clock(DECISECONDS, epoch=epoch.nanoseconds)
            test = EqualTimingExperiment(
                control_timer=time.time,
                experiment_timer=clock.time,
                epoch=epoch,
            )
            span = test.correct_range(
                control_conversion=self.seconds_to_deciseconds
            )
            if TIME_RESOLUTION <= 1e-09:
                assert test.experiment in span
            else:
                assert test.experiment in range(
                    span.start - (TIME_VARIANCE // 100_000_000),
                    span.stop + (TIME_VARIANCE // 100_000_000),
                )

    def test_seconds_correctness(self) -> None:
        for epoch in EPOCHS_TESTED:
            clock = Clock(SECONDS, epoch=epoch.nanoseconds)
            test = EqualTimingExperiment(
                control_timer=time.time,
                experiment_timer=clock.time,
                epoch=epoch,
            )
            assert test.experiment in test.correct_range(
                control_conversion=self.seconds_to_seconds
            )

    def test_minutes_correctness(self) -> None:
        for epoch in EPOCHS_TESTED:
            clock = Clock(MINUTES, epoch=epoch.nanoseconds)
            test = EqualTimingExperiment(
                control_timer=time.time,
                experiment_timer=clock.time,
                epoch=epoch,
            )
            assert test.experiment in test.correct_range(
                control_conversion=self.seconds_to_minutes
            )

    def test_hours_correctness(self) -> None:
        for epoch in EPOCHS_TESTED:
            clock = Clock(HOURS, epoch=epoch.nanoseconds)
            test = EqualTimingExperiment(
                control_timer=time.time,
                experiment_timer=clock.time,
                epoch=epoch,
            )
            assert test.experiment in test.correct_range(
                control_conversion=self.seconds_to_hours
            )

    def test_days_correctness(self) -> None:
        for epoch in EPOCHS_TESTED:
            clock = Clock(DAYS, epoch=epoch.nanoseconds)
            test = EqualTimingExperiment(
                control_timer=time.time,
                experiment_timer=clock.time,
                epoch=epoch,
            )
            assert test.experiment in test.correct_range(
                control_conversion=self.seconds_to_days
            )

    def test_months_correctness(self) -> None:
        for epoch in EPOCHS_TESTED:
            clock = Clock(MONTHS, epoch=epoch.nanoseconds)
            test = EqualTimingExperiment(
                control_timer=time.time,
                experiment_timer=clock.time,
                epoch=epoch,
            )
            assert test.experiment in test.correct_range(
                control_conversion=self.seconds_to_months
            )

    def test_years_correctness(self) -> None:
        for epoch in EPOCHS_TESTED:
            clock = Clock(YEARS, epoch=epoch.nanoseconds)
            test = EqualTimingExperiment(
                control_timer=time.time,
                experiment_timer=clock.time,
                epoch=epoch,
            )
            assert test.experiment in test.correct_range(
                control_conversion=self.seconds_to_years
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
            (MILLISECONDS, 2 * 10**2, [5, 6, 7, 8]),
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
        timestamp_bytes: t.List[int],
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
            (MILLISECONDS, [5, 6, 7, 8]),
            (SECONDS, [4, 5, 6, 7, 8]),
            (MINUTES, [4, 5, 6, 7, 8]),
            (HOURS, [3, 5, 6, 8]),
            (DAYS, [2, 3, 4, 8]),
            (MONTHS, [2, 3, 4, 8]),
            (YEARS, [1, 2, 4, 8]),
        ],
    )
    async def test_delta_greater_than_ttl_fails(
        self, units: str, timestamp_bytes: t.List[int], ttl: int
    ) -> None:
        clock = Clock(units)
        past_time = max(0, clock.time() - ttl - 1)
        if ttl - past_time >= 0:
            ttl = past_time - 1
        for size in timestamp_bytes:
            problem = (  # fmt: skip
                f"Expired {clock=} timestamp of {size=} with {ttl=} was "
                "not caught."
            )
            past = past_time.to_bytes(size, BIG)
            with Ignore(TimestampExpired, if_else=violation(problem)) as r:
                await clock.atest_timestamp(past, ttl=ttl)
            assert r.error.expired_by >= 1
            with Ignore(TimestampExpired, if_else=violation(problem)) as r:
                clock.test_timestamp(past, ttl=ttl)
            assert r.error.expired_by >= 1


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
