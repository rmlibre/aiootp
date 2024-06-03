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

from test_initialization import *


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
    ):
        self.epoch = epoch
        self.early_control, self.experiment, self.late_control = (
            control_timer(), experiment_timer(), control_timer()
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
        assert time.get_clock_info("perf_counter").monotonic == True

    def test_is_nanosecond_precise(self) -> None:
        problem = (
            "Platform perf counter doesn't have nanosecond resolution."
        )
        resolution_warning = lambda relay: warnings.warn(problem) or True
        with Ignore(AssertionError, if_except=resolution_warning):
            assert time.get_clock_info("perf_counter").resolution <= 1e-09
        assert time.get_clock_info("perf_counter").resolution <= 1e-07


class TestAPlatformTime:

    def test_is_at_least_millisecond_precise(self) -> None:
        problem = (
            "Platform time doesn't have at least millisecond resolution."
        )
        resolution_warning = lambda relay: warnings.warn(problem) or True
        with Ignore(AssertionError, if_except=resolution_warning):
            assert time.get_clock_info("time").resolution <= 1e-03
        assert time.get_clock_info("time").resolution <= 1 / 64


class TestClockConversions:
    seconds_to_nanoseconds = staticmethod(
        lambda control, epoch: int((control - epoch.seconds) * 1_000_000_000)
    )
    seconds_to_microseconds = staticmethod(
        lambda control, epoch: int((control - epoch.seconds) * 1_000_000)
    )
    seconds_to_milliseconds = staticmethod(
        lambda control, epoch: int((control - epoch.seconds) * 1_000)
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
        lambda control, epoch: int((control - epoch.seconds) / (60 * 60 * 24))
    )
    seconds_to_months = staticmethod(
        lambda control, epoch: int((control - epoch.seconds) / (60 * 60 * 24 * YEAR_WITH_LEAP_DAYS / 12))
    )
    seconds_to_years = staticmethod(
        lambda control, epoch: int((control - epoch.seconds) / (60 * 60 * 24 * YEAR_WITH_LEAP_DAYS))
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
        problem = (
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


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

