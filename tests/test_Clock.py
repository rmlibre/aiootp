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
import random
import time
import warnings

from conftest import *


TIME_RESOLUTION = time.get_clock_info("time").resolution


class EpochType:
    seconds: t.ClassVar[int]
    nanoseconds: t.ClassVar[int]


class UnixEpoch(EpochType):
    seconds: t.ClassVar[int] = 0
    nanoseconds: t.ClassVar[int] = 0


class PackageEpoch(EpochType):
    seconds: t.ClassVar[int] = EPOCH
    nanoseconds: t.ClassVar[int] = EPOCH_NS


EPOCHS_TESTED = [UnixEpoch, PackageEpoch]


TIME_UNITS: tuple[t.TimeUnitType] = tuple(Clock._times.values())


def min_safe_timestamp_bytes(unit: t.TimeUnitType) -> int:
    bit_length = unit.time().bit_length()
    if 0 < bit_length % 8 < 4:
        return math.ceil(bit_length / 8)
    return math.ceil(bit_length / 8) + 1


class EqualTimingExperiment:
    __slots__ = (
        "unit",
        "epoch",
        "early_control",
        "experiment",
        "late_control",
    )

    def __init__(
        self,
        control_timer: t.Callable[[], t.PositiveRealNumber],
        experiment_timer: t.Callable[[], int],
        epoch: EpochType,
        unit: t.TimeUnitType,
    ) -> None:
        self.unit = unit
        self.epoch = epoch
        self.early_control, self.experiment, self.late_control = (
            control_timer(),
            experiment_timer(),
            control_timer(),
        )

    def correct_range(self) -> range:
        shifted_early_control = self.early_control - self.epoch.seconds
        shifted_late_control = self.late_control - self.epoch.seconds

        return range(
            int(shifted_early_control * self.unit.per_s),
            math.ceil(shifted_late_control * self.unit.per_s) + 1,
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

    @pytest.mark.parametrize("unit", TIME_UNITS)
    async def test_resolution_needed_is_same_seconds_per_unit_or_smaller(
        self,
        unit: t.TimeUnitType,
    ) -> None:

        class MockClock(Clock):
            _SYSTEM_TIME_RESOLUTION: float = 1 / unit.per_s

        clock = MockClock(unit.name)
        assert clock.has_adequate_resolution()

        MockClock._SYSTEM_TIME_RESOLUTION = 1 / (1.0001 * unit.per_s)
        assert clock.has_adequate_resolution()

        MockClock._SYSTEM_TIME_RESOLUTION = 1 / (0.9999 * unit.per_s)
        assert not clock.has_adequate_resolution()


class TestClockConversions:
    def test_package_epoch_starts_year_2023(self) -> None:
        info = time.gmtime(Clock(SECONDS, epoch=0).time())
        year_difference = info.tm_year - 2023
        assert year_difference >= 0

        package_info = time.gmtime(Clock(SECONDS).time())
        assert year_difference == package_info.tm_year - 1970

    def test_epoch_representations_are_equivalent(self) -> None:
        assert EPOCH == (EPOCH_NS // 1_000_000_000)

    @pytest.mark.parametrize("unit", TIME_UNITS)
    async def test_units_per_second_is_scaled_units_per_nanosecond(
        self,
        unit: t.TimeUnitType,
    ) -> None:
        assert round(unit.per_s, 6) == round(10**9 / unit.as_ns, 6)

    @pytest.mark.parametrize("epoch", EPOCHS_TESTED)
    @pytest.mark.parametrize("unit", TIME_UNITS)
    def test_time_unit_clock_correctness(
        self,
        epoch: EpochType,
        unit: t.TimeUnitType,
    ) -> None:
        clock = Clock(unit.name, epoch=epoch.nanoseconds)
        test = EqualTimingExperiment(
            control_timer=time.time,
            experiment_timer=clock.time,
            epoch=epoch,
            unit=unit,
        )
        assert test.experiment in test.correct_range()


class TestClock:
    async def test_invalid_unit_throws_error(self) -> None:
        problem = (  # fmt: skip
            "An invalid time unit successfully initialized an instance."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            Clock("attoseconds")

    @pytest.mark.parametrize("epoch", EPOCHS_TESTED)
    @pytest.mark.parametrize("unit", TIME_UNITS)
    async def test_instance_repr(
        self,
        unit: t.TimeUnitType,
        epoch: EpochType,
    ) -> None:
        units = unit.name
        epoch = epoch.nanoseconds

        string = repr(Clock(units, epoch=epoch))
        assert str(units) in string
        assert str(epoch) in string
        assert string == f"Clock({units!r}, {epoch=})"

    @given(ttl=st.integers(min_value=0))
    @pytest.mark.parametrize("unit", TIME_UNITS)
    async def test_adelta_less_than_equal_to_ttl_passes(
        self,
        unit: t.TimeUnitType,
        ttl: int,
    ) -> None:

        class MockClock(Clock):
            __slots__ = ()

            async def adelta(
                self,
                /,
                timestamp: bytes,  # noqa
                *,
                byte_order: str = BIG,  # noqa
            ) -> int:
                return random.randint(0, ttl)

        clock = MockClock(unit.name)
        min_timestamp_bytes = min_safe_timestamp_bytes(unit)
        for size in range(min_timestamp_bytes, min_timestamp_bytes + 4):
            now = await clock.amake_timestamp(size=size)
            await clock.atest_timestamp(now, ttl=ttl)

    @given(ttl=st.integers(min_value=0))
    @pytest.mark.parametrize("unit", TIME_UNITS)
    async def test_delta_less_than_equal_to_ttl_passes(
        self,
        unit: t.TimeUnitType,
        ttl: int,
    ) -> None:

        class MockClock(Clock):
            __slots__ = ()

            def delta(
                self,
                /,
                timestamp: bytes,  # noqa
                *,
                byte_order: str = BIG,  # noqa
            ) -> int:
                return random.randint(0, ttl)

        clock = MockClock(unit.name)
        min_timestamp_bytes = min_safe_timestamp_bytes(unit)
        for size in range(min_timestamp_bytes, min_timestamp_bytes + 4):
            now = clock.make_timestamp(size=size)
            clock.test_timestamp(now, ttl=ttl)

    @given(ttl=st.integers(min_value=0))
    @pytest.mark.parametrize("unit", TIME_UNITS)
    async def test_adelta_greater_than_ttl_fails(
        self,
        unit: t.TimeUnitType,
        ttl: int,
    ) -> None:

        class MockClock(Clock):
            __slots__ = ()

            async def adelta(
                self,
                /,
                timestamp: bytes,  # noqa
                *,
                byte_order: str = BIG,  # noqa
            ) -> int:
                return _delta

        clock = MockClock(unit.name)
        timestamp = await clock.amake_timestamp()
        _delta = random.randint(ttl + 1, 32 * (ttl + 1))

        problem = (  # fmt: skip
            f"Expired {clock=} timestamp with a delta={_delta} & {ttl=} "
            f"was not caught."
        )
        with Ignore(TimestampExpired, if_else=violation(problem)) as r:
            await clock.atest_timestamp(timestamp, ttl=ttl)

        assert r.error.expired_by == _delta - ttl

    @given(ttl=st.integers(min_value=0))
    @pytest.mark.parametrize("unit", TIME_UNITS)
    async def test_delta_greater_than_ttl_fails(
        self,
        unit: t.TimeUnitType,
        ttl: int,
    ) -> None:

        class MockClock(Clock):
            __slots__ = ()

            def delta(
                self,
                /,
                timestamp: bytes,  # noqa
                *,
                byte_order: str = BIG,  # noqa
            ) -> int:
                return _delta

        clock = MockClock(unit.name)
        timestamp = clock.make_timestamp()
        _delta = random.randint(ttl + 1, 32 * (ttl + 1))

        problem = (  # fmt: skip
            f"Expired {clock=} timestamp with a delta={_delta} & {ttl=} "
            f"was not caught."
        )
        with Ignore(TimestampExpired, if_else=violation(problem)) as r:
            clock.test_timestamp(timestamp, ttl=ttl)

        assert r.error.expired_by == _delta - ttl


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
