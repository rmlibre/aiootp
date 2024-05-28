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


from test_initialization import *


async def arun_function(relay: Ignore) -> bool:
    relay.bus.error = getattr(relay, "error", None)
    return True


def run_function(relay: Ignore) -> bool:
    relay.bus.error = getattr(relay, "error", None)
    return True


async def arun_function_return_false(relay: Ignore) -> bool:
    relay.bus.error = getattr(relay, "error", None)
    return False


def run_function_return_false(relay: Ignore) -> bool:
    relay.bus.error = getattr(relay, "error", None)
    return False


def arun_function_order_checking(*, name: str) -> None:
    async def mutate_mapping(relay: Ignore) -> bool:
        setattr(relay.bus, name, relay.bus.count)
        relay.bus.count += 1
        return True
    return mutate_mapping


def run_function_order_checking(*, name: str) -> None:
    def mutate_mapping(relay: Ignore) -> bool:
        setattr(relay.bus, name, relay.bus.count)
        relay.bus.count += 1
        return True
    return mutate_mapping


class TestIgnore:

    async def test_if_else_runs_when_no_exceptions(self) -> None:
        async with Ignore(ZeroDivisionError, if_else=arun_function) as relay:
            pass
        assert relay.bus.error is None

        with Ignore(ZeroDivisionError, if_else=run_function) as relay:
            pass
        assert relay.bus.error is None

    async def test_if_else_doesnt_run_when_exceptions(self) -> None:
        async with Ignore(ZeroDivisionError, if_else=arun_function) as relay:
            1/0
        assert not hasattr(relay.bus, "error")

        with Ignore(ZeroDivisionError, if_else=run_function) as relay:
            1/0
        assert not hasattr(relay.bus, "error")

    async def test_if_except_doesnt_run_when_no_exceptions(self) -> None:
        async with Ignore(ZeroDivisionError, if_except=arun_function) as relay:
            pass
        assert not hasattr(relay.bus, "error")

        with Ignore(ZeroDivisionError, if_except=run_function) as relay:
            pass
        assert not hasattr(relay.bus, "error")

    async def test_if_except_doesnt_run_when_wrong_exceptions(self) -> None:
        try:
            async with Ignore(ZeroDivisionError, if_except=arun_function) as relay:
                raise TypeError()
        except TypeError:
            relay.bus.wrong_exception_not_handled = True
        assert not hasattr(relay.bus, "error")
        assert getattr(relay.bus, "wrong_exception_not_handled", False)

        try:
            with Ignore(ZeroDivisionError, if_except=run_function) as relay:
                raise TypeError()
        except TypeError:
            relay.bus.wrong_exception_not_handled = True
        assert not hasattr(relay.bus, "error")
        assert getattr(relay.bus, "wrong_exception_not_handled", False)

    async def test_if_except_runs_when_correct_exceptions(self) -> None:
        async with Ignore(ZeroDivisionError, if_except=arun_function) as relay:
            1/0
        assert relay.bus.error.__class__ is ZeroDivisionError

        with Ignore(ZeroDivisionError, if_except=run_function) as relay:
            1/0
        assert relay.bus.error.__class__ is ZeroDivisionError

    async def test_if_except_returns_control_bool_when_correct_exceptions(self) -> None:
        try:
            async with Ignore(ZeroDivisionError, if_except=arun_function_return_false) as relay:
                1/0
        except ZeroDivisionError as exception:
            error = exception
        assert relay.bus.error is error

        try:
            with Ignore(ZeroDivisionError, if_except=run_function_return_false) as relay:
                1/0
        except ZeroDivisionError as exception:
            error = exception
        assert relay.bus.error is error

    async def test_finally_run_goes_after_if_else(self) -> None:
        async with Ignore(
            ZeroDivisionError,
            if_else=arun_function_order_checking(name="if_else"),
            if_except=arun_function_order_checking(name="if_except"),
            finally_run=arun_function_order_checking(name="finally_run"),
        ) as relay:
            relay.bus.count = 0
        assert relay.bus.count == 2
        assert relay.bus.if_else == 0
        assert not hasattr(relay.bus, "if_except")
        assert relay.bus.finally_run == 1

        with Ignore(
            ZeroDivisionError,
            if_else=run_function_order_checking(name="if_else"),
            if_except=arun_function_order_checking(name="if_except"),
            finally_run=run_function_order_checking(name="finally_run"),
        ) as relay:
            relay.bus.count = 0
        assert relay.bus.count == 2
        assert relay.bus.if_else == 0
        assert not hasattr(relay.bus, "if_except")
        assert relay.bus.finally_run == 1

    async def test_finally_run_goes_after_if_except(self) -> None:
        async with Ignore(
            ZeroDivisionError,
            if_else=run_function_order_checking(name="if_else"),
            if_except=arun_function_order_checking(name="if_except"),
            finally_run=arun_function_order_checking(name="finally_run"),
        ) as relay:
            relay.bus.count = 0
            1/0
        assert relay.bus.count == 2
        assert not hasattr(relay.bus, "if_else")
        assert relay.bus.if_except == 0
        assert relay.bus.finally_run == 1

        with Ignore(
            ZeroDivisionError,
            if_else=run_function_order_checking(name="if_else"),
            if_except=run_function_order_checking(name="if_except"),
            finally_run=run_function_order_checking(name="finally_run"),
        ) as relay:
            relay.bus.count = 0
            1/0
        assert relay.bus.count == 2
        assert not hasattr(relay.bus, "if_else")
        assert relay.bus.if_except == 0
        assert relay.bus.finally_run == 1

    async def test_raised_error_is_shown_in_object_repr(self) -> None:
        with Ignore(ZeroDivisionError) as ignored:
            relay = ignored
            1/0
        assert "ZeroDivisionError" in repr(relay)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

