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


from collections import deque

from conftest import *

from aiootp.asynchs import ConcurrencyGuard


class TestConcurrencyGuard:
    async def test_detects_async_out_of_order_execution(self) -> None:
        problem = (  # fmt: skip
            "Another execution authorization token was allowed to skip "
            "the current's place in line."
        )
        error = ConcurrencyGuard.IncoherentConcurrencyState

        with Ignore(error, if_else=violation(problem)):
            queue = deque()
            async with ConcurrencyGuard(queue):
                queue.appendleft(ConcurrencyGuard(queue))

        with Ignore(error, if_else=violation(problem)):
            queue = deque()
            async with ConcurrencyGuard(queue):
                queue[0] = ConcurrencyGuard(queue)

        with Ignore(IndexError, if_else=violation(problem)):
            queue = deque()
            async with ConcurrencyGuard(queue):
                queue.popleft()

    async def test_detects_sync_out_of_order_execution(self) -> None:
        problem = (  # fmt: skip
            "Another execution authorization token was allowed to skip "
            "the current's place in line."
        )
        error = ConcurrencyGuard.IncoherentConcurrencyState

        with Ignore(error, if_else=violation(problem)):
            queue = deque()
            with ConcurrencyGuard(queue):
                queue.appendleft(ConcurrencyGuard(queue))

        with Ignore(error, if_else=violation(problem)):
            queue = deque()
            with ConcurrencyGuard(queue):
                queue[0] = ConcurrencyGuard(queue)

        with Ignore(IndexError, if_else=violation(problem)):
            queue = deque()
            with ConcurrencyGuard(queue):
                queue.popleft()

    async def test_async_instance_may_only_be_used_once(self) -> None:
        queue = deque()
        async with (instance := ConcurrencyGuard(queue)):
            pass

        problem = (
            "A single-use ConcurrencyGuard object was allowed to be used "
            "multiple times as a context manager."
        )
        with Ignore(t.SingleUseObjectWasReused, if_else=violation(problem)):
            async with instance:
                pass

    async def test_sync_instance_may_only_be_used_once(self) -> None:
        queue = deque()
        with (instance := ConcurrencyGuard(queue)):
            pass

        problem = (
            "A single-use ConcurrencyGuard object was allowed to be used "
            "multiple times as a context manager."
        )
        with Ignore(t.SingleUseObjectWasReused, if_else=violation(problem)):
            with instance:
                pass

    async def test_non_exclusive_instance_may_only_be_used_once(
        self,
    ) -> None:
        queue = deque()
        policy = ConcurrencyGuard.policies.NonExclusive()
        with (instance := ConcurrencyGuard(queue, policy=policy)):
            pass

        problem = (
            "A single-use ConcurrencyGuard object was allowed to be used "
            "multiple times as a context manager."
        )
        with Ignore(t.SingleUseObjectWasReused, if_else=violation(problem)):
            with instance:
                pass

    async def test_mixed_instance_may_only_be_used_once(self) -> None:
        queue = deque()
        with (instance := ConcurrencyGuard(queue)):
            pass

        problem = (
            "A single-use ConcurrencyGuard object was allowed to be used "
            "multiple times as a context manager."
        )
        with Ignore(t.SingleUseObjectWasReused, if_else=violation(problem)):
            async with instance:
                pass

    @pytest.mark.parametrize(
        "policy_cls",
        ConcurrencyGuard.policies.values(),
    )
    async def test_async_policy_must_be_instance_not_class(
        self,
        policy_cls,
    ) -> None:
        queue = deque()
        problem = (
            "A non-instantiated policy was allowed as the provided policy"
        )
        with Ignore(TypeError, if_else=violation(problem)):
            ConcurrencyGuard(queue, policy=policy_cls)

        ConcurrencyGuard(queue, policy=policy_cls())

    @pytest.mark.parametrize(
        "policy_cls",
        ConcurrencyGuard.policies.values(),
    )
    async def test_sync_policy_must_be_instance_not_class(
        self,
        policy_cls,
    ) -> None:
        queue = deque()
        problem = (
            "A non-instantiated policy was allowed as the provided policy"
        )
        with Ignore(TypeError, if_else=violation(problem)):
            ConcurrencyGuard(queue, policy=policy_cls)

        ConcurrencyGuard(queue, policy=policy_cls())


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
