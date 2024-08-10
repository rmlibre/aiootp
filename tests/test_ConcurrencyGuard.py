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
                queue.appendleft(token_bytes(32))

        with Ignore(error, if_else=violation(problem)):
            queue = deque()
            async with ConcurrencyGuard(queue):
                queue[0] = token_bytes(32)

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
                queue.appendleft(token_bytes(32))

        with Ignore(error, if_else=violation(problem)):
            queue = deque()
            with ConcurrencyGuard(queue):
                queue[0] = token_bytes(32)

        with Ignore(IndexError, if_else=violation(problem)):
            queue = deque()
            with ConcurrencyGuard(queue):
                queue.popleft()


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
