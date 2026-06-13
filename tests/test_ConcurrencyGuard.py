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


from conftest import *

from aiootp.asynchs import ConcurrencyGuard


class TestConcurrencyGuard:
    USE_TRACKER_STATES = (
        t.ConcurrencyGuardUseTracker.Unused,
        t.ConcurrencyGuardUseTracker.Pending,
        t.ConcurrencyGuardUseTracker.Running,
        t.ConcurrencyGuardUseTracker.Done,
    )

    async def test_detects_async_out_of_order_execution(self) -> None:
        problem = (  # fmt: skip
            "Another execution authorization token was allowed to skip "
            "the current's place in line."
        )
        error = ConcurrencyGuard.IncoherentConcurrencyState

        with Ignore(error, if_else=violation(problem)):
            deques = ConcurrencyGuard.DequePair()
            async with ConcurrencyGuard(deques):
                deques.queue.appendleft(ConcurrencyGuard(deques))

        with Ignore(error, if_else=violation(problem)):
            deques = ConcurrencyGuard.DequePair()
            async with ConcurrencyGuard(deques):
                deques.queue[0] = ConcurrencyGuard(deques)

        with Ignore(IndexError, if_else=violation(problem)):
            deques = ConcurrencyGuard.DequePair()
            async with ConcurrencyGuard(deques):
                deques.queue.popleft()

    async def test_detects_sync_out_of_order_execution(self) -> None:
        problem = (  # fmt: skip
            "Another execution authorization token was allowed to skip "
            "the current's place in line."
        )
        error = ConcurrencyGuard.IncoherentConcurrencyState

        with Ignore(error, if_else=violation(problem)):
            deques = ConcurrencyGuard.DequePair()
            with ConcurrencyGuard(deques):
                deques.queue.appendleft(ConcurrencyGuard(deques))

        with Ignore(error, if_else=violation(problem)):
            deques = ConcurrencyGuard.DequePair()
            with ConcurrencyGuard(deques):
                deques.queue[0] = ConcurrencyGuard(deques)

        with Ignore(IndexError, if_else=violation(problem)):
            deques = ConcurrencyGuard.DequePair()
            with ConcurrencyGuard(deques):
                deques.queue.popleft()

    def tuple_of_transitions(self, tracker) -> tuple[t.Callable]:
        return (
            tracker.transition_to_pending,
            tracker.transition_to_running,
            tracker.transition_to_done,
        )

    def tuple_of_statuses(self, tracker) -> tuple[t.Callable]:
        return (
            tracker.is_unused,
            tracker.is_pending,
            tracker.is_running,
            tracker.is_done,
        )

    @pytest.mark.parametrize("state", USE_TRACKER_STATES)
    async def test_only_valid_transitions_allowed(self, state) -> None:
        tracker = t.ConcurrencyGuardUseTracker()
        index = self.USE_TRACKER_STATES.index(state)
        transitions = self.tuple_of_transitions(tracker)
        for i, transition in enumerate(transitions):
            tracker._state.append(state())

            if i == index:
                transition()
                continue

            problem = (  # fmt: off
                f"An invalid use tracker state {transition=} from "
                f"{state=} was allowed."
            )
            with Ignore(
                t.InvalidStateTransition,
                if_else=violation(problem),
            ):
                transition()

    @pytest.mark.parametrize("state", USE_TRACKER_STATES)
    async def test_status_is_incoherent_after_invalid_transition(
        self,
        state,
    ) -> None:
        tracker = t.ConcurrencyGuardUseTracker()
        transitions = self.tuple_of_transitions(tracker)
        statuses = self.tuple_of_statuses(tracker)
        for transition in transitions:
            try:
                tracker._state.append(state())
                transition()
                continue
            except t.InvalidStateTransition:
                pass

            for status in statuses:
                assert not status()

            assert tracker.has_faulted()

    async def test_async_guard_may_only_be_used_once(self) -> None:
        deques = ConcurrencyGuard.DequePair()
        async with (guard := ConcurrencyGuard(deques)):
            pass

        problem = (
            "A single-use ConcurrencyGuard object was allowed to be used "
            "multiple times as a context manager."
        )
        with Ignore(t.InvalidStateTransition, if_else=violation(problem)):
            async with guard:
                pass

        with Ignore(t.InvalidStateTransition, if_else=violation(problem)):
            guard._use_tracker.__init__()

    async def test_sync_guard_may_only_be_used_once(self) -> None:
        deques = ConcurrencyGuard.DequePair()
        with (guard := ConcurrencyGuard(deques)):
            pass

        problem = (
            "A single-use ConcurrencyGuard object was allowed to be used "
            "multiple times as a context manager."
        )
        with Ignore(t.InvalidStateTransition, if_else=violation(problem)):
            with guard:
                pass

        with Ignore(t.InvalidStateTransition, if_else=violation(problem)):
            guard._use_tracker.__init__()

    async def test_non_exclusive_guard_may_only_be_used_once(
        self,
    ) -> None:
        deques = ConcurrencyGuard.DequePair()
        policy = ConcurrencyGuard.policies.NonExclusive()
        with (guard := ConcurrencyGuard(deques, policy=policy)):
            pass

        problem = (
            "A single-use ConcurrencyGuard object was allowed to be used "
            "multiple times as a context manager."
        )
        with Ignore(t.InvalidStateTransition, if_else=violation(problem)):
            with guard:
                pass

        with Ignore(t.InvalidStateTransition, if_else=violation(problem)):
            guard._use_tracker.__init__()

    async def test_mixed_guard_may_only_be_used_once(self) -> None:
        deques = ConcurrencyGuard.DequePair()
        with (guard := ConcurrencyGuard(deques)):
            pass

        problem = (
            "A single-use ConcurrencyGuard object was allowed to be used "
            "multiple times as a context manager."
        )
        with Ignore(t.InvalidStateTransition, if_else=violation(problem)):
            async with guard:
                pass

        with Ignore(t.InvalidStateTransition, if_else=violation(problem)):
            guard._use_tracker.__init__()

    @pytest.mark.parametrize(
        "policy_cls",
        [*ConcurrencyGuard.policies.values()],
    )
    async def test_async_policy_must_be_instance_not_class(
        self,
        policy_cls,
    ) -> None:
        deques = ConcurrencyGuard.DequePair()
        problem = (
            "A non-instantiated policy was allowed as the provided policy"
        )
        with Ignore(TypeError, if_else=violation(problem)):
            ConcurrencyGuard(deques, policy=policy_cls)

        ConcurrencyGuard(deques, policy=policy_cls())

    @pytest.mark.parametrize(
        "policy_cls",
        [*ConcurrencyGuard.policies.values()],
    )
    async def test_sync_policy_must_be_instance_not_class(
        self,
        policy_cls,
    ) -> None:
        deques = ConcurrencyGuard.DequePair()
        problem = (
            "A non-instantiated policy was allowed as the provided policy"
        )
        with Ignore(TypeError, if_else=violation(problem)):
            ConcurrencyGuard(deques, policy=policy_cls)

        ConcurrencyGuard(deques, policy=policy_cls())


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
