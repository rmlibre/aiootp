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

from aiootp.asynchs import ConcurrencyGuard, DequePair
from aiootp.asynchs.guards.state_machine import (
    ConcurrencyGuardState,
    UnusedState,
    PendingState,
    RunningState,
    DoneState,
    ConcurrencyGuardUseTracker,
    IncoherentConcurrencyState,
    InvalidStateTransition,
)


USE_TRACKER_STATES = (
    UnusedState,
    PendingState,
    RunningState,
    DoneState,
)


def tuple_of_transitions(
    tracker: t.ConcurrencyGuardUseTrackerType,
) -> tuple[t.Callable[[], bool]]:
    return (
        tracker.transition_to_pending,
        tracker.transition_to_running,
        tracker.transition_to_done,
    )


def tuple_of_statuses(
    tracker: t.ConcurrencyGuardUseTrackerType,
) -> tuple[t.Callable[[], bool]]:
    return (
        tracker.is_unused,
        tracker.is_pending,
        tracker.is_running,
        tracker.is_done,
    )


POLICIES = tuple(ConcurrencyGuard.policies.values())


async def run_async_context(guard: t.ConcurrencyGuardType) -> None:
    async with guard:
        pass


async def run_sync_context(guard: t.ConcurrencyGuardType) -> None:
    with guard:
        pass


CONTEXT_RUNNERS = (run_async_context, run_sync_context)


class TestConcurrencyGuard:
    async def test_guard_state_machine_may_only_initialize_once(
        self,
    ) -> None:
        deques = DequePair()
        guard = ConcurrencyGuard(deques)

        problem = (
            "A ConcurrencyGuard's single-use state machine object was "
            "allowed to reinitialize."
        )
        with Ignore(InvalidStateTransition, if_else=violation(problem)):
            guard._use_tracker.__init__()

    @pytest.mark.parametrize("state", USE_TRACKER_STATES)
    async def test_only_valid_transitions_allowed(
        self,
        state: ConcurrencyGuardState,
    ) -> None:
        tracker = ConcurrencyGuardUseTracker()
        transitions = tuple_of_transitions(tracker)
        index = USE_TRACKER_STATES.index(state)
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
                InvalidStateTransition,
                if_else=violation(problem),
            ):
                transition()

    @pytest.mark.parametrize("state", USE_TRACKER_STATES)
    async def test_status_is_incoherent_after_invalid_transition(
        self,
        state: ConcurrencyGuardState,
    ) -> None:
        tracker = ConcurrencyGuardUseTracker()
        transitions = tuple_of_transitions(tracker)
        statuses = tuple_of_statuses(tracker)
        index = USE_TRACKER_STATES.index(state)
        for transition in transitions:
            try:
                tracker._state.append(state())

                assert statuses[index]()
                transition()
                assert statuses[index + 1]()

                continue
            except InvalidStateTransition:
                pass

            for status in statuses:
                assert not status()

            assert tracker.has_faulted()

    @pytest.mark.parametrize("policy_type", POLICIES)
    async def test_policy_must_be_instantiated(
        self,
        policy_type: t.ConcurrencyGuardPolicyType,
    ) -> None:
        deques = DequePair()
        problem = (
            "A non-instantiated policy was allowed as the provided policy."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            ConcurrencyGuard(deques, policy=policy_type)

        ConcurrencyGuard(deques, policy=policy_type())

    async def test_can_check_guard_is_and_equals(self) -> None:
        deques = DequePair()
        guard_0 = guard_0_ref = ConcurrencyGuard(deques)
        guard_1 = ConcurrencyGuard(deques)
        guard_2 = ConcurrencyGuard(deques)
        guards = [guard_0, guard_1]
        guards_set = set(guards)

        assert guard_0 == guard_0_ref
        assert guard_0 is guard_0_ref
        assert guard_0 != guard_1
        assert guard_0 is not guard_1
        assert guard_0 in guards
        assert guard_1 in guards
        assert guard_2 not in guards
        assert guard_0 in guards_set
        assert guard_1 in guards_set
        assert guard_2 not in guards_set

        problem = (  # fmt: skip
            "References to the same guard were reported to be unequal."
        )
        with Ignore(AssertionError, if_else=violation(problem)):
            assert guard_0 != guard_0_ref

        problem = (  # fmt: skip
            "References to the same guard were reported as not the same."
        )
        with Ignore(AssertionError, if_else=violation(problem)):
            assert guard_0 is not guard_0_ref

        problem = (  # fmt: skip
            "A list contains check for a guard falsely reported the "
            "guard was not present."
        )
        with Ignore(AssertionError, if_else=violation(problem)):
            assert guard_0 not in guards

        problem = (  # fmt: skip
            "A set contains check for a guard falsely reported the "
            "guard was not present."
        )
        with Ignore(AssertionError, if_else=violation(problem)):
            assert guard_0 not in guards_set

    async def test_detects_async_out_of_order_execution(self) -> None:
        error = IncoherentConcurrencyState
        problem = (  # fmt: skip
            "An exclusive guard's place at the front of the order queue "
            "was inappropriately changed while it was running."
        )
        with Ignore(error, if_else=violation(problem)):
            deques = DequePair()
            async with ConcurrencyGuard(deques):
                deques.queue.appendleft(ConcurrencyGuard(deques))

        with Ignore(error, if_else=violation(problem)):
            deques = DequePair()
            async with ConcurrencyGuard(deques):
                deques.queue[0] = ConcurrencyGuard(deques)

        with Ignore(IndexError, if_else=violation(problem)):
            deques = DequePair()
            async with ConcurrencyGuard(deques):
                deques.queue.popleft()

    async def test_detects_sync_out_of_order_execution(self) -> None:
        error = IncoherentConcurrencyState
        problem = (  # fmt: skip
            "An exclusive guard's place at the front of the order queue "
            "was inappropriately changed while it was running."
        )
        with Ignore(error, if_else=violation(problem)):
            deques = DequePair()
            with ConcurrencyGuard(deques):
                deques.queue.appendleft(ConcurrencyGuard(deques))

        with Ignore(error, if_else=violation(problem)):
            deques = DequePair()
            with ConcurrencyGuard(deques):
                deques.queue[0] = ConcurrencyGuard(deques)

        with Ignore(IndexError, if_else=violation(problem)):
            deques = DequePair()
            with ConcurrencyGuard(deques):
                deques.queue.popleft()

    async def test_guard_may_only_initialize_once(self) -> None:
        deques = DequePair()
        guard = ConcurrencyGuard(deques)

        problem = (
            "A single-use ConcurrencyGuard object was allowed to "
            "reinitialize."
        )
        with Ignore(PermissionError, if_else=violation(problem)):
            guard.__init__(deques)

    @pytest.mark.parametrize("first_context", CONTEXT_RUNNERS)
    @pytest.mark.parametrize("second_context", CONTEXT_RUNNERS)
    async def test_guard_may_only_be_used_once(
        self,
        first_context,
        second_context,
    ) -> None:
        deques = DequePair()

        await first_context(guard := ConcurrencyGuard(deques))

        problem = (
            f"After first entering {first_context=}, a single-use "
            f"ConcurrencyGuard object was allowed to then enter a "
            f"{second_context=} context manager."
        )
        with Ignore(InvalidStateTransition, if_else=violation(problem)):
            await second_context(guard)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
