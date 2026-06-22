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


from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from threading import Lock

from aiootp.asynchs.loops import gather, new_task
from aiootp.asynchs import DefaultDictOfStates, DequePair
from aiootp.asynchs import ConcurrencyGuard, MultiConcurrencyGaurd
from aiootp.asynchs.guards.manager import TargetState
from aiootp.asynchs.guards.state_machine import (
    ConcurrencyGuardUseTracker,
    IncoherentConcurrencyState,
    InvalidStateTransition,
)
from aiootp.asynchs.guards.policies import (
    ExclusivePolicy,
    QueueManuallyPolicy,
    NonExclusivePolicy,
    NonExclusiveQueueManuallyPolicy,
)

from conftest import *


GUARD_STATUSES = (
    (IS_UNUSED := "is_unused"),
    (IS_PENDING := "is_pending"),
    (IS_RUNNING := "is_running"),
    (IS_DONE := "is_done"),
    (HAS_FAULTED := "has_faulted"),
)

POLICIES = tuple(MultiConcurrencyGaurd.policies.values())


class PopFaultQueue(deque):
    def popleft(self, /) -> t.ConcurrencyGuardType:
        correct_guard = super().popleft()
        incorrect_guard = ConcurrencyGuard(
            correct_guard.deques,
            policy=NonExclusivePolicy(),
        )
        return incorrect_guard


class PopFaultDequePair(DequePair):
    __slots__ = ()

    def __init__(self, /) -> None:
        self.queue = PopFaultQueue()
        self.observers = deque()


class PopFaultTargetState(TargetState):
    _DequePair: type = PopFaultDequePair


class PopFaultDefaultDictOfStates(DefaultDictOfStates):
    _TargetState: type = PopFaultTargetState


class PopFaultMultiConcurrencyGaurd(MultiConcurrencyGaurd):
    _Targets: type = PopFaultDefaultDictOfStates


class RunFaultUseTracker(ConcurrencyGuardUseTracker):
    def transition_to_running(self, /) -> None:
        non_pending_states = [self.Unused(), self.Running(), self.Done()]
        self._state.append(choice(non_pending_states))
        super().transition_to_running()


class DoneFaultUseTracker(ConcurrencyGuardUseTracker):
    def transition_to_done(self, /) -> None:
        non_running_states = [self.Unused(), self.Pending(), self.Done()]
        self._state.append(choice(non_running_states))
        super().transition_to_done()


def is_exclusive(guard: t.ConcurrencyGuardType) -> bool:
    return guard.policy.is_exclusive()


class TestDefaultDictOfStates:
    @given(
        value=st.one_of(
            st.none(),
            st.booleans(),
            st.integers(),
            st.floats(),
            st.text(),
            st.lists(st.binary(max_size=64)),
            st.tuples(st.binary(max_size=64)),
        ),
    )
    async def test_adding_non_states_is_not_allowed(self, value) -> None:
        mapping = DefaultDictOfStates()

        problem = (  # fmt: skip
            "A non-state object was able to be set within the custom "
            "defaultdict object."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            mapping["setitem_test"] = value

        with Ignore(TypeError, if_else=violation(problem)):
            mapping.update(update_test=value)

    async def test_adding_states_is_allowed(self) -> None:
        mapping = DefaultDictOfStates()

        mapping["setitem_test"] = TargetState()
        mapping.update(update_test=TargetState())

    async def test_adding_state_subclass_is_allowed(self) -> None:
        class StateSubclass(TargetState):
            pass

        mapping = DefaultDictOfStates()

        mapping["setitem_test"] = StateSubclass()
        mapping.update(update_test=StateSubclass())


class TestMultiConcurrencyGaurd:
    def check_guard_status(
        self,
        guard: t.ConcurrencyGuardType,
        correct_status_method: str,
    ) -> None:
        for status in GUARD_STATUSES:
            is_status = getattr(guard, status)()
            if status == correct_status_method:
                assert is_status, (correct_status_method, status)
            else:
                assert not is_status, (correct_status_method, status)

    def non_exclusive_guards_group_correctly_during_runtime(
        self,
        target: t.Hashable,
        control_group: list[t.ConcurrencyGuardType],
        group: list[bytes],
    ) -> None:
        exclusive_guard_indexes = [
            i
            for i, guard in enumerate(control_group)
            if is_exclusive(guard)
        ]
        for i in exclusive_guard_indexes:
            assert control_group[i] == group[i], (i, target)
            assert set(control_group[:i]) == set(group[:i]), (i, target)
            assert set(control_group[i:]) == set(group[i:]), (i, target)

    @pytest.mark.parametrize("policy_type", POLICIES)
    async def test_guard_method_needs_exclusive_policy(
        self,
        policy_type,
    ) -> None:
        guards = MultiConcurrencyGaurd()

        if issubclass(policy_type, NonExclusivePolicy):
            problem = (  # fmt: skip
                "A non-exclusive policy was able to be passed into the "
                "guard() method."
            )
            with Ignore(TypeError, if_else=violation(problem)):
                guards.guard(target="test", policy=policy_type())
        else:
            guards.guard(target="test", policy=policy_type())

    @pytest.mark.parametrize("policy_type", POLICIES)
    async def test_monitor_method_needs_non_exclusive_policy(
        self,
        policy_type,
    ) -> None:
        guards = MultiConcurrencyGaurd()

        if issubclass(policy_type, ExclusivePolicy):
            problem = (  # fmt: skip
                "An exclusive policy was able to be passed into the "
                "monitor() method."
            )
            with Ignore(TypeError, if_else=violation(problem)):
                guards.monitor(target="test", policy=policy_type())
        else:
            guards.monitor(target="test", policy=policy_type())

    async def test_use_tracker_stages_manually(self) -> None:
        guards = MultiConcurrencyGaurd()

        for guard in [guards.monitor(0), guards.guard(0)]:
            self.check_guard_status(guard, IS_UNUSED)

            guard._use_tracker.transition_to_pending()
            self.check_guard_status(guard, IS_PENDING)

            guard._use_tracker.transition_to_running()
            self.check_guard_status(guard, IS_RUNNING)

            guard._use_tracker.transition_to_done()
            self.check_guard_status(guard, IS_DONE)

            guard._use_tracker.enter_fault_state()
            self.check_guard_status(guard, HAS_FAULTED)

    async def test_async_use_tracker_stages(self) -> None:
        async def track_stages(
            _: t.Hashable,
            guard: t.ConcurrencyGuardType,
        ) -> None:
            await arandom_sleep(0.0001)
            self.check_guard_status(guard, IS_UNUSED)

            guard.policy.use(guard)
            self.check_guard_status(guard, IS_PENDING)

            tracker = guard._use_tracker
            tracker._state.append(tracker.Unused())
            self.check_guard_status(guard, IS_UNUSED)

            async with guard:
                await arandom_sleep(0.0001)
                self.check_guard_status(guard, IS_RUNNING)

            self.check_guard_status(guard, IS_DONE)

            tracker.enter_fault_state()
            self.check_guard_status(guard, HAS_FAULTED)

        def choose_policy(target) -> t.ConcurrencyGuardPolicyType:
            return (
                guards.monitor(target)
                if token_bits(2)
                else guards.guard(target)
            )

        guards = MultiConcurrencyGaurd()

        unique_targets = [*range(16)]
        targets = 4 * unique_targets
        instances = [(target, choose_policy(target)) for target in targets]

        tasks = [track_stages(target, guard) for target, guard in instances]
        await gather(*tasks)

    async def test_sync_use_tracker_stages(self) -> None:
        def track_stages(
            _: t.Hashable,
            guard: t.ConcurrencyGuardType,
        ) -> None:
            random_sleep(0.0001)
            self.check_guard_status(guard, IS_UNUSED)

            guard.policy.use(guard)
            self.check_guard_status(guard, IS_PENDING)

            tracker = guard._use_tracker
            tracker._state.append(tracker.Unused())
            self.check_guard_status(guard, IS_UNUSED)

            with guard:
                random_sleep(0.0001)
                self.check_guard_status(guard, IS_RUNNING)

            self.check_guard_status(guard, IS_DONE)

            tracker.enter_fault_state()
            self.check_guard_status(guard, HAS_FAULTED)

        def choose_policy(target) -> t.ConcurrencyGuardPolicyType:
            return (
                guards.monitor(target)
                if token_bits(2)
                else guards.guard(target)
            )

        guards = MultiConcurrencyGaurd()

        unique_targets = [*range(16)]
        targets = 4 * unique_targets
        instances = [(target, choose_policy(target)) for target in targets]

        with ThreadPoolExecutor(max_workers=len(targets)) as threads:
            results = threads.map(
                track_stages,
                (target for target, _ in instances),
                (guard for _, guard in instances),
            )
            list(results)

    async def test_async_references_cleaned_if_queue_faults(
        self,
    ) -> None:
        guards = MultiConcurrencyGaurd()
        guard = guards.guard(0)
        bad_guard = guards.guard(0)

        problem = (  # fmt: skip
            "A faulty order queue was not detected."
        )
        with Ignore(IncoherentConcurrencyState, if_else=violation(problem)):
            async with guard:
                assert guard.queue == deque([guard])
                # simulate another guard taking control of the order queue
                # from the exclusive context. this is never ok, and will
                # likely cause a deadlock if it happens.
                guard.queue[0] = bad_guard

        # the reference objects were cleaned up
        assert not guard.queue
        assert not guard.observers
        assert not guards.targets

    async def test_sync_references_cleaned_if_queue_faults(
        self,
    ) -> None:
        guards = MultiConcurrencyGaurd()
        guard = guards.guard(0)
        bad_guard = guards.guard(0)

        problem = (  # fmt: skip
            "A faulty order queue was not detected."
        )
        async with Ignore(
            IncoherentConcurrencyState,
            if_else=violation(problem),
        ):
            with guard:
                assert guard.queue == deque([guard])
                # simulate another guard taking control of the order queue
                # from the exclusive context. this is never ok, and will
                # likely cause a deadlock if it happens.
                guard.queue[0] = bad_guard

        # the reference objects were cleaned up
        assert not guard.queue
        assert not guard.observers
        assert not guards.targets

    async def test_async_references_cleaned_if_run_transition_faults(
        self,
    ) -> None:
        guards = MultiConcurrencyGaurd()

        for guard in (guards.monitor(0), guards.guard(0)):
            object.__setattr__(guard, "_use_tracker", RunFaultUseTracker())

            problem = (  # fmt: skip
                "A faulty state manager was not detected."
            )
            with Ignore(InvalidStateTransition, if_else=violation(problem)):
                async with guard:
                    pass

            # the reference objects were cleaned up
            assert not guard.queue
            assert not guard.observers
            assert not guards.targets

    async def test_sync_references_cleaned_if_run_transition_faults(
        self,
    ) -> None:
        guards = MultiConcurrencyGaurd()

        for guard in (guards.monitor(0), guards.guard(0)):
            object.__setattr__(guard, "_use_tracker", RunFaultUseTracker())

            problem = (  # fmt: skip
                "A faulty state manager was not detected."
            )
            async with Ignore(
                InvalidStateTransition,
                if_else=violation(problem),
            ):
                with guard:
                    pass

            # the reference objects were cleaned up
            assert not guard.queue
            assert not guard.observers
            assert not guards.targets

    async def test_async_references_cleaned_if_non_exclusive_can_run_faults(
        self,
    ) -> None:
        guards = PopFaultMultiConcurrencyGaurd()
        guard = guards.monitor(0)

        problem = (  # fmt: skip
            "A faulty order queue was not detected when a non-exclusive "
            "guard attempted to pop itself off the order queue before "
            "running."
        )
        with Ignore(IncoherentConcurrencyState, if_else=violation(problem)):
            async with guard:
                pytest.fail(problem)

        # the reference objects were cleaned up
        assert not guard.queue
        assert not guard.observers
        assert not guards.targets

    async def test_sync_references_cleaned_if_non_exclusive_can_run_faults(
        self,
    ) -> None:
        guards = PopFaultMultiConcurrencyGaurd()
        guard = guards.monitor(0)

        problem = (  # fmt: skip
            "A faulty order queue was not detected when a non-exclusive "
            "guard attempted to pop itself off the order queue before "
            "running."
        )
        async with Ignore(
            IncoherentConcurrencyState,
            if_else=violation(problem),
        ):
            with guard:
                pytest.fail(problem)

        # the reference objects were cleaned up
        assert not guard.queue
        assert not guard.observers
        assert not guards.targets

    async def test_async_references_cleaned_if_done_transition_faults(
        self,
    ) -> None:
        guards = MultiConcurrencyGaurd()

        guard = guards.guard(0)
        object.__setattr__(guard, "_use_tracker", DoneFaultUseTracker())

        problem = (  # fmt: skip
            "A faulty state manager was not detected."
        )
        with Ignore(InvalidStateTransition, if_else=violation(problem)):
            async with guard:
                pass

        # the reference objects were cleaned up
        assert not guard.queue
        assert not guard.observers
        assert not guards.targets

    async def test_sync_references_cleaned_if_done_transition_faults(
        self,
    ) -> None:
        guards = MultiConcurrencyGaurd()

        guard = guards.guard(0)
        object.__setattr__(guard, "_use_tracker", DoneFaultUseTracker())

        problem = (  # fmt: skip
            "A faulty state manager was not detected."
        )
        async with Ignore(
            InvalidStateTransition,
            if_else=violation(problem),
        ):
            with guard:
                pass

        # the reference objects were cleaned up
        assert not guard.queue
        assert not guard.observers
        assert not guards.targets

    @settings(deadline=None, max_examples=1)
    @given(
        unique_target_count=st.integers(min_value=32, max_value=40),
        guards_per_target=st.integers(min_value=5, max_value=7),
    )
    async def test_free_async_queue_execution_order_is_respected(
        self,
        unique_target_count: int,
        guards_per_target: int,
    ) -> None:
        async def record_ordering(
            target: t.Hashable,
            guard: t.ConcurrencyGuardType,
            *,
            is_spontaneous: bool,
        ) -> None:
            await arandom_sleep(0.0001)
            async with guard:
                await arandom_sleep(0.0001)

                target_results.append(target)
                groups[target].append(guard)

                # the target reference shouldn't be cleared while a
                # guard is running
                assert target in guards.targets

                # avoid iteration during concurrent mutation
                obs = guard.observers.copy()

                if is_exclusive(guard):
                    # this guard should still be holding up the queue
                    assert guard is guard.queue[0], target

                    # no non-exclusive guards are running
                    assert all(is_exclusive(ob) for ob in obs), target
                else:
                    # this guard should've removed itself before starting
                    assert guard not in guard.queue, target

                    # at least one non-exclusive guard should be here
                    assert not is_exclusive(obs[0]), target

                if is_spontaneous:
                    targets.append(target)
                    return
                elif token_bits(2):
                    return

                task = record_ordering(
                    target,
                    await choose_policy(target),
                    is_spontaneous=True,
                )
                spontaneous_tasks.append(new_task(task))

        async def choose_policy(target) -> t.ConcurrencyGuardPolicyType:
            guard = (
                guards.monitor(target, policy=NonExclusivePolicy())
                if token_bits(2)
                else guards.guard(target, policy=Policy())
            )
            with resource_lock:
                control_groups[target].append(guard)
                guards.targets[target].deques.queue.append(guard)
            return guard

        guards = MultiConcurrencyGaurd()
        Policy = QueueManuallyPolicy
        NonExclusivePolicy = NonExclusiveQueueManuallyPolicy

        unique_targets = deque(range(unique_target_count))
        targets = guards_per_target * unique_targets
        control_groups = defaultdict(deque)
        resource_lock = Lock()
        instances = [
            (target, await choose_policy(target)) for target in targets
        ]

        target_results = deque()
        groups = defaultdict(deque)

        # gather up & run all tasks
        spontaneous_tasks = deque()
        tasks = [
            record_ordering(target, guard, is_spontaneous=False)
            for target, guard in instances
        ]
        await gather(*tasks)
        await gather(*spontaneous_tasks)

        # were all target executions run?
        assert sorted(target_results) == sorted(targets)

        # is the global execution order independent for different target
        # contexts?
        assert target_results != targets

        # were all target references & deques cleaned after use?
        for target, guard in instances:
            assert not guard.queue, target
            assert not guard.observers, target
            assert target not in guards.targets, target

        assert not guards.targets

        # did all non-exclusive guards run before the exclusive guards
        # scheduled after them?
        for target, control_group in control_groups.items():
            self.non_exclusive_guards_group_correctly_during_runtime(
                target,
                control_group=list(control_group),
                group=list(groups[target]),
            )

    @settings(deadline=None, max_examples=1)
    @given(
        unique_target_count=st.integers(min_value=32, max_value=40),
        guards_per_target=st.integers(min_value=5, max_value=7),
    )
    async def test_free_thread_queue_execution_order_is_respected(
        self,
        unique_target_count: int,
        guards_per_target: int,
    ) -> None:
        def record_ordering(
            target: t.Hashable,
            guard: t.ConcurrencyGuardType,
            *,
            is_spontaneous: bool,
        ) -> None:
            random_sleep(0.0001)
            with guard:
                random_sleep(0.0001)

                target_results.append(target)
                groups[target].append(guard)

                # the target reference shouldn't be cleared while a
                # guard is running
                assert target in guards.targets

                # avoid iteration during concurrent mutation
                obs = guard.observers.copy()

                if is_exclusive(guard):
                    # this guard should still be holding up the queue
                    assert guard is guard.queue[0], target

                    # no non-exclusive guards are running
                    assert all(is_exclusive(ob) for ob in obs), target
                else:
                    # this guard should've removed itself before starting
                    assert guard not in guard.queue, target

                    # at least one non-exclusive guard should be here
                    assert not is_exclusive(obs[0]), target

                if is_spontaneous:
                    targets.append(target)
                    return
                elif token_bits(2):
                    return

                task = spontaneous_threads.submit(
                    record_ordering,
                    target,
                    choose_policy(target),
                    is_spontaneous=True,
                )
                spontaneous_tasks.append(task)

        def choose_policy(target) -> t.ConcurrencyGuardPolicyType:
            guard = (
                guards.monitor(target, policy=NonExclusivePolicy())
                if token_bits(2)
                else guards.guard(target, policy=Policy())
            )
            with resource_lock:
                control_groups[target].append(guard)
                guards.targets[target].deques.queue.append(guard)
            return guard

        guards = MultiConcurrencyGaurd()
        Policy = QueueManuallyPolicy
        NonExclusivePolicy = NonExclusiveQueueManuallyPolicy

        unique_targets = deque(range(unique_target_count))
        targets = guards_per_target * unique_targets
        workers = len(targets)
        control_groups = defaultdict(deque)
        resource_lock = Lock()
        instances = [(target, choose_policy(target)) for target in targets]

        target_results = deque()
        groups = defaultdict(deque)

        # gather up & run all tasks
        spontaneous_tasks = deque()
        spontaneous_threads = ThreadPoolExecutor(max_workers=workers)
        with ThreadPoolExecutor(max_workers=workers) as threads:
            results = threads.map(
                partial(record_ordering, is_spontaneous=False),
                (target for target, _ in instances),
                (guard for _, guard in instances),
            )
            list(results)
        with spontaneous_threads:
            for task in spontaneous_tasks:
                task.result()

        # were all target executions run?
        assert sorted(target_results) == sorted(targets)

        # is the global execution order independent for different target
        # contexts?
        assert target_results != targets

        # were all target references & deques cleaned after use?
        for target, guard in instances:
            assert not guard.queue, target
            assert not guard.observers, target
            assert target not in guards.targets, target

        assert not guards.targets

        # did all non-exclusive guards run before the exclusive guards
        # scheduled after them?
        for target, control_group in control_groups.items():
            self.non_exclusive_guards_group_correctly_during_runtime(
                target,
                control_group=list(control_group),
                group=list(groups[target]),
            )

    async def test_async_policy_pops_during_done_fault_align_with_convention(
        self,
    ) -> None:
        async def catch_incoherence(guard: t.ConcurrencyGuardType) -> None:
            try:
                await arandom_sleep(0.0001)
                async with guard:
                    await arandom_sleep(0.0001)

                    group.append(guard)
                    while any(g.is_unused() for g in instances):
                        await asleep(guard.probe_delay)

                    # avoid iteration during concurrent mutation
                    obs = guard.observers.copy()

                    if is_exclusive(guard):
                        # this guard should still be holding up the queue
                        assert guard is guard.queue[0], target

                        # no non-exclusive guards are running
                        assert all(is_exclusive(ob) for ob in obs), target

                        guard.queue[0] = guards.monitor(0)
                    else:
                        # this guard should've removed itself before starting
                        assert guard not in guard.queue, target

                        # at least one non-exclusive guard should be here
                        assert not is_exclusive(obs[0]), target
            except IncoherentConcurrencyState as error:
                assert guard.has_faulted()

                if not is_exclusive(guard):
                    raise error

        def choose_policy() -> t.ConcurrencyGuardPolicyType:
            guard = (
                guards.monitor(target, policy=NonExclusivePolicy())
                if token_bits(2)
                else guards.guard(target, policy=Policy())
            )
            guards.targets[target].deques.queue.append(guard)
            return guard

        guards = MultiConcurrencyGaurd()
        Policy = QueueManuallyPolicy
        NonExclusivePolicy = NonExclusiveQueueManuallyPolicy

        target = 0
        group = deque()
        instances = [choose_policy() for _ in range(32)]

        # gather up & run all tasks
        tasks = [catch_incoherence(guard) for guard in instances]
        await gather(*tasks)

        # were all target references & deques cleaned after use?
        for guard in instances:
            assert not guard.observers
            assert not guard.queue

        assert not guards.targets

        # did all non-exclusive guards run before the exclusive guards
        # scheduled after them?
        self.non_exclusive_guards_group_correctly_during_runtime(
            target,
            control_group=instances,
            group=list(group),
        )

    async def test_sync_policy_pops_during_done_fault_align_with_convention(
        self,
    ) -> None:
        def catch_incoherence(guard: t.ConcurrencyGuardType) -> None:
            try:
                random_sleep(0.0001)
                with guard:
                    random_sleep(0.0001)

                    group.append(guard)
                    while any(g.is_unused() for g in instances):
                        sleep(guard.probe_delay)

                    # avoid iteration during concurrent mutation
                    obs = guard.observers.copy()

                    if is_exclusive(guard):
                        # this guard should still be holding up the queue
                        assert guard is guard.queue[0], target

                        # no non-exclusive guards are running
                        assert all(is_exclusive(ob) for ob in obs), target

                        guard.queue[0] = guards.monitor(0)
                    else:
                        # this guard should've removed itself before starting
                        assert guard not in guard.queue, target

                        # at least one non-exclusive guard should be here
                        assert not is_exclusive(obs[0]), target
            except IncoherentConcurrencyState as error:
                assert guard.has_faulted()

                if not is_exclusive(guard):
                    raise error

        def choose_policy() -> t.ConcurrencyGuardPolicyType:
            guard = (
                guards.monitor(target, policy=NonExclusivePolicy())
                if token_bits(2)
                else guards.guard(target, policy=Policy())
            )
            guards.targets[target].deques.queue.append(guard)
            return guard

        guards = MultiConcurrencyGaurd()
        Policy = QueueManuallyPolicy
        NonExclusivePolicy = NonExclusiveQueueManuallyPolicy

        target = 0
        group = deque()
        instances = [choose_policy() for _ in range(32)]

        # gather up & run all tasks
        with ThreadPoolExecutor(max_workers=len(instances)) as threads:
            list(threads.map(catch_incoherence, instances))

        # were all target references & deques cleaned after use?
        for guard in instances:
            assert not guard.observers
            assert not guard.queue

        assert not guards.targets

        # did all non-exclusive guards run before the exclusive guards
        # scheduled after them?
        self.non_exclusive_guards_group_correctly_during_runtime(
            target,
            control_group=instances,
            group=list(group),
        )


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
