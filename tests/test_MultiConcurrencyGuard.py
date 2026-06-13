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

from aiootp.asynchs.loops import gather, new_task
from aiootp.asynchs.guards import DefaultDictOfStates
from aiootp.asynchs.guards import MultiConcurrencyGaurd
from aiootp.asynchs.guards.manager import TargetState

from conftest import *


class RunFaultUseTracker(t.ConcurrencyGuardUseTracker):
    def transition_to_running(self, /) -> None:
        non_pending_states = [self.Unused(), self.Running(), self.Done()]
        self._state.append(choice(non_pending_states))
        super().transition_to_running()


class DoneFaultUseTracker(t.ConcurrencyGuardUseTracker):
    def transition_to_done(self, /) -> None:
        non_running_states = [self.Unused(), self.Pending(), self.Done()]
        self._state.append(choice(non_running_states))
        super().transition_to_done()


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
    async def test_adding_non_deques_is_not_allowed(self, value) -> None:
        mapping = DefaultDictOfStates()

        problem = (  # fmt: skip
            "A non-deque object was able to be set within the custom "
            "defaultdict object."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            mapping["setitem_test"] = value

        with Ignore(TypeError, if_else=violation(problem)):
            mapping.update(update_test=value)

    async def test_adding_deques_is_allowed(self) -> None:
        mapping = DefaultDictOfStates()

        mapping["setitem_test"] = TargetState()
        mapping.update(update_test=TargetState())

    async def test_adding_deque_subclass_is_allowed(self) -> None:
        class DequeSubclass(TargetState):
            pass

        mapping = DefaultDictOfStates()

        mapping["setitem_test"] = DequeSubclass()
        mapping.update(update_test=DequeSubclass())


class TestMultiConcurrencyGaurd:
    async def test_async_queue_execution_order_is_respected(self) -> None:
        async def record_ordering(
            target: t.Hashable,
            guard: t.ConcurrencyGuardType,
        ) -> None:
            await arandom_sleep(0.0001)

            async with guard:
                await arandom_sleep(0.0001)

                target_results.append(target)
                token_results[target].append(guard.token)

        guards = MultiConcurrencyGaurd()
        Policy = guards.policies.QueueManually

        unique_targets = [*range(64)]
        targets = 4 * unique_targets
        instances = [
            (target, guards.guard(target, policy=Policy()))
            for target in targets
        ]
        queues = defaultdict(list)
        for target, guard in instances:
            queues[target].append(guard.token)
            guards.targets[target].deques.queue.append(guard)

        target_results = []
        token_results = defaultdict(list)

        tasks = [
            record_ordering(target, guard) for target, guard in instances
        ]
        await gather(*tasks)

        # were all target executions run?
        assert sorted(target_results) == sorted(targets)

        # is the global execution order independent for different target
        # contexts?
        assert target_results != targets

        # is the same-target execution order respecting the order
        # declared by the target queue?
        for target, guard in instances:
            assert not guard.queue, target
            assert not guard.observers, target
            assert token_results[target] == queues[target]

    async def test_thread_queue_execution_order_is_respected(self) -> None:
        def record_ordering(
            target: t.Hashable,
            guard: t.ConcurrencyGuardType,
        ) -> None:
            random_sleep(0.0001)

            with guard:
                random_sleep(0.0001)

                target_results.append(target)
                token_results[target].append(guard.token)

        guards = MultiConcurrencyGaurd()
        Policy = guards.policies.QueueManually

        unique_targets = [*range(64)]
        targets = 4 * unique_targets
        instances = [
            (target, guards.guard(target, policy=Policy()))
            for target in targets
        ]
        queues = defaultdict(list)
        for target, guard in instances:
            queues[target].append(guard.token)
            guards.targets[target].deques.queue.append(guard)

        target_results = []
        token_results = defaultdict(list)

        with ThreadPoolExecutor(max_workers=len(targets)) as threads:
            results = threads.map(
                record_ordering,
                (target for target, _ in instances),
                (guard for _, guard in instances),
            )
            list(results)

        # were all target executions run?
        assert sorted(target_results) == sorted(targets)

        # is the global execution order independent for different target
        # contexts?
        assert target_results != targets

        # is the same-target execution order respecting the order
        # declared by the target queue?
        for target, guard in instances:
            assert not guard.queue, target
            assert not guard.observers, target
            assert token_results[target] == queues[target]

    async def test_free_async_queue_execution_order_is_respected(
        self,
    ) -> None:
        async def record_ordering(
            target: t.Hashable,
            guard: t.ConcurrencyGuardType,
        ) -> None:
            await arandom_sleep(0.0001)

            async with guard:
                await arandom_sleep(0.0001)

                if guard.policy.is_exclusive():
                    token_results[target].append(guard.token)
                    assert all(
                        obs.policy.is_exclusive() for obs in guard.observers
                    )
                    observers[target].pop()
                else:
                    assert not guard.observers[0].policy.is_exclusive()
                    observers[target].popleft()

                target_results.append(target)

        def choose_policy(target) -> t.ConcurrencyGuardPolicyType:
            return (
                guards.monitor(target, policy=NonExclusivePolicy())
                if token_bits(2)
                else guards.guard(target, policy=Policy())
            )

        guards = MultiConcurrencyGaurd()
        Policy = guards.policies.QueueManually
        NonExclusivePolicy = guards.policies.NonExclusiveQueueManually

        unique_targets = [*range(64)]
        targets = 4 * unique_targets
        instances = [(target, choose_policy(target)) for target in targets]
        queues = defaultdict(list)
        observers = defaultdict(deque)
        for target, guard in instances:
            guards.targets[target].deques.queue.append(guard)
            if guard.policy.is_exclusive():
                observers[target].append(guard)
                queues[target].append(guard.token)
            else:
                observers[target].appendleft(guard)

        target_results = []
        token_results = defaultdict(list)

        tasks = [
            record_ordering(target, guard) for target, guard in instances
        ]
        await gather(*tasks)

        # were all target executions run?
        assert sorted(target_results) == sorted(targets)

        # is the global execution order independent for different target
        # contexts?
        assert target_results != targets

        # is the same-target execution order respecting the order
        # declared by the target queue?
        for target, guard in instances:
            assert not guard.queue, target
            assert not guard.observers, target
            assert not observers[target], target
            assert target not in guards.targets, target
            if guard.policy.is_exclusive():
                assert token_results[target] == queues[target], target

    async def test_free_thread_queue_execution_order_is_respected(
        self,
    ) -> None:
        def record_ordering(
            target: t.Hashable,
            guard: t.ConcurrencyGuardType,
        ) -> None:
            random_sleep(0.0001)

            with guard:
                random_sleep(0.0001)

                if guard.policy.is_exclusive():
                    token_results[target].append(guard.token)
                    assert all(
                        obs.policy.is_exclusive() for obs in guard.observers
                    )
                    observers[target].pop()
                else:
                    assert not guard.observers[0].policy.is_exclusive()
                    observers[target].popleft()

                target_results.append(target)

        def choose_policy(target) -> t.ConcurrencyGuardPolicyType:
            return (
                guards.monitor(target, policy=NonExclusivePolicy())
                if token_bits(2)
                else guards.guard(target, policy=Policy())
            )

        guards = MultiConcurrencyGaurd()
        Policy = guards.policies.QueueManually
        NonExclusivePolicy = guards.policies.NonExclusiveQueueManually

        unique_targets = [*range(64)]
        targets = 4 * unique_targets
        instances = [(target, choose_policy(target)) for target in targets]
        queues = defaultdict(list)
        observers = defaultdict(deque)
        for target, guard in instances:
            guards.targets[target].deques.queue.append(guard)
            if guard.policy.is_exclusive():
                observers[target].append(guard)
                queues[target].append(guard.token)
            else:
                assert isinstance(queues[target], list)
                observers[target].appendleft(guard)

        target_results = []
        token_results = defaultdict(list)

        with ThreadPoolExecutor(max_workers=len(targets)) as threads:
            results = threads.map(
                record_ordering,
                (target for target, _ in instances),
                (guard for _, guard in instances),
            )
            list(results)

        # were all target executions run?
        assert sorted(target_results) == sorted(targets)

        # is the global execution order independent for different target
        # contexts?
        assert target_results != targets

        # is the same-target execution order respecting the order
        # declared by the target queue?
        for target, guard in instances:
            assert not guard.queue, target
            assert not guard.observers, target
            assert not observers[target], target
            assert target not in guards.targets, target
            if guard.policy.is_exclusive():
                assert token_results[target] == queues[target], target

    @pytest.mark.parametrize(
        "policy_cls",
        [*MultiConcurrencyGaurd.policies.values()],
    )
    async def test_guard_method_needs_exclusive_policy(
        self,
        policy_cls,
    ) -> None:
        guards = MultiConcurrencyGaurd()

        if issubclass(policy_cls, guards.policies.NonExclusive):
            problem = (  # fmt: skip
                "A non-exclusive policy was able to be passed into the "
                "guard() method."
            )
            with Ignore(TypeError, if_else=violation(problem)):
                guards.guard(target="test", policy=policy_cls())
        else:
            guards.guard(target="test", policy=policy_cls())

    @pytest.mark.parametrize(
        "policy_cls",
        [*MultiConcurrencyGaurd.policies.values()],
    )
    async def test_monitor_method_needs_non_exclusive_policy(
        self,
        policy_cls,
    ) -> None:
        guards = MultiConcurrencyGaurd()

        if issubclass(policy_cls, guards.policies.Exclusive):
            problem = (  # fmt: skip
                "An exclusive policy was able to be passed into the "
                "monitor() method."
            )
            with Ignore(TypeError, if_else=violation(problem)):
                guards.monitor(target="test", policy=policy_cls())
        else:
            guards.monitor(target="test", policy=policy_cls())

    async def test_async_references_cleaned_when_work_is_done(self) -> None:
        async def record_ordering(
            target: t.Hashable,
            guard: t.ConcurrencyGuardType,
            *,
            is_spontaneous: bool,
        ) -> None:
            await arandom_sleep(0.0001)

            async with guard:
                await arandom_sleep(0.0001)

                assert target in guards.targets
                if guard.policy.is_exclusive():
                    assert guard.token == guard.queue[0].token
                else:
                    assert guard.token not in guard.queue

                if is_spontaneous or token_bits(2):
                    return
                task = record_ordering(
                    target,
                    choose_policy(target),
                    is_spontaneous=True,
                )
                spontaneous_tasks.append(new_task(task))

        def choose_policy(target) -> t.ConcurrencyGuardPolicyType:
            return (
                guards.monitor(target)
                if token_bits(2)
                else guards.guard(target)
            )

        guards = MultiConcurrencyGaurd()

        unique_targets = [*range(64)]
        targets = 4 * unique_targets
        instances = [(target, choose_policy(target)) for target in targets]

        spontaneous_tasks = deque()
        tasks = [
            record_ordering(target, guard, is_spontaneous=False)
            for target, guard in instances
        ]
        await gather(*tasks)
        await gather(*spontaneous_tasks)

        # are the target references cleaned up after all work is done?
        for target in unique_targets:
            assert target not in guards.targets, target

        assert not guards.targets

    async def test_sync_references_cleaned_when_work_is_done(self) -> None:
        def record_ordering(
            target: t.Hashable,
            guard: t.ConcurrencyGuardType,
            *,
            is_spontaneous: bool,
        ) -> None:
            random_sleep(0.0001)

            with guard:
                random_sleep(0.0001)

                assert target in guards.targets
                if guard.policy.is_exclusive():
                    assert guard.token == guard.queue[0].token
                else:
                    assert guard.token not in guard.queue

                if is_spontaneous or token_bits(2):
                    return

                task = spontaneous_threads.submit(
                    record_ordering,
                    target,
                    choose_policy(target),
                    is_spontaneous=True,
                )
                spontaneous_tasks.append(task)

        def choose_policy(target) -> t.ConcurrencyGuardPolicyType:
            return (
                guards.monitor(target)
                if token_bits(2)
                else guards.guard(target)
            )

        guards = MultiConcurrencyGaurd()

        unique_targets = [*range(64)]
        targets = 4 * unique_targets
        instances = [(target, choose_policy(target)) for target in targets]

        spontaneous_tasks = deque()
        spontaneous_threads = ThreadPoolExecutor(max_workers=len(targets))
        with ThreadPoolExecutor(max_workers=len(targets)) as threads:
            results = threads.map(
                partial(record_ordering, is_spontaneous=False),
                (target for target, _ in instances),
                (guard for _, guard in instances),
            )
            list(results)
        with spontaneous_threads:
            for task in spontaneous_tasks:
                task.result()

        # are the target references cleaned up after all work is done?
        for target in unique_targets:
            assert target not in guards.targets, target

        assert not guards.targets

    async def test_async_references_cleaned_if_queue_faults(
        self,
    ) -> None:
        guards = MultiConcurrencyGaurd()
        guard = guards.guard(0)

        problem = (  # fmt: skip
            "A faulty order queue was not detected."
        )
        with Ignore(IncoherentConcurrencyState, if_else=violation(problem)):
            async with guard:
                guard.queue[0] = guards.guard(0)

        assert not guard.queue
        assert not guard.observers

        assert not guards.targets

    async def test_sync_references_cleaned_if_queue_faults(
        self,
    ) -> None:
        guards = MultiConcurrencyGaurd()
        guard = guards.guard(0)

        problem = (  # fmt: skip
            "A faulty order queue was not detected."
        )
        async with Ignore(
            IncoherentConcurrencyState,
            if_else=violation(problem),
        ):
            with guard:
                guard.queue[0] = guards.guard(0)

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

        assert not guard.queue
        assert not guard.observers

        assert not guards.targets

    async def test_async_policy_pops_during_done_fault_align_with_convention(
        self,
    ) -> None:
        async def catch_incoherence(guard: t.ConcurrencyGuardType) -> None:
            try:
                async with guard:
                    while any(g.is_unused() for g in instances):
                        await asleep(guard.probe_delay)

                    if guard.policy.is_exclusive():
                        assert all(
                            obs.policy.is_exclusive()
                            for obs in guard.observers
                        )
                        guard.queue[0] = guards.monitor(0)
                    else:
                        assert not guard.observers[0].policy.is_exclusive()
            except IncoherentConcurrencyState as error:
                assert guard.has_faulted()

                if not guard.policy.is_exclusive():
                    raise error

        def choose_policy() -> t.ConcurrencyGuardPolicyType:
            return guards.monitor(0) if token_bits(2) else guards.guard(0)

        guards = MultiConcurrencyGaurd()
        instances = [choose_policy() for _ in range(64)]

        tasks = [catch_incoherence(guard) for guard in instances]
        await gather(*tasks)

        for guard in instances:
            assert not guard.observers
            assert not guard.queue

        assert not guards.targets

    async def test_sync_policy_pops_during_done_fault_align_with_convention(
        self,
    ) -> None:
        def catch_incoherence(guard: t.ConcurrencyGuardType) -> None:
            try:
                with guard:
                    while any(g.is_unused() for g in instances):
                        sleep(guard.probe_delay)

                    if guard.policy.is_exclusive():
                        assert all(
                            obs.policy.is_exclusive()
                            for obs in guard.observers
                        )
                        guard.queue[0] = guards.monitor(0)
                    else:
                        assert not guard.observers[0].policy.is_exclusive()
            except IncoherentConcurrencyState as error:
                assert guard.has_faulted()

                if not guard.policy.is_exclusive():
                    raise error

        def choose_policy() -> t.ConcurrencyGuardPolicyType:
            return guards.monitor(0) if token_bits(2) else guards.guard(0)

        guards = MultiConcurrencyGaurd()
        instances = [choose_policy() for _ in range(64)]

        with ThreadPoolExecutor(max_workers=len(instances)) as threads:
            list(threads.map(catch_incoherence, instances))

        for guard in instances:
            assert not guard.observers
            assert not guard.queue

        assert not guards.targets

    async def test_async_use_tracker_stages(self) -> None:
        async def track_stages(
            _: t.Hashable,
            guard: t.ConcurrencyGuardType,
        ) -> None:
            await arandom_sleep(0.0001)
            assert guard.is_unused()
            assert not guard.is_pending()
            assert not guard.is_running()
            assert not guard.is_done()

            guard.policy.use(guard)
            assert not guard.is_unused()
            assert guard.is_pending()
            assert not guard.is_running()
            assert not guard.is_done()

            tracker = guard._use_tracker
            tracker._state.append(tracker.Unused())
            assert guard.is_unused()
            assert not guard.is_pending()
            assert not guard.is_running()
            assert not guard.is_done()

            async with guard:
                await arandom_sleep(0.0001)
                assert not guard.is_unused()
                assert not guard.is_pending()
                assert guard.is_running()
                assert not guard.is_done()

            assert not guard.is_unused()
            assert not guard.is_pending()
            assert not guard.is_running()
            assert guard.is_done()

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
            assert guard.is_unused()
            assert not guard.is_pending()
            assert not guard.is_running()
            assert not guard.is_done()

            guard.policy.use(guard)
            assert not guard.is_unused()
            assert guard.is_pending()
            assert not guard.is_running()
            assert not guard.is_done()

            tracker = guard._use_tracker
            tracker._state.append(tracker.Unused())
            assert guard.is_unused()
            assert not guard.is_pending()
            assert not guard.is_running()
            assert not guard.is_done()

            with guard:
                random_sleep(0.0001)
                assert not guard.is_unused()
                assert not guard.is_pending()
                assert guard.is_running()
                assert not guard.is_done()

            assert not guard.is_unused()
            assert not guard.is_pending()
            assert not guard.is_running()
            assert guard.is_done()

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

    async def test_use_tracker_stages_manually(self) -> None:
        guards = MultiConcurrencyGaurd()

        for guard in [guards.monitor(0), guards.guard(0)]:
            assert guard.is_unused()
            assert not guard.is_pending()
            assert not guard.is_running()
            assert not guard.is_done()

            guard._use_tracker.transition_to_pending()
            assert not guard.is_unused()
            assert guard.is_pending()
            assert not guard.is_running()
            assert not guard.is_done()

            guard._use_tracker.transition_to_running()
            assert not guard.is_unused()
            assert not guard.is_pending()
            assert guard.is_running()
            assert not guard.is_done()

            guard._use_tracker.transition_to_done()
            assert not guard.is_unused()
            assert not guard.is_pending()
            assert not guard.is_running()
            assert guard.is_done()


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
