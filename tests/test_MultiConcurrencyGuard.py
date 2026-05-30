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

from aiootp.asynchs.loops import gather, new_task
from aiootp.asynchs.guard_manager import DefaultDictOfDeques
from aiootp.asynchs.guard_manager import MultiConcurrencyGaurd

from conftest import *


class TestDefaultDictOfDeques:
    @given(
        value=st.one_of(
            st.none(),
            st.booleans(),
            st.integers(),
            st.floats(),
            st.text(),
            st.lists(st.binary(max_size=64)),
            st.tuples(st.binary(max_size=64)),
        )
    )
    async def test_adding_non_deques_is_not_allowed(self, value) -> None:
        mapping = DefaultDictOfDeques()

        problem = (  # fmt: skip
            "A non-deque object was able to be set within the custom "
            "defaultdict object."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            mapping["setitem_test"] = value

        with Ignore(TypeError, if_else=violation(problem)):
            mapping.update(update_test=value)

    async def test_adding_deques_is_allowed(self) -> None:
        mapping = DefaultDictOfDeques()

        mapping["setitem_test"] = deque()
        mapping.update(update_test=deque())

    async def test_adding_deque_subclass_is_allowed(self) -> None:
        class DequeSubclass(deque):
            pass

        mapping = DefaultDictOfDeques()

        mapping["setitem_test"] = DequeSubclass()
        mapping.update(update_test=DequeSubclass())


class TestMultiConcurrencyGaurd:
    async def test_async_queue_execution_order_is_respected(self) -> None:
        async def record_ordering(
            target: t.Hashable, instance: MultiConcurrencyGaurd
        ) -> None:
            await arandom_sleep(0.0001)
            async with instance:
                await arandom_sleep(0.0001)
                target_results.append(target)
                token_results[target].append(instance.token)

        guards = MultiConcurrencyGaurd()
        Policy = guards.policies.QueueManually

        unique_targets = [*range(64)]
        targets = 4 * unique_targets
        instances = [
            (target, guards.guard(target, policy=Policy()))
            for target in targets
        ]
        queues = defaultdict(list)
        for target, instance in instances:
            queues[target].append(instance.token)
            guards.queues[target].append(instance)

        target_results = []
        token_results = defaultdict(list)
        tasks = [
            record_ordering(target, instance)
            for target, instance in instances
        ]
        await gather(*tasks)

        # were all target executions run?
        assert sorted(target_results) == sorted(targets)

        # is the global execution order independent for different target
        # contexts?
        assert target_results != targets

        # is the same-target execution order respecting the order
        # declared by the target queue?
        for _, (target, instance) in zip(unique_targets, instances):
            assert not instance.queue, target
            assert not instance.observers, target
            assert token_results[target] == queues[target]

    async def test_thread_queue_execution_order_is_respected(self) -> None:
        def record_ordering(
            items: t.Tuple[t.Hashable, MultiConcurrencyGaurd],
        ) -> None:
            target, instance = items
            random_sleep(0.0001)
            with instance:
                random_sleep(0.0001)
                target_results.append(target)
                token_results[target].append(instance.token)

        guards = MultiConcurrencyGaurd()
        Policy = guards.policies.QueueManually

        unique_targets = [*range(64)]
        targets = 4 * unique_targets
        instances = [
            (target, guards.guard(target, policy=Policy()))
            for target in targets
        ]
        queues = defaultdict(list)
        for target, instance in instances:
            queues[target].append(instance.token)
            guards.queues[target].append(instance)

        target_results = []
        token_results = defaultdict(list)
        tasks = [
            Threads._type(target=record_ordering, args=(items,))
            for items in instances
        ]
        for task in tasks:
            task.start()
        for task in tasks:
            task.join()

        # were all target executions run?
        assert sorted(target_results) == sorted(targets)

        # is the global execution order independent for different target
        # contexts?
        assert target_results != targets

        # is the same-target execution order respecting the order
        # declared by the target queue?
        for _, (target, instance) in zip(unique_targets, instances):
            assert not instance.queue, target
            assert not instance.observers, target
            assert token_results[target] == queues[target]

    async def test_free_async_queue_execution_order_is_respected(
        self,
    ) -> None:
        async def record_ordering(
            target: t.Hashable, instance: MultiConcurrencyGaurd
        ) -> None:
            await arandom_sleep(0.0001)
            async with instance:
                await arandom_sleep(0.0001)
                if instance.policy.is_exclusive():
                    token_results[target].append(instance.token)
                    assert all(
                        obs.policy.is_exclusive()
                        for obs in instance.observers
                    )
                    observers[target].pop()
                else:
                    assert not instance.observers[0].policy.is_exclusive()
                    observers[target].popleft()

                target_results.append(target)

        def choose_policy(target) -> t.ConcurrencyGuardPolicy:
            return (
                guards.guard(target, policy=Policy())
                if token_bits(1)
                else guards.monitor(target)
            )

        guards = MultiConcurrencyGaurd()
        Policy = guards.policies.QueueManually

        unique_targets = [*range(64)]
        targets = 4 * unique_targets
        instances = [(target, choose_policy(target)) for target in targets]
        queues = defaultdict(list)
        observers = defaultdict(deque)
        for target, instance in instances:
            if instance.policy.is_exclusive():
                observers[target].append(instance)
                queues[target].append(instance.token)
                guards.queues[target].append(instance)
            else:
                observers[target].appendleft(instance)

        target_results = []
        token_results = defaultdict(list)
        tasks = [
            record_ordering(target, instance)
            for target, instance in instances
        ]
        await gather(*tasks)

        # were all target executions run?
        assert sorted(target_results) == sorted(targets)

        # is the global execution order independent for different target
        # contexts?
        assert target_results != targets

        # is the same-target execution order respecting the order
        # declared by the target queue?
        for target, instance in instances:
            assert not instance.queue, target
            assert not instance.observers, target
            assert not observers[target], target
            if instance.policy.is_exclusive():
                assert token_results[target] == queues[target], target

    async def test_free_thread_queue_execution_order_is_respected(
        self,
    ) -> None:
        def record_ordering(
            items: t.Tuple[t.Hashable, MultiConcurrencyGaurd],
        ) -> None:
            target, instance = items
            random_sleep(0.0001)
            with instance:
                random_sleep(0.0001)
                if instance.policy.is_exclusive():
                    token_results[target].append(instance.token)
                    assert all(
                        obs.policy.is_exclusive()
                        for obs in instance.observers
                    )
                    observers[target].pop()
                else:
                    assert not instance.observers[0].policy.is_exclusive()
                    observers[target].popleft()

                target_results.append(target)

        def choose_policy(target) -> t.ConcurrencyGuardPolicy:
            return (
                guards.guard(target, policy=Policy())
                if token_bits(1)
                else guards.monitor(target)
            )

        guards = MultiConcurrencyGaurd()
        Policy = guards.policies.QueueManually

        unique_targets = [*range(64)]
        targets = 4 * unique_targets
        instances = [(target, choose_policy(target)) for target in targets]
        queues = defaultdict(list)
        observers = defaultdict(deque)
        for target, instance in instances:
            if instance.policy.is_exclusive():
                observers[target].append(instance)
                queues[target].append(instance.token)
                guards.queues[target].append(instance)
            else:
                assert isinstance(queues[target], list)
                observers[target].appendleft(instance)

        target_results = []
        token_results = defaultdict(list)
        tasks = [
            Threads._type(target=record_ordering, args=(items,))
            for items in instances
        ]
        for task in tasks:
            task.start()
        for task in tasks:
            task.join()

        # were all target executions run?
        assert sorted(target_results) == sorted(targets)

        # is the global execution order independent for different target
        # contexts?
        assert target_results != targets

        # is the same-target execution order respecting the order
        # declared by the target queue?
        for target, instance in instances:
            assert not instance.queue, target
            assert not instance.observers, target
            assert not observers[target], target
            if instance.policy.is_exclusive():
                assert token_results[target] == queues[target], target

    async def test_guard_method_needs_exclusive_policy(self) -> None:
        guards = MultiConcurrencyGaurd()

        problem = (  # fmt: skip
            "A non-exclusive policy was able to be passed into the "
            "guard() method."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            guards.guard(
                target="test",
                policy=guards.policies.NonExclusive(),
            )

        guards.guard(
            target="test",
            policy=guards.policies.Exclusive(),
        )

        guards.guard(
            target="test",
            policy=guards.policies.QueueManually(),
        )

    async def test_monitor_method_needs_non_exclusive_policy(self) -> None:
        guards = MultiConcurrencyGaurd()

        problem = (  # fmt: skip
            "An exclusive policy was able to be passed into the "
            "monitor() method."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            guards.monitor(
                target="test",
                policy=guards.policies.Exclusive(),
            )

        with Ignore(TypeError, if_else=violation(problem)):
            guards.monitor(
                target="test",
                policy=guards.policies.QueueManually(),
            )

        guards.monitor(
            target="test",
            policy=guards.policies.NonExclusive(),
        )

    async def test_async_references_cleaned_when_work_is_done(self) -> None:
        async def record_ordering(
            target: t.Hashable,
            instance: MultiConcurrencyGaurd,
            *,
            is_spontaneous: bool,
        ) -> None:
            await arandom_sleep(0.0001)
            async with instance:
                await arandom_sleep(0.0001)
                assert target in guards.users
                if instance.policy.is_exclusive():
                    assert instance.token == instance.queue[0].token
                else:
                    assert instance.token not in instance.queue

                if is_spontaneous or token_bits(3) < 0b110:
                    return
                task = record_ordering(
                    target, choose_policy(target), is_spontaneous=True
                )
                spontaneous_tasks.append(new_task(task))

        def choose_policy(target) -> t.ConcurrencyGuardPolicy:
            return (
                guards.guard(target)
                if token_bits(1)
                else guards.monitor(target)
            )

        guards = MultiConcurrencyGaurd()

        unique_targets = [*range(64)]
        targets = 4 * unique_targets
        instances = [(target, choose_policy(target)) for target in targets]
        spontaneous_tasks = deque()

        tasks = [
            record_ordering(target, instance, is_spontaneous=False)
            for target, instance in instances
        ]
        await gather(*tasks)
        await gather(*spontaneous_tasks)

        # are the target references cleaned up after all work is done?
        for target in unique_targets:
            assert target not in guards.observers
            assert target not in guards.queues
            assert target not in guards.users

        assert not guards.observers
        assert not guards.queues
        assert not guards.users

    async def test_sync_references_cleaned_when_work_is_done(self) -> None:
        def record_ordering(
            target: t.Hashable,
            instance: MultiConcurrencyGaurd,
            *,
            is_spontaneous: bool,
        ) -> None:
            random_sleep(0.0001)
            with instance:
                random_sleep(0.0001)
                assert target in guards.users
                if instance.policy.is_exclusive():
                    assert instance.token == instance.queue[0].token
                else:
                    assert instance.token not in instance.queue

                if is_spontaneous or token_bits(3) < 0b110:
                    return
                task = Threads._type(
                    target=record_ordering,
                    args=(target, choose_policy(target)),
                    kwargs=dict(is_spontaneous=True),
                )
                spontaneous_tasks.append(task)
                task.start()

        def choose_policy(target) -> t.ConcurrencyGuardPolicy:
            return (
                guards.guard(target)
                if token_bits(1)
                else guards.monitor(target)
            )

        guards = MultiConcurrencyGaurd()

        unique_targets = [*range(64)]
        targets = 4 * unique_targets
        instances = [(target, choose_policy(target)) for target in targets]
        spontaneous_tasks = deque()

        tasks = [
            Threads._type(
                target=record_ordering,
                args=(target, choose_policy(target)),
                kwargs=dict(is_spontaneous=False),
            )
            for target, instance in instances
        ]
        for task in tasks:
            task.start()
        for task in tasks:
            task.join()
        for task in spontaneous_tasks:
            task.join()

        # are the target references cleaned up after all work is done?
        for target in unique_targets:
            assert target not in guards.observers
            assert target not in guards.queues
            assert target not in guards.users

        assert not guards.observers
        assert not guards.queues
        assert not guards.users

    async def test_async_use_tracker_stages(self) -> None:
        async def track_stages(
            _: t.Hashable, instance: MultiConcurrencyGaurd
        ) -> None:
            await arandom_sleep(0.0001)
            assert instance.is_unused()
            assert not instance.is_pending()
            assert not instance.is_running()
            assert not instance.is_done()

            instance.policy.use(instance)
            assert not instance.is_unused()
            assert instance.is_pending()
            assert not instance.is_running()
            assert not instance.is_done()

            instance._use_tracker.clear()
            assert instance.is_unused()
            assert not instance.is_pending()
            assert not instance.is_running()
            assert not instance.is_done()

            async with instance:
                await arandom_sleep(0.0001)
                assert not instance.is_unused()
                assert not instance.is_pending()
                assert instance.is_running()
                assert not instance.is_done()

            assert not instance.is_unused()
            assert not instance.is_pending()
            assert not instance.is_running()
            assert instance.is_done()

        def choose_policy(target) -> t.ConcurrencyGuardPolicy:
            return (
                guards.guard(target)
                if token_bits(1)
                else guards.monitor(target)
            )

        guards = MultiConcurrencyGaurd()

        unique_targets = [*range(16)]
        targets = 4 * unique_targets
        instances = [(target, choose_policy(target)) for target in targets]

        tasks = [
            track_stages(target, instance) for target, instance in instances
        ]
        await gather(*tasks)

    async def test_sync_use_tracker_stages(self) -> None:
        def track_stages(
            _: t.Hashable, instance: MultiConcurrencyGaurd
        ) -> None:
            random_sleep(0.0001)
            assert instance.is_unused()
            assert not instance.is_pending()
            assert not instance.is_running()
            assert not instance.is_done()

            instance.policy.use(instance)
            assert not instance.is_unused()
            assert instance.is_pending()
            assert not instance.is_running()
            assert not instance.is_done()

            instance._use_tracker.clear()
            assert instance.is_unused()
            assert not instance.is_pending()
            assert not instance.is_running()
            assert not instance.is_done()

            with instance:
                random_sleep(0.0001)
                assert not instance.is_unused()
                assert not instance.is_pending()
                assert instance.is_running()
                assert not instance.is_done()

            assert not instance.is_unused()
            assert not instance.is_pending()
            assert not instance.is_running()
            assert instance.is_done()

        def choose_policy(target) -> t.ConcurrencyGuardPolicy:
            return (
                guards.guard(target)
                if token_bits(1)
                else guards.monitor(target)
            )

        guards = MultiConcurrencyGaurd()

        unique_targets = [*range(16)]
        targets = 4 * unique_targets
        instances = [(target, choose_policy(target)) for target in targets]

        tasks = [
            Threads._type(
                target=track_stages,
                args=(target, choose_policy(target)),
            )
            for target, instance in instances
        ]
        for task in tasks:
            task.start()
        for task in tasks:
            task.join()

    async def test_use_tracker_stages_manually(self) -> None:
        guards = MultiConcurrencyGaurd()

        for instance in [guards.monitor(0), guards.guard(0)]:
            assert instance.is_unused()
            assert not instance.is_pending()
            assert not instance.is_running()
            assert not instance.is_done()

            instance._use_tracker.append(False)
            assert not instance.is_unused()
            assert instance.is_pending()
            assert not instance.is_running()
            assert not instance.is_done()

            instance._use_tracker.append(True)
            assert not instance.is_unused()
            assert not instance.is_pending()
            assert instance.is_running()
            assert not instance.is_done()

            instance._use_tracker.append(False)
            assert not instance.is_unused()
            assert not instance.is_pending()
            assert not instance.is_running()
            assert instance.is_done()


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
