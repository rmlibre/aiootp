# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2025 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


from collections import defaultdict

from aiootp.asynchs.loops import gather
from aiootp.asynchs.concurrency_interface import DefaultDictOfDeques
from aiootp.asynchs.concurrency_interface import MultiConcurrencyGaurd

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
    async def test_added_values_must_be_deques(self, value) -> None:
        mapping = DefaultDictOfDeques()

        problem = (  # fmt: skip
            "A non-deque object was able to be set within the custom "
            "defaultdict object."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            mapping["setitem_test"] = value

        with Ignore(TypeError, if_else=violation(problem)):
            mapping.update(update_test=value)


class TestMultiConcurrencyGaurd:
    async def test_async_queue_execution_order_is_respected(self) -> None:
        async def record_ordering(
            target: t.Hashable, instance: MultiConcurrencyGaurd
        ) -> None:
            async with instance:
                await arandom_sleep(0.0001)
                target_results.append(target)
                token_results[target].append(instance.token)

        guards = MultiConcurrencyGaurd()

        unique_targets = [*range(64)]
        targets = 4 * unique_targets
        instances = [
            (target, guards.guard(target, append_token_manually=True))
            for target in targets
        ]
        queues = defaultdict(list)
        for target, instance in instances:
            queues[target].append(instance.token)
            instance.queue.append(instance.token)

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
            assert len(instance.queue) == 0
            assert token_results[target] == queues[target]

    async def test_thread_queue_execution_order_is_respected(self) -> None:
        def record_ordering(
            items: t.Tuple[t.Hashable, MultiConcurrencyGaurd],
        ) -> None:
            target, instance = items
            with instance:
                random_sleep(0.0001)
                target_results.append(target)
                token_results[target].append(instance.token)

        guards = MultiConcurrencyGaurd()

        unique_targets = [*range(64)]
        targets = 4 * unique_targets
        instances = [
            (target, guards.guard(target, append_token_manually=True))
            for target in targets
        ]
        queues = defaultdict(list)
        for target, instance in instances:
            queues[target].append(instance.token)
            instance.queue.append(instance.token)

        target_results = []
        token_results = defaultdict(list)
        with Threads.pool as executor:
            list(executor.map(record_ordering, instances))

        # were all target executions run?
        assert sorted(target_results) == sorted(targets)

        # is the global execution order independent for different target
        # contexts?
        assert target_results != targets

        # is the same-target execution order respecting the order
        # declared by the target queue?
        for _, (target, instance) in zip(unique_targets, instances):
            assert len(instance.queue) == 0
            assert token_results[target] == queues[target]


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
