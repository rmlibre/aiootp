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


"""
A general interface for automated async/thread-safe management of
multiple targeted execution contexts.
"""

__all__ = ["DefaultDictOfDeques", "MultiConcurrencyGaurd"]


from secrets import token_bytes
from collections import defaultdict, deque

from aiootp._typing import Typing as t
from aiootp._exceptions import Issue, IncoherentConcurrencyState
from aiootp.commons import FrozenTypedSlots, OpenFrozenTypedSlots

from .loops import asleep
from .concurrency_interface import process_probe_delay
from .concurrency_guard import ConcurrencyGuard, ConcurrencyGuardPolicies


class SelfReferences(OpenFrozenTypedSlots):
    """
    An efficient & typed mapping container to store manager-relevant
    references in the guard instance.
    """

    __slots__ = ("manager", "target")

    slots_types = dict(
        manager=t.MultiConcurrencyGaurdType,
        target=t.Hashable,
    )


class ManagedConcurrecyGuard(ConcurrencyGuard):
    """
    An interface for queuing execution contexts that are managed by a
    MultiConcurrencyGuard instance. With only constant time-complexity
    state checks, prevents simultaneous / out of order runs of blocks of
    code; as well as contexts which are allowed to run freely, but with
    async/thread-safe awareness & concession to new contexts which
    require exclusive access to execution time.

     _____________________________________
    |                                     |
    |         Example As Diagram:         |
    |_____________________________________|

                           ----------------------
                           |   Shared Context   |
                           ----------------------

                       guards = MultiConcurrencyGuard()
                           target = "config.yaml"
                           -----------------------
            -----------------         |        -----------------
            |   Context A   |         |        |   Context B   |
            -----------------         |        -----------------
                                      |
    with guards.guard(target):        |  with guards.guard(target):
        mutable_thing[0] = 0          |      assert mutable_thing[0] == "done."
        ...                           |      mutable_thing[0] = 1
        ...                           |
        assert mutable_thing[0] == 0  |
        mutable_thing[0] = "done."    |
                                      |
    --------------------------------------------------------------------
    Explanation:

    Context A is called first, & Context B waits for A to finish.
    --------------------------------------------------------------------

     _____________________________________
    |                                     |
    |         Example As Diagram:         |
    |_____________________________________|

                           ----------------------
                           |   Shared Context   |
                           ----------------------

                       guards = MultiConcurrencyGuard()
                           target = "config.yaml"
                           -----------------------
            -----------------         |        -----------------
            |   Context A   |         |        |   Context B   |
            -----------------         |        -----------------
                                      |
    with guards.monitor(target) as a: |  with guards.guard(target) as b:
        assert a.is_running()         |      assert b.is_running()
        ...                           |      assert a.is_done()
        assert c.is_running()         |      assert c.is_done()
        ...                           |      assert d.is_pending()
        assert b.is_pending()         |
                                      |
            -----------------         |        -----------------
            |   Context C   |         |        |   Context D   |
            -----------------         |        -----------------
                                      |
    with guards.monitor(target) as c: |  d = guards.monitor(target)
        assert c.is_running()         |  assert d.is_unused()
        ...                           |  assert b.is_pending()
        assert a.is_running()         |
        assert b.is_pending()         |  with d:
                                      |      assert d.is_running()
                                      |      assert a.is_done()
                                      |      assert b.is_done()
                                      |      assert c.is_done()
                                      |
    --------------------------------------------------------------------
    Explanation:

    Context A is entered first, then Context C. Since they both have non-
    exclusive policies, they can both run simultaneously. But Context B
    waits for them to finish so that it can take exclusive control of
    execution time. Context D enters last, & even though it uses a non-
    exclusive policy, it will wait for Context B to finish because b's
    exclusive policy ensures no other contexts are running while b is.
    --------------------------------------------------------------------
    """

    __slots__ = ("_refs",)

    slots_types = dict(_refs=SelfReferences)

    def __init__(
        self,
        /,
        *,
        policy: t.ConcurrencyGuardPolicy | None = None,
        probe_delay: t.PositiveRealNumber | None = None,
        token: bytes | None = None,
    ) -> None:
        """
        `policy`: A `ManagedConcurrencyGuard` policy instance which
                manages the logic necessary for async/thread-safe
                ordering of execution contexts.

        `probe_delay`: The float/fractional number of seconds to wait
                before each attempt to detect if the instance's token
                has been authorized to run.

        `token`: The unique authorization token held by this context.
        """
        self._set_policy(policy)
        self._use_tracker = deque(maxlen=2)
        self.probe_delay = process_probe_delay(
            probe_delay,
            default=self._default_probe_delay,
        )
        self.token = token or token_bytes(32)

    async def __aenter__(self, /) -> t.Self:
        """
        Prevents entering the context by asynchronously sleeping until
        the instance's unique authorization token is held by the current
        instance in the 0th position of the order queue, & other logic
        depending on the instance's policy. Allows the manager to pass
        the correct state to the instance prior to running the context
        start-up code.
        """
        await asleep()

        manager, target = self._refs.manager, self._refs.target
        await manager._ainitialize_guard(target, self)
        return await super().__aenter__()

    def __enter__(self, /) -> t.Self:
        """
        Prevents entering the context by synchronously sleeping until
        the instance's unique authorization token is held by the current
        instance in the 0th position of the order queue, & other logic
        depending on the instance's policy. Allows the manager to pass
        the correct state to the instance prior to running the context
        start-up code.
        """
        manager, target = self._refs.manager, self._refs.target
        manager._initialize_guard(target, self)
        return super().__enter__()

    async def __aexit__(
        self,
        /,
        exc_type: type | None = None,
        exc_value: Exception | None = None,
        traceback: t.TracebackType | None = None,
    ) -> bool:
        """
        If using an exclusive policy, raises `IncoherentConcurrencyState`
        if another instance with a different authorization token has
        taken this instance's place in the order queue.

        Otherwise, raises any exception raised in the context's code
        block.

        Otherwise, closes the context silently.

        Always attempts to allow the manager to cleanup its references
        prior to returning.
        """
        try:
            return await super().__aexit__(exc_type, exc_value, traceback)
        finally:
            manager, target = self._refs.manager, self._refs.target
            await manager._acleanup_references(target)

    def __exit__(
        self,
        /,
        exc_type: type | None = None,
        exc_value: Exception | None = None,
        traceback: t.TracebackType | None = None,
    ) -> bool:
        """
        If using an exclusive policy, raises `IncoherentConcurrencyState`
        if another instance with a different authorization token has
        taken this instance's place in the order queue.

        Otherwise, raises any exception raised in the context's code
        block.

        Otherwise, closes the context silently.

        Always attempts to allow the manager to cleanup its references
        prior to returning.
        """
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            manager, target = self._refs.manager, self._refs.target
            manager._cleanup_references(target)


class DefaultDictOfDeques(defaultdict):
    """
    A mapping of target ID keys to deque queues which are used to
    enforce the turn order of distinct execution contexts only if the
    target keys are the same between them.
    """

    __slots__ = ("__queue", "__observers")

    _Guard: t.ConcurrencyGuardType = ConcurrencyGuard
    _Type: t.SupportsAppendPopleft = deque

    def __init__(self, /) -> None:
        """
        Applies `collections.deque` or a subclass thereof as the default
        value type of new instances.
        """
        super().__init__(self._Type)
        self.__queue = deque()
        self.__observers = deque()

    def __setitem__(
        self,
        name: t.Hashable,
        value: deque[t.ConcurrencyGuardType],
        /,
    ) -> None:
        """
        Before adding values to the collection, ensures they're of type
        `collections.deque` or a subclass thereof.
        """
        if not issubclass(value.__class__, deque):
            raise Issue.must_be_subtype("value", deque) from None

        super().__setitem__(name, value)

    def update(
        self,
        queues: t.Mapping[t.Hashable, deque[t.ConcurrencyGuardType]] = {},
        /,
        **target_deque_pairs: deque[t.ConcurrencyGuardType],
    ) -> None:
        """
        Updates the instance with new key-values from a mapping of
        `queues`, & optional keyword arguments. Before adding values to
        the collection, ensures they're of type `collections.deque` or a
        subclass thereof.
        """
        for name, value in {**dict(queues), **target_deque_pairs}.items():
            self[name] = value  # type enforcement happens here

    def exclusive_context(self) -> t.ConcurrencyGuardType:
        """
        Creates contexts which only start after all other already
        started non-exclusive & exclusive contexts finish. This allows
        wrapped code to run & modify the collection's state safely.
        """
        return self._Guard(self.__queue, observers=self.__observers)

    def non_exclusive_context(self) -> t.ConcurrencyGuardType:
        """
        Creates contexts which allow other non-exclusive contexts to run
        simultaneously such as those which don't modify the collection's
        state, but will concede their starts until any new exclusive
        contexts finish.
        """
        return self._Guard(
            self.__queue,
            observers=self.__observers,
            policy=self._Guard.policies.NonExclusive(),
        )


class MultiConcurrencyGaurd(FrozenTypedSlots):
    """
    Facilitates async/thread-safety for execution contexts which can be
    categorized by a hashable target key from call-sites. Execution
    contexts which operate on distinct targets are allowed to run freely
    & independently from each other. Those operating on the same target
    will delay their turn or run freely depending on whether they're
    using an exclusive or non-exclusive policy, & whether there's
    already an exclusive context running or there are only non-exclusive
    contexts running.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from asyncio import gather
    from pathlib import Path
    from typing import Awaitable, Callable

    from aiootp.asynchs import MultiConcurrencyGuard


    async def do_something(
        target: str,
        guards: MultiConcurrencyGuard,
        operation: Callable[..., Awaitable],
    ) -> None:
        '''
        Applies protection against race conditions for operations on
        the same target between distinct execution contexts.
        '''
        if target.startswith("read_jobs/"):
            async with guards.monitor(target):
                await operation(target)
                ...
        elif target.startswith("write_jobs/"):
            async with guards.guard(target):
                await operation(target)
                ...


    guards = MultiConcurrencyGuard()
    filenames = list(Path().iterdir())

    tasks = [
        do_something(filename, guards, operation)
        for operation in user_actions
        for filename in filenames
    ]
    await gather(*tasks)
    """

    __slots__ = ("observers", "queues", "users")

    _ManagedGuard: type = ManagedConcurrecyGuard
    _Observers: type = DefaultDictOfDeques
    _Queues: type = DefaultDictOfDeques
    _SelfReferences: type = SelfReferences
    _Users: type = DefaultDictOfDeques

    IncoherentConcurrencyState: type = IncoherentConcurrencyState

    policies: ConcurrencyGuardPolicies = _ManagedGuard.policies
    slots_types = dict(observers=_Observers, queues=_Queues, users=_Users)

    def __init__(
        self,
        /,
        *,
        queues: _Queues | None = None,
        observers: _Observers | None = None,
        users: _Users | None = None,
    ) -> None:
        """
        Initializes the instance with its defaultdict subclass mappings
        used to manage state across all user-specified targets. These
        containers come packaged with utilities for creating async/
        thread-safe execution contexts for operations that read from or
        modify the containers. These utilities are used internally by
        the manager to protect against race conditions that'd otherwise
        make access logic undefined.
        """
        self.observers = (
            self._Observers() if observers is None else observers
        )
        self.queues = self._Queues() if queues is None else queues
        self.users = self._Users() if users is None else users

    async def _ainitialize_guard(
        self,
        /,
        target: t.Hashable,
        guard: t.ConcurrencyGuardType,
    ) -> None:
        """
        Ensures the target references given to the guard instance are
        consistent with the other running instances of the same target.
        Since only reads are done, an async/thread-safe non-exclusive
        execution context is used to avoid race-conditions with any
        potentially running exclusive contexts that would be changing
        the state.
        """
        async with self.users.non_exclusive_context():
            (users := self.users[target]).appendleft(None)
            if (user := users[-1]) is None:
                guard.queue = self.queues[target]
                guard.observers = self.observers[target]
            else:
                guard.queue = user.queue
                guard.observers = user.observers

            users.append(guard)
            users.popleft()

    def _initialize_guard(
        self,
        /,
        target: t.Hashable,
        guard: t.ConcurrencyGuardType,
    ) -> None:
        """
        Ensures the target references given to the guard instance are
        consistent with the other running instances of the same target.
        Since only reads are done, an async/thread-safe non-exclusive
        execution context is used to avoid race-conditions with any
        potentially running exclusive contexts that would be changing
        the state.
        """
        with self.users.non_exclusive_context():
            (users := self.users[target]).appendleft(None)
            if (user := users[-1]) is None:
                guard.queue = self.queues[target]
                guard.observers = self.observers[target]
            else:
                guard.queue = user.queue
                guard.observers = user.observers

            users.append(guard)
            users.popleft()

    def _pass_self_references(
        self,
        /,
        target: t.Hashable,
        guard: t.ConcurrencyGuardType,
    ) -> None:
        """
        Gives the guard instance access to the references the manager
        needs to properly locate the requested resources during
        initialization & tear-down.
        """
        guard._refs = self._SelfReferences(manager=self, target=target)

    def guard(
        self,
        /,
        target: t.Hashable,
        *,
        policy: t.ConcurrencyGuardPolicy | None = None,
        probe_delay: t.PositiveRealNumber | None = None,
        token: bytes | None = None,
    ) -> _ManagedGuard:
        """
        Returns an exclusive guard instance which can be entered using
        either the sync or async context manager syntaxes.

        `target`: A hashable index key used to identify resources which
                need the async/thread-safety of atomic turn ordering for
                their execution contexts.

        `policy`: An exclusive `ConcurrencyGuard` policy instance which
                manages the logic necessary for async/thread-safe
                ordering of execution contexts.

        `probe_delay`: The float/fractional number of seconds to wait
                before each attempt to detect if the instance's token
                has been authorized to run.

        `token`: The unique authorization token held by this context.

         _____________________________________
        |                                     |
        |           Syntax Example:           |
        |_____________________________________|

        guards = MultiConcurrencyGuard()

        async with guards.guard(target):
            await async_mutate_target(target)

        with guards.guard(target):
            mutate_target(target)
        """
        ExclusivePolicy = self.policies.Exclusive
        if policy is None:
            policy = ExclusivePolicy()
        elif not issubclass(policy.__class__, ExclusivePolicy):
            raise Issue.must_be_subtype("policy", ExclusivePolicy)

        guard = self._ManagedGuard(
            policy=policy,
            probe_delay=probe_delay,
            token=token,
        )
        self._pass_self_references(target, guard)
        return guard

    def monitor(
        self,
        /,
        target: t.Hashable,
        *,
        policy: t.ConcurrencyGuardPolicy | None = None,
        probe_delay: t.PositiveRealNumber | None = None,
        token: bytes | None = None,
    ) -> _ManagedGuard:
        """
        Returns the non-exclusive guard instance which can be entered
        using either the sync or async context manager syntaxes.
        Instances that are run in monitor mode execute freely with other
        non-exclusive instances as long as no exclusive mode instances
        have been added to the observers queue. In the latter case, non-
        exclusive instances will wait for all such exclusive instances
        to finish running before signaling that they're ready to run.

        `target`: A hashable index key used to identify resources which
                need the async/thread-safety of atomic turn ordering for
                their execution contexts.

        `policy`: A non-exclusive `ConcurrencyGuard` policy instance
                which manages the logic necessary for async/thread-safe
                ordering of execution contexts.

        `probe_delay`: The float/fractional number of seconds to wait
                before each attempt to detect if the instance's token
                has been authorized to run.

        `token`: The unique authorization token held by this context.

         _____________________________________
        |                                     |
        |           Syntax Example:           |
        |_____________________________________|

        guards = MultiConcurrencyGuard()

        async with guards.monitor(target):
            await async_read_target(target)

        with guards.monitor(target):
            read_target(target)
        """
        NonExclusivePolicy = self.policies.NonExclusive
        if policy is None:
            policy = NonExclusivePolicy()
        elif not issubclass(policy.__class__, NonExclusivePolicy):
            raise Issue.must_be_subtype("policy", NonExclusivePolicy)

        guard = self._ManagedGuard(
            policy=policy,
            probe_delay=probe_delay,
            token=token,
        )
        self._pass_self_references(target, guard)
        return guard

    async def _acleanup_references(self, /, target: t.Hashable) -> None:
        """
        Removes unused target references to avoid unmanaged memory
        buildups using an async/thread-safe exclusive execution context.
        """
        async with self.users.exclusive_context():
            (users := self.users[target]).pop()
            if users or self.queues[target] or self.observers[target]:
                return

            self.observers.pop(target)
            self.queues.pop(target)
            self.users.pop(target)

    def _cleanup_references(self, /, target: t.Hashable) -> None:
        """
        Removes unused target references to avoid unmanaged memory
        buildups using an async/thread-safe exclusive execution context.
        """
        with self.users.exclusive_context():
            (users := self.users[target]).pop()
            if users or self.queues[target] or self.observers[target]:
                return

            self.observers.pop(target)
            self.queues.pop(target)
            self.users.pop(target)


module_api = dict(
    DefaultDictOfDeques=t.add_type(DefaultDictOfDeques),
    ManagedConcurrecyGuard=t.add_type(ManagedConcurrecyGuard),
    MultiConcurrencyGaurd=t.add_type(MultiConcurrencyGaurd),
    SelfReferences=t.add_type(SelfReferences),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
