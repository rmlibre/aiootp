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

__all__ = [
    "DefaultDictOfStates",
    "ManagedConcurrecyGuard",
    "MultiConcurrencyGaurd",
    "TargetState",
]


from collections import defaultdict, deque
from threading import Lock

from aiootp._typing import Typing as t
from aiootp._exceptions import Issue, IncoherentConcurrencyState
from aiootp._exceptions import InvalidStateTransition, Metadata
from aiootp.commons import FrozenTypedSlots, OpenFrozenTypedSlots
from aiootp.asynchs.loops import asleep
from aiootp.asynchs.concurrency_interface import process_probe_delay

from .concurrency_guard import ConcurrencyGuard, ConcurrencyGuardPolicies
from .concurrency_guard import DequePair


try:
    # in Python <3.13 threading.Lock is a function, not a type, making it
    # uncheckable at runtime. TODO: @rmlibre: remove when 3.12 deprecated.
    issubclass(Lock, Lock)
    _LockType = Lock  # pragma: no cover
except TypeError:  # pragma: no cover
    _LockType = type(Lock())  # pragma: no cover


class TargetState(FrozenTypedSlots):
    """
    Bundles target state information into an efficient & type checked
    container.
    """

    __slots__ = ("deques", "users")

    _DequePair: type = DequePair

    slots_types = dict(deques=_DequePair, users=deque)

    def __init__(self, /) -> None:
        """
        Initializes the deque-pair shared across guard instances that
        are referenced by the same target, as well as the users deque
        which tracks the number of guard instance's currently utilizing
        the target shared state.
        """
        self.deques = self._DequePair()
        self.users = deque()


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


class DefaultDictOfStates(defaultdict):
    """
    A mapping of target ID keys to state objects which are used to
    enforce the turn order of distinct execution contexts only if the
    target keys are the same between them.
    """

    __slots__ = ("__deques",)

    _DequePair: type = DequePair
    _Guard: type = ConcurrencyGuard
    _TargetState: type = TargetState

    def __init__(self, /) -> None:
        """
        Applies `self._TargetState` or a subclass thereof as the default
        type of new elements.
        """
        super().__init__(self._TargetState)
        self.__deques = self._DequePair()

    def __setitem__(
        self,
        target: t.Hashable,
        state: _TargetState,
        /,
    ) -> None:
        """
        Before adding states to the collection, ensures they're of type
        `self._TargetState` or a subclass thereof.
        """
        if not issubclass(state.__class__, self._TargetState):
            raise Issue.must_be_subtype(Metadata(state), self._TargetState)

        super().__setitem__(target, state)

    def update(
        self,
        target_states: t.Mapping[t.Hashable, _TargetState] = {},
        /,
        **states: _TargetState,
    ) -> None:
        """
        Updates the instance with new key-values from a mapping of
        `target_states`, & optional `states` keyword arguments. Before
        adding states to the collection, ensures they're of type
        `self._TargetState` or a subclass thereof.
        """
        for target, state in dict(target_states, **states).items():
            self[target] = state  # type enforcement happens here

    def exclusive_context(self, /) -> t.ConcurrencyGuardType:
        """
        Creates contexts which only start after all other already
        started non-exclusive & exclusive contexts finish. This allows
        wrapped code to run & modify the collection's state safely.
        """
        return self._Guard(self.__deques)

    def non_exclusive_context(self, /) -> t.ConcurrencyGuardType:
        """
        Creates contexts which allow other non-exclusive contexts to run
        simultaneously such as those which don't modify the collection's
        state, but will concede their starts until any new exclusive
        contexts finish.
        """
        return self._Guard(
            self.__deques,
            policy=self._Guard.policies.NonExclusive(),
        )


class ManagedConcurrecyGuard(ConcurrencyGuard):
    """
    An interface for queuing execution contexts that are managed by a
    MultiConcurrencyGuard instance. With only constant time-complexity
    state checks, prevents simultaneous / out of order runs of blocks of
    code; as well as enabling non-exclusive contexts which are allowed
    to run freely with each other, but with async/thread-safe awareness
    of & concession to new contexts which require exclusive access to
    execution time.

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

    _UNMAPPED_ATTRIBUTES: frozenset[str] = frozenset({"_refs"})
    _DIRLESS_ATTRIBUTES: frozenset[str] = frozenset({"_refs"})
    _RESTRICTED_ATTRIBUTES: frozenset[str] = frozenset(
        {"__aenter__", "__enter__", "__aexit__", "__exit__"},
    )

    slots_types = dict(_refs=SelfReferences)

    def __init__(
        self,
        /,
        *,
        policy: t.ConcurrencyGuardPolicyType | None = None,
        probe_delay: t.PositiveRealNumber | None = None,
    ) -> None:
        """
        `policy`: A `ManagedConcurrencyGuard` policy instance which
                manages the logic necessary for async/thread-safe
                ordering of execution contexts.

        `probe_delay`: The float/fractional number of seconds to wait
                before each attempt to detect if the instance has been
                authorized to run.
        """
        self._set_policy(policy)
        self._use_tracker = self._UseTracker()
        self.probe_delay = process_probe_delay(
            probe_delay,
            default=self._default_probe_delay,
        )

    async def __aenter__(self, /) -> t.Self:
        """
        Prevents entering the context by asynchronously sleeping until
        the instance is in the 0th position of the order queue, & other
        logic depending on the instance's policy. Allows the manager to
        pass the correct state to the instance prior to running the
        context start-up code.
        """
        await asleep()

        manager, target = self._refs.manager, self._refs.target
        await manager._ainitialize_guard(target, self)
        try:
            return await super().__aenter__()
        except Exception as error:
            await manager._acleanup_references(target)
            raise error

    def __enter__(self, /) -> t.Self:
        """
        Prevents entering the context by synchronously sleeping until
        the instance is in the 0th position of the order queue, & other
        logic depending on the instance's policy. Allows the manager to
        pass the correct state to the instance prior to running the
        context start-up code.
        """
        manager, target = self._refs.manager, self._refs.target
        manager._initialize_guard(target, self)
        try:
            return super().__enter__()
        except Exception as error:
            manager._cleanup_references(target)
            raise error

    async def __aexit__(
        self,
        /,
        exc_type: type | None = None,
        exc_value: Exception | None = None,
        traceback: t.TracebackType | None = None,
    ) -> bool:
        """
        If using an exclusive policy, raises `IncoherentConcurrencyState`
        if another instance has taken this guard's place in the order
        queue.

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
        if another instance has taken this guard's place in the order
        queue.

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
        elif target.startswith("modify_jobs/"):
            async with guards.guard(target):
                await operation(target)
                ...


    guards = MultiConcurrencyGuard()
    filenames = list(Path().iterdir())

    tasks = [
        do_something(filename, guards, operation)
        for filename, operation in user_actions
    ]
    await gather(*tasks)
    """

    __slots__ = ("_resource_lock", "targets")

    _Lock: type = Lock
    _ManagedGuard: type = ManagedConcurrecyGuard
    _SelfReferences: type = SelfReferences
    _Targets: type = DefaultDictOfStates

    IncoherentConcurrencyState: type = IncoherentConcurrencyState
    InvalidStateTransition: type = InvalidStateTransition

    policies: ConcurrencyGuardPolicies = _ManagedGuard.policies
    slots_types = dict(_resource_lock=_LockType, targets=_Targets)

    def __init__(self, /, *, targets: _Targets | None = None) -> None:
        """
        Initializes the instance with its defaultdict subclass mapping
        used to manage state across all user-specified targets. This
        container comes packaged with utilities for creating async/
        thread-safe execution contexts for operations that read from or
        modify the container. These utilities are used internally by
        the manager to protect against race conditions that'd otherwise
        make access logic undefined.
        """
        self._resource_lock = self._Lock()
        self.targets = self._Targets() if targets is None else targets

    def _ensure_valid_policy(
        self,
        /,
        policy: t.ConcurrencyGuardPolicyType,
        *,
        policy_type: t.ConcurrencyGuardPolicyType | type,
    ) -> t.ConcurrencyGuardPolicyType:
        """
        Returns an instance of the provided default base policy if
        `None` is passed as the desired guard policy.

        Otherwise, if the desired guard policy is not a subtype of the
        provided default base policy, raises `TypeError`.

        Otherwise, returns the desired guard policy that was passed.
        """
        if policy is None:
            return policy_type()
        elif not issubclass(policy.__class__, policy_type):
            raise Issue.must_be_subtype(Metadata(policy), policy_type)

        return policy

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
        potentially running exclusive contexts that would be deleting
        references to the state.
        """
        with self._resource_lock:
            (state := self.targets[target]).users.append(guard)
            guard._set_deques(state.deques)

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
        potentially running exclusive contexts that would be deleting
        references to the state.
        """
        with self._resource_lock:
            (state := self.targets[target]).users.append(guard)
            guard._set_deques(state.deques)

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
        policy: t.ConcurrencyGuardPolicyType | None = None,
        probe_delay: t.PositiveRealNumber | None = None,
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
                before each attempt to detect if the instance has been
                authorized to run.

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
        policy = self._ensure_valid_policy(
            policy=policy,
            policy_type=self.policies.Exclusive,
        )
        guard = self._ManagedGuard(
            policy=policy,
            probe_delay=probe_delay,
        )
        self._pass_self_references(target, guard)
        return guard

    def monitor(
        self,
        /,
        target: t.Hashable,
        *,
        policy: t.ConcurrencyGuardPolicyType | None = None,
        probe_delay: t.PositiveRealNumber | None = None,
    ) -> _ManagedGuard:
        """
        Returns a non-exclusive guard instance which can be entered
        using either the sync or async context manager syntaxes. Monitor
        mode allows guard instances to execute freely with other non-
        exclusive guard instances as long as no exclusive mode instances
        have been added to the order queue. In the latter case, when an
        exclusive instance arrives at the front of the order queue, it
        will wait for all running non-exclusive instances to finish,
        then run alone until it finishes.

        `target`: A hashable index key used to identify resources which
                need the async/thread-safety of atomic turn ordering for
                their execution contexts.

        `policy`: A non-exclusive `ConcurrencyGuard` policy instance
                which manages the logic necessary for async/thread-safe
                ordering of execution contexts.

        `probe_delay`: The float/fractional number of seconds to wait
                before each attempt to detect if the instance has been
                authorized to run.

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
        policy = self._ensure_valid_policy(
            policy=policy,
            policy_type=self.policies.NonExclusive,
        )
        guard = self._ManagedGuard(
            policy=policy,
            probe_delay=probe_delay,
        )
        self._pass_self_references(target, guard)
        return guard

    async def _acleanup_references(self, /, target: t.Hashable) -> None:
        """
        Removes unused target references to avoid unmanaged memory
        buildups using an async/thread-safe exclusive execution context.
        """
        with self._resource_lock:
            state = self.targets[target]
            (users := state.users).popleft()
            if users or state.deques.queue or state.deques.observers:
                return

            self.targets.pop(target)

    def _cleanup_references(self, /, target: t.Hashable) -> None:
        """
        Removes unused target references to avoid unmanaged memory
        buildups using an async/thread-safe exclusive execution context.
        """
        with self._resource_lock:
            state = self.targets[target]
            (users := state.users).popleft()
            if users or state.deques.queue or state.deques.observers:
                return

            self.targets.pop(target)


module_api = dict(
    DefaultDictOfStates=t.add_type(DefaultDictOfStates),
    ManagedConcurrecyGuard=t.add_type(ManagedConcurrecyGuard),
    MultiConcurrencyGaurd=t.add_type(MultiConcurrencyGaurd),
    SelfReferences=t.add_type(SelfReferences),
    TargetState=t.add_type(TargetState),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
