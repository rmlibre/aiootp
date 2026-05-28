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
A general interface for async/thread-safe management of execution
contexts.
"""

__all__ = [
    "ConcurrencyGuard",
    "ConcurrencyGuardPolicies",
    "MultiConcurrencyGaurd",
]


from hmac import compare_digest
from secrets import token_bytes
from collections import defaultdict, deque

from aiootp._typing import Typing as t
from aiootp._exceptions import Issue, IncoherentConcurrencyState
from aiootp._exceptions import Metadata, SingleUseObjectWasReused
from aiootp.commons import FrozenInstance
from aiootp.commons import FrozenTypedSlots, OpenFrozenTypedSlots

from .loops import asleep, sleep
from .concurrency_interface import process_probe_delay


class ExclusivePolicy(FrozenInstance):
    __slots__ = ()

    def is_exclusive(self, /) -> bool:
        """
        Exclusive policies return `True`, whereas non-exclusive
        policies return `False`.
        """
        return True

    def use(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        Uses an atomic deque to invalidate multiple uses of the guard
        instance.
        """
        (tracker := guard._use_tracker).append(False)

        if len(tracker) > 1:
            raise SingleUseObjectWasReused(Metadata(guard))

    def notify_on(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        Using an exclusive policy, appends the guard to the observers
        deque.
        """
        guard.observers.append(guard)

    def notify_off(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        Using an exclusive policy, pops an exclusive guard off of the
        observers deque.
        """
        guard.observers.pop()

    def get_in_queue(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        Adds the guard instance to the order queue.
        """
        guard.queue.append(guard)

    def get_off_queue(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        Removes the guard from the order queue. If the guard's token is
        different from the token retrieved from the removed guard,
        raises `IncoherentConcurrencyState`.
        """
        guard._use_tracker.append(False)
        if not compare_digest(guard.token, guard.queue.popleft().token):
            raise guard.IncoherentConcurrencyState

    def is_free_to_run(self, /, guard: t.ConcurrencyGuardType) -> bool:
        """
        If the guard is next on the order queue & there are no non-
        exclusive guards currently running, returns `True` to signal it
        can safely take its turn to run.
        """
        is_next_in_queue = compare_digest(guard.token, guard.queue[0].token)
        no_others_running = guard.observers[0].policy.is_exclusive()
        if can_run := is_next_in_queue and no_others_running:
            guard._use_tracker.append(True)
        return can_run


class QueueManuallyPolicy(ExclusivePolicy):
    """
    Signals to the `ConcurrencyGuard` instance that the caller will
    manually append the guard instance to the order queue to achieve the
    desired ordering of events. This overrides the default behavior of
    the guard being automatically appended when the instance context
    manager is entered. The instance remains responsible for
    automatically removing the appropriate guard from the order queue
    when the context manager is exited.
    ********
    CAUTION: Care must be taken not to use the same guard token multiple
    ******** times. Doing so may cause a deadlock, incoherent state, or
    exception if two instances with the same token enter their contexts
    simultaneously, & then during exit, pop a guard off the queue
    expecting it to be itself.
    """

    __slots__ = ()

    def get_in_queue(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        A no-op since the caller has signaled that they'll handle
        appending the guard to the order queue manually.
        """


class NonExclusivePolicy(FrozenInstance):
    """
    Signals to the `ConcurrencyGuard` instance that it can run freely
    when it arrives at the front of the order queue. Exclusive instances
    will wait for all non-exclusive instances to signal that they're
    done working & no longer on the observers deque before beginning.
    Meanwhile, non-exclusive instances will always run once they've
    prepended themselves to the observers deque.
    """

    __slots__ = ()

    def is_exclusive(self, /) -> bool:
        """
        Non-exclusive policies return `False`, whereas exclusive
        policies return `True`.
        """
        return False

    def use(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        Uses an atomic deque to invalidate multiple uses of the guard
        instance.
        """
        (tracker := guard._use_tracker).append(False)

        if len(tracker) > 1:
            raise SingleUseObjectWasReused(Metadata(guard))

    def notify_on(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        A no-op since non-exclusive policies notify other guards using
        the observers deque only after they've arrived at the front of
        the order queue. This is safe because either an exclusive guard
        just finished running & removed itself from the order queue,
        meaning there are now no other guards running; or only non-
        exclusive guards are running, which is allowed.
        """

    def notify_off(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        Using a non-exclusive policy, removes a prepended non-exclusive
        guard off of the observers deque.
        """
        guard.observers.popleft()

    def get_in_queue(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        Adds the guard instance to the order queue. Using a non-
        exclusive policy, the guard will wait for it's turn on the order
        queue to notify other guards that it is running using the
        observer deque. It will then remove itself immediately from the
        order queue allowing other non-exclusive guards to run, &
        exclusive guards to wait for all non-exclusive guards to signal
        they're done running by each of them removing a prepended guard
        from the observers deque.
        """
        guard.queue.append(guard)

    def get_off_queue(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        A no-op since non-exclusive policies remove themselves from the
        order queue immediately after their turn in the order queue has
        arrived & they've prepended themselves to the observers deque.
        """
        guard._use_tracker.append(False)

    def is_free_to_run(self, /, guard: t.ConcurrencyGuardType) -> bool:
        """
        If the guard is next on the order queue, notifies other guards
        immediately that it will run by prepending itself to the
        observers deque, & removing itself from the order queue to allow
        other guards to take their turn & make the appropriate informed
        decisions.
        """
        if can_run := compare_digest(guard.token, guard.queue[0].token):
            guard.observers.appendleft(guard)  # append first to rule-
            guard.queue.popleft()  # out race-conditions
            guard._use_tracker.append(True)
        return can_run


class ConcurrencyGuardPolicies(OpenFrozenTypedSlots):
    """
    An efficient & typed mapping container for policy types.
    """

    __slots__ = ("Exclusive", "QueueManually", "NonExclusive")

    slots_types = dict(
        Exclusive=t.ConcurrencyGuardPolicy,
        QueueManually=t.ConcurrencyGuardPolicy,
        NonExclusive=t.ConcurrencyGuardPolicy,
    )


class ConcurrencyGuard(FrozenTypedSlots):
    """
    An interface for queuing execution contexts given only a pair of
    shared, atomic `deque` double-ended queues. With only constant time-
    complexity state checks, prevents simultaneous / out of order runs
    of blocks of code; as well as contexts which are allowed to run
    freely, but with async/thread-safe awareness & concession to new
    contexts which require exclusive access to execution time.

     _____________________________________
    |                                     |
    |         Example As Diagram:         |
    |_____________________________________|

                           ----------------------
                           |   Shared Context   |
                           ----------------------

                               queue = deque()
                           -----------------------
            -----------------         |        -----------------
            |   Context A   |         |        |   Context B   |
            -----------------         |        -----------------
                                      |
    with ConcurrencyGuard(queue):     |  with ConcurrencyGuard(queue):
        mutable_thing[0] = 0          |      assert mutable_thing[0] == "done."
        ...                           |      mutable_thing[0] = 1
        ...                           |
        assert mutable_thing[0] == 0  |
        mutable_thing[0] = "done."    |
                                      |
    --------------------------------------------------------------------
    Context A is called first, & Context B waits for A to finish.
    --------------------------------------------------------------------
    """

    __slots__ = (
        "_use_tracker",
        "observers",
        "policy",
        "probe_delay",
        "queue",
        "token",
    )

    slots_types: t.Mapping[str, type] = dict(
        _use_tracker=deque,
        observers=deque,
        policy=t.ConcurrencyGuardPolicy,
        probe_delay=float,
        queue=deque,
        token=bytes,
    )

    _default_probe_delay: float = 0.00001

    policies: ConcurrencyGuardPolicies = ConcurrencyGuardPolicies(
        Exclusive=ExclusivePolicy,
        QueueManually=QueueManuallyPolicy,
        NonExclusive=NonExclusivePolicy,
    )

    IncoherentConcurrencyState: type = IncoherentConcurrencyState

    def __init__(
        self,
        /,
        queue: deque[t.ConcurrencyGuardType],
        *,
        observers: t.Optional[deque[t.ConcurrencyGuardType]] = None,
        policy: t.Optional[t.ConcurrencyGuardPolicy] = None,
        probe_delay: t.Optional[t.PositiveRealNumber] = None,
        token: t.Optional[bytes] = None,
    ) -> None:
        """
        `queue`: Shared, atomic `deque` data structure used to order the
                execution contexts of guard instances.

        `observers`: Shared, atomic `deque` data structure used to track
                any running non-exclusive guard instances on the 0th
                side of the queue, & any waiting/running exclusive guard
                instances on the -1th side. This queue is not ordered,
                but the invariant stated above is preserved.

        `policy`: A `ConcurrencyGuard` policy instance which manages the
                logic necessary for async/thread-safe ordering of
                execution contexts.

        `probe_delay`: The float/fractional number of seconds to wait
                before each attempt to detect if the instance's token
                has been authorized to run.

        `token`: The unique authorization token held by this context.
        """
        self._set_policy(policy)
        self._use_tracker = deque(maxlen=2)
        self.probe_delay = process_probe_delay(
            probe_delay, default=self._default_probe_delay
        )
        self.observers = deque() if observers is None else observers
        self.queue = queue
        self.token = token or token_bytes(32)

    def _set_policy(
        self, /, policy: t.Optional[t.ConcurrencyGuardPolicy]
    ) -> None:
        """
        Ensures the passed policy value is an instance of a policy class
        which matches the ConcurrencyGuardPolicy protocol. If `None` is
        passed, then a default ExclusivePolicy instance is chosen.
        """
        if policy is None:
            self.policy = self.policies.Exclusive()
        elif isinstance(policy, type):
            raise Issue.must_be_type("policy", t.ConcurrencyGuardPolicy)
        else:
            self.policy = policy

    async def __aenter__(self, /) -> t.Self:
        """
        Prevents entering the context by asynchronously sleeping until
        the instance's unique authorization token is the current token
        in the 0th position of the order queue & other logic depending
        on the instance's policy.
        """
        await asleep()
        policy = self.policy
        policy.use(self)
        policy.notify_on(self)
        policy.get_in_queue(self)

        while not policy.is_free_to_run(self):
            await asleep(self.probe_delay)

        return self

    def is_pending(self, /) -> bool:
        """
        Returns `True` if the guard instance still hasn't signaled that
        it's begun moving to enter the context. Otherwise returns
        `False` if either it has signaled this move, or it has signaled
        that it has exited the context.
        """
        return len(self._use_tracker) < 2

    def is_running(self, /) -> bool:
        """
        Returns `True` if the guard instance has signaled that it has
        begun moving to enter the context. Otherwise returns `False` if
        either it hasn't signaled this move, or it has signaled that it
        has exited the context.
        """
        try:
            return self._use_tracker[-1]
        except IndexError:
            return False

    def is_done(self, /) -> bool:
        """
        Returns `True` if the guard instance has signaled that it's
        already exited the context. Otherwise returns `False`.
        """
        try:
            return self._use_tracker[0]
        except IndexError:
            return False

    def __enter__(self, /) -> t.Self:
        """
        Prevents entering the context by synchronously sleeping until
        the instance's unique authorization token is the current token
        in the 0th position of the order queue & other logic depending
        on the instance's policy.
        """
        policy = self.policy
        policy.use(self)
        policy.notify_on(self)
        policy.get_in_queue(self)

        while not policy.is_free_to_run(self):
            sleep(self.probe_delay)

        return self

    async def __aexit__(
        self,
        /,
        exc_type: t.Optional[type] = None,
        exc_value: t.Optional[Exception] = None,
        traceback: t.Optional[t.TracebackType] = None,
    ) -> bool:
        """
        Raises `self.IncoherentConcurrencyState` if another instance's
        authorization token has taken this instance's place in the token
        queue.

        Otherwise, raises any exception raised in the context's code
        block.

        Otherwise, closes the context silently.
        """
        await asleep()
        self.policy.notify_off(self)
        self.policy.get_off_queue(self)
        return exc_type is None

    def __exit__(
        self,
        /,
        exc_type: t.Optional[type] = None,
        exc_value: t.Optional[Exception] = None,
        traceback: t.Optional[t.TracebackType] = None,
    ) -> bool:
        """
        Raises `self.IncoherentConcurrencyState` if another instance's
        authorization token has taken this instance's place in the token
        queue.

        Otherwise, raises any exception raised in the context's code
        block.

        Otherwise, closes the context silently.
        """
        self.policy.notify_off(self)
        self.policy.get_off_queue(self)
        return exc_type is None


class SelfReferences(OpenFrozenTypedSlots):
    """
    An efficient & typed mapping container to store manager-relevant
    references in the guard instance.
    """

    __slots__ = ("manager", "target")

    slots_types = dict(
        manager=t.MultiConcurrencyGaurdType, target=t.Hashable
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
    Context A is called first, & Context B waits for A to finish.
    --------------------------------------------------------------------
    """

    __slots__ = ("_refs",)

    slots_types = dict(_refs=SelfReferences)

    def __init__(
        self,
        /,
        *,
        policy: t.Optional[t.ConcurrencyGuardPolicy] = None,
        probe_delay: t.Optional[t.PositiveRealNumber] = None,
        token: t.Optional[bytes] = None,
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
            probe_delay, default=self._default_probe_delay
        )
        self.token = token or token_bytes(32)

    async def __aenter__(self, /) -> t.Self:
        """
        Prevents entering the context by asynchronously sleeping until
        the instance's unique authorization token is the current token
        in the 0th position of the order queue & other logic depending
        on the instance's policy. Allows the manager to pass the correct
        state to the instance prior to running the context start-up
        code.
        """
        await asleep()

        manager, target = self._refs.manager, self._refs.target
        await manager._ainitialize_guard(target, self)
        return await super().__aenter__()

    def __enter__(self, /) -> t.Self:
        """
        Prevents entering the context by synchronously sleeping until
        the instance's unique authorization token is the current token
        in the 0th position of the order queue & other logic depending
        on the instance's policy. Allows the manager to pass the correct
        state to the instance prior to running the context start-up
        code.
        """
        manager, target = self._refs.manager, self._refs.target
        manager._initialize_guard(target, self)
        return super().__enter__()

    async def __aexit__(
        self,
        /,
        exc_type: t.Optional[type] = None,
        exc_value: t.Optional[Exception] = None,
        traceback: t.Optional[t.TracebackType] = None,
    ) -> bool:
        """
        Raises `self.IncoherentConcurrencyState` if another instance's
        authorization token has taken this instance's place in the token
        queue.

        Otherwise, raises any exception raised in the context's code
        block.

        Otherwise, closes the context silently.

        Always attempts to allow the manager to cleanup its references
        prior to returning.
        """
        try:
            ok = await super().__aexit__(exc_type, exc_value, traceback)
        finally:
            manager, target = self._refs.manager, self._refs.target
            await manager._acleanup_references(target)
        return ok

    def __exit__(
        self,
        /,
        exc_type: t.Optional[type] = None,
        exc_value: t.Optional[Exception] = None,
        traceback: t.Optional[t.TracebackType] = None,
    ) -> bool:
        """
        Raises `self.IncoherentConcurrencyState` if another instance's
        authorization token has taken this instance's place in the token
        queue.

        Otherwise, raises any exception raised in the context's code
        block.

        Otherwise, closes the context silently.

        Always attempts to allow the manager to cleanup its references
        prior to returning.
        """
        try:
            ok = super().__exit__(exc_type, exc_value, traceback)
        finally:
            manager, target = self._refs.manager, self._refs.target
            manager._cleanup_references(target)
        return ok


class DefaultDictOfDeques(defaultdict):
    """
    A mapping of target ID keys to deque queues which are used to
    enforce the turn order of distinct execution contexts only if the
    target keys are the same between them.
    """

    __slots__ = ("__queue", "__observers")

    _Guard: t.ConcurrencyGuardType = ConcurrencyGuard

    def __init__(self, /) -> None:
        """
        Applies `collections.deque` as the default value type of new
        instances.
        """
        super().__init__(deque)
        self.__queue = deque()
        self.__observers = deque()

    def __setitem__(
        self, name: t.Hashable, value: deque[t.ConcurrencyGuardType], /
    ) -> None:
        """
        Before adding values to the collection, ensures they're of type
        `collections.deque`.
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
        the collection, ensures they're of type `collections.deque`.
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
        which don't modify the collection's state simultaneously, but
        which concede their starts until any new exclusive contexts
        finish.
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
    & independently from each other, & those operating on the same
    target will delay their turn to run by appending their unique tokens
    to atomic queues & awaiting their arrival at the front of the order
    queue.

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
        queues: t.Optional[_Queues] = None,
        /,
        *,
        observers: t.Optional[_Observers] = None,
        users: t.Optional[_Users] = None,
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
        self, /, target: t.Hashable, guard: t.ConcurrencyGuardType
    ) -> None:
        """
        Ensures the target references given to the guard instance are
        consistent with the other running instances of the same target
        Since only reads are done an async/thread-safe non-exclusive
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
        self, /, target: t.Hashable, guard: t.ConcurrencyGuardType
    ) -> None:
        """
        Ensures the target references given to the guard instance are
        consistent with the other running instances of the same target
        Since only reads are done an async/thread-safe non-exclusive
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
        self, /, target: t.Hashable, guard: t.ConcurrencyGuardType
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
        policy: t.Optional[t.ConcurrencyGuardPolicy] = None,
        probe_delay: t.Optional[t.PositiveRealNumber] = None,
        token: t.Optional[bytes] = None,
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
            policy=policy, probe_delay=probe_delay, token=token
        )
        self._pass_self_references(target, guard)
        return guard

    def monitor(
        self,
        /,
        target: t.Hashable,
        *,
        policy: t.Optional[t.ConcurrencyGuardPolicy] = None,
        probe_delay: t.Optional[t.PositiveRealNumber] = None,
        token: t.Optional[bytes] = None,
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
            policy=policy, probe_delay=probe_delay, token=token
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
    QueueManuallyPolicy=t.add_type(QueueManuallyPolicy),
    ConcurrencyGuard=t.add_type(ConcurrencyGuard),
    ConcurrencyGuardPolicies=t.add_type(ConcurrencyGuardPolicies),
    DefaultDictOfDeques=t.add_type(DefaultDictOfDeques),
    ExclusivePolicy=t.add_type(ExclusivePolicy),
    ManagedConcurrecyGuard=t.add_type(ManagedConcurrecyGuard),
    MultiConcurrencyGaurd=t.add_type(MultiConcurrencyGaurd),
    NonExclusivePolicy=t.add_type(NonExclusivePolicy),
    SelfReferences=t.add_type(SelfReferences),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
