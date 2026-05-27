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

__all__ = ["ConcurrencyGuard", "MultiConcurrencyGaurd"]


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

    def __bool__(self, /) -> bool:
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
        (tracker := guard._use_tracker).append(True)

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
        if not compare_digest(guard.token, guard.queue.popleft().token):
            raise guard.IncoherentConcurrencyState

    def is_free_to_run(self, /, guard: t.ConcurrencyGuardType) -> bool:
        """
        If the guard is next on the queue & there are no non-exclusive
        guards currently running, returns `True` to signal it can safely
        take its turn to run.
        """
        is_next_in_queue = compare_digest(guard.token, guard.queue[0].token)
        no_others_running = bool(guard.observers[0].policy)
        return is_next_in_queue and no_others_running


class AppendTokenManuallyPolicy(ExclusivePolicy):
    """
    Signals to the `ConcurrencyGuard` instance that the caller will
    manually append the guard instance to the queue to acheive the
    desired ordering of events. This overrides the default behavior of
    the guard being automatically appended when the instance context
    manager is entered. The instance remains responsible for
    automatically removing the appropriate guard from the queue when the
    context manager is exited.
    ********
    CAUTION: Care must be taken not to use the same guard token multiple
    ******** times. Doing so may cause a deadlock, incoherent state, or
    exception if two instances with the same token enter their contexts
    simultaneously, & then during exit, pop a token off the queue
    expecting it to be their own.
    """

    __slots__ = ()

    def get_in_queue(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        A no-op since the caller has signalled that they'll handle
        appending the guard to the order queue manually.
        """


class NonExclusivePolicy(FrozenInstance):
    """
    Signals to the `ConcurrencyGuard` instance that it can run freely
    when it arrives at the front of the queue. Exclusive instances will
    wait for all non-exclusive instances to signal that they're done
    working & no longer observing the queue before beginning. Meanwhile,
    non-exclusive instances will always run once they've signalled that
    they're observing the queue.
    """

    __slots__ = ()

    def __bool__(self, /) -> bool:
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
        (tracker := guard._use_tracker).append(True)

        if len(tracker) > 1:
            raise SingleUseObjectWasReused(Metadata(guard))

    def notify_on(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        A no-op since non-exclusive policies notify other guards using
        the observers deque only after they've arrived at the front of
        the order queue. This is safe because either an exlusive guard
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
        exclusive policy, the guard will wait for it's turn on the queue
        to notify other guards that it is running using the observer
        deque. It will then remove itself immediately from the order
        queue allowing other non-exclusive guards to run, & exclusive
        guards to wait for all non-exclusive guards to signal they're
        done running by vacating themselves from the observers deque.
        """
        guard.queue.append(guard)

    def get_off_queue(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        A no-op since non-exclusive policies remove themselves from the
        order queue immediately after their turn in the queue has
        arrived & they've prepended themselves to the observers deque.
        """

    def is_free_to_run(self, /, guard: t.ConcurrencyGuardType) -> bool:
        """
        If the guard is next on the queue, notifies other guards
        immediately that it will run by prepending itself to the
        observers deque, & removing itself from the order queue to allow
        other guards to take their turn & make the appropriate informed
        decisions.
        """
        if can_run := compare_digest(guard.token, guard.queue[0].token):
            guard.observers.appendleft(guard)  # append first to rule-
            guard.queue.popleft()  # out race-conditions
        return can_run


class ConcurrencyGuardPolicies(OpenFrozenTypedSlots):
    """ """

    __slots__ = ("Exclusive", "AppendTokenManually", "NonExclusive")

    slots_types = dict(
        Exclusive=t.ConcurrencyGuardPolicy,
        AppendTokenManually=t.ConcurrencyGuardPolicy,
        NonExclusive=t.ConcurrencyGuardPolicy,
    )


class ConcurrencyGuard(FrozenTypedSlots):
    """
    An interface for queueing execution contexts given only a pair of
    shared, atomic `deque` double-ended queues. Prevents simultaneous /
    out of order runs of blocks of code; as well as contexts which are
    allowed to run freely, but with async/thread-safe awareness &
    concession to new contexts which require exclusive access to
    execution time.

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
        AppendTokenManually=AppendTokenManuallyPolicy,
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
        `queue`: Shared, atomic `deque` datastructure used to order the
                execution contexts of guard instances.

        `observers`: Shared, atomic `deque` datastructure used to track
                running non-exclusive guard instances on the 0th side of
                the queue, & waiting/running exclusive guard instances
                on the -1th side.

        `policy`: A `ConcurrencyGuard` policy instance which manages the
                logic necessary for async/thread-safe ordering of
                execution contexts.

        `probe_delay`: The float/fractional number of seconds to wait
                before each attempt to detect if the instance's token
                has been authorized to run.

        `token`: The unique authorization token held by this context.
        """
        if isinstance(policy, type):
            raise Issue.value_must_be_type(
                "policy", t.ConcurrencyGuardPolicy
            )

        self._use_tracker = deque(maxlen=2)
        self.policy = (
            self.policies.Exclusive() if policy is None else policy
        )
        self.probe_delay = process_probe_delay(
            probe_delay, default=self._default_probe_delay
        )
        self.observers = deque() if observers is None else observers
        self.queue = queue
        self.token = token or token_bytes(32)

    async def __aenter__(self, /) -> t.Self:
        """
        Prevents entering the context by asynchronously sleeping until
        the instance's unique authorization token is the current token
        in the 0th position of the queue.
        """
        policy = self.policy
        policy.use(self)
        policy.notify_on(self)
        policy.get_in_queue(self)

        while not policy.is_free_to_run(self):
            await asleep(self.probe_delay)

        return self

    def __enter__(self, /) -> t.Self:
        """
        Prevents entering the context by synchronously sleeping until
        the instance's unique authorization token is the current token
        in the 0th position of the queue.
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
        await asleep()
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


class DefaultDictOfDeques(defaultdict):
    """
    A mapping of target ID keys to deque queues which are used to
    enforce the turn order of distinct execution contexts only if the
    target keys are the same between them.
    """

    __slots__ = ()

    def __init__(self, /) -> None:
        """
        Applies `collections.deque` as the default value type of new
        instances.
        """
        super().__init__(deque)

    def __setitem__(
        self, name: t.Hashable, value: deque[t.ConcurrencyGuardType], /
    ) -> None:
        """
        Before adding values to the collection, ensures they're of type
        `collections.deque`.
        """
        if value.__class__ is not deque:
            raise Issue.must_be_type("value", deque) from None

        super().__setitem__(name, value)

    def update(
        self,
        targets: t.Mapping[t.Hashable, deque[t.ConcurrencyGuardType]] = {},
        /,
        **target_deque_pairs: deque[t.ConcurrencyGuardType],
    ) -> None:
        """
        Updates the instance with new key-values from a mapping of
        `targets`, & optional keyword arguments. Operations on targets
        only need concurrency management if the target keys are the same,
        so those on different targets are allowed to run freely &
        independently from each other. Before adding values to the
        collection, ensures they're of type `collections.deque`.
        """
        for name, value in {**dict(targets), **target_deque_pairs}.items():
            self[name] = value  # type enforcement happens here


class MultiConcurrencyGaurd(FrozenTypedSlots):
    """
    Facilitates async/thread-safety for execution contexts which can be
    categorized by a hashable target key from call-sites. Executuion
    contexts which operate on distinct targets are allowed to run freely
    & independently from each other, & those operating on the same
    target will delay their turn to run by appending their unique tokens
    to atomic queues & awaiting their arrival at the front of the queue.

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

    __slots__ = ("observers", "targets")

    _Guard: type = ConcurrencyGuard
    _Observers: type = DefaultDictOfDeques
    _Targets: type = DefaultDictOfDeques

    IncoherentConcurrencyState: type = IncoherentConcurrencyState

    slots_types = dict(observers=_Observers, targets=_Targets)

    def __init__(
        self,
        targets: t.Optional[_Targets] = None,
        /,
        *,
        observers: t.Optional[_Observers] = None,
    ) -> None:
        """
        Initializes the instance with a default mapping of target ID
        keys to deque queues.
        """
        self.observers = (
            self._Observers() if observers is None else observers
        )
        self.targets = self._Targets() if targets is None else targets

    def guard(
        self,
        /,
        target: t.Hashable,
        *,
        policy: t.Optional[t.ConcurrencyGuardPolicy] = None,
        probe_delay: t.Optional[t.PositiveRealNumber] = None,
        token: t.Optional[bytes] = None,
    ) -> _Guard:
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
        ExclusivePolicy = self._Guard.policies.Exclusive
        policy = ExclusivePolicy() if policy is None else policy
        if not issubclass(policy.__class__, ExclusivePolicy):
            raise Issue.value_must_be_subtype("policy", ExclusivePolicy)

        return self._Guard(
            observers=self.observers[target],
            queue=self.targets[target],
            probe_delay=probe_delay,
            token=token,
            policy=policy,
        )

    def monitor(
        self,
        /,
        target: t.Hashable,
        *,
        policy: t.Optional[t.ConcurrencyGuardPolicy] = None,
        probe_delay: t.Optional[t.PositiveRealNumber] = None,
        token: t.Optional[bytes] = None,
    ) -> _Guard:
        """
        Returns the non-exclusive guard instance which can be entered
        using either the sync or async context manager syntaxes.
        Instances that are run in monitor mode execute freely with other
        non-exclusive instances as long as no exclusive mode instances
        have been added to the observers queue. In the latter case, non-
        exclusive instances will wait for all such exclusive instances
        to finish running before signalling that they're ready to run.

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
        NonExclusivePolicy = self._Guard.policies.NonExclusive
        policy = NonExclusivePolicy() if policy is None else policy
        if not issubclass(policy.__class__, NonExclusivePolicy):
            raise Issue.value_must_be_subtype("policy", NonExclusivePolicy)

        return self._Guard(
            observers=self.observers[target],
            queue=self.targets[target],
            probe_delay=probe_delay,
            token=token,
            policy=policy,
        )


module_api = dict(
    AppendTokenManuallyPolicy=t.add_type(AppendTokenManuallyPolicy),
    ConcurrencyGuard=t.add_type(ConcurrencyGuard),
    ConcurrencyGuardPolicies=t.add_type(ConcurrencyGuardPolicies),
    DefaultDictOfDeques=t.add_type(DefaultDictOfDeques),
    ExclusivePolicy=t.add_type(ExclusivePolicy),
    MultiConcurrencyGaurd=t.add_type(MultiConcurrencyGaurd),
    NonExclusivePolicy=t.add_type(NonExclusivePolicy),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
