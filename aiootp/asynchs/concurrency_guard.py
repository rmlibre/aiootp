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

__all__ = ["ConcurrencyGuard"]


from hmac import compare_digest
from secrets import token_bytes
from collections import deque

from aiootp._typing import Typing as t
from aiootp._exceptions import Issue, IncoherentConcurrencyState
from aiootp._exceptions import Metadata, SingleUseObjectWasReused
from aiootp.commons import FrozenInstance
from aiootp.commons import FrozenTypedSlots, OpenFrozenTypedSlots

from .loops import asleep, sleep
from .concurrency_interface import process_probe_delay


class ExclusivePolicy(FrozenInstance):
    """
    Signals to the `ConcurrencyGuard` instance that when it arrives at
    the front of the order queue, & there are no other non-exclusive
    guards running, that it may run freely. Until the guard exits its
    context & its policy removes it from the order queue, no other
    guards will be allowed to run.
    """

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
    automatically being removed from the order queue when the context
    manager is exited.
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
        the observers deque only after the guard instance has arrived at
        the front of the order queue. This is safe because either an
        exclusive guard just finished running & was removed from the
        order queue, meaning there are now no other guards running; or
        only non-exclusive guards are running, which is allowed.
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
        observer deque. It will then immediately be removed from the
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


class NonExclusiveQueueManuallyPolicy(NonExclusivePolicy):
    """
    Signals to the `ConcurrencyGuard` instance that the caller will
    manually append the guard instance to the order queue to achieve the
    desired ordering of events. This overrides the default behavior of
    the guard being automatically appended when the instance context
    manager is entered. The instance remains responsible for
    automatically being removed from the order queue when it detects its
    turn to run has come. Non-exclusive policies don't ensure the
    deterministic ordering of events when run simultaneously with other
    guards using non-exclusive policies, but this policy can be used for
    ordering events to run before or after other guards using exclusive
    policies as desired.
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


class ConcurrencyGuardPolicies(OpenFrozenTypedSlots):
    """
    An efficient & typed mapping container for policy types.
    """

    __slots__ = (
        "Exclusive",
        "QueueManually",
        "NonExclusive",
        "NonExclusiveQueueManually",
    )

    slots_types = dict(
        Exclusive=t.ConcurrencyGuardPolicy,
        QueueManually=t.ConcurrencyGuardPolicy,
        NonExclusive=t.ConcurrencyGuardPolicy,
        NonExclusiveQueueManually=t.ConcurrencyGuardPolicy,
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

                               queue = deque()
                             observers = deque()
        NonExclusivePolicy = ConcurrencyGuard.policies.NonExclusive
                           -----------------------
            -----------------         |        -----------------
            |   Context A   |         |        |   Context B   |
            -----------------         |        -----------------
                                      |
    with ConcurrencyGuard(            |  with ConcurrencyGuard(
        queue,                        |      queue,
        observers=observers,          |      observers=observers,
        policy=NonExclusivePolicy(),  |  ) as b:
    ) as a:                           |      assert b.is_running()
        assert a.is_running()         |      assert a.is_done()
        ...                           |      assert c.is_done()
        assert c.is_running()         |      assert d.is_pending()
        ...                           |
        assert b.is_pending()         |
                                      |
            -----------------         |        -----------------
            |   Context C   |         |        |   Context D   |
            -----------------         |        -----------------
                                      |
    with ConcurrencyGuard(            |  d = ConcurrencyGuard(
        queue,                        |      queue,
        observers=observers,          |      observers=observers,
        policy=NonExclusivePolicy(),  |      policy=NonExclusivePolicy(),
    ) as c:                           |  )
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
        NonExclusiveQueueManually=NonExclusiveQueueManuallyPolicy,
    )

    IncoherentConcurrencyState: type = IncoherentConcurrencyState

    def _set_policy(
        self, /, policy: t.ConcurrencyGuardPolicy | None
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

    def __init__(
        self,
        /,
        queue: deque[t.ConcurrencyGuardType],
        *,
        observers: deque[t.ConcurrencyGuardType] | None = None,
        policy: t.ConcurrencyGuardPolicy | None = None,
        probe_delay: t.PositiveRealNumber | None = None,
        token: bytes | None = None,
    ) -> None:
        """
        `queue`: Shared, atomic `deque` data structure used to order the
                execution contexts of guard instances.

        `observers`: Shared, atomic `deque` data structure used to track
                any running non-exclusive guard instances on the 0th
                side of the queue, & any waiting/running exclusive guard
                instances on the -1th side. This queue is not ordered,
                but the invariant stated above is preserved. A shared
                deque only needs to be provided by the user if they'll
                be utilizing non-exclusive policies.

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

    def is_unused(self, /) -> bool:
        """
        Returns `True` if the guard instance still hasn't been placed
        in a context manager, so it has sent no usage signals at all.
        Otherwise returns `False`.

        Unused state:

        _use_tracker == deque([], maxlen=2)
        """
        return not self._use_tracker

    def is_pending(self, /) -> bool:
        """
        Returns `True` if the guard instance has been placed in a
        context manager, & has signaled that it's ready & waiting for
        its turn, but its turn hasn't yet arrived. Otherwise returns
        `False`.

        Pending state:

        _use_tracker == deque([False], maxlen=2)
        """
        return len(self._use_tracker) == 1

    def is_running(self, /) -> bool:
        """
        Returns `True` if the guard instance's turn has arrived & it has
        begun moving to enter the context. Otherwise returns `False` if
        either it hasn't signaled this move, or it has signaled that it
        has exited the context.

        Running state:

        _use_tracker == deque([False, True], maxlen=2)
        """
        tracker = self._use_tracker
        return bool(tracker) and tracker[-1]

    def is_done(self, /) -> bool:
        """
        Returns `True` if the guard instance has signaled that it's
        already exited the context. Otherwise returns `False`.

        Done state:

        _use_tracker == deque([True, False], maxlen=2)
        """
        tracker = self._use_tracker
        return bool(tracker) and tracker[0]

    async def __aenter__(self, /) -> t.Self:
        """
        Prevents entering the context by asynchronously sleeping until
        the instance's unique authorization token is held by the current
        instance in the 0th position of the order queue, & other logic
        depending on the instance's policy.
        """
        await asleep()
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
        the instance's unique authorization token is held by the current
        instance in the 0th position of the order queue, & other logic
        depending on the instance's policy.
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
        """
        await asleep()
        self.policy.notify_off(self)
        self.policy.get_off_queue(self)
        return exc_type is None

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
        """
        self.policy.notify_off(self)
        self.policy.get_off_queue(self)
        return exc_type is None


module_api = dict(
    QueueManuallyPolicy=t.add_type(QueueManuallyPolicy),
    ConcurrencyGuard=t.add_type(ConcurrencyGuard),
    ConcurrencyGuardPolicies=t.add_type(ConcurrencyGuardPolicies),
    ExclusivePolicy=t.add_type(ExclusivePolicy),
    NonExclusivePolicy=t.add_type(NonExclusivePolicy),
    NonExclusiveQueueManuallyPolicy=t.add_type(
        NonExclusiveQueueManuallyPolicy
    ),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
