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
Types which guide guard instances through the template of steps that
ensure async/thread-safe state management, as well as exclusive & non-
exclusive context features.
"""

__all__ = [
    "ConcurrencyGuardPolicies",
    "ExclusivePolicy",
    "NonExclusivePolicy",
    "NonExclusiveQueueManuallyPolicy",
    "QueueManuallyPolicy",
]


from aiootp._typing import Typing as t
from aiootp.commons import FrozenInstance, OpenFrozenTypedSlots


class ConcurrencyGuardPolicy(FrozenInstance):
    """
    A base type for `ConcurrencyGuard` policy types.
    """

    __slots__ = ()

    def __init__(self, /) -> None:
        """
        A no-op to override the default `FrozenInstance` initializer.
        """


class ExclusivePolicy(ConcurrencyGuardPolicy):
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
        Uses an atomic state machine object to invalidate multiple uses
        of the guard instance.
        """
        guard._use_tracker.transition_to_pending()

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
        Removes the guard from the order queue. If the guard isn't in
        the 0th position, raises `IncoherentConcurrencyState`.
        """
        if guard is not guard.queue.popleft():
            guard._use_tracker.enter_fault_state()
            raise guard.IncoherentConcurrencyState from None

        guard._use_tracker.transition_to_done()

    def is_free_to_run(self, /, guard: t.ConcurrencyGuardType) -> bool:
        """
        If the guard is next on the order queue & there are no non-
        exclusive guards currently running, returns `True` to signal it
        can safely take its turn to run.
        """
        is_next_in_queue = guard is guard.queue[0]
        no_others_running = guard.observers[0].policy.is_exclusive()
        if can_run := is_next_in_queue and no_others_running:
            with guard._use_tracker as tracker:
                tracker.add_fault_signal(guard.observers.pop)
                tracker.add_fault_signal(guard.queue.popleft)
                tracker.transition_to_running()
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
    """

    __slots__ = ()

    def get_in_queue(self, /, guard: t.ConcurrencyGuardType) -> None:
        """
        A no-op since the caller has signaled that they'll handle
        appending the guard to the order queue manually.
        """


class NonExclusivePolicy(ConcurrencyGuardPolicy):
    """
    Signals to the `ConcurrencyGuard` instance that it can run freely
    when it arrives at the front of the order queue. Exclusive instances
    will wait for all non-exclusive instances to signal that they're
    done working & no longer on the observers deque before beginning.
    Meanwhile, non-exclusive instances will always run once they've been
    prepended to the observers deque.
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
        Uses an atomic state machine object to invalidate multiple uses
        of the guard instance.
        """
        guard._use_tracker.transition_to_pending()

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
        A no-op since non-exclusive policies remove their guard from the
        order queue immediately after its turn in the order queue has
        arrived & they've prepended it to the observers deque.
        """
        guard._use_tracker.transition_to_done()

    def is_free_to_run(self, /, guard: t.ConcurrencyGuardType) -> bool:
        """
        If the guard is next on the order queue, notifies other guards
        immediately that it will run by prepending its guard to the
        observers deque, & removing it from the order queue to allow
        other guards to take their turn & make the appropriate informed
        decisions.
        """
        if can_run := guard is guard.queue[0]:
            with guard._use_tracker as tracker:
                # append first to rule-out race conditions
                guard.observers.appendleft(guard)
                tracker.add_fault_signal(guard.observers.popleft)
                if guard is not guard.queue.popleft():
                    raise guard.IncoherentConcurrencyState from None
                tracker.transition_to_running()
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
        Exclusive=t.ConcurrencyGuardPolicyType,
        QueueManually=t.ConcurrencyGuardPolicyType,
        NonExclusive=t.ConcurrencyGuardPolicyType,
        NonExclusiveQueueManually=t.ConcurrencyGuardPolicyType,
    )


module_api = dict(
    ConcurrencyGuardPolicies=t.add_type(ConcurrencyGuardPolicies),
    ExclusivePolicy=t.add_type(ExclusivePolicy),
    NonExclusivePolicy=t.add_type(NonExclusivePolicy),
    NonExclusiveQueueManuallyPolicy=t.add_type(
        NonExclusiveQueueManuallyPolicy,
    ),
    QueueManuallyPolicy=t.add_type(QueueManuallyPolicy),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
