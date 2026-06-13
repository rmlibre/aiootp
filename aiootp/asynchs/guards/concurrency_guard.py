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


from secrets import token_bytes
from collections import deque

from aiootp._typing import Typing as t
from aiootp._exceptions import Issue, IncoherentConcurrencyState
from aiootp._exceptions import InvalidStateTransition, Metadata
from aiootp.commons import FrozenTypedSlots
from aiootp.asynchs.loops import asleep, sleep
from aiootp.asynchs.concurrency_interface import process_probe_delay

from .state_machine import ConcurrencyGuardUseTracker
from .policies import ConcurrencyGuardPolicies
from .policies import ExclusivePolicy, QueueManuallyPolicy
from .policies import NonExclusivePolicy, NonExclusiveQueueManuallyPolicy


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

    _UseTracker: type = ConcurrencyGuardUseTracker

    _default_probe_delay: float = 0.00001

    slots_types: t.Mapping[str, type] = dict(
        _use_tracker=t.ConcurrencyGuardUseTrackerType,
        observers=deque,
        policy=t.ConcurrencyGuardPolicyType,
        probe_delay=float,
        queue=deque,
        token=bytes,
    )

    policies: ConcurrencyGuardPolicies = ConcurrencyGuardPolicies(
        Exclusive=ExclusivePolicy,
        QueueManually=QueueManuallyPolicy,
        NonExclusive=NonExclusivePolicy,
        NonExclusiveQueueManually=NonExclusiveQueueManuallyPolicy,
    )

    IncoherentConcurrencyState: type = IncoherentConcurrencyState
    InvalidStateTransition: type = InvalidStateTransition

    def _set_policy(
        self,
        /,
        policy: t.ConcurrencyGuardPolicyType | None,
    ) -> None:
        """
        Ensures the passed policy value is an instance of a policy class
        which matches the ConcurrencyGuardPolicyType protocol. If `None` is
        passed, then a default ExclusivePolicy instance is chosen.
        """
        if policy is None:
            self.policy = self.policies.Exclusive()
        elif isinstance(policy, type):
            raise Issue.must_be_type(
                Metadata(policy),
                t.ConcurrencyGuardPolicyType,
            )
        else:
            self.policy = policy

    def __init__(
        self,
        /,
        queue: deque[t.ConcurrencyGuardType],
        *,
        observers: deque[t.ConcurrencyGuardType] | None = None,
        policy: t.ConcurrencyGuardPolicyType | None = None,
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
        self._use_tracker = self._UseTracker()
        self.probe_delay = process_probe_delay(
            probe_delay,
            default=self._default_probe_delay,
        )
        self.observers = deque() if observers is None else observers
        self.queue = queue
        self.token = token or token_bytes(32)

    def is_unused(self, /) -> bool:
        """
        Returns `True` if the guard instance still hasn't been placed
        in a context manager, so it has sent no usage signals at all.
        Otherwise returns `False`.
        """
        return self._use_tracker.is_unused()

    def is_pending(self, /) -> bool:
        """
        Returns `True` if the guard instance has been placed in a
        context manager, & has signaled that it's ready & waiting for
        its turn, but its turn hasn't yet arrived. Otherwise returns
        `False`.
        """
        return self._use_tracker.is_pending()

    def is_running(self, /) -> bool:
        """
        Returns `True` if the guard instance's turn has arrived & it has
        begun moving to enter the context. Otherwise returns `False` if
        either it hasn't signaled this move, or it has signaled that it
        has exited the context.
        """
        return self._use_tracker.is_running()

    def is_done(self, /) -> bool:
        """
        Returns `True` if the guard instance has signaled that it's
        already exited the context. Otherwise returns `False`.
        """
        return self._use_tracker.is_done()

    def has_faulted(self, /) -> bool:
        """
        Returns `True` if the guard instance has flowed through an
        invalid state transition or encountered an incoherent state.
        Otherwise returns `False`.
        """
        return self._use_tracker.has_faulted()

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
    ConcurrencyGuard=t.add_type(ConcurrencyGuard),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
