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
Helper types which ensure guard instances & their policies are used
correctly & transition through their states in the correct order.
"""

__all__ = [
    "ConcurrencyGuardState",
    "ConcurrencyGuardUseTracker",
    "DoneState",
    "PendingState",
    "RunningState",
    "UnusedState",
]


from collections import deque

from aiootp._typing import Typing as t
from aiootp._exceptions import InvalidStateTransition
from aiootp.commons import FrozenInstance


class ConcurrencyGuardState(FrozenInstance):
    """
    A type to signify the distinct states of guard instances.
    """

    __slots__ = ()

    def __init__(self, /) -> None:
        """
        No-op to override the default `FrozenInstance` initializer.
        """


class UnusedState(ConcurrencyGuardState):
    """
    A type to signify a guard instance has only just been initialized.
    """

    __slots__ = ()

    def begin_waiting(
        self,
        /,
        tracker: t.ConcurrencyGuardUseTrackerType,
    ) -> "PendingState":
        """
        Returns a `Pending` state object for guard instances. Being the
        only state type with this method, attempting to call this method
        from another state causes an `InvalidStateTransition` exception.
        """
        return tracker.Pending()


class PendingState(ConcurrencyGuardState):
    """
    A type to signify a guard instance is waiting to enter its context.
    """

    __slots__ = ()

    def run(
        self,
        /,
        tracker: t.ConcurrencyGuardUseTrackerType,
    ) -> "RunningState":
        """
        Returns a `Running` state object for guard instances. Being the
        only state type with this method, attempting to call this method
        from another state causes an `InvalidStateTransition` exception.
        """
        return tracker.Running()


class RunningState(ConcurrencyGuardState):
    """
    A type to signify a guard instance has entered its context.
    """

    __slots__ = ()

    def finish(
        self,
        /,
        tracker: t.ConcurrencyGuardUseTrackerType,
    ) -> "DoneState":
        """
        Returns a `Done` state object for guard instances. Being the
        only state type with this method, attempting to call this method
        from another state causes an `InvalidStateTransition` exception.
        """
        return tracker.Done()


class DoneState(ConcurrencyGuardState):
    """
    A type to signify a guard instance has exited its context.
    """

    __slots__ = ()


class ConcurrencyGuardUseTracker(FrozenInstance):
    """
    Manages & validates the initialization & transition between states
    for `ConcurrencyGuard` instances.
    """

    __slots__ = ("_signals", "_state")

    Unused: type = UnusedState
    Pending: type = PendingState
    Running: type = RunningState
    Done: type = DoneState

    def __init__(self, /) -> None:
        """
        Initializes the atomic state tracker container for async/thread-
        safe management of `ConcurrencyGuard` state transitions. Raises
        `InvalidStateTransition` if multiple calls to this initializer
        are attempted.
        """
        try:
            self._signals = deque()
            self._state = deque([self.Unused()], maxlen=1)
        except PermissionError as error:
            raise InvalidStateTransition from error

    def add_fault_signal(self, /, signal: t.Callable[[], t.Any]) -> None:
        """
        To maintain coherent queue states where possible, allows the
        caller to register non-blocking callbacks which will be executed
        in FIFO order in case `InvalidStateTransition` is raised within
        the instance's context manager.
        """
        self._signals.append(signal)

    def __enter__(self, /) -> t.Self:
        """
        Allows call sites to wrap codeblocks which try state transitions
        so that `InvalidStateTransition` exceptions are caught. The
        caller can provide non-blocking, ordered callbacks to run that
        attempt to keep queue states coherent & clear of unused
        references after fault.
        """
        return self

    def __exit__(
        self,
        /,
        exc_type: type | None = None,
        exc_value: Exception | None = None,
        traceback: t.TracebackType | None = None,
    ) -> bool:
        """
        If an `InvalidStateTransition` is raised within the context,
        executes the caller's provided non-blocking state fault signals.

        Raises any exception raised in the context's code block.

        Otherwise, closes the context silently.

        Always attempts to clear out all provided state fault signals
        from the signals queue.
        """
        signals = self._signals
        if isinstance(exc_value, InvalidStateTransition):
            while signals:
                signals.popleft()()
        else:
            signals.clear()

        return exc_type is None

    def transition_to_pending(self, /) -> None:
        """
        Moves to the pending state only if the instance is currently in
        the unused state. Otherwise throws `InvalidStateTransition`.
        """
        try:
            pending_state = self._state.pop().begin_waiting(self)
        except (IndexError, AttributeError) as error:
            raise InvalidStateTransition from error

        self._state.append(pending_state)

    def transition_to_running(self, /) -> None:
        """
        Moves to the running state only if the instance is currently in
        the pending state. Otherwise throws `InvalidStateTransition`.
        """
        try:
            running_state = self._state.pop().run(self)
        except (IndexError, AttributeError) as error:
            raise InvalidStateTransition from error

        self._state.append(running_state)

    def transition_to_done(self, /) -> None:
        """
        Moves to the done state only if the instance is currently in the
        running state. Otherwise throws `InvalidStateTransition`.
        """
        try:
            done_state = self._state.pop().finish(self)
        except (IndexError, AttributeError) as error:
            raise InvalidStateTransition from error

        self._state.append(done_state)

    def enter_fault_state(self, /) -> None:
        """
        Moves the instance to a state which signals that the guard
        instance has flowed through an invalid state transition or
        encountered an incoherent state.
        """
        self._state.clear()

    def is_unused(self, /) -> bool:
        """
        Returns `True` if the guard instance still hasn't been placed
        in a context manager, so it has sent no usage signals at all.
        Otherwise returns `False`.
        """
        try:
            return isinstance(self._state[0], self.Unused)
        except IndexError:
            return False

    def is_pending(self, /) -> bool:
        """
        Returns `True` if the guard instance has been placed in a
        context manager, & has signaled that it's ready & waiting for
        its turn, but its turn hasn't yet arrived. Otherwise returns
        `False`.
        """
        try:
            return isinstance(self._state[0], self.Pending)
        except IndexError:
            return False

    def is_running(self, /) -> bool:
        """
        Returns `True` if the guard instance's turn has arrived & it has
        begun moving to enter the context. Otherwise returns `False` if
        either it hasn't signaled this move, or it has signaled that it
        has exited the context.
        """
        try:
            return isinstance(self._state[0], self.Running)
        except IndexError:
            return False

    def is_done(self, /) -> bool:
        """
        Returns `True` if the guard instance has signaled that it's
        already exited the context. Otherwise returns `False`.
        """
        try:
            return isinstance(self._state[0], self.Done)
        except IndexError:
            return False

    def has_faulted(self, /) -> bool:
        """
        Returns `True` if the guard instance has flowed through an
        invalid state transition or encountered an incoherent state.
        Otherwise returns `False`.
        """
        return not self._state


module_api = dict(
    ConcurrencyGuardState=t.add_type(ConcurrencyGuardState),
    ConcurrencyGuardUseTracker=t.add_type(ConcurrencyGuardUseTracker),
    DoneState=DoneState,
    PendingState=PendingState,
    RunningState=RunningState,
    UnusedState=UnusedState,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
