# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2024 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["EntropyDaemon"]


__doc__ = (
    "A type responsible for starting an entropy gathering background "
    "thread."
)


from collections import deque

from aiootp._typing import Typing as t
from aiootp._exceptions import Issue
from aiootp.asynchs import Threads, asleep, s_counter

from .simple import acanonical_token, arandom_sleep


class EntropyDaemon:
    """
    Creates & manages a background thread which asynchronously extracts
    from & seeds new entropy into this module's entropy pools. Mixing
    background threading, asynchrony, system entropy, nanosecond
    timestamps, pseudo random sleeps, & SHA3 hashing with a shared
    global object results in prediction & backtracking resistant, non-
    deterministic effects on entropy generation for the whole package.
    """

    __slots__ = (
        "_cache",
        "_cancel",
        "_currently_mutating_frequency",
        "_daemon",
        "_frequency_mutation_deadline",
        "_gadget",
        "_initial_max_delay",
        "_max_delay",
        "_pool",
    )

    def __init__(
        self,
        *,
        entropy_pool: t.Deque[bytes],
        gadget: t.EntropyHashingType,
        max_delay: t.PositiveRealNumber = 1,
    ) -> None:
        """
        Prepares an instance to safely start a background thread.
        """
        self._pool = entropy_pool
        self._gadget = gadget
        self._cache = deque(maxlen=2)
        self._cancel = False
        self._currently_mutating_frequency = False
        self.set_max_delay(max_delay)

    async def _new_snapshot(self) -> bytes:
        """
        Returns a snapshot of the newest & oldest parts of the instance
        entropy pool prepended with a canonical token.
        """
        return await acanonical_token() + self._pool[0] + self._pool[-1]

    async def _acknowledge_temporary_frequency_deadline(self) -> None:
        """
        Switch off the temporary frequency flags if the duration given
        by the user has elapsed.
        """
        await asleep()
        if not self._currently_mutating_frequency:
            return
        deadline_delta = self._frequency_mutation_deadline - s_counter()
        deadline_reached = deadline_delta <= 0
        delay_skips_deadline = self._max_delay - deadline_delta > 1
        if deadline_reached:
            self._max_delay = self._initial_max_delay
            self._currently_mutating_frequency = False
        elif delay_skips_deadline:
            self._max_delay = deadline_delta  # pragma: no cover

    def set_temporary_max_delay(
        self,
        max_delay: t.PositiveRealNumber = 0.001,
        *,
        duration: t.PositiveRealNumber = 1,
    ) -> t.Self:
        """
        Sets a temporary maximum number of seconds a started entropy
        daemon will pseudo-randomly sleep in-between each iteration. The
        initial instance frequency will be restored after `duration`
        number of seconds.
        """
        if max_delay > 0:
            self._frequency_mutation_deadline = s_counter() + duration
            self._max_delay = max_delay
            self._currently_mutating_frequency = True
            return self
        else:
            raise Issue.value_must("max_delay", "be > 0")

    def set_max_delay(
        self, max_delay: t.PositiveRealNumber = 1
    ) -> t.Self:
        """
        Sets the maximum number of seconds a started entropy daemon will
        pseudo-randomly sleep in-between each iteration. Setting
        `max_delay` to smaller numbers will cause more cpu power to be
        consumed by the background daemon thread.
        """
        if max_delay > 0:
            self._initial_max_delay = max_delay
            self._max_delay = max_delay
            return self
        else:
            raise Issue.value_must("max_delay", "be > 0")

    async def _araw_loop(self) -> None:
        """
        Takes snapshots of & feeds entropy into the module's entropy
        pools before & after sleeping for a pseudo-random amount of time.
        This is done asynchronously & in a background thread to
        automatically keep the package entropy fresh, & to increase the
        unpredictability & non-determinism of entropy generation.
        """
        while True:
            self._cache.appendleft(await self._new_snapshot())
            entropy = await self._gadget.ahash(*self._cache, size=32)
            self._pool.appendleft(entropy)
            await self._acknowledge_temporary_frequency_deadline()
            await arandom_sleep(self._max_delay)
            if self._cancel:
                return

    def start(self) -> t.Self:
        """
        Runs an entropy updating & gathering thread in the background.

        This supports the package by asynchronously & continuously
        seeding into & extracting new entropy from its entropy pools.
        """
        state = Threads._Manager().list()
        self._daemon = Threads._type(
            target=Threads._arun_func,
            args=(self._araw_loop, state),
        )
        self._daemon.daemon = True
        self._daemon.start()
        return self

    def cancel(self) -> t.Self:
        """
        Cancels the background thread.
        """
        self._cancel = True
        return self


module_api = dict(
    EntropyDaemon=t.add_type(EntropyDaemon),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

