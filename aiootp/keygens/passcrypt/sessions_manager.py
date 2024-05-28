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


__all__ = ["PasscryptProcesses"]


__doc__ = (
    "A type that manages spawning multiple `Passcrypt` sessions in "
    "separate processes to run the full algorithm."
)


import math

from aiootp._typing import Typing as t
from aiootp._constants import BIG, INT_BYTES
from aiootp._gentools import abytes_range, bytes_range
from aiootp.asynchs import Processes
from aiootp.commons import FrozenInstance
from aiootp.generics import canonical_pack

from .session_init import PasscryptSession


class PasscryptProcesses(FrozenInstance):
    """
    A type that manages spawning multiple `Passcrypt` sessions in
    separate processes to run the full algorithm.
    """

    __slots__ = ("_sessions",)

    def __init__(self) -> None:
        pass

    @staticmethod
    def _work_memory_prover(session: PasscryptSession) -> bytes:
        """
        Returns the digest of a keyed scanning function. It sequentially
        passes over a memory cache with an intuitive & tunable amount of
        difficulty. This scheme is secret independent with regard to how
        it chooses to pass over memory.

        Through proofs of work & memory, it ensures an attacker
        attempting to crack a passphrase hash cannot complete the
        algorithm substantially faster by storing more memory than
        what's already necessary, or with substantially less memory, by
        dropping cache entries, without drastically increasing the
        computational cost.
        """
        ram, update, digest, row_size, total_size = session
        assert total_size == len(ram)
        column_start_indexes = range(0, row_size, 336)
        row_start_indexes = [*range(0, total_size, row_size)]
        for column_start in column_start_indexes:
            for row_start in row_start_indexes:
                index = row_start + column_start
                ref_row_start = -row_start - row_size
                reflection = ref_row_start + column_start + 168
                ref_end = reflection + 168
                ref_end = ref_end if ref_end < 0 else None

                update(ram[row_start : row_start + row_size])
                ram[index : index + 168] = digest(168)

                update(ram[ref_row_start : ref_row_start + row_size])
                ram[reflection:ref_end] = digest(168)
        for iteration in range(session.cpu + 2):
            seek = 168 * iteration
            ram[seek : seek + 84] = digest(84)
            update(ram)
        return digest(168)

    @classmethod
    def _passcrypt(cls, session: PasscryptSession) -> bytes:
        """
        This method implements an Argon2i-like passphrase-based key
        derivation function that's designed to be resistant to cache-
        timing side-channel attacks & time-memory trade-offs.
        """
        session.prepare_session().allocate_ram()
        return cls._work_memory_prover(session)

    async def aspawn(
        self,
        *,
        passphrase: bytes,
        salt: bytes,
        aad: bytes,
        pepper: bytes,
        mb: int,
        cpu: int,
        cores: int,
        tag_size: int,
        config: t.ConfigType,
    ) -> t.List[t.Future]:
        """
        Returns a list of started key derivation sessions that are run
        inside process pool `Future`'s.
        """
        sessions = []
        total_mb = mb.to_bytes(INT_BYTES, BIG)
        core_mb = math.ceil(mb / cores)
        async for core in abytes_range(cores):
            core_aad = canonical_pack(pepper, aad, core, total_mb)
            session = PasscryptSession(
                passphrase,
                salt,
                aad=core_aad,
                mb=core_mb,
                cpu=cpu,
                cores=cores,
                tag_size=tag_size,
                config=config,
            )
            kw = dict(session=session, probe_delay=0.001)
            sessions.append(
                await Processes.asubmit(self._passcrypt, **kw)
            )
        return sessions

    def spawn(
        self,
        *,
        passphrase: bytes,
        salt: bytes,
        aad: bytes,
        pepper: bytes,
        mb: int,
        cpu: int,
        cores: int,
        tag_size: int,
        config: t.ConfigType,
    ) -> t.List[t.Future]:
        """
        Returns a list of started key derivation sessions that are run
        inside process pool `Future`'s.
        """
        sessions = []
        total_mb = mb.to_bytes(INT_BYTES, BIG)
        core_mb = math.ceil(mb / cores)
        for core in bytes_range(cores):
            core_aad = canonical_pack(pepper, aad, core, total_mb)
            session = PasscryptSession(
                passphrase,
                salt,
                aad=core_aad,
                mb=core_mb,
                cpu=cpu,
                cores=cores,
                tag_size=tag_size,
                config=config,
            )
            kw = dict(session=session, probe_delay=0.001)
            sessions.append(Processes.submit(self._passcrypt, **kw))
        return sessions


module_api = dict(
    PasscryptProcesses=t.add_type(PasscryptProcesses),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

