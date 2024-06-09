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


__all__ = [
    "acanonical_token",
    "achoice",
    "arandom_sleep",
    "atoken_bits",
    "atoken_bytes",
    "auniform",
    "canonical_token",
    "choice",
    "random_sleep",
    "token_bits",
    "token_bytes",
    "uniform",
]


__doc__ = "Lower assurance randomness functions."


import random as _stdlib_random
from secrets import choice, token_bytes
from secrets import randbits as token_bits

from aiootp._typing import Typing as t
from aiootp._constants import BIG
from aiootp.asynchs import get_process_id, get_thread_id
from aiootp.asynchs import asleep, sleep, ns_counter


# initializing weakly entropic functionalities
_random = _stdlib_random.Random(token_bytes(2500))
uniform = _random.uniform


async def auniform(a: t.RealNumber, b: t.RealNumber) -> float:
    """
    Asynchronous version of the standard library's `random.uniform`.
    """
    await asleep()
    return uniform(a=a, b=b)


async def achoice(seq: t.Sequence[t.Any]) -> t.Any:
    """
    Asynchronous version of the standard library's `secrets.choice`.
    """
    await asleep()
    return choice(seq=seq)


async def arandom_sleep(seconds: t.PositiveRealNumber = 1) -> t.Any:
    """
    Asynchronously sleeps for a psuedo-random duration less than the
    provided maximum number of `seconds`.
    """
    await asleep(seconds * await auniform(0, 1))


def random_sleep(seconds: t.PositiveRealNumber = 1) -> t.Any:
    """
    Synchronously sleeps for a psuedo-random duration less than the
    provided maximum number of `seconds`.
    """
    sleep(seconds * uniform(0, 1))


async def atoken_bits(k: int) -> int:
    """
    Returns `k` entropic bits from `secrets.randbits`.
    """
    await asleep()
    return token_bits(k=k)


async def atoken_bytes(nbytes: int) -> bytes:
    """
    Returns `nbytes` entropic bytes from `secrets.token_bytes`.
    """
    await asleep()
    return token_bytes(nbytes=nbytes)


async def acanonical_token() -> bytes:
    """
    Combines 256-bits of system entropy, a monotonic nanosecond counter,
    as well as process & thread identifiers into a 56-byte token to
    uniquely identify the current context of the function call. These
    tokens SHOULD NOT be exposed publicly.
     _____________________________________
    |                                     |
    |           Format Diagram:           |
    |_____________________________________|
     ___________________________________________________________________
    |                            |            |            |            |
    |         token_bits         |  time (ns) |  thread ID | process ID |
    |----------------------------|------------|------------|------------|
    |                            |            |            |            |
    |          32-bytes          |   8-bytes  |   8-bytes  |   8-bytes  |
    |____________________________|____________|____________|____________|
    |                                                                   |
    |                  56 == (32 + 8 + 8 + 8)-bytes                     |
    |___________________________________________________________________|
    """
    await asleep()
    return (
        (token_bits(256) << 192)
        ^ (ns_counter() << 128)
        ^ (get_thread_id() << 64)
        ^ get_process_id()
    ).to_bytes(56, BIG)


def canonical_token() -> bytes:
    """
    Combines 256-bits of system entropy, a monotonic nanosecond counter,
    as well as process & thread identifiers into a 56-byte token to
    uniquely identify the current context of the function call. These
    tokens SHOULD NOT be exposed publicly.
     _____________________________________
    |                                     |
    |           Format Diagram:           |
    |_____________________________________|
     ___________________________________________________________________
    |                            |            |            |            |
    |         token_bits         |  time (ns) |  thread ID | process ID |
    |----------------------------|------------|------------|------------|
    |                            |            |            |            |
    |          32-bytes          |   8-bytes  |   8-bytes  |   8-bytes  |
    |____________________________|____________|____________|____________|
    |                                                                   |
    |                  56 == (32 + 8 + 8 + 8)-bytes                     |
    |___________________________________________________________________|
    """
    return (
        (token_bits(256) << 192)
        ^ (ns_counter() << 128)
        ^ (get_thread_id() << 64)
        ^ get_process_id()
    ).to_bytes(56, BIG)


module_api = dict(
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    acanonical_token=acanonical_token,
    achoice=achoice,
    arandom_sleep=arandom_sleep,
    atoken_bits=atoken_bits,
    atoken_bytes=atoken_bytes,
    auniform=auniform,
    canonical_token=canonical_token,
    choice=choice,
    random_sleep=random_sleep,
    token_bits=token_bits,
    token_bytes=token_bytes,
    uniform=uniform,
)

