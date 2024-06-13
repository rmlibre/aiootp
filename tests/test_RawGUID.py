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


from test_initialization import *

from aiootp._constants.misc import SECONDS, MILLISECONDS, MICROSECONDS


class TestRawGUIDConfig:

    async def test_declared_size_must_be_sum_of_components(self) -> None:
        problem = (
            "An inconsistent `size` declaration was allowed."
        )
        for bad_size in (15, 17):
            with Ignore(ValueError, if_else=violation(problem)):
                t.RawGUIDConfig(
                    timestamp_bytes=8,
                    prf_bytes=6,
                    node_id_bytes=1,
                    ticker_bytes=1,
                    size=bad_size,
                )

    async def test_custom_clock_can_be_supplied(self) -> None:
        for (size, timestamp_bytes, units) in (
            (16, 4, SECONDS), (18, 6, MILLISECONDS), (20, 8, MICROSECONDS)
        ):
            config = t.RawGUIDConfig(
                timestamp_bytes=timestamp_bytes,
                prf_bytes=10,
                node_id_bytes=1,
                ticker_bytes=1,
                size=size,
                clock=t.Clock(units),
            )
            assert units == config.clock._units


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

