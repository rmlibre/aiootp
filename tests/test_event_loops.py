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


class TestConcurrentExecution:

    async def test_tasks_run_in_background(self) -> None:

        async def increment_over_time(track: int) -> None:
            nonlocal value_0, value_1

            if track == 0:
                while value_0 < 16:
                    value_0 += 1
                    await asleep()
            elif track == 1:
                while value_1 < 16:
                    value_1 += 1
                    await asleep()

        value_0 = 0
        value_1 = 0
        asynchs.new_task(increment_over_time(track=0)); await asleep(0.0001)
        assert 0 < value_0
        assert 0 == value_1
        asynchs.new_task(increment_over_time(track=1)); await asleep(0.0001)
        assert 1 < value_0
        assert 0 < value_1

        await asleep(0.0001)
        assert 2 < value_0
        assert 1 < value_1

    async def test_futures_run_in_background(self) -> None:

        async def increment_over_time(track: int) -> None:
            nonlocal value_0, value_1

            if track == 0:
                while value_0 < 16:
                    value_0 += 1
                    await asleep()
            elif track == 1:
                while value_1 < 16:
                    value_1 += 1
                    await asleep()

        value_0 = 0
        value_1 = 0
        asynchs.new_future(increment_over_time(track=0)); await asleep(0.0001)
        assert 0 < value_0
        assert 0 == value_1
        asynchs.new_future(increment_over_time(track=1)); await asleep(0.0001)
        assert 1 < value_0
        assert 0 < value_1

        await asleep(0.0001)
        assert 2 < value_0
        assert 1 < value_1


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

