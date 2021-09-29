# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["__all__", "test_Enumerate"]


from init_tests import *


def test_Enumerate():
    async def async_iteration():
        zero_to_15 = cycle(range(16))
        async for i, n in gentools.Enumerate(iterable):
            assert i == zero_to_15()
            assert n == iterable[i]

    def sync_iteration():
        zero_to_15 = cycle(range(16))
        for i, n in gentools.Enumerate(iterable):
            assert i == zero_to_15()
            assert n == iterable[i]

    iterable = "0123456789abcdef"
    run(async_iteration())
    sync_iteration()

