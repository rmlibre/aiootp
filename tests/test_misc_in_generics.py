# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "__all__",
    "test_Enumerate",
    "test_binary_tree",
]


from init_tests import *


def test_Enumerate():
    async def async_iteration():
        zero_to_15 = cycle(range(16))
        async for i, n in generics.Enumerate(iterable):
            assert i == zero_to_15()
            assert n == iterable[i]

    def sync_iteration():
        zero_to_15 = cycle(range(16))
        for i, n in generics.Enumerate(iterable):
            assert i == zero_to_15()
            assert n == iterable[i]

    iterable = "0123456789abcdef"
    run(async_iteration())
    sync_iteration()


def test_binary_tree():
    depth = randoms.random_range(1, 6)
    width = randoms.random_range(1, 6)
    leaf = bytes.fromhex(salt[:16])
    kwargs = dict(depth=depth, width=width, leaf=leaf)

    atree = run(generics.abuild_tree(**kwargs))
    tree = generics.build_tree(**kwargs)

    assert atree == tree

    failing_kwargs_0 = dict(depth=-1, width=width, leaf=leaf)
    try:
        run(generics.abuild_tree(**failing_kwargs_0))
    except:
        pass
    else:
        raise AssertionError("Invalid depth accepted.")
    try:
        generics.build_tree(**failing_kwargs_0)
    except:
        pass
    else:
        raise AssertionError("Invalid depth accepted.")

    failing_kwargs_1 = dict(depth=depth, width=0, leaf=leaf)
    try:
        run(generics.abuild_tree(**failing_kwargs_1))
    except:
        pass
    else:
        raise AssertionError("Invalid width accepted.")
    try:
        generics.build_tree(**failing_kwargs_1)
    except:
        pass
    else:
        raise AssertionError("Invalid width accepted.")

