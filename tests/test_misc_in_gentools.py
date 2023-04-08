# This file is part of aiootp, an asynchronous crypto and anonymity
# library. Home of the Chunky2048 psuedo one-time pad stream cipher.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


async def test_Enumerate():
    iterable = b"".join(i.to_bytes(1, BIG) for i in range(16))

    # ASYNC
    # by default enumerates async iterables from zero
    async for i, n in Enumerate(aunpack(iterable)):
        assert i == n

    # by default enumerates iterables from zero
    async for i, n in Enumerate(iterable):
        assert i == n

    # the start kwarg indicates where enumeration begins for async
    # iterables
    async for i, n in Enumerate(aunpack(iterable), start=32):
        assert i == n + 32

    # the start kwarg indicates where enumeration begins
    async for i, n in Enumerate(iterable, start=32):
        assert i == n + 32

    # the "bytes" encoding string by default calls the `to_bytes`
    # method with 8 & the default byteorder of the package for async
    # iterables
    async for e, item in Enumerate(aunpack(iterable), encoding="bytes"):
        assert e == item.to_bytes(8, BIG)

    # the "bytes" encoding string by default calls the `to_bytes`
    # method with 8 & the default byteorder of the package
    async for e, item in Enumerate(iterable, encoding="bytes"):
        assert e == item.to_bytes(8, BIG)

    # the "bytes" encoding string calls the `to_bytes` method given
    # the values in the `a` kwarg as arguments for async iterables
    async for e, item in Enumerate(aunpack(iterable), encoding="bytes", a=(12, BIG)):
        assert e == item.to_bytes(12, BIG)

    # the "bytes" encoding string calls the `to_bytes` method given
    # the values in the `a` kwarg as arguments
    async for e, item in Enumerate(iterable, encoding="bytes", a=(12, BIG)):
        assert e == item.to_bytes(12, BIG)

    async for e, item in Enumerate(iterable, encoding="bytes", a=(12,), kw={"byteorder": BIG}):
        assert e == item.to_bytes(12, BIG)

    # enumeration begins where the `start` kwarg indicates, AND the
    # "bytes" encoding string calls the `to_bytes` method with 8 &
    # the default byteorder of the package as arguments, for async
    # iterables
    async for e, item in Enumerate(aunpack(iterable), start=32, encoding="bytes"):
        assert e == (item + 32).to_bytes(8, BIG)

    # enumeration begins where the `start` kwarg indicates, AND the
    # "bytes" encoding string calls the `to_bytes` method with 8 &
    # the default byteorder of the package as arguments
    async for e, item in Enumerate(iterable, start=32, encoding="bytes"):
        assert e == (item + 32).to_bytes(8, BIG)

    # enumeration begins where the `start` kwarg indicates, AND the
    # "bytes" encoding string calls the `to_bytes` method given
    # the values in the `a` kwarg as arguments, for async iterables
    async for e, item in Enumerate(aunpack(iterable), start=32, encoding="bytes", a=(12, BIG)):
        assert e == (item + 32).to_bytes(12, BIG)

    # enumeration begins where the `start` kwarg indicates, AND the
    # "bytes" encoding string calls the `to_bytes` method given
    # the values in the `a` kwarg as arguments
    async for e, item in Enumerate(iterable, start=32, encoding="bytes", a=(12, BIG)):
        assert e == (item + 32).to_bytes(12, BIG)


    # SYNC
    # by default enumerates from zero
    for i, n in Enumerate(iterable):
        assert i == n

    # the start kwarg is where enumeration begins
    for i, n in Enumerate(iterable, start=32):
        assert i == n + 32

    # the "bytes" encoding string by default calls the `to_bytes`
    # method with 8 & the default byteorder of the package
    for e, item in Enumerate(iterable, encoding="bytes"):
        assert e == item.to_bytes(8, BIG)

    # the "bytes" encoding string calls the `to_bytes` method given
    # the values in the `a` kwarg as arguments
    for e, item in Enumerate(iterable, encoding="bytes", a=(12, BIG)):
        assert e == item.to_bytes(12, BIG)

    for e, item in Enumerate(iterable, encoding="bytes", a=(12,), kw={"byteorder": BIG}):
        assert e == item.to_bytes(12, BIG)

    for e, item in Enumerate(iterable, encoding="bytes", a=(12,), kw={"byteorder": "little"}):
        assert e == item.to_bytes(12, "little")

    # enumeration begins where the `start` kwarg indicates, AND the
    # "bytes" encoding string calls the `to_bytes` method with 8 &
    # the default byteorder of the package as arguments
    for e, item in Enumerate(iterable, start=32, encoding="bytes"):
        assert e == (item + 32).to_bytes(8, BIG)

    # enumeration begins where the `start` kwarg indicates, AND the
    # "bytes" encoding string calls the `to_bytes` method given
    # the values in the `a` kwarg as arguments
    for e, item in Enumerate(iterable, start=32, encoding="bytes", a=(12, BIG)):
        assert e == (item + 32).to_bytes(12, BIG)

    for e, item in Enumerate(iterable, start=32, encoding="bytes", a=(12,), kw={"byteorder": BIG}):
        assert e == (item + 32).to_bytes(12, BIG)

    for e, item in Enumerate(iterable, start=32, encoding="bytes", a=(12,), kw={"byteorder": "little"}):
        assert e == (item + 32).to_bytes(12, "little")


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

