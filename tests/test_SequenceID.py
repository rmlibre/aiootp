# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


def test_range_uniqueness():
    for n in range(1, 5):
        # lower the minimum size of outputs to provide at least two
        # complete testable spaces of inputs & outputs
        SequenceID._MIN_SIZE = 1

        _range = PrimeGroups()[f"p{8 * n}"]
        _subrange = PrimeGroups()[f"o{8*n}"]

        # the primes dataset returns the primes by byte-length at least
        # as large that the primes SequenceID chooses.
        assert _range > 1 << (8 * n - 1) and _range < 1 << (8 * n)
        assert _subrange > 1 << (8 * n - 1) and _subrange < 1 << (8 * n)
        assert _subrange < _range

        salt = token_bytes(16 + n)
        sid = SequenceID(salt, size=n)

        # the primes dataset returns the same primes by byte-length
        # as the primes SequenceID chooses.
        assert sid._prime == _range
        assert sid._subprime == _subrange

        # the sequence ids produced are unique for every given sequential
        # integer up to the amount of all possible unique ids for the
        # supplied size of outputs & the prime used, capped at 66536
        # queries
        history = set()
        for index in range(min([_subrange, 256 ** 2])):
            result = sid.new(index)
            assert result not in history, f"index={index}, n={n}"
            history.add(result)

        # return the minimum size back to default configuration
        SequenceID._MIN_SIZE = 4


async def test_sizes():
    # lower the minimum size of outputs to ensure all size declarations
    # are respected
    SequenceID._MIN_SIZE = 1

    for n in range(SequenceID._MIN_SIZE, SequenceID._MAX_SIZE):
        # the salt must be at least the length of output sizes
        context = (
            "The salt was allowed to be less than the length of the "
            "declared size of sequence ids"
        )
        with ignore(ValueError, if_else=violation(context)):
            sid = SequenceID(salt=token_bytes(n - 1), size=n)

        sid = SequenceID(token_bytes(max([16, n])), size=n)
        # the size of produced sequential ids is the same as the defined
        # size
        result = sid.new(n)
        assert len(result) == n
        assert result == await sid.anew(n)

        # urlsafe base64 encoding without '=' characters is at most
        # 50% larger than the raw bytes format
        result = sid.new(n, encode=True)
        assert len(result) >= n or len(result) < 1.5 * n
        assert result == await sid.anew(n, encode=True)

    # return the minimum size back to default configuration
    SequenceID._MIN_SIZE = 4


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

