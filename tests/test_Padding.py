# This file is part of aiootp:
# an application agnostic — async-compatible — anonymity & cryptography
# library, providing access to high-level Pythonic utilities to simplify
# the tasks of secure data processing, communication & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


def test_when_new_padding_blocks_are_created():
    FIRST_BLOCKSIZE = BLOCKSIZE - INNER_HEADER_BYTES - SENTINEL_BYTES_PER_BLOCKSIZE
    DOUBLE_BLOCKSIZE = 2 * BLOCKSIZE

    start = INNER_HEADER_BYTES
    for n in range(FIRST_BLOCKSIZE + BLOCKSIZE):
        pt = n * b"0"
        padded_pt = Padding.pad_plaintext(pt)
        sentinel = -(padded_pt[-1] if padded_pt[-1] else BLOCKSIZE)

        # The data is prepended with a constant size inner-header &
        # appended with extra padding that is measured by the value of
        # the final byte of padded plaintext modulo the blocksize.
        assert padded_pt[start:sentinel] == pt, f"n={n}, sentinel={sentinel}"


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

