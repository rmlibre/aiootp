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


class TestPlaintextPadding:

    async def test_variable_length_plaintexts(self) -> None:
        for (config, cipher, _, _) in all_ciphers:
            Pad = Padding(config)
            assert config is Pad.config
            assert config is cipher._padding.config

            FIRST_BLOCKSIZE = (
                config.BLOCKSIZE
                - config.INNER_HEADER_BYTES
                - config.SENTINEL_BYTES
            )

            start = config.INNER_HEADER_BYTES
            for n in range(FIRST_BLOCKSIZE + config.BLOCKSIZE):
                pt = n * b"0"
                padded_pt = Pad.pad_plaintext(pt)
                sentinel = int.from_bytes(padded_pt[config.SENTINEL_SLICE], BIG)
                end = -(sentinel if sentinel else config.BLOCKSIZE)

                # The data is prepended with a constant size inner-header &
                # appended with extra padding that is measured by the value of
                # the final byte of padded plaintext modulo the blocksize.
                assert padded_pt[start:end] == pt, f"{n=} : {sentinel=} : {start=} : {end=}"


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

