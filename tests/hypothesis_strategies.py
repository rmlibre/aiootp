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


__all__ = ["identifiers"]


import keyword
from string import ascii_letters, digits
from hypothesis.strategies import DrawFn, composite, text


@composite
def identifiers(draw: DrawFn) -> str:
    first_chars = f"_{ascii_letters}"
    first_chars_st = text(alphabet=first_chars, min_size=1, max_size=1)

    final_chars = f"_{ascii_letters}{digits}"
    final_chars_st = text(alphabet=final_chars, min_size=0, max_size=16)

    result = draw(first_chars_st) + draw(final_chars_st)
    while keyword.iskeyword(result):
        result += draw(final_chars_st)

    return result
