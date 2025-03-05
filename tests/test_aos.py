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


import os
import warnings

from aiootp.asynchs import aos

from conftest import *


OS_VARNAMES: t.List[str] = dir(os)


def name_will_proc_warning(name: str) -> bool:
    return name.isidentifier() and (name not in OS_VARNAMES)


@given(name=st.text().filter(name_will_proc_warning))
async def test_not_implemented_placeholder(name: str) -> None:
    with warnings.catch_warnings(record=True) as warning:
        await aos._not_implemented_placeholder(name)()

        assert isinstance(warning[-1].message, UserWarning)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
