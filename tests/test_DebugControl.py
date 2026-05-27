# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2026 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


from aiootp._debug_control import DebugControl

from conftest import *


class TestDebugControl:
    async def test_toggles(self) -> None:
        was_debugging = DebugControl.is_debugging()

        DebugControl.enable_debugging(silence_warnings=True)
        assert DebugControl.is_debugging()

        DebugControl.enable_debugging(silence_warnings=True)
        assert DebugControl.is_debugging()

        DebugControl.disable_debugging()
        assert not DebugControl.is_debugging()

        DebugControl.disable_debugging()
        assert not DebugControl.is_debugging()

        DebugControl.enable_debugging(silence_warnings=True)
        assert DebugControl.is_debugging()

        DebugControl.disable_debugging()
        assert not DebugControl.is_debugging()

        if was_debugging:
            DebugControl.enable_debugging(silence_warnings=True)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
