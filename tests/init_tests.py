# This file is part of tiny_onion, a small-as-possible solution for p2p
# networking over tor v3 onion services.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#          © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


import sys
import json
import pytest
from pathlib import Path


PACKAGE_PATH = str(Path(__file__).absolute().parent.parent)
sys.path.append(PACKAGE_PATH)


import aiootp
from aiootp import *


key = csprng()
salt = csprng()
pid = sha_256(key, salt)


__all__ = [
    "sys",
    "json",
    "pytest",
    "Path",
    "PACKAGE_PATH",
    "aiootp",
    *aiootp.__all__,
    "key",
    "salt",
    "pid",
]

