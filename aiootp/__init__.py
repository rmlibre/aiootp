# This file is part of aiootp, an asynchronous one-time-pad based crypto
# and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__version__ = "0.9.0"


__license__ = "AGPLv3"


__doc__ = """
aiootp - an asynchronous one-time-pad based crypto and anonymity library.
"""


DEBUG_MODE = False


from .paths import *
from .asynchs  import *
from .commons import *
from .debuggers import *
from .generics import *
from .randoms import *
from .keygens import *
from .ciphers import *
from .__ui_coordination import *


__all__ = [
    *paths.__main_exports__,
    *asynchs.__main_exports__,
    *commons.__main_exports__,
    *debuggers.__main_exports__,
    *generics.__main_exports__,
    *randoms.__main_exports__,
    *keygens.__main_exports__,
    *ciphers.__main_exports__,
]


del __ui_coordination

