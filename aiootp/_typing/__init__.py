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


__all__ = ["Typing"]


__doc__ = "Type-hinting utilities for the package."


from .interface import *
from ._commons import *
from ._generics import *
from ._asynchs import *
from ._paths import *
from ._randoms import *
from ._permutations import *
from ._ciphers import *
from ._keygens import *
from ._databases import *


modules = dict(
    _asynchs=_asynchs,
    _ciphers=_ciphers,
    _commons=_commons,
    _databases=_databases,
    _generics=_generics,
    _keygens=_keygens,
    _paths=_paths,
    _permutations=_permutations,
    _randoms=_randoms,
    interface=interface,
)


module_api = dict(
    Typing=Typing,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

