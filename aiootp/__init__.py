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


__version__ = "0.23.7"


__license__ = "AGPLv3"


__author__ = "rmlibre@riseup.net"


__PUBLIC_ED25519_KEY__ = (
    "70d1740f2a439da98243c43a4d7ef1cf993b87a75f3bb0851ae79de675af5b3b"
)


__PUBLIC_X25519_KEY__ = (
    "4457276dbcae91cc5b69f1aed4384b9eb6f933343bb44d9ed8a80e2ce438a450"
)


__doc__ = (
    "a high-level async cryptographic anonymity library to scale, simplify, "
    "& automate privacy best practices for secure data & identity processing, "
    "communication, & storage."
)


import sys

from .commons import *
from .commons import remake_subpackage
from .asynchs import *
from .generics import *
from .randoms import *
from .ciphers import *
from .keygens import *
from .databases import *
from .__engagement.issue_reporting import report_security_issue


__all__ = [
    "commons",
    *commons.__all__,
    "asynchs",
    *asynchs.__all__,
    "generics",
    *generics.__all__,
    "randoms",
    *randoms.__all__,
    "ciphers",
    *ciphers.__all__,
    "keygens",
    *keygens.__all__,
    "databases",
    *databases.__all__,
]


subpackages = dict(
    _typing=_typing,
    _constants=_constants,
    _permutations=_permutations,
    commons=commons,
    asynchs=asynchs,
    generics=generics,
    randoms=randoms,
    ciphers=ciphers,
    keygens=keygens,
    databases=databases,
)


modules = dict(
    _exceptions=_exceptions,
    _debug_control=_debug_control,
    _gentools=_gentools,
    _paths=_paths,
)


module_api = dict(
    **{
        name: globals()[name]
        for name in __all__
        if not hasattr(globals()[name], "__spec__")
    },
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __author__=__author__,
    __loader__=__loader__,
    __license__=__license__,
    __package__=__package__,
    __version__=__version__,
    __PUBLIC_ED25519_KEY__=__PUBLIC_ED25519_KEY__,
    __PUBLIC_X25519_KEY__=__PUBLIC_X25519_KEY__,
    report_security_issue=report_security_issue,
)


aiootp = remake_subpackage(sys.modules[__name__])


del sys
del databases
del subpackages
del modules
del module_api
del __engagement
del remake_subpackage

