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


"""
Interfaces & utilities which facilitate the creation of async/thread-
safe contexts in either exclusive or non-exclusive modes for performant
management of shared state in concurrent applications.
"""

__all__ = [
    "ConcurrencyGuard",
    "DefaultDictOfDeques",
    "MultiConcurrencyGaurd",
]


from .concurrency_guard import *
from .manager import *
from .policies import *
from .state_machine import *


modules = dict(
    concurrency_guard=concurrency_guard,
    manager=manager,
    policies=policies,
    state_machine=state_machine,
)


module_api = dict(
    ConcurrencyGuard=ConcurrencyGuard,
    DefaultDictOfDeques=DefaultDictOfDeques,
    MultiConcurrencyGaurd=MultiConcurrencyGaurd,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
