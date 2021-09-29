# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["gentools"]


__doc__ = (
    "A module for gathering the package's various utility generators in"
    "to one place for neater organization."
)


from . import commons
from . import gentools


__all__ += [*gentools.namespace]


globals().update(gentools.namespace)


gentools = commons.make_module("gentools", mapping=gentools.namespace)

