# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from init_tests import *


__exports = []


from test_misc_in_generics import *
for variable in __all__:
    __exports.append(variable)


from test_BytesIO import *
for variable in __all__:
    __exports.append(variable)


from test_Comprende import *
for variable in __all__:
    __exports.append(variable)


__all__ = __exports
__exports = set(__exports)


assert not __exports.difference(__all__), "duplicated tests!!!"

