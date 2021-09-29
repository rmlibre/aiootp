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


from test_misc_in_ciphers import *
for variable in __all__:
    __exports.append(variable)


from test_Database_AsyncDatabase import *
for variable in __all__:
    __exports.append(variable)


from test_high_level_encryption import *
for variable in __all__:
    __exports.append(variable)


from test_StreamHMAC import *
for variable in __all__:
    __exports.append(variable)


from test_passcrypt_apasscrypt import *
for variable in __all__:
    __exports.append(variable)


# The Ropake class has been removed from the package pending changes to
# the protocol & its implementation.
# from test_Ropake import *
# for variable in __all__:
    # __exports.append(variable)


from test_X25519_Ed25519 import *
for variable in __all__:
    __exports.append(variable)


__all__ = __exports
__exports = set(__exports)


assert not __exports.difference(__all__), "duplicated tests!!!"

