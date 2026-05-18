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


from all_test_framework_tests import *
from all_typing_tests import *
from all_paths_tests import *
from all_exceptions_tests import *
from all_commons_tests import *
from all_asynchs_tests import *
from all_gentools_tests import *
from all_generics_tests import *
from all_permutations_tests import *
from all_randoms_tests import *
from all_ciphers_tests import *
from all_keygens_tests import *
from all_databases_tests import *
from all_zzz_time_to_live_tests import *


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
