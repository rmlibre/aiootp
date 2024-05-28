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


__all__ = ["AsyncDatabase", "Database"]


__doc__ = (
    "Implements synchronous & asynchronous transparently encrypted data "
    "persistance classes."
)


from .dbdomains import *
from .dbkdf import *
from .profile_tokens import *
from .database_properties import *
from .async_database import *
from .sync_database import *


modules = dict(
    database_properties=database_properties,
    dbdomains=dbdomains,
    dbkdf=dbkdf,
    profile_tokens=profile_tokens,
    async_database=async_database,
    sync_database=sync_database,
)


module_api = dict(
    AsyncDatabase=AsyncDatabase,
    Database=Database,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

