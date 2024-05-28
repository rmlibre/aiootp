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


__all__ = ["Passcrypt"]


__doc__ = (
    "Implementation of an Argon2i-like, memory hard, passphrase key "
    "derivation function that's designed to be resistant to cache-timing "
    "side-channel attacks & time-memory trade-offs."
)


from .config import *
from .hash_format import *
from .session_init import *
from .sessions_manager import *
from .interface import *


modules = dict(
    config=config,
    hash_format=hash_format,
    session_init=session_init,
    sessions_manager=sessions_manager,
    interface=interface,
)


module_api = dict(
    PasscryptHash=PasscryptHash,
    Passcrypt=Passcrypt,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

