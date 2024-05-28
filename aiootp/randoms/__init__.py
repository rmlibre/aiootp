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


__all__ = ["GUID", "SequenceID", "acsprng", "csprng"]


__doc__ = (
    "Randomness generation, tools, & unique pseudo-random identifiers."
)


from .simple import *
from .threading_safe_entropy_pool import *
from .rng import *
from .entropy_daemon import *
from .ids import *


subpackages = dict(ids=ids)


modules = dict(
    _early_salts=_early_salts,
    entropy_daemon=entropy_daemon,
    rng=rng,
    simple=simple,
    threading_safe_entropy_pool=threading_safe_entropy_pool,
)


module_api = dict(
    GUID=GUID,
    SequenceID=SequenceID,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    achoice=achoice,
    acsprng=acsprng,
    arandom_number_generator=arandom_number_generator,
    arandom_sleep=arandom_sleep,
    atoken_bits=atoken_bits,
    atoken_bytes=atoken_bytes,
    auniform=auniform,
    choice=choice,
    csprng=csprng,
    random_number_generator=random_number_generator,
    random_sleep=random_sleep,
    token_bits=token_bits,
    token_bytes=token_bytes,
    uniform=uniform,
)

