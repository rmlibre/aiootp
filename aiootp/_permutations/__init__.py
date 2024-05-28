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


__all__ = ["FastAffineXORChain"]


__doc__ = "Implementations of simple keyed permutations."


from .affine_permutation_config import *
from .affine_permutation import *
from .affine_xor_chain_config import *
from .affine_xor_chain import *
from .fast_affine_xor_chain import *


modules = dict(
    affine_permutation_config=affine_permutation_config,
    affine_permutation=affine_permutation,
    affine_xor_chain=affine_xor_chain,
    affine_xor_chain_config=affine_xor_chain_config,
    fast_affine_xor_chain=fast_affine_xor_chain,
)


module_api = dict(
    FastAffineXORChain=FastAffineXORChain,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

