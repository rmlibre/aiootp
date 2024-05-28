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


__doc__ = (
    "Improves the efficiency of the `AffineXORChain` by chaining "
    "duplicates of the same permutation state."
)


from aiootp._typing import Typing as t
from aiootp.commons import ConfigMap

from .affine_permutation import AffinePermutation
from .affine_xor_chain_config import AffineXORChainConfig
from .affine_xor_chain import AffineXORChain


class FastAffineXORChain(AffineXORChain):
    """
    A more efficient subclass of the `AffineXORChain` permutation which
    saves on memory, time & cache miss costs by chaining together calls
    the same affine permutation instead of three independent ones.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp._permutations import FastAffineXORChain

    domain_size = 1
    key = token_bytes(FastAffineXORChain.key_size(domain_size))
    aff = FastAffineXORChain(key=key, config_id=domain_size)

    latin_square = []
    domain = tuple(range(256 * domain_size))
    for _ in domain:
        row = tuple(aff.permute(element) for element in domain)
        latin_square.append(row)
        aff.step()

    assert len(set(latin_square)) == len(domain)
    assert all(len(set(row)) == len(domain) for row in latin_square)
    columns = [[row[column] for row in latin_square] for column in domain]
    assert all(len(set(column)) == len(domain) for column in columns)
    """

    __slots__ = ()

    _configs = ConfigMap(
        mapping={
            config_id: AffineXORChainConfig(
                config_id=config_id,
                size=config_id,
                permutation_type=AffinePermutation,
                permutation_config_id=config_id,
                key_types=AffineXORChainConfig._FAST_CHAIN_KEY_TYPES,
            ) for config_id in [*range(1, 33), 64, 128, 192, 256]
        },
        config_type=AffineXORChainConfig,
    )

    def _initialize_permutations(
        self, key_reader: t.Callable[[int], bytes], size: int
    ) -> t.Tuple[t.PermutationType]:
        """
        Uses the permutation configuration ID saved in the instance's
        config to initialize & return three pointers to the same affine
        permutation object, which will be chained together. This
        overwrites the superclass' usage of this method in a compliant
        way while customizing the three pointers returned, enabling the
        improvement in efficiency.
        """
        cid = self.config.PERMUTATION_CONFIG_ID
        Permutation = self.config.Permutation
        aff = Permutation(key=key_reader(), config_id=cid)
        return (aff, aff, aff)


module_api = dict(
    FastAffineXORChain=t.add_type(FastAffineXORChain),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

