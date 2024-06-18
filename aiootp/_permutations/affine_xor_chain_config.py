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


__all__ = ["AffineXORChainConfig"]


__doc__ = "A configuration type for the `AffineXORChain`."


from aiootp._typing import Typing as t
from aiootp._exceptions import Issue
from aiootp.commons import Config

from .affine_permutation_config import AffinePermutationConfig


class AffineXORChainConfig(Config):
    """
    Configuration type for `AffineXORChain`.
    """

    __slots__ = (
        "SIZE",
        "IPAD",
        "OPAD",
        "XPAD",
        "DOMAIN",
        "KEY_TYPES",
        "KEY_SIZE",
        "ADD_KEY_SIZE",
        "XOR_KEY_SIZE",
        "PERMUTATION_CONFIG_ID",
        "Permutation",
    )

    slots_types: t.Mapping[str, type] = dict(
        SIZE=int,
        IPAD=int,
        OPAD=int,
        XPAD=int,
        DOMAIN=int,
        KEY_TYPES=tuple,
        KEY_SIZE=int,
        ADD_KEY_SIZE=int,
        XOR_KEY_SIZE=int,
        PERMUTATION_CONFIG_ID=t.Hashable,
        Permutation=t.PermutationType,
    )

    _DEFAULT_KEY_TYPES: t.Tuple[t.Tuple[str, int]] = (
        ("in_xor", 1),
        ("in_add", 2),
        ("mid_xor", 1),
        ("mid_add", 2),
        ("out_xor", 1),
        ("out_add", 2),
    )
    _FAST_CHAIN_KEY_TYPES: t.Tuple[t.Tuple[str, int]] = (
        ("add", 2), ("in_xor", 1), ("mid_xor", 1), ("out_xor", 1)
    )

    def _process_size(self, size: int) -> int:
        """
        Returns `size` if it passes preliminary non type-based value
        checks, otherwise raises `ValueError`.
        """
        if 4096 >= size > 0:
            return size
        else:
            raise Issue.value_must("size", "be > 0 and <= 4096")

    def _process_key_types(
        self, key_types: t.Optional[t.Tuple[t.Tuple[str, int]]]
    ) -> t.Tuple[t.Tuple[str, int]]:
        """
        Returns `key_types` if it contains at least one (str, int) pair,
        otherwise raises `ValueError`. Unless `key_types` isn't
        provided, then the class' default tuple is provided.
        """
        if key_types is None:
            return self._DEFAULT_KEY_TYPES
        elif not all(
            (
                name.isidentifier()
                and size_multiple.__class__ is int
                and 33 > size_multiple > 0
            )
            for name, size_multiple in key_types
        ):
            raise Issue.value_must("key_types", "contain (str, int) pairs")
        else:
            return key_types

    def _process_permutation_config_id(
        self, permutation_config_id: t.Optional[t.Hashable]
    ) -> t.Hashable:
        """
        Returns the input `permutation_config_id` if it's provided,
        otherwise defaults to returning the instance's `config_id`.
        """
        if permutation_config_id is None:
            return self.CONFIG_ID
        else:
            return permutation_config_id

    def _process_permutation(self, permutation_type: type) -> type:
        """
        Returns the input `permutation_type` if it follows the correct
        `PermutationType` protocol, otherwise raises `TypeError`.
        """
        if issubclass(permutation_type, t.PermutationType):
            return permutation_type
        else:
            raise Issue.value_must_be_subtype(
                f"{permutation_type=}", t.PermutationType
            )

    def __init__(
        self,
        *,
        config_id: t.Hashable,
        size: int,
        permutation_type: type,
        permutation_config_id: t.Optional[t.Hashable] = None,
        key_types: t.Optional[t.Tuple[t.Tuple[str, int]]] = None,
    ) -> None:
        """
        Caches the instance's static configuration after type-checking
        & doing injection of defaults for the inputs not provided.
        """
        self.CONFIG_ID = config_id
        self.SIZE = self._process_size(size)
        self.IPAD = int(self.SIZE * "a3", 16)
        self.OPAD = int(self.SIZE * "1b", 16)
        self.XPAD = int(self.SIZE * "8d", 16)
        self.DOMAIN = 1 << (8 * self.SIZE)
        self.KEY_TYPES = self._process_key_types(key_types)
        self.KEY_SIZE = sum(
            multiple for name, multiple in self.KEY_TYPES
        ) * self.SIZE
        self.ADD_KEY_SIZE = 2 * self.SIZE
        self.XOR_KEY_SIZE = self.SIZE
        self.PERMUTATION_CONFIG_ID = self._process_permutation_config_id(
            permutation_config_id
        )
        self.Permutation = self._process_permutation(permutation_type)


module_api = dict(
    AffineXORChainConfig=t.add_type(AffineXORChainConfig),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

