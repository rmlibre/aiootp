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


__all__ = ["SequenceIDConfig"]


__doc__ = "Configuration type for `SequenceID`."


from aiootp._typing import Typing as t
from aiootp._exceptions import Issue
from aiootp.commons import Config


class SequenceIDConfig(Config):
    """
    Configuration type for `SequenceID`.
    """

    __slots__ = (
        "SIZE", "KEY_SIZE", "PERMUTATION_CONFIG_ID", "Permutation"
    )

    slots_types: t.Mapping[str, type] = dict(
        SIZE=int,
        KEY_SIZE=int,
        PERMUTATION_CONFIG_ID=t.Hashable,
        Permutation=t.PermutationType,
    )

    def _process_size(self, size: int) -> int:
        """
        Returns `size` only if it passes value-based validity checks,
        otherwise raises `ValueError`.
        """
        if 4096 >= size > 0:
            return size
        else:
            raise Issue.value_must("size", "be > 0 and <= 4096")

    def _process_permutation_config_id(
        self, permutation_config_id: t.Optional[t.Hashable]
    ) -> t.Hashable:
        """
        Allows the configuration ID given to the initializer of the
        permutation type to be specified. If it's `None` then it's
        assumed the correct configuration ID is the same used by this
        instance. Returns the configuration ID that's selected.
        """
        if permutation_config_id is None:
            return self.CONFIG_ID
        else:
            return permutation_config_id

    def __init__(
        self,
        *,
        config_id: t.Hashable,
        size: int,
        permutation_type: t.PermutationType,
        permutation_config_id: t.Optional[t.Hashable] = None,
    ) -> None:
        self.CONFIG_ID = config_id
        self.SIZE = self._process_size(size)
        self.PERMUTATION_CONFIG_ID = self._process_permutation_config_id(
            permutation_config_id
        )
        self.Permutation = permutation_type
        self.KEY_SIZE = self.Permutation.key_size(config_id)


module_api = dict(
    SequenceIDConfig=t.add_type(SequenceIDConfig),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

