# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2025 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


"""
Configuration logic & constants for `Chunky2048`.
"""

__all__ = ["chunky2048_spec"]


from hashlib import shake_128

from aiootp._typing import Typing as t
from aiootp._constants import EPOCH_NS, SECONDS
from aiootp._permutations import FastAffineXORChain

from .dual_output_shake_cipher_config import DualOutputShakeCipherConfig
from .cipher_kdfs import ShakeConfig


BLOCK_ID_KDF: str = "block_id_kdf"
SHMAC_KDF: str = "shmac_kdf"
LEFT_KDF: str = "left_kdf"
RIGHT_KDF: str = "right_kdf"


def _dual_output_shake_config_inputs(**kw: t.Any) -> t.Dict[str, t.Any]:
    """
    Simplifies the process of creating new cipher config objects. While
    this will not generally be needed by users of pre-built recipes,
    it's quite helpful in testing. Custom configurations can be passed
    as keyword-arguments, which will override the defaults.

    Returns a dict of the default, or overridden, settings which can
    then be passed into the config's initializer.
    """
    inputs = dict(
        name="Chunky2048",
        config_id=b"Chunky2048",
        blocksize=256,
        min_padding_blocks=0,
        epoch_ns=EPOCH_NS,
        time_unit=SECONDS,
        timestamp_bytes=4,
        siv_key_bytes=16,
        shmac_bytes=32,
        block_id_bytes=24,
        max_block_id_bytes=32,
        min_block_id_bytes=16,
        salt_bytes=8,
        iv_bytes=8,
        block_id_kdf=BLOCK_ID_KDF,
        block_id_kdf_config=ShakeConfig(
            name=BLOCK_ID_KDF,
            pad=b"\xac",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(None),
        ),
        shmac_kdf=SHMAC_KDF,
        shmac_kdf_config=ShakeConfig(
            name=SHMAC_KDF,
            pad=b"\x9a",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(None),
        ),
        left_kdf=LEFT_KDF,
        left_kdf_config=ShakeConfig(
            name=LEFT_KDF,
            pad=b"\x5c",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(0, None, 2),  # Even index bytes
        ),
        right_kdf=RIGHT_KDF,
        right_kdf_config=ShakeConfig(
            name=RIGHT_KDF,
            pad=b"\x36",
            offset_amount=0,
            hasher=shake_128,
            key_slice=slice(1, None, 2),  # Odd index bytes
        ),
        permutation_type=FastAffineXORChain,
    )
    inputs.update(kw)
    return inputs


chunky2048_spec: t.ConfigType = DualOutputShakeCipherConfig(
    **_dual_output_shake_config_inputs(),
)


module_api = dict(
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    _dual_output_shake_config_inputs=_dual_output_shake_config_inputs,
    chunky2048_spec=chunky2048_spec,
)
