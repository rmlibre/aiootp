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


__all__ = ["slick256_spec"]


__doc__ = "Configuration logic & constants for `Slick256`."


from hashlib import shake_128

from aiootp._typing import Typing as t
from aiootp._constants import EPOCH_NS, SECONDS
from aiootp._permutations import FastAffineXORChain

from .shake_permute_cipher_config import ShakePermuteCipherConfig
from .cipher_kdfs import ShakeConfig


BLOCK_ID_KDF: str = "block_id_kdf"
SHMAC_KDF: str = "shmac_kdf"


slick256_spec: t.ConfigType = ShakePermuteCipherConfig(
    name="Slick256",
    config_id=b"Slick256",
    blocksize=32,
    min_padding_blocks=0,
    epoch_ns=EPOCH_NS,
    time_unit=SECONDS,
    timestamp_bytes=4,
    siv_key_bytes=8,
    shmac_bytes=24,
    block_id_bytes=16,
    max_block_id_bytes=32,
    min_block_id_bytes=16,
    salt_bytes=8,
    iv_bytes=8,
    block_id_kdf=BLOCK_ID_KDF,
    block_id_kdf_config=ShakeConfig(
        name=BLOCK_ID_KDF,
        pad=b"\x9a",
        offset_amount=0,
        hasher=shake_128,
        key_slice=slice(None),
    ),
    shmac_kdf=SHMAC_KDF,
    shmac_kdf_config=ShakeConfig(
        name=SHMAC_KDF,
        pad=b"\xac",
        offset_amount=0,
        hasher=shake_128,
        key_slice=slice(None),
    ),
    permutation_type=FastAffineXORChain,
)


module_api = dict(
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    slick256_spec=slick256_spec,
)

