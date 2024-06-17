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


__all__ = ["Ciphertext"]


__doc__ = "A configurable container interface for ciphertexts."


from io import BytesIO

from aiootp._typing import Typing as t
from aiootp._exceptions import InvalidCiphertextSize
from aiootp.asynchs import asleep
from aiootp.commons import OpenFrozenSlots


class Ciphertext(OpenFrozenSlots):
    """
    Efficiently stores bytes type ciphertext organized by instance
    attributes.
    """

    __slots__ = ("shmac", "salt", "iv", "ciphertext", "config")

    _MAPPED_ATTRIBUTES: t.Tuple[str] = (
        "shmac", "salt", "iv", "ciphertext"
    )

    InvalidCiphertextSize: type = InvalidCiphertextSize

    def __init__(self, data: bytes, *, config: t.ConfigType) -> None:
        """
        Decomposes a blob of ciphertext `data` bytes into an organized
        instance where the `shmac` auth tag, `salt`, & `iv` randomizers &
        the body of `ciphertext` are queriable through dotted attribute
        lookup. `config_id` finds a specific cipher's ciphertext format
        within the class' mapping of configurations.
        """
        self.config = config
        self._ensure_valid_size(len(data))
        data = BytesIO(data)
        self.shmac = data.read(config.SHMAC_BYTES)
        self.salt = data.read(config.SALT_BYTES)
        self.iv = data.read(config.IV_BYTES)
        self.ciphertext = data.read()

    def __iter__(self) -> t.Generator[str, None, None]:
        yield from self._MAPPED_ATTRIBUTES

    def _ensure_valid_size(self, data_length: int) -> None:
        """
        Accepts the integer length of a blob of ciphertext & throws
        `InvalidCiphertextSize` if an impossible value is detected.
        """
        size = data_length - self.config.HEADER_BYTES
        if size <= 0 or size % self.config.BLOCKSIZE:
            raise InvalidCiphertextSize(data_length)


module_api = dict(
    Ciphertext=t.add_type(Ciphertext),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

