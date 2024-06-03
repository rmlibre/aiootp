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


__all__ = ["SequenceID"]


__doc__ = (
    "A type for converting secret `int`s into bytes-type identification "
    "numbers using a bijective, keyed permutation."
)


from aiootp._typing import Typing as t
from aiootp._constants import BIG
from aiootp._permutations import FastAffineXORChain
from aiootp.commons import ConfigMap, FrozenInstance

from .sequence_id_config import SequenceIDConfig


class SequenceID(FrozenInstance):
    """
    A class for producing unique, deterministic pseudo-random sequential
    identifiers from integer indexes. The identifiers don't suffer from
    birthday collisions if the difference between the minimum & maximum
    index values is no larger than 256**size, where 'size' is the number
    of bytes of the produced identifiers.

    The produced identifiers are randomized by a unique, secret, uniform
    key. Any instance created using the key is able to create the same
    sequence of identifiers. Normal birthday collision probabilities
    apply when a different key is used.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp.randoms import SequenceID, token_bytes
    from aiootp.ciphers import ChaCha20Poly1305
    from aiootp.keygens import DomainKDF

    seed = token_bytes(32)
    kdf = DomainKDF(b"movie-server", seed, key=session.shared_key)
    key = kdf.shake_128(size=32 + SequenceID.key_size(12), aad=b"joint-key")
    cipher = ChaCha20Poly1305(key[:32])
    sid = SequenceID(key=key[32:], config_id=12)

    yield seed
    for i, movie in enumerate(movie_collection):
        yield cipher.encrypt(
            nonce=sid.new(i), data=movie, associated_data=session.aad
        )
    """

    __slots__ = ("_permutation", "config")

    _configs = ConfigMap(
        {
            config_id: SequenceIDConfig(
                config_id=config_id,
                size=config_id,
                permutation_type=FastAffineXORChain,
                permutation_config_id=config_id,
            ) for config_id in range(1, 33)
        },
        config_type=SequenceIDConfig,
    )

    @classmethod
    def key_size(cls, config_id: t.Hashable) -> int:
        """
        Returns the number of bytes a uniform random key needs to be
        to initialize the instance's permutation.
        """
        return cls._configs[config_id].KEY_SIZE

    def _initialize_permutation(self, key: bytes) -> t.PermutationType:
        """
        Returns a bijective, keyed permutation as specified by the
        instance's configuration.
        """
        config_id = self.config.PERMUTATION_CONFIG_ID
        return self.config.Permutation(key=key, config_id=config_id)

    def __init__(
        self, *, key: t.Optional[bytes], config_id: t.Hashable = 12
    ) -> None:
        """
        Initialized the keyed permutation.
        """
        self.config = self._configs[config_id]
        self._permutation = self._initialize_permutation(key)

    async def anew(self, value: int) -> bytes:
        """
        Permutes the secret `value` using a bijective, keyed permutation.
        """
        sid = await self._permutation.apermute(value)
        return sid.to_bytes(self.config.SIZE, BIG)

    def new(self, value: int) -> bytes:
        """
        Permutes the secret `value` using a bijective, keyed permutation.
        """
        sid = self._permutation.permute(value)
        return sid.to_bytes(self.config.SIZE, BIG)

    async def aread(self, value: bytes) -> int:
        """
        Returns the secret int that created the permutation `value`.
        """
        return await self._permutation.ainvert(int.from_bytes(value, BIG))

    def read(self, value: bytes) -> int:
        """
        Returns the secret int that created the permutation `value`.
        """
        return self._permutation.invert(int.from_bytes(value, BIG))


module_api = dict(
    SequenceID=t.add_type(SequenceID),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

