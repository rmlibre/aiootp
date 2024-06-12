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


__all__ = ["ThreadingSafeEntropyPool"]


__doc__ = (
    "An interface for feeding & retrieving from a SHA3 XOF object used "
    "as an entropy pool."
)


from secrets import choice, token_bytes

from aiootp._typing import Typing as t
from aiootp._constants import HASHER_TYPES, INT_BYTES, BIG
from aiootp.commons import FrozenInstance
from aiootp.asynchs import get_process_id, get_thread_id
from aiootp.asynchs import asleep, ns_counter
from aiootp.generics import acanonical_pack, canonical_pack

from .simple import acanonical_token, canonical_token, token_bits


class ThreadingSafeEntropyPool(FrozenInstance):
    """
    A definition for bidirectional sponge objects which incorporate,
    store, & extract useful entropy.
    """

    __slots__ = ("_obj", "_pool")

    def __init__(
        self,
        data: bytes,
        *,
        obj: t.Callable[[bytes], t.Union[t.HasherType, t.XOFType]],
        pool: t.Sequence[bytes],
    ) -> None:
        """
        Copies over the object dictionary of the `obj` hashing object.
        """
        self._pool = pool
        self._obj = obj(data)
        self._obj.update(token_bytes(3 * self._obj.block_size))

    @property
    def name(self) -> str:
        return self._obj.name

    @property
    def block_size(self) -> int:
        return self._obj.block_size

    @property
    def digest_size(self) -> int:
        return self._obj.digest_size

    @property
    def update(self) -> t.Callable[[bytes], None]:
        return self._obj.update

    @property
    def digest(self) -> t.Callable[..., bytes]:
        """
        ************************
        BEWARE: NOT THREAD SAFE.
        ************************
        """
        return self._obj.digest

    @property
    def hexdigest(self) -> t.Callable[..., bytes]:
        """
        ************************
        BEWARE: NOT THREAD SAFE.
        ************************
        """
        return self._obj.hexdigest

    def copy(self) -> t.Cls:
        """
        Allows the user to create a copy instance of the hashing object.
        """
        new_self = self.__class__.__new__(self.__class__)
        new_self._obj = self._obj.copy()
        new_self._pool = self._pool.copy()
        return new_self

    async def _amake_token(self, *data: bytes) -> bytes:
        """
        Returns a PRIVATE, unique, & canonically encoded token.
        """
        return await acanonical_pack(
            await acanonical_token(),
            self._pool[0],
            *data,
            blocksize=self.block_size,
            pad=b"\x5c",
        )

    def _make_token(self, *data: bytes) -> bytes:
        """
        Returns a PRIVATE, unique, & canonically encoded token.
        """
        return canonical_pack(
            canonical_token(),
            self._pool[0],
            *data,
            blocksize=self.block_size,
            pad=b"\x36",
        )

    async def ahash(self, *data: bytes, size: int) -> bytes:
        """
        Receives any number of arguments of bytes type `data` &
        updates the instance with them all sequentially & canonically
        encoded.
        """
        digest_size = size.to_bytes(INT_BYTES, BIG)
        token = await self._amake_token(digest_size, *data)
        self.update(token)
        entropy = self._obj.copy()
        entropy.update(token)
        return entropy.digest(size) if size else entropy.digest()

    def hash(self, *data: bytes, size: int) -> bytes:
        """
        Receives any number of arguments of bytes type `data` &
        updates the instance with them all sequentially & canonically
        encoded.
        """
        digest_size = size.to_bytes(INT_BYTES, BIG)
        token = self._make_token(digest_size, *data)
        self.update(token)
        entropy = self._obj.copy()
        entropy.update(token)
        return entropy.digest(size) if size else entropy.digest()


module_api = dict(
    ThreadingSafeEntropyPool=t.add_type(ThreadingSafeEntropyPool),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

