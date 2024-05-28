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


__all__ = ["AuthFail", "CipherStreamProperties"]


__doc__ = (
    "A definition of shared properties between cipher streaming types."
)


from aiootp._typing import Typing as t
from aiootp._exceptions import Issue, TimestampExpired
from aiootp._exceptions import InvalidBlockID, InvalidSHMAC
from aiootp.commons import OpenFrozenSlots


class AuthFail(OpenFrozenSlots):
    """
    Creates efficient containers for data lost in a buffer during
    authentication failure of a block ID in (Async)DecipherStream
    objects.
    """

    __slots__ = ("block_id", "block", "buffer")

    def __init__(
        self, block_id: bytes, block: bytes, buffer: t.Callable
    ) -> None:
        self.block_id = block_id
        self.block = block
        self.buffer = buffer


class CipherStreamProperties:
    """
    A definition of shared properties between cipher streaming types.
    """

    InvalidBlockID: type = InvalidBlockID
    InvalidSHMAC: type = InvalidSHMAC
    TimestampExpired: type = TimestampExpired

    @property
    def PACKETSIZE(self) -> int:
        """
        Returns the number of combined bytes each iteration of the
        stream will produce. Equal to the header bytes + the blocksize.
        """
        return self._config.PACKETSIZE

    @property
    def aad(self) -> bytes:
        """
        An arbitrary bytes value that a user decides to categorize
        keystreams. It's authenticated as associated data & safely
        differentiates keystreams as a tweak when it's unique for
        each permutation of `key`, `salt`, & `iv`.
        """
        return self._key_bundle.aad

    @property
    def salt(self) -> bytes:
        """
        A [pseudo]random salt that may be supplied by the user.
        By default it's sent in the clear attached to the
        ciphertext. Thus it may simplify implementing efficient
        features, such as search or routing, though care must still
        be taken when considering how leaking such metadata may be
        harmful. Keeping this value constant is strongly discouraged,
        though the salt misuse-reuse resistance of the cipher
        extends up to ~256**(len(iv)/2 + len(siv_key)/2)
        encryptions/second.
        """
        return self._key_bundle.salt

    @property
    def iv(self) -> bytes:
        """
        An ephemeral, uniform, random value that's generated by
        the encryption algorithm. Ensures salt misue / reuse
        security even if the `key`, `salt`, & `aad` are the same for
        ~256**(len(iv)/2 + len(siv_key)/2) encryptions/second.
        """
        return self._key_bundle.iv


module_api = dict(
    AuthFail=t.add_type(AuthFail),
    CipherStreamProperties=t.add_type(CipherStreamProperties),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

