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


__all__ = ["SyntheticIV"]


__doc__ = "A general definition for the SyntheticIV interface."


from aiootp._typing import Typing as t
from aiootp._constants import ENCRYPTION
from aiootp._exceptions import Issue
from aiootp.commons import FrozenInstance


class SyntheticIV(FrozenInstance):
    """
    Manages the application of synthetic IVs which improve the salt
    misuse-reuse resistance of dual-output mode ciphers, since if either
    the timestamp or ephemeral SIV-key are unique, then the entire
    stream of key material will be unique. The required plaintext
    padding is handled within the `Padding` class.
    """

    __slots__ = ()

    @classmethod
    async def avalidated_transform(
        cls,
        datastream: t.AsyncDatastream,
        keystream: t.Callable[[bytes], t.Awaitable[bytes]],
        shmac: t.StreamHMACType,
    ) -> bytes:
        """
        Derives the synthetic IV from the timestamp & ephemeral SIV-key
        in the plaintext header then seeds it into the keystream to
        randomize it before encrypting / decrypting the first block of
        payload data.

        This method ciphers / deciphers the first block of plaintext /
        ciphertext depending on whether the shmac has been set to
        encryption or decryption modes.
        """
        try:
            block = await datastream.asend(None)
        except StopAsyncIteration:
            raise Issue.stream_is_empty()
        if shmac._mode == ENCRYPTION:
            return await cls._aunique_cipher(block, keystream, shmac)
        else:
            return await cls._aunique_decipher(block, keystream, shmac)

    @classmethod
    def validated_transform(
        cls,
        datastream: t.Datastream,
        keystream: t.Callable[[bytes], bytes],
        shmac: t.StreamHMACType,
    ) -> bytes:
        """
        Derives the synthetic IV from the timestamp & ephemeral SIV-key
        in the plaintext header then seeds it into the keystream to
        randomize it before encrypting / decrypting the first block of
        payload data.

        This method ciphers / deciphers the first block of plaintext /
        ciphertext depending on whether the shmac has been set to
        encryption or decryption modes.
        """
        try:
            block = datastream.send(None)
        except StopIteration:
            raise Issue.stream_is_empty()
        if shmac._mode == ENCRYPTION:
            return cls._unique_cipher(block, keystream, shmac)
        else:
            return cls._unique_decipher(block, keystream, shmac)


module_api = dict(
    SyntheticIV=t.add_type(SyntheticIV),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

