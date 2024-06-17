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


__all__ = ["StreamJunction"]


__doc__ = (
    "Where data & key streams meet for confidentiality & "
    "authenticity."
)


from aiootp._typing import Typing as t
from aiootp._constants import ENCRYPTION, DECRYPTION, ASYNC, SYNC
from aiootp._exceptions import Issue, KeyAADIssue
from aiootp.asynchs import asleep
from aiootp.commons import FrozenInstance

from .stream_hmac import StreamHMAC


class StreamJunction(FrozenInstance):
    """
    A general definition for how the key & data streams are combined.
    """

    __slots__ = ()

    @classmethod
    def abytes_encipher(
        cls, data: t.AsyncOrSyncDatastream, *, shmac: StreamHMAC
    ) -> t.AsyncGenerator[bytes, None]:
        """
        A low-level function which returns an async generator that
        streams this package's ciphers.

        WARNING: `data` MUST produce plaintext in blocksize chunks or
        smaller per iteration or security MAY BE BROKEN by directly
        leaking plaintext. The cipher is designed for plaintext be
        padded using the `Padding` class.

        WARNING: The `finalize` or `afinalize` methods must be called on
        the `shmac` once all of the cipehrtext has been created /
        decrypted. Then the final SHMAC is available from the `aresult`
        & `result` methods. Authentication is attained by running the
        `(a)test_shmac` method. The `shmac` also has `(a)next_block_id`
        methods that can be used to authenticate unfinished streams of
        cipehrtext on the fly.
        """
        shmac._key_bundle._register_shmac(shmac)
        if shmac.mode != ENCRYPTION:
            raise Issue.must_set_value("shmac", ENCRYPTION)
        elif shmac._key_bundle._mode != ASYNC:
            raise KeyAADIssue.mode_isnt_correct(ASYNC)
        return cls.acombine_streams(data, shmac=shmac)

    @classmethod
    def bytes_encipher(
        cls, data: t.Datastream, *, shmac: StreamHMAC
    ) -> t.Generator[bytes, None, None]:
        """
        A low-level function which returns a sync generator that streams
        this package's ciphers.

        WARNING: `data` MUST produce plaintext in blocksize chunks or
        smaller per iteration or security MAY BE BROKEN by directly
        leaking plaintext. The cipher is designed for plaintext be
        padded using the `Padding` class.

        WARNING: The `finalize` or `afinalize` methods must be called on
        the `shmac` once all of the cipehrtext has been created /
        decrypted. Then the final SHMAC is available from the `aresult`
        & `result` methods. Authentication is attained by running the
        `(a)test_shmac` method. The `shmac` also has `(a)next_block_id`
        methods that can be used to authenticate unfinished streams of
        cipehrtext on the fly.
        """
        shmac._key_bundle._register_shmac(shmac)
        if shmac.mode != ENCRYPTION:
            raise Issue.must_set_value("shmac", ENCRYPTION)
        elif shmac._key_bundle._mode != SYNC:
            raise KeyAADIssue.mode_isnt_correct(SYNC)
        return cls.combine_streams(data, shmac=shmac)

    @classmethod
    def abytes_decipher(
        cls, data: t.AsyncOrSyncDatastream, *, shmac: StreamHMAC
    ) -> t.AsyncGenerator[bytes, None]:
        """
        A low-level function which returns an async generator that
        streams this package's ciphers.

        WARNING: The `finalize` or `afinalize` methods must be called on
        the `shmac` once all of the cipehrtext has been created /
        decrypted. Then the final SHMAC is available from the `aresult`
        & `result` methods. Authentication is attained by running the
        `(a)test_shmac` method. The `shmac` also has `(a)next_block_id`
        methods that can be used to authenticate unfinished streams of
        cipehrtext on the fly.
        """
        shmac._key_bundle._register_shmac(shmac)
        if shmac.mode != DECRYPTION:
            raise Issue.must_set_value("shmac", DECRYPTION)
        elif shmac._key_bundle._mode != ASYNC:
            raise KeyAADIssue.mode_isnt_correct(ASYNC)
        return cls.acombine_streams(data, shmac=shmac)

    @classmethod
    def bytes_decipher(
        cls, data: t.Datastream, *, shmac: StreamHMAC
    ) -> t.Generator[bytes, None, None]:
        """
        A low-level function which returns a sync generator that streams
        this package's ciphers.

        WARNING: The `finalize` or `afinalize` methods must be called on
        the `shmac` once all of the cipehrtext has been created /
        decrypted. Then the final SHMAC is available from the `aresult`
        & `result` methods. Authentication is attained by running the
        `(a)test_shmac` method. The `shmac` also has `(a)next_block_id`
        methods that can be used to authenticate unfinished streams of
        cipehrtext on the fly.
        """
        shmac._key_bundle._register_shmac(shmac)
        if shmac.mode != DECRYPTION:
            raise Issue.must_set_value("shmac", DECRYPTION)
        elif shmac._key_bundle._mode != SYNC:
            raise KeyAADIssue.mode_isnt_correct(SYNC)
        return cls.combine_streams(data, shmac=shmac)


module_api = dict(
    StreamJunction=t.add_type(StreamJunction),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

