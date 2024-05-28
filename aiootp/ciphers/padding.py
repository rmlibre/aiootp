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


__all__ = ["Padding", "PlaintextMeasurements"]


__doc__ = "Types for handling plaintext padding."


from secrets import token_bytes

from aiootp._typing import Typing as t
from aiootp._constants import BIG
from aiootp.asynchs import asleep
from aiootp.commons import FrozenSlots, FrozenInstance


class PlaintextMeasurements(FrozenSlots):
    """
    Efficiently stores plaintext measurements in instance attributes
    which are used to determine the padding that's needed.
    """

    __slots__ = ("padding_size", "pad_sentinel")

    def __init__(self, padding_size: int, pad_sentinel: bytes) -> None:
        self.padding_size = padding_size
        self.pad_sentinel = pad_sentinel


class Padding(FrozenInstance):
    """
    Manages the (de-)padding of plaintext with various values which
    improve the salt misuse-reuse resistance, replay attack mitigations,
    & deniability, of the package's ciphers.

     ______________________________________
    |                                      |
    |  Format Diagram:  Plaintext Padding  |
    |______________________________________|
     __________________________________________________________________
    |                      |                      |                    |
    |      Inner-Header    |        Body          |       Footer       |
    |-----------|----------|----------------------|---------|----------|
    | timestamp | SIV-key  |      plaintext       | padding | sentinel |
    |___________|__________|______________________|_________|__________|

    `Inner-Header`: Prepends a timestamp & SIV-key. The timestamp supports
        a time-to-live feature for ciphertexts which can mitigate replay
        attacks. Together with the random SIV-key, the uniqueness of the
        session's initialization is ensured on every tick of the clock,
        therefore extending salt misuse-reuse resistance to an impressive
        ~256**(len(iv)/2 + len(siv_key)/2) encryptions/second even if
        the `key`, `salt`, & `aad` remain static.

    `Footer`: The end padding is random bytes & an encoded length up to
        the block size. The randomness of the end padding, its minimal
        corroborability with secret data / session values, & the
        cipher's large & variable effective key-space, aims to aid the
        cipher's deniability.
    """

    __slots__ = ("config",)

    def __init__(self, config: t.ConfigType) -> None:
        """
        Populates the instance with the specified configuration.
        """
        self.config = config

    async def _amake_timestamp(self) -> bytes:
        """
        Returns a timestamp measured in seconds from the epoch set by
        the package (1672531200: Sun, 01 Jan 2023 00:00:00 UTC).
        """
        c = self.config
        return await c.clock.amake_timestamp(size=c.TIMESTAMP_BYTES)

    def _make_timestamp(self) -> bytes:
        """
        Returns a timestamp measured in seconds from the epoch set by
        the package (1672531200: Sun, 01 Jan 2023 00:00:00 UTC).
        """
        c = self.config
        return c.clock.make_timestamp(size=c.TIMESTAMP_BYTES)

    async def _amake_siv_key(self) -> bytes:
        """
        Returns a sequence of random bytes. This value is used to ensure
        every encryption is randomized & unique even if the `key`,
        `salt`, `aad`, & `iv` remain static.
        """
        await asleep()
        return token_bytes(self.config.SIV_KEY_BYTES)

    def _make_siv_key(self) -> bytes:
        """
        Returns a sequence of random bytes. This value is used to ensure
        every encryption is randomized & unique even if the `key`,
        `salt`, `aad`, & `iv` remain static.
        """
        return token_bytes(self.config.SIV_KEY_BYTES)

    async def astart_padding(self) -> bytes:
        """
        Prepends a timestamp & SIV-key. The timestamp supports a
        time-to-live feature for ciphertexts which can mitigate replay
        attacks. Together with the random SIV-key, the uniqueness of the
        session's initialization is ensured on every tick of the clock,
        therefore extending salt misuse-reuse resistance to an impressive
        ~256**(len(iv)/2 + len(siv_key)/2) encryptions/second even if
        the `key`, `salt`, & `aad` remain static.
        """
        return await self._amake_timestamp() + await self._amake_siv_key()

    def start_padding(self) -> bytes:
        """
        Prepends a timestamp & SIV-key. The timestamp supports a
        time-to-live feature for ciphertexts which can mitigate replay
        attacks. Together with the random SIV-key, the uniqueness of the
        session's initialization is ensured on every tick of the clock,
        therefore extending salt misuse-reuse resistance to an impressive
        ~256**(len(iv)/2 + len(siv_key)/2) encryptions/second even if
        the `key`, `salt`, & `aad` remain static.
        """
        return self._make_timestamp() + self._make_siv_key()

    async def _amake_extra_padding(self) -> bytes:
        """
        Returns a number of random bytes equal to a positive integer
        multiple of the length of a block. The multiple is `1` by
        default.

        These bytes provide a kind of deniability, where an adversary
        with even unlimited computational capability can't distinguish
        between all possible legitimate plaintexts. This is because
        there are enough random padding degrees of freedom (for large a
        blocksize) for such an adversary to create a super-exponentially
        large number of plaintexts which appear legitimate under any key
        (satisfy verification tags) & appear plausible (they can be made
        to be almost any message + random padding).
        """
        await asleep()
        return token_bytes(self.config.PADDING_FRAME)

    def _make_extra_padding(self) -> bytes:
        """
        Returns a number of random bytes equal to a positive integer
        multiple of the length of a block. The multiple is `1` by
        default.

        These bytes provide a kind of deniability, where an adversary
        with even unlimited computational capability can't distinguish
        between all possible legitimate plaintexts. This is because
        there are enough random padding degrees of freedom (for large a
        blocksize) for such an adversary to create a super-exponentially
        large number of plaintexts which appear legitimate under any key
        (satisfy verification tags) & appear plausible (they can be made
        to be almost any message + random padding).
        """
        return token_bytes(self.config.PADDING_FRAME)

    async def _adata_measurements(self, size: int) -> PlaintextMeasurements:
        """
        Does padding measurements based on the `size` of some unpadded
        data & stores the findings in an object for convenient usage.
        """
        await asleep()
        c = self.config
        remainder = (c.INNER_HEADER_BYTES + size) % c.PADDING_FRAME
        padding_size = c.PADDING_FRAME - remainder
        sentinel = padding_size % c.PADDING_FRAME
        return PlaintextMeasurements(
            padding_size=padding_size,
            pad_sentinel=sentinel.to_bytes(c.SENTINEL_BYTES, BIG),
        )

    def _data_measurements(self, size: int) -> PlaintextMeasurements:
        """
        Does padding measurements based on the `size` of some unpadded
        data & stores the findings in an object for convenient usage.
        """
        c = self.config
        remainder = (c.INNER_HEADER_BYTES + size) % c.PADDING_FRAME
        padding_size = c.PADDING_FRAME - remainder
        sentinel = padding_size % c.PADDING_FRAME
        return PlaintextMeasurements(
            padding_size=padding_size,
            pad_sentinel=sentinel.to_bytes(c.SENTINEL_BYTES, BIG),
        )

    async def _amake_end_padding(
        self, report: PlaintextMeasurements
    ) -> bytes:
        """
        Returns an excess (frame) of random padding & its encoded length
        to equalize the time it takes to apply the padding even for
        varying plaintext lengths.
        """
        extra_padding = await self._amake_extra_padding()
        return extra_padding + report.pad_sentinel

    def _make_end_padding(self, report: PlaintextMeasurements) -> bytes:
        """
        Returns an excess (frame) of random padding & its encoded length
        to equalize the time it takes to apply the padding even for
        varying plaintext lengths.
        """
        extra_padding = self._make_extra_padding()
        return extra_padding + report.pad_sentinel

    async def aend_padding(self, size: int) -> bytes:
        """
        The end padding is random bytes & an encoded length up to the
        block size. The randomness of the end padding, its minimal
        corroborability with user secrets / session values, & the
        cipher's large & variable effective key-space, aims to aid the
        cipher's deniability.
        """
        report = await self._adata_measurements(size)
        padding = await self._amake_end_padding(report)
        return padding[-report.padding_size :]

    def end_padding(self, size: int) -> bytes:
        """
        The end padding is random bytes & an encoded length up to the
        block size. The randomness of the end padding, its minimal
        corroborability with user secrets / session values, & the
        cipher's large & variable effective key-space, aims to aid the
        cipher's deniability.
        """
        report = self._data_measurements(size)
        padding = self._make_end_padding(report)
        return padding[-report.padding_size :]

    async def apad_plaintext(self, data: bytes) -> bytes:
        """
        Pads & returns the plaintext `data` with various values that
        aids a cipher's salt misuse-reuse resistance, replay attack
        mitigations, & deniability.

        Prepends a timestamp & SIV-key. The timestamp supports a
        time-to-live feature for ciphertexts which can mitigate replay
        attacks. Together with the random SIV-key, the uniqueness of the
        session's initialization is ensured on every tick of the clock,
        therefore extending salt misuse-reuse resistance to an impressive
        ~256**(len(iv)/2 + len(siv_key)/2) encryptions/second even if
        the `key`, `salt`, & `aad` remain static.

        The end padding is random bytes & an encoded length up to the
        block size. The randomness of the end padding, its minimal
        corroborability with user secrets / session values, & the
        cipher's large & variable effective key-space, aims to aid the
        cipher's deniability.
        """
        start_padding = await self.astart_padding()
        end_padding = await self.aend_padding(len(data))
        return b"".join((start_padding, data, end_padding))

    def pad_plaintext(self, data: bytes) -> bytes:
        """
        Pads & returns the plaintext `data` with various values that
        aids a cipher's salt misuse-reuse resistance, replay attack
        mitigations, & deniability.

        Prepends a timestamp & SIV-key. The timestamp supports a
        time-to-live feature for ciphertexts which can mitigate replay
        attacks. Together with the random SIV-key, the uniqueness of the
        session's initialization is ensured on every tick of the clock,
        therefore extending salt misuse-reuse resistance to an impressive
        ~256**(len(iv)/2 + len(siv_key)/2) encryptions/second even if
        the `key`, `salt`, & `aad` remain static.

        The end padding is random bytes & an encoded length up to the
        block size. The randomness of the end padding, its minimal
        corroborability with user secrets / session values, & the
        cipher's large & variable effective key-space, aims to aid the
        cipher's deniability.
        """
        start_padding = self.start_padding()
        end_padding = self.end_padding(len(data))
        return b"".join((start_padding, data, end_padding))

    async def adepadding_start_index(self) -> int:
        """
        Returns a start index which is used to slice off the prepended
        timestamp & SIV-key from a plaintext.
        """
        return self.config.INNER_HEADER_BYTES

    def depadding_start_index(self) -> int:
        """
        Returns a start index which is used to slice off the prepended
        timestamp & SIV-key from a plaintext.
        """
        return self.config.INNER_HEADER_BYTES

    async def adepadding_end_index(self, data: bytes) -> int:
        """
        Returns an end index which is used to slice off the appended
        values from some plaintext `data`:
        - The appended random padding.
        - The appended padding sentinel.
        """
        sentinel = int.from_bytes(data[self.config.SENTINEL_SLICE], BIG)
        return -(sentinel if sentinel else self.config.PADDING_FRAME)

    def depadding_end_index(self, data: bytes) -> int:
        """
        Returns an end index which is used to slice off the appended
        values from some plaintext `data`:
        - The appended random padding.
        - The appended padding sentinel.
        """
        sentinel = int.from_bytes(data[self.config.SENTINEL_SLICE], BIG)
        return -(sentinel if sentinel else self.config.PADDING_FRAME)

    async def adepad_plaintext(self, data: bytes, *, ttl: int = 0) -> bytes:
        """
        Returns `data` after these values are removed:
        - The prepended timestamp.
        - The prepended SIV-key.
        - The appended random padding.
        - The appended padding sentinel.
        """
        config = self.config
        config.clock.test_timestamp(data[config.TIMESTAMP_SLICE], ttl=ttl)
        start_index = await self.adepadding_start_index()
        end_index = await self.adepadding_end_index(data)
        return data[start_index:end_index]

    def depad_plaintext(self, data: bytes, *, ttl: int = 0) -> bytes:
        """
        Returns `data` after these values are removed:
        - The prepended timestamp.
        - The prepended SIV-key.
        - The appended random padding.
        - The appended padding sentinel.
        """
        config = self.config
        config.clock.test_timestamp(data[config.TIMESTAMP_SLICE], ttl=ttl)
        start_index = self.depadding_start_index()
        end_index = self.depadding_end_index(data)
        return data[start_index:end_index]


module_api = dict(
    Padding=t.add_type(Padding),
    PlaintextMeasurements=t.add_type(PlaintextMeasurements),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

