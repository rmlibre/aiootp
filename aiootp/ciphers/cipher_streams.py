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
Streaming manager classes for the package's ciphers.
"""

__all__ = ["AsyncCipherStream", "CipherStream"]


import io
from collections import deque
from hmac import compare_digest
from secrets import token_bytes

from aiootp._typing import Typing as t
from aiootp._constants.misc import DEFAULT_AAD
from aiootp._exceptions import CipherStreamIsClosed
from aiootp._gentools import apopleft, popleft, abatch, batch
from aiootp.asynchs import AsyncInit, ConcurrencyGuard, asleep

from .cipher_stream_properties import CipherStreamProperties


class AsyncCipherStream(CipherStreamProperties, metaclass=AsyncInit):
    """
    A high-level public interface to the package's online, salt reuse /
    misuse resistant, tweakable, AEAD ciphers.

    Validation using `StreamHMAC` `block_id`'s provides robustness to
    communication channels. It does so by detecting forgeries & out-of-
    order messages without changing its internal state. If a tag fails
    to validate, the cipher stream can continue functioning once the
    authentic messages, in their correct order, begin coming in.
    --------
    HOWEVER: The more blocks that are allowed to fail without aborting,
    -------- the more chances an attacker has to spoof the auth tag.

     _____________________________________
    |                                     |
    |      Usage Example: Encryption      |
    |_____________________________________|


    stream = await AsyncCipherStream(key, aad=session.transcript)
    session.transmit(salt=stream.salt, iv=stream.iv)

    for plaintext in session.upload.buffer(4 * stream.PACKETSIZE):
        await stream.abuffer(plaintext)
        async for block_id, ciphertext in stream:
            session.send_packet(block_id + ciphertext)

    async for block_id, ciphertext in stream.afinalize():
        session.send_packet(block_id + ciphertext)

    # Send the stream termination / authentication tag. <--------
    session.transmit(shmac=await stream.shmac.result)
    """

    __slots__ = (
        "_buffer",
        "_byte_count",
        "_config",
        "_digesting_now",
        "_finalizing_now",
        "_key_bundle",
        "_padding",
        "_stream",
        "shmac",
    )

    _MAX_SIMULTANEOUS_BUFFERS: int = 1024

    async def __init__(
        self,
        cipher: t.CipherInterfaceType,
        *,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
    ) -> None:
        """
        Derives encryption keys & initializes a mutable buffer to
        automatically prepare plaintext given by the user with the
        necessary padding.

        `salt`: A [pseudo]random salt that may be supplied by the user. By
                default it's sent in the clear attached to the ciphertext.
                Thus it may simplify implementing efficient features, such
                as search or routing, though care must still be taken when
                considering how leaking such metadata may be harmful.

                Keeping this value constant is strongly discouraged. Though,
                the cipher's salt misuse-reuse resistance is ruled by the
                combination of the automatically incorporated `timestamp`,
                `iv`, & `siv_key`. The risk calculation starts with setting
                r = len(iv + siv_key) / 3. Then, all else staying constant,
                after 256**r messages are encrypted within a second, the
                probability of a repeat context having occurred is ~256**(-r),
                with the probability resetting back to negligible each
                time the timestamp rolls over to the next second.

                See: https://github.com/rmlibre/aiootp/issues/16
                     https://crypto.stackexchange.com/a/112586

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.
        """
        self._config = cipher._config
        self._padding = cipher._padding
        self._byte_count = 0
        self._digesting_now = deque(maxlen=self._MAX_SIMULTANEOUS_BUFFERS)
        self._finalizing_now = deque()  # don't let maxlen remove entries
        self._buffer = buffer = deque([self._padding.start_padding()])
        self._key_bundle = key_bundle = await cipher._KeyAADBundle(
            kdfs=cipher._kdfs, salt=salt, aad=aad
        ).async_mode()
        self.shmac = cipher._StreamHMAC(key_bundle)._for_encryption()
        self._stream = cipher._Junction.abytes_encipher(
            apopleft(buffer), shmac=self.shmac
        )

    @property
    def _iter_shortcuts(
        self,
    ) -> t.Tuple[
        t.Callable[..., bytes],
        t.Deque[bytes],
        t.Callable[[None], bytes],
    ]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self.shmac.anext_block_id, self._buffer, self._stream.asend

    @property
    def _buffer_shortcuts(
        self,
    ) -> t.Tuple[t.Deque[bytes], t.Callable[[bytes], None]]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self._buffer, self._buffer.append

    async def __aiter__(
        self,
    ) -> t.AsyncGenerator[t.Tuple[bytes, bytes], None]:
        """
        Allows the object to be entered in for-loops an unlimited amount
        of times in the process of gathering data to buffer for the
        stream. This leads to a very pythonic API.
        """
        MIN_STREAM_QUEUE = self._config.MIN_STREAM_QUEUE
        anext_block_id, buffer, cipher = self._iter_shortcuts
        while len(buffer) > MIN_STREAM_QUEUE:
            block = await cipher(None)
            yield await anext_block_id(block), block

    async def afinalize(
        self,
    ) -> t.AsyncGenerator[t.Tuple[bytes, bytes], None]:
        """
        Instructs the instance to finish receiving data into the buffer
        & to flush all ciphertext results out to the user.

         _____________________________________
        |                                     |
        |      Usage Example: Encryption      |
        |_____________________________________|


        for plaintext in session.upload.buffer(4 * stream.PACKETSIZE):
            await stream.abuffer(plaintext)
            async for block_id, ciphertext in stream:
                session.send_packet(block_id + ciphertext)

        async for block_id, ciphertext in stream.afinalize():  # <------
            session.send_packet(block_id + ciphertext)
        """
        self._finalizing_now.append(token := token_bytes(32))
        if not compare_digest(token, self._finalizing_now[0]):
            raise ConcurrencyGuard.IncoherentConcurrencyState

        async with ConcurrencyGuard(self._digesting_now, token=token):
            end_padding = await self._padding.aend_padding(self._byte_count)
            final_blocks = abatch(
                self._buffer.pop() + end_padding,
                size=self._config.BLOCKSIZE,
            )
            async for block in final_blocks:
                self._buffer.append(block)
            while self._buffer:
                block = await self._stream.asend(None)
                block_id = await self.shmac.anext_block_id(block)
                yield block_id, block
            await self.shmac.afinalize()

    async def _adigest_data(
        self,
        data: t.Callable[[int], bytes],
        buffer: t.Deque[bytes],
        append: t.Callable[[bytes], None],
    ) -> None:
        """
        Prepares the input plaintext `data` for encryption by dividing
        it into blocksize chunks.
        """
        BLOCKSIZE = self._config.BLOCKSIZE
        if buffer and len(buffer[-1]) != BLOCKSIZE:
            missing_bytes = BLOCKSIZE - len(buffer[-1])
            chunk = data(missing_bytes)
            buffer[-1] += chunk
            if len(chunk) != missing_bytes:
                return
        while True:
            await asleep()
            block = data(BLOCKSIZE)
            append(block)
            if len(block) != BLOCKSIZE:
                break

    async def abuffer(self, data: bytes) -> t.Self:
        """
        Prepares the input plaintext `data` for encryption by dividing
        it into blocksize chunks & taking plaintext measuremenets for
        automated message padding.

         _____________________________________
        |                                     |
        |      Usage Example: Encryption      |
        |_____________________________________|


        for plaintext in session.upload.buffer(4 * stream.PACKETSIZE):
            await stream.abuffer(plaintext)  # <------------------------
            async for block_id, ciphertext in stream:
                session.send_packet(block_id + ciphertext)

        async for block_id, ciphertext in stream.afinalize():
            session.send_packet(block_id + ciphertext)
        """
        async with ConcurrencyGuard(self._digesting_now):
            if await self._aconstant_time_final_context_is_done():
                raise CipherStreamIsClosed
            self._byte_count += len(data)
            data = io.BytesIO(data).read
            _buffer, append = self._buffer_shortcuts
            await self._adigest_data(data, _buffer, append)
        return self


class CipherStream(CipherStreamProperties):
    """
    A high-level public interface to the package's online, salt reuse /
    misuse resistant, tweakable, AEAD ciphers.

    Validation using `StreamHMAC` `block_id`'s provides robustness to
    communication channels. It does so by detecting forgeries & out-of-
    order messages without changing its internal state. If a tag fails
    to validate, the cipher stream can continue functioning once the
    authentic messages, in their correct order, begin coming in.
    --------
    HOWEVER: The more blocks that are allowed to fail without aborting,
    -------- the more chances an attacker has to spoof the auth tag.

     _____________________________________
    |                                     |
    |      Usage Example: Encryption      |
    |_____________________________________|


    stream = CipherStream(key, aad=session.transcript)
    session.transmit(salt=stream.salt, iv=stream.iv)

    for plaintext in session.upload.buffer(4 * stream.PACKETSIZE):
        stream.buffer(plaintext)
        for block_id, ciphertext in stream:
            session.send_packet(block_id + ciphertext)

    for block_id, ciphertext in stream.finalize():
        session.send_packet(block_id + ciphertext)

    # Send the stream termination / authentication tag. <--------
    session.transmit(shmac=stream.shmac.result)
    """

    __slots__ = (
        "_buffer",
        "_byte_count",
        "_config",
        "_digesting_now",
        "_finalizing_now",
        "_key_bundle",
        "_padding",
        "_stream",
        "shmac",
    )

    _MAX_SIMULTANEOUS_BUFFERS: int = 1024

    def __init__(
        self,
        cipher: t.CipherInterfaceType,
        *,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
    ) -> None:
        """
        Derives encryption keys & initializes a mutable buffer to
        automatically prepare plaintext given by the user with the
        necessary padding.

        `salt`: A [pseudo]random salt that may be supplied by the user. By
                default it's sent in the clear attached to the ciphertext.
                Thus it may simplify implementing efficient features, such
                as search or routing, though care must still be taken when
                considering how leaking such metadata may be harmful.

                Keeping this value constant is strongly discouraged. Though,
                the cipher's salt misuse-reuse resistance is ruled by the
                combination of the automatically incorporated `timestamp`,
                `iv`, & `siv_key`. The risk calculation starts with setting
                r = len(iv + siv_key) / 3. Then, all else staying constant,
                after 256**r messages are encrypted within a second, the
                probability of a repeat context having occurred is ~256**(-r),
                with the probability resetting back to negligible each
                time the timestamp rolls over to the next second.

                See: https://github.com/rmlibre/aiootp/issues/16
                     https://crypto.stackexchange.com/a/112586

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.
        """
        self._config = cipher._config
        self._padding = cipher._padding
        self._byte_count = 0
        self._digesting_now = deque(maxlen=self._MAX_SIMULTANEOUS_BUFFERS)
        self._finalizing_now = deque()  # don't let maxlen remove entries
        self._buffer = buffer = deque([self._padding.start_padding()])
        self._key_bundle = key_bundle = cipher._KeyAADBundle(
            kdfs=cipher._kdfs, salt=salt, aad=aad
        ).sync_mode()
        self.shmac = cipher._StreamHMAC(key_bundle)._for_encryption()
        self._stream = cipher._Junction.bytes_encipher(
            popleft(buffer), shmac=self.shmac
        )

    @property
    def _iter_shortcuts(
        self,
    ) -> t.Tuple[
        t.Callable[..., bytes],
        t.Deque[bytes],
        t.Callable[[None], bytes],
    ]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self.shmac.next_block_id, self._buffer, self._stream.send

    @property
    def _buffer_shortcuts(
        self,
    ) -> t.Tuple[t.Deque[bytes], t.Callable[[bytes], None]]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self._buffer, self._buffer.append

    def __iter__(self) -> t.Generator[t.Tuple[bytes, bytes], None, None]:
        """
        Allows the object to be entered in for-loops an unlimited amount
        of times in the process of gathering data to buffer for the
        stream. This leads to a very pythonic API.
        """
        MIN_STREAM_QUEUE = self._config.MIN_STREAM_QUEUE
        next_block_id, buffer, cipher = self._iter_shortcuts
        while len(buffer) > MIN_STREAM_QUEUE:
            block = cipher(None)
            yield next_block_id(block), block

    def finalize(self) -> t.Generator[t.Tuple[bytes, bytes], None, None]:
        """
        Instructs the instance to finish receiving data into the buffer
        & to flush all ciphertext results out to the user.

         _____________________________________
        |                                     |
        |      Usage Example: Encryption      |
        |_____________________________________|


        for plaintext in session.upload.buffer(4 * stream.PACKETSIZE):
            stream.buffer(plaintext)
            for block_id, ciphertext in stream:
                session.send_packet(block_id + ciphertext)

        for block_id, ciphertext in stream.finalize():  # <-------------
            session.send_packet(block_id + ciphertext)
        """
        self._finalizing_now.append(token := token_bytes(32))
        if not compare_digest(token, self._finalizing_now[0]):
            raise ConcurrencyGuard.IncoherentConcurrencyState

        with ConcurrencyGuard(
            self._digesting_now, probe_delay=0.0001, token=token
        ):
            end_padding = self._padding.end_padding(self._byte_count)
            final_blocks = batch(
                self._buffer.pop() + end_padding,
                size=self._config.BLOCKSIZE,
            )
            for block in final_blocks:
                self._buffer.append(block)
            while self._buffer:
                block = self._stream.send(None)
                block_id = self.shmac.next_block_id(block)
                yield block_id, block
            self.shmac.finalize()

    def _digest_data(
        self,
        data: t.Callable[[int], bytes],
        buffer: t.Deque[bytes],
        append: t.Callable[[bytes], None],
    ) -> None:
        """
        Prepares the input plaintext `data` for encryption by dividing
        it into blocksize chunks.
        """
        BLOCKSIZE = self._config.BLOCKSIZE
        if buffer and len(buffer[-1]) != BLOCKSIZE:
            missing_bytes = BLOCKSIZE - len(buffer[-1])
            chunk = data(missing_bytes)
            buffer[-1] += chunk
            if len(chunk) != missing_bytes:
                return
        while True:
            block = data(BLOCKSIZE)
            append(block)
            if len(block) != BLOCKSIZE:
                break

    def buffer(self, data: bytes) -> t.Self:
        """
        Prepares the input plaintext `data` for encryption by dividing
        it into blocksize chunks & taking plaintext measuremenets for
        automated message padding.

         _____________________________________
        |                                     |
        |      Usage Example: Encryption      |
        |_____________________________________|


        for plaintext in session.upload.buffer(4 * stream.PACKETSIZE):
            stream.buffer(plaintext)  # <-------------------------------
            for block_id, ciphertext in stream:
                session.send_packet(block_id + ciphertext)

        for block_id, ciphertext in stream.finalize():
            session.send_packet(block_id + ciphertext)
        """
        with ConcurrencyGuard(self._digesting_now, probe_delay=0.0001):
            if self._constant_time_final_context_is_done():
                raise CipherStreamIsClosed
            self._byte_count += len(data)
            data = io.BytesIO(data).read
            _buffer, append = self._buffer_shortcuts
            self._digest_data(data, _buffer, append)
        return self


module_api = dict(
    AsyncCipherStream=t.add_type(AsyncCipherStream),
    CipherStream=t.add_type(CipherStream),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
