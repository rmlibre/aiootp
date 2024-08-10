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


__all__ = ["AsyncDecipherStream", "DecipherStream"]


__doc__ = "Streaming manager classes for the package's ciphers."


import io
from collections import deque
from hmac import compare_digest
from secrets import token_bytes

from aiootp._typing import Typing as t
from aiootp._constants import DEFAULT_AAD, DEFAULT_TTL
from aiootp._exceptions import Issue, CipherStreamIssue
from aiootp._gentools import apopleft, popleft, abatch, batch
from aiootp.asynchs import AsyncInit, ConcurrencyGuard, asleep

from .cipher_stream_properties import AuthFail, CipherStreamProperties


class AsyncDecipherStream(CipherStreamProperties, metaclass=AsyncInit):
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
    |      Usage Example: Decryption      |
    |_____________________________________|


    stream = await AsyncDecipherStream(
        key, salt=session.salt, aad=session.transcript, iv=session.iv
    )
    for ciphertext in session.download.buffer(4 * stream.PACKETSIZE):
        await stream.abuffer(ciphertext)  # <--- raises InvalidBlockID if
        async for plaintext in stream:    # auth failure in last 4 packets
            yield plaintext

    async for plaintext in stream.afinalize():
        yield plaintext

    # Verify the stream termination / authentication tag. <--------
    await stream.shmac.atest_shmac(session.shmac)
    """

    __slots__ = (
        "_buffer",
        "_bytes_to_trim",
        "_config",
        "_digesting_now",
        "_finalizing_now",
        "_is_streaming",
        "_key_bundle",
        "_padding",
        "_result_queue",
        "_stream",
        "_ttl",
        "shmac",
    )

    _MAX_SIMULTANEOUS_BUFFERS: int = 1024

    async def __init__(
        self,
        cipher: t.CipherInterfaceType,
        *,
        salt: bytes,
        aad: bytes = DEFAULT_AAD,
        iv: bytes,
        ttl: t.Optional[int] = DEFAULT_TTL,
    ) -> None:
        """
        Derives decryption keys & initializes a mutable buffer to
        automatically decrypt & return plaintext with padding removed.

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
                once 256**r messages are encrypted within a second, each
                additional encrypted message within that same second begins
                to have more than a 256**(-r) chance of generating a repeat
                context.

                See: https://github.com/rmlibre/aiootp/issues/16

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.

        `iv`: An ephemeral, uniform, random value that's generated by
                the encryption algorithm.

        `ttl`: An amount of seconds that dictate the allowable age of
                a ciphertext stream, but ONLY checks the time for expiry
                at the very start of a stream. Has no effect on how long
                a stream can continue to live for.
        """
        self._config = cipher._config
        self._padding = cipher._padding
        self._ttl = ttl
        self._digesting_now = deque(maxlen=self._MAX_SIMULTANEOUS_BUFFERS)
        self._finalizing_now = deque()  # don't let maxlen remove entries
        self._is_streaming = False
        self._result_queue = deque()
        self._buffer = buffer = deque()
        self._bytes_to_trim = self._config.INNER_HEADER_BYTES
        self._key_bundle = key_bundle = await cipher._KeyAADBundle(
            kdfs=cipher._kdfs,
            salt=salt,
            aad=aad,
            iv=iv,
        ).async_mode()
        self.shmac = cipher._StreamHMAC(key_bundle)._for_decryption()
        self._stream = cipher._Junction.abytes_decipher(
            apopleft(buffer), shmac=self.shmac
        )

    @property
    def _iter_shortcuts(
        self,
    ) -> t.Tuple[t.Deque[bytes], t.Callable[[], bytes]]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self._result_queue, self._result_queue.popleft

    @property
    def _digest_data_shortcuts(
        self,
    ) -> t.Tuple[t.Callable[[None], bytes], t.Callable[[bytes], None]]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self._stream.asend, self._result_queue.append

    @property
    def _buffer_shortcuts(
        self,
    ) -> t.Tuple[t.Callable[..., None], t.Callable[[bytes], None]]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self.shmac.atest_next_block_id, self._buffer.append

    async def _atest_timestamp(
        self, queue: t.Callable[[bytes], None]
    ) -> None:
        """
        Raises `TimestampExpired` if the timestamp prepended to the
        plaintext is older than the time-to-live specified by the
        instance.
        """
        try:
            self._is_streaming = True
            timestamp = queue[0][self._config.TIMESTAMP_SLICE]
            await self._config.clock.atest_timestamp(timestamp, self._ttl)
        except self.TimestampExpired as error:
            self._is_streaming = False
            raise error

    async def _aremove_inner_header(
        self, queue: t.Callable[[bytes], None]
    ) -> None:
        """
        Strips the inner header from the buffered plaintext in the queue
        in the cases where the inner header spans multiple blocks.
        """
        await asleep()
        inner_header = queue[0][: self._bytes_to_trim]
        block = queue[0][self._bytes_to_trim :]
        self._bytes_to_trim -= len(inner_header)
        if block:
            queue[0] = block
        else:
            queue.popleft()

    async def __aiter__(self) -> t.AsyncGenerator[bytes, None]:
        """
        Allows the object to be entered in for-loops an unlimited amount
        of times in the process of gathering data to buffer for the
        stream. This leads to a very pythonic API.
        """
        MIN_STREAM_QUEUE = self._config.MIN_STREAM_QUEUE
        result_queue, pop_result = self._iter_shortcuts
        if not self._is_streaming:
            await self._atest_timestamp(result_queue)
        while self._bytes_to_trim and result_queue:
            await self._aremove_inner_header(result_queue)
        while len(result_queue) > MIN_STREAM_QUEUE:
            yield pop_result()
            await asleep()

    async def afinalize(self) -> t.AsyncGenerator[bytes, None]:
        """
        Instructs the instance to finish receiving data into the buffer
        & to flush all results out to the user with its plaintext
        padding removed.

         _____________________________________
        |                                     |
        |      Usage Example: Decryption      |
        |_____________________________________|


        for ciphertext in session.download.buffer(4 * stream.PACKETSIZE):
            await stream.abuffer(ciphertext)  # <--- raises InvalidBlockID if
            async for plaintext in stream:    # auth failure in last 4 packets
                yield plaintext

        async for plaintext in stream.afinalize():
            yield plaintext
        """
        self._finalizing_now.append(token := token_bytes(32))
        if not compare_digest(token, self._finalizing_now[0]):
            raise ConcurrencyGuard.IncoherentConcurrencyState

        async with ConcurrencyGuard(self._digesting_now, token=token):
            await self.shmac.afinalize()
            async for result in self:
                yield result
            queue = self._result_queue
            footer_index = await self._padding.adepadding_end_index(
                queue[-1]
            )
            async for block in abatch(
                b"".join(queue)[:footer_index], size=self._config.BLOCKSIZE
            ):
                yield block

    async def _adigest_data(
        self,
        data: t.Callable[[int], bytes],
        atest_block_id: t.Callable[..., None],
        append: t.Callable[[bytes], None],
    ) -> None:
        """
        Prepares the input ciphertext `data` for decryption by dividing
        it into blocksize chunks & validating each packet's block ID.
        """
        config = self._config
        BLOCKSIZE, BLOCK_ID_BYTES = config.BLOCKSIZE, config.BLOCK_ID_BYTES
        cipher, queue_result = self._digest_data_shortcuts
        while True:
            block_id = data(BLOCK_ID_BYTES)
            if not block_id:
                break
            block = data(BLOCKSIZE)
            try:
                await atest_block_id(block_id, block)
            except self.InvalidBlockID as auth_fail:
                # Package the current state of buffering for the caller
                # to handle authentication failures & negotiation of
                # data retransmission if desired.
                auth_fail.failure_state = AuthFail(block_id, block, data)
                raise auth_fail
            append(block)
            queue_result(await cipher(None))

    async def abuffer(self, data: bytes) -> t.Self:
        """
        Prepares the input ciphertext `data` for decryption by
        dividing it into blocksize chunks & validating each packet's
        block ID.

         _____________________________________
        |                                     |
        |      Usage Example: Decryption      |
        |_____________________________________|


        for ciphertext in session.download.buffer(4 * stream.PACKETSIZE):
            await stream.abuffer(ciphertext)  # <--- raises InvalidBlockID if
            async for plaintext in stream:    # auth failure in last 4 packets
                yield plaintext

        async for plaintext in stream.afinalize():
            yield plaintext
        """
        if not data or len(data) % self.PACKETSIZE:
            raise Issue.invalid_length("data", len(data))

        async with ConcurrencyGuard(self._digesting_now):
            if self._finalizing_now:
                raise CipherStreamIssue.stream_has_been_closed()
            data = io.BytesIO(data).read
            atest_block_id, append = self._buffer_shortcuts
            await self._adigest_data(data, atest_block_id, append)
        return self


class DecipherStream(CipherStreamProperties):
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
    |      Usage Example: Decryption      |
    |_____________________________________|


    stream = DecipherStream(
        key, salt=session.salt, aad=session.transcript, iv=session.iv
    )
    for ciphertext in session.download.buffer(4 * stream.PACKETSIZE):
        stream.buffer(ciphertext)   # <--- raises InvalidBlockID if
        for plaintext in stream:    # auth failure in last 4 packets
            yield plaintext

    for plaintext in stream.finalize():
        yield plaintext

    # Verify the stream termination / authentication tag. <--------
    stream.shmac.test_shmac(session.shmac)
    """

    __slots__ = (
        "_buffer",
        "_config",
        "_bytes_to_trim",
        "_digesting_now",
        "_finalizing_now",
        "_is_streaming",
        "_key_bundle",
        "_padding",
        "_result_queue",
        "_stream",
        "_ttl",
        "shmac",
    )

    _MAX_SIMULTANEOUS_BUFFERS: int = 1024

    def __init__(
        self,
        cipher: t.CipherInterfaceType,
        *,
        salt: bytes,
        aad: bytes = DEFAULT_AAD,
        iv: bytes,
        ttl: t.Optional[int] = DEFAULT_TTL,
    ) -> None:
        """
        Derives decryption keys & initializes a mutable buffer to
        automatically decrypt & return plaintext with padding removed.

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
                once 256**r messages are encrypted within a second, each
                additional encrypted message within that same second begins
                to have more than a 256**(-r) chance of generating a repeat
                context.

                See: https://github.com/rmlibre/aiootp/issues/16

        `aad`: An arbitrary bytes value that a user decides to categorize
                keystreams. It's authenticated as associated data & safely
                differentiates keystreams as a tweak when it's unique for
                each permutation of `key`, `salt`, & `iv`.

        `iv`: An ephemeral, uniform, random value that's generated by
                the encryption algorithm.

        `ttl`: An amount of seconds that dictate the allowable age of
                a ciphertext stream, but ONLY checks the time for expiry
                at the very start of a stream. Has no effect on how long
                a stream can continue to live for.
        """
        self._config = cipher._config
        self._padding = cipher._padding
        self._ttl = ttl
        self._digesting_now = deque(maxlen=self._MAX_SIMULTANEOUS_BUFFERS)
        self._finalizing_now = deque()  # don't let maxlen remove entries
        self._is_streaming = False
        self._result_queue = deque()
        self._buffer = buffer = deque()
        self._bytes_to_trim = self._config.INNER_HEADER_BYTES
        self._key_bundle = key_bundle = cipher._KeyAADBundle(
            kdfs=cipher._kdfs,
            salt=salt,
            aad=aad,
            iv=iv,
        ).sync_mode()
        self.shmac = cipher._StreamHMAC(key_bundle)._for_decryption()
        self._stream = cipher._Junction.bytes_decipher(
            popleft(buffer), shmac=self.shmac
        )

    @property
    def _iter_shortcuts(
        self,
    ) -> t.Tuple[t.Deque[bytes], t.Callable[[], bytes]]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self._result_queue, self._result_queue.popleft

    @property
    def _digest_data_shortcuts(
        self,
    ) -> t.Tuple[t.Callable[[None], bytes], t.Callable[[bytes], None]]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self._stream.send, self._result_queue.append

    @property
    def _buffer_shortcuts(
        self,
    ) -> t.Tuple[t.Callable[..., None], t.Callable[[bytes], None]]:
        """
        Returns method pointers so calls in tight loops during
        processing don't have to continually getattr on instance
        objects.
        """
        return self.shmac.test_next_block_id, self._buffer.append

    def _test_timestamp(self, queue: t.Callable[[bytes], None]) -> None:
        """
        Raises `TimestampExpired` if the timestamp prepended to the
        plaintext is older than the time-to-live specified by the
        instance.
        """
        try:
            self._is_streaming = True
            timestamp = queue[0][self._config.TIMESTAMP_SLICE]
            self._config.clock.test_timestamp(timestamp, self._ttl)
        except self.TimestampExpired as error:
            self._is_streaming = False
            raise error

    def _remove_inner_header(
        self, queue: t.Callable[[bytes], None]
    ) -> None:
        """
        Strips the inner header from the buffered plaintext in the queue
        in the cases where the inner header spans multiple blocks.
        """
        inner_header = queue[0][: self._bytes_to_trim]
        block = queue[0][self._bytes_to_trim :]
        self._bytes_to_trim -= len(inner_header)
        if block:
            queue[0] = block
        else:
            queue.popleft()

    def __iter__(self) -> t.Generator[bytes, None, None]:
        """
        Allows the object to be entered in for-loops an unlimited amount
        of times in the process of gathering data to buffer for the
        stream. This leads to a very pythonic API.
        """
        MIN_STREAM_QUEUE = self._config.MIN_STREAM_QUEUE
        result_queue, pop_result = self._iter_shortcuts
        if not self._is_streaming:
            self._test_timestamp(result_queue)
        while self._bytes_to_trim and result_queue:
            self._remove_inner_header(result_queue)
        while len(result_queue) > MIN_STREAM_QUEUE:
            yield pop_result()

    def finalize(self) -> t.Generator[bytes, None, None]:
        """
        Instructs the instance to finish receiving data into the buffer
        & to flush all results out to the user with its plaintext
        padding removed.

         _____________________________________
        |                                     |
        |      Usage Example: Decryption      |
        |_____________________________________|

        for ciphertext in source.download.buffer(4 * stream.PACKETSIZE):
            stream.buffer(ciphertext)   # <--- raises InvalidBlockID if
            for plaintext in stream:    # auth failure in last 4 packets
                yield plaintext
        for plaintext in stream.finalize():
            yield plaintext
        """
        self._finalizing_now.append(token := token_bytes(32))
        if not compare_digest(token, self._finalizing_now[0]):
            raise ConcurrencyGuard.IncoherentConcurrencyState

        with ConcurrencyGuard(
            self._digesting_now, probe_delay=0.0001, token=token
        ):
            self.shmac.finalize()
            yield from self
            queue = self._result_queue
            footer_index = self._padding.depadding_end_index(queue[-1])
            yield from batch(
                b"".join(queue)[:footer_index], size=self._config.BLOCKSIZE
            )

    def _digest_data(
        self,
        data: t.Callable[[int], bytes],
        test_block_id: t.Callable[..., None],
        append: t.Callable[[bytes], None],
    ) -> None:
        """
        Prepares the input ciphertext `data` for decryption by dividing
        it into blocksize chunks & validating each packet's block ID.
        """
        config = self._config
        BLOCKSIZE, BLOCK_ID_BYTES = config.BLOCKSIZE, config.BLOCK_ID_BYTES
        cipher, queue_result = self._digest_data_shortcuts
        while True:
            block_id = data(BLOCK_ID_BYTES)
            if not block_id:
                break
            block = data(BLOCKSIZE)
            try:
                test_block_id(block_id, block)
            except self.InvalidBlockID as auth_fail:
                # Package the current state of buffering for the caller
                # to handle authentication failures & negotiation of
                # data retransmission if desired.
                auth_fail.failure_state = AuthFail(block_id, block, data)
                raise auth_fail
            append(block)
            queue_result(cipher(None))

    def buffer(self, data: bytes) -> t.Self:
        """
        Prepares the input ciphertext `data` for decryption by
        dividing it into blocksize chunks & validating each packet's
        block ID.

         _____________________________________
        |                                     |
        |      Usage Example: Decryption      |
        |_____________________________________|

        for ciphertext in source.download.buffer(4 * stream.PACKETSIZE):
            stream.buffer(ciphertext)   # <--- raises InvalidBlockID if
            for plaintext in stream:    # auth failure in last 4 packets
                yield plaintext
        for plaintext in stream.finalize():
            yield plaintext
        """
        if not data or len(data) % self.PACKETSIZE:
            raise Issue.invalid_length("data", len(data))

        with ConcurrencyGuard(self._digesting_now, probe_delay=0.0001):
            if self._finalizing_now:
                raise CipherStreamIssue.stream_has_been_closed()
            data = io.BytesIO(data).read
            atest_block_id, append = self._buffer_shortcuts
            self._digest_data(data, atest_block_id, append)
        return self


module_api = dict(
    AsyncDecipherStream=t.add_type(AsyncDecipherStream),
    DecipherStream=t.add_type(DecipherStream),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
