# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2026 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


from conftest import *


# NOTE: The tests run in alphabetical order, so a Z is prepended to their
#       names. This way time will naturally pass from the start of the
#       tests to the end, eliminating idle waiting time.


class TestZCipherTimeToLive:
    async def test_async_json_decrypt(self) -> None:
        problem = (  # fmt: skip
            "Life-time for async json ciphertext is malfunctioning."
        )
        with Ignore(
            TimestampExpired,
            if_else=violation(problem),
        ) as ignored:
            relay = ignored
            await ttl_test_cipher.cipher.ajson_decrypt(
                atest_json_ciphertext,
                aad=ttl_test_cipher.aad,
                ttl=1,
            )
        assert relay.error.expired_by >= 1

    async def test_sync_json_decrypt(self) -> None:
        problem = (  # fmt: skip
            "Life-time for sync json ciphertext is malfunctioning."
        )
        with Ignore(
            TimestampExpired,
            if_else=violation(problem),
        ) as ignored:
            relay = ignored
            ttl_test_cipher.cipher.json_decrypt(
                test_json_ciphertext,
                aad=ttl_test_cipher.aad,
                ttl=1,
            )
        assert relay.error.expired_by >= 1

    async def test_async_read_token(self) -> None:
        problem = (  # fmt: skip
            "Life-time for async tokens is malfunctioning."
        )
        with Ignore(
            TimestampExpired,
            if_else=violation(problem),
        ) as ignored:
            relay = ignored
            await ttl_test_cipher.cipher.aread_token(
                atest_token_ciphertext,
                aad=ttl_test_cipher.aad,
                ttl=1,
            )
        assert relay.error.expired_by >= 1

    async def test_sync_read_token(self) -> None:
        problem = (  # fmt: skip
            "Life-time for sync tokens is malfunctioning."
        )
        with Ignore(
            TimestampExpired,
            if_else=violation(problem),
        ) as ignored:
            relay = ignored
            ttl_test_cipher.cipher.read_token(
                test_token_ciphertext,
                aad=ttl_test_cipher.aad,
                ttl=1,
            )
        assert relay.error.expired_by >= 1

    async def test_async_cipher_stream(self) -> None:
        problem = (  # fmt: skip
            "Life-time for async cipher streams is malfunctioning."
        )
        enc_stream, ciphertext = attl_cipher_stream, attl_stream_ciphertext
        with Ignore(
            TimestampExpired,
            if_else=violation(problem),
        ) as ignored:
            relay = ignored
            dec_stream = await ttl_test_cipher.cipher.astream_decrypt(
                salt=enc_stream.salt,
                aad=enc_stream.aad,
                iv=enc_stream.iv,
                ttl=1,
            )
            await dec_stream.abuffer(ciphertext)
            b"".join([block async for block in dec_stream])
        assert relay.error.expired_by >= 1

    async def test_sync_cipher_stream(self) -> None:
        problem = (  # fmt: skip
            "Life-time for sync cipher streams is malfunctioning."
        )
        enc_stream, ciphertext = ttl_cipher_stream, ttl_stream_ciphertext
        with Ignore(
            TimestampExpired,
            if_else=violation(problem),
        ) as ignored:
            relay = ignored
            dec_stream = ttl_test_cipher.cipher.stream_decrypt(
                salt=enc_stream.salt,
                aad=enc_stream.aad,
                iv=enc_stream.iv,
                ttl=1,
            )
            b"".join(dec_stream.buffer(ciphertext))
        assert relay.error.expired_by >= 1


class PasscryptTarget(t.NamedTuple):
    config: t.PasscryptConfig
    token: bytes
    bus: Namespace


class TestZPasscryptTimeToLive:
    ms_config = milliseconds_pcrypt._config
    s_config = seconds_pcrypt._config
    light_config = light_pcrypt._config
    async_targets = [
        PasscryptTarget(
            config=ms_config,
            token=aexpired_pcrypt_hash_milliseconds,
            bus=Namespace(),
        ),
        PasscryptTarget(
            config=s_config,
            token=aexpired_pcrypt_hash_seconds,
            bus=Namespace(),
        ),
        PasscryptTarget(
            config=light_config,
            token=aexpired_pcrypt_hash,
            bus=Namespace(),
        ),
    ]
    sync_targets = [
        PasscryptTarget(
            config=ms_config,
            token=expired_pcrypt_hash_milliseconds,
            bus=Namespace(),
        ),
        PasscryptTarget(
            config=s_config,
            token=expired_pcrypt_hash_seconds,
            bus=Namespace(),
        ),
        PasscryptTarget(
            config=light_config,
            token=expired_pcrypt_hash,
            bus=Namespace(),
        ),
    ]

    @pytest.mark.parametrize("target", async_targets)
    async def test_expired_timestamps_caught_in_averify(
        self,
        target: PasscryptTarget,
    ) -> None:
        problem = (  # fmt: skip
            "Life-time for async passcrypt hashes are malfunctioning."
        )
        with Ignore(
            TimestampExpired,
            if_else=violation(problem),
        ) as ignored:
            relay = ignored
            target.bus.time_before_test = target.config.clock.time()
            await Passcrypt.averify(
                target.token,
                passphrase_0,
                ttl=1,
                config=target.config,
            )
        target.bus.time_after_test = target.config.clock.time()
        target.bus.expired_by = relay.error.expired_by

    @pytest.mark.parametrize("target", async_targets)
    async def test_async_pcrypt_ttl_accuracy(
        self,
        target: PasscryptTarget,
    ) -> None:
        unit = target.config.clock.unit
        bus = target.bus
        ttl = 1

        ts = target.token[target.config.TIMESTAMP_SLICE]
        adjusted_timestamp = int.from_bytes(ts, BIG) + ttl * unit.per_s

        test_before_delta = int(bus.time_before_test - adjusted_timestamp)
        test_after_delta = int(bus.time_after_test - adjusted_timestamp)
        expected_span = range(test_before_delta, test_after_delta + 1)

        assert bus.expired_by in expected_span

    @pytest.mark.parametrize("target", sync_targets)
    async def test_expired_timestamps_caught_in_verify(
        self,
        target: PasscryptTarget,
    ) -> None:
        problem = (  # fmt: skip
            "Life-time for sync passcrypt hashes are malfunctioning."
        )
        with Ignore(
            TimestampExpired,
            if_else=violation(problem),
        ) as ignored:
            relay = ignored
            target.bus.time_before_test = target.config.clock.time()
            Passcrypt.verify(
                target.token,
                passphrase_0,
                ttl=1,
                config=target.config,
            )
        target.bus.time_after_test = target.config.clock.time()
        target.bus.expired_by = relay.error.expired_by

    @pytest.mark.parametrize("target", sync_targets)
    async def test_sync_pcrypt_ttl_accuracy(
        self,
        target: PasscryptTarget,
    ) -> None:
        unit = target.config.clock.unit
        bus = target.bus
        ttl = 1

        ts = target.token[target.config.TIMESTAMP_SLICE]
        adjusted_timestamp = int.from_bytes(ts, BIG) + ttl * unit.per_s

        test_before_delta = int(bus.time_before_test - adjusted_timestamp)
        test_after_delta = int(bus.time_after_test - adjusted_timestamp)
        expected_span = range(test_before_delta, test_after_delta + 1)

        assert bus.expired_by in expected_span


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
