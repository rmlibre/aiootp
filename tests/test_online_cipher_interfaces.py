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


import pytest
from random import randrange

from aiootp.asynchs import ConcurrencyGuard

from conftest import *


class TestOnlineCipherInterfaces:
    async def test_sync_cipher_decipher_streams_with_varied_data_sizes(
        self,
    ) -> None:
        for config, cipher, salt, aad in all_ciphers:
            for i in range(
                0, 512 - config.INNER_HEADER_BYTES - 1, randrange(1, 64)
            ):
                stream_enc = cipher.stream_encrypt(salt=salt, aad=aad)
                pt_enc = i * b"a"
                stream_enc.buffer(pt_enc)

                stream_dec = cipher.stream_decrypt(
                    salt=stream_enc.salt,
                    aad=stream_enc.aad,
                    iv=stream_enc.iv,
                )
                for var in ("salt", "iv", "aad", "PACKETSIZE"):
                    assert getattr(stream_enc, var) == getattr(
                        stream_dec, var
                    )
                pt_dec = b""
                join = b"".join
                for id_ct in stream_enc:
                    problem = (  # fmt: skip
                        "Invalid packet sizes were allowed."
                    )
                    with Ignore(ValueError, if_else=violation(problem)):
                        stream_dec.buffer(
                            join(id_ct)[: stream_dec.PACKETSIZE - 1]
                        )

                    stream_dec.buffer(join(id_ct))
                    for pt in stream_dec:
                        pt_dec += pt
                for id_ct in stream_enc.finalize():
                    stream_dec.buffer(join(id_ct))
                for pt in stream_dec.finalize():
                    pt_dec += pt

                problem = (  # fmt: skip
                    "Processing was allowed to continue after finalization."
                )
                with Ignore(InterruptedError, if_else=violation(problem)):
                    stream_enc.buffer(pt_enc)
                with Ignore(InterruptedError, if_else=violation(problem)):
                    stream_dec.buffer(b"".join(id_ct))
                stream_dec.shmac.test_shmac(stream_enc.shmac.result)
                assert pt_enc == pt_dec, (
                    f"{i=} : plaintext_len={len(pt_enc)} : decrypted_plaintext_len={len(pt_dec)}"
                )

    async def test_async_cipher_decipher_streams_with_varied_data_sizes(
        self,
    ) -> None:
        for config, cipher, salt, aad in all_ciphers:
            for i in range(
                0, 512 - config.INNER_HEADER_BYTES - 1, randrange(1, 64)
            ):
                stream_enc = await cipher.astream_encrypt(
                    salt=salt, aad=aad
                )
                pt_enc = i * b"a"
                await stream_enc.abuffer(pt_enc)

                stream_dec = await cipher.astream_decrypt(
                    salt=stream_enc.salt,
                    aad=stream_enc.aad,
                    iv=stream_enc.iv,
                )
                for var in ("salt", "iv", "aad", "PACKETSIZE"):
                    assert getattr(stream_enc, var) == getattr(
                        stream_dec, var
                    )
                pt_dec = b""
                join = b"".join
                async for id_ct in stream_enc:
                    problem = (  # fmt: skip
                        "Invalid packet sizes were allowed."
                    )
                    with Ignore(ValueError, if_else=violation(problem)):
                        await stream_dec.abuffer(
                            join(id_ct)[: stream_dec.PACKETSIZE - 1]
                        )

                    await stream_dec.abuffer(join(id_ct))
                    async for pt in stream_dec:
                        pt_dec += pt
                async for id_ct in stream_enc.afinalize():
                    await stream_dec.abuffer(join(id_ct))
                async for pt in stream_dec.afinalize():
                    pt_dec += pt

                problem = (  # fmt: skip
                    "Processing was allowed to continue after finalization."
                )
                with Ignore(InterruptedError, if_else=violation(problem)):
                    await stream_enc.abuffer(pt_enc)
                with Ignore(InterruptedError, if_else=violation(problem)):
                    await stream_dec.abuffer(b"".join(id_ct))
                await stream_dec.shmac.atest_shmac(stream_enc.shmac.result)
                assert pt_enc == pt_dec, (
                    f"{i=} : plaintext_len={len(pt_enc)} : decrypted_plaintext_len={len(pt_dec)}"
                )

    async def test_async_encipher_sync_decipher_interop(self) -> None:
        for _, cipher, salt, aad in all_ciphers:
            stream_enc = await cipher.astream_encrypt(salt=salt, aad=aad)
            pt_enc = plaintext_bytes
            await stream_enc.abuffer(pt_enc)

            stream_dec = cipher.stream_decrypt(
                salt=stream_enc.salt, aad=stream_enc.aad, iv=stream_enc.iv
            )
            for var in ("salt", "iv", "aad", "PACKETSIZE"):
                assert getattr(stream_enc, var) == getattr(stream_dec, var)
            pt_dec = b""
            join = b"".join

            async for block_id, block in stream_enc:
                # the cipher can be resumed after the failure state of an
                # InvalidBlockID exception is recovered & the correct data
                # is supplied to the buffer
                problem = (  # fmt: skip
                    "An altered block_id was not detected."
                )
                fake_block_id = xi_mix(
                    block_id + b"\x01", size=len(block_id)
                )
                with Ignore(
                    InvalidBlockID, if_else=violation(problem)
                ) as relay:
                    stream_dec.buffer(fake_block_id + block)
                assert fake_block_id == relay.error.failure_state.block_id
                assert block == relay.error.failure_state.block
                assert 0 == len(relay.error.failure_state.buffer())

                problem = (  # fmt: skip
                    "An altered block was not detected."
                )
                fake_block = xi_mix(block + b"\x01", size=len(block))
                with Ignore(
                    InvalidBlockID, if_else=violation(problem)
                ) as relay:
                    stream_dec.buffer(block_id + fake_block)
                assert block_id == relay.error.failure_state.block_id
                assert fake_block == relay.error.failure_state.block
                assert 0 == len(relay.error.failure_state.buffer())

                # correct data is processed without failure
                stream_dec.buffer(block_id + block)
                for pt in stream_dec:
                    pt_dec += pt
            async for id_ct in stream_enc.afinalize():
                stream_dec.buffer(join(id_ct))
            for pt in stream_dec.finalize():
                pt_dec += pt
            await stream_dec.shmac.atest_shmac(stream_enc.shmac.result)
            assert pt_dec == pt_enc

    async def test_sync_encipher_async_decipher_interop(self) -> None:
        for _, cipher, salt, aad in all_ciphers:
            stream_enc = cipher.stream_encrypt(salt=salt, aad=aad)
            pt_enc = plaintext_bytes
            stream_enc.buffer(pt_enc)

            stream_dec = await cipher.astream_decrypt(
                salt=stream_enc.salt, aad=stream_enc.aad, iv=stream_enc.iv
            )
            for var in ("salt", "iv", "aad", "PACKETSIZE"):
                assert getattr(stream_enc, var) == getattr(stream_dec, var)
            pt_dec = b""
            join = b"".join

            for block_id, block in stream_enc:
                # the cipher can be resumed after the failure state of an
                # InvalidBlockID exception is recovered & the correct data
                # is supplied to the buffer
                problem = (  # fmt: skip
                    "An altered block_id was not detected."
                )
                fake_block_id = xi_mix(
                    block_id + b"\x01", size=len(block_id)
                )
                async with Ignore(
                    InvalidBlockID, if_else=violation(problem)
                ) as relay:
                    await stream_dec.abuffer(fake_block_id + block)
                assert fake_block_id == relay.error.failure_state.block_id
                assert block == relay.error.failure_state.block
                assert 0 == len(relay.error.failure_state.buffer())

                problem = (  # fmt: skip
                    "An altered block was not detected."
                )
                fake_block = xi_mix(block + b"\x01", size=len(block))
                async with Ignore(
                    InvalidBlockID, if_else=violation(problem)
                ) as relay:
                    await stream_dec.abuffer(block_id + fake_block)
                assert block_id == relay.error.failure_state.block_id
                assert fake_block == relay.error.failure_state.block
                assert 0 == len(relay.error.failure_state.buffer())

                # correct data is processed without failure
                await stream_dec.abuffer(block_id + block)
                async for pt in stream_dec:
                    pt_dec += pt

            for id_ct in stream_enc.finalize():
                await stream_dec.abuffer(join(id_ct))
            async for pt in stream_dec.afinalize():
                pt_dec += pt
            stream_dec.shmac.test_shmac(stream_enc.shmac.result)
            assert pt_dec == pt_enc

    async def test_data_type_must_be_bytes(self) -> None:
        problem = (  # fmt: skip
            "A non-bytes data type was allowed to be buffered."
        )
        for config, cipher, salt, _ in all_ciphers:
            for data in ("test", 0, None):
                with Ignore(TypeError, if_else=violation(problem)):
                    astream_enc = await cipher.astream_encrypt()
                    await astream_enc.abuffer(data)

                with Ignore(TypeError, if_else=violation(problem)):
                    stream_enc = cipher.stream_encrypt()
                    stream_enc.buffer(data)

                errors = (TypeError, ValueError)

                with Ignore(*errors, if_else=violation(problem)):
                    astream_dec = await cipher.astream_decrypt(
                        salt=salt, iv=csprng(config.IV_BYTES)
                    )
                    await astream_dec.abuffer(data)

                with Ignore(*errors, if_else=violation(problem)):
                    stream_dec = cipher.stream_decrypt(
                        salt=salt, iv=csprng(config.IV_BYTES)
                    )
                    stream_dec.buffer(data)

    async def test_async_buffer_concurrency_handling(self) -> None:
        config, cipher, salt, aad = choice(all_ciphers)
        chunk_size = 1024 * config.BLOCKSIZE
        data_a = (chunk_size * b"a")[config.INNER_HEADER_BYTES :]
        data_b = (chunk_size * b"b")[: -config.SENTINEL_BYTES]

        stream_enc = await cipher.astream_encrypt(salt=salt, aad=aad)
        fut_a = asynchs.new_task(stream_enc.abuffer(data_a))
        await asleep(0.00001)
        fut_b = asynchs.new_task(stream_enc.abuffer(data_b))
        await fut_a
        await fut_b
        ct = [b"".join(id_ct) async for id_ct in stream_enc.afinalize()]

        stream_dec = await cipher.astream_decrypt(
            salt=salt, aad=aad, iv=stream_enc.iv
        )
        ct_a = b"".join(ct[: len(ct) // 2])
        ct_b = b"".join(ct[len(ct) // 2 :])
        fut_a = asynchs.new_task(stream_dec.abuffer(ct_a))
        await asleep(0.00001)
        fut_b = asynchs.new_task(stream_dec.abuffer(ct_b))
        await fut_a
        await fut_b
        pt = b"".join([pt async for pt in stream_dec.afinalize()])

        assert data_a + data_b == pt

    async def test_sync_buffer_concurrency_handling(self) -> None:
        config, cipher, salt, aad = choice(all_ciphers)
        chunk_size = 16 * 1024 * config.BLOCKSIZE
        data_a = (chunk_size * b"a")[config.INNER_HEADER_BYTES :]
        data_b = (chunk_size * b"b")[: -config.SENTINEL_BYTES]

        stream_enc = cipher.stream_encrypt(salt=salt, aad=aad)
        fut_a = Threads.submit(stream_enc.buffer, data_a)
        asynchs.sleep(0.005)
        fut_b = Threads.submit(stream_enc.buffer, data_b)
        fut_a.result()
        fut_b.result()
        ct = [b"".join(id_ct) for id_ct in stream_enc.finalize()]

        stream_dec = cipher.stream_decrypt(
            salt=salt, aad=aad, iv=stream_enc.iv
        )
        ct_a = b"".join(ct[: len(ct) // 2])
        ct_b = b"".join(ct[len(ct) // 2 :])
        fut_a = Threads.submit(stream_dec.buffer, ct_a)
        asynchs.sleep(0.005)
        fut_b = Threads.submit(stream_dec.buffer, ct_b)
        fut_a.result()
        fut_b.result()
        pt = b"".join(stream_dec.finalize())

        assert data_a + data_b == pt

    async def test_async_finalize_concurrency_handling(self) -> None:
        config, cipher, salt, aad = choice(all_ciphers)
        chunk_size = 1024 * config.BLOCKSIZE
        data = chunk_size * b"a"

        stream_enc = await cipher.astream_encrypt(salt=salt, aad=aad)
        await stream_enc.abuffer(data)
        finalizing = stream_enc.afinalize()
        ct = b"".join(await finalizing.asend(None))

        problem = (  # fmt: skip
            "Multiple calls to afinalize were allowed."
        )
        with Ignore(
            ConcurrencyGuard.IncoherentConcurrencyState,
            if_else=violation(problem),
        ):
            async for _ in stream_enc.afinalize():
                pytest.fail(problem)

        ct += b"".join([b"".join(id_ct) async for id_ct in finalizing])

        stream_dec = await cipher.astream_decrypt(
            salt=salt, aad=aad, iv=stream_enc.iv
        )
        await stream_dec.abuffer(ct)
        finalizing = stream_dec.afinalize()
        pt = await finalizing.asend(None)

        problem = (  # fmt: skip
            "Multiple calls to afinalize were allowed."
        )
        with Ignore(
            ConcurrencyGuard.IncoherentConcurrencyState,
            if_else=violation(problem),
        ):
            async for _ in stream_dec.afinalize():
                pytest.fail(problem)

        pt += b"".join([pt async for pt in finalizing])
        assert data == pt

    async def test_sync_finalize_concurrency_handling(self) -> None:
        config, cipher, salt, aad = choice(all_ciphers)
        chunk_size = 1024 * config.BLOCKSIZE
        data = chunk_size * b"a"

        stream_enc = cipher.stream_encrypt(salt=salt, aad=aad).buffer(data)
        finalizing = stream_enc.finalize()
        ct = b"".join(finalizing.send(None))

        problem = (  # fmt: skip
            "Multiple calls to finalize were allowed."
        )
        with Ignore(
            ConcurrencyGuard.IncoherentConcurrencyState,
            if_else=violation(problem),
        ):
            for _ in stream_enc.finalize():
                pytest.fail(problem)

        ct += b"".join(b"".join(id_ct) for id_ct in finalizing)

        stream_dec = cipher.stream_decrypt(
            salt=salt, aad=aad, iv=stream_enc.iv
        ).buffer(ct)
        finalizing = stream_dec.finalize()
        pt = finalizing.send(None)

        problem = (  # fmt: skip
            "Multiple calls to finalize were allowed."
        )
        with Ignore(
            ConcurrencyGuard.IncoherentConcurrencyState,
            if_else=violation(problem),
        ):
            for _ in stream_dec.finalize():
                pytest.fail(problem)

        pt += b"".join(finalizing)
        assert data == pt


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
