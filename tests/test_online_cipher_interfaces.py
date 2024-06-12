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


from random import randrange

from test_initialization import *


class TestOnlineCipherInterfaces:

    async def test_sync_cipher_decipher_streams_with_varied_data_sizes(
        self
    ) -> None:
        for (config, cipher, salt, aad) in all_ciphers:
            for i in range(0, 512 - config.INNER_HEADER_BYTES - 1, randrange(1, 64)):
                stream_enc = cipher.stream_encrypt(salt=salt, aad=aad)
                pt_enc = i * b"a"
                stream_enc.buffer(pt_enc)

                stream_dec = cipher.stream_decrypt(
                    salt=stream_enc.salt, aad=stream_enc.aad, iv=stream_enc.iv
                )
                for var in ("salt", "iv", "aad", "PACKETSIZE"):
                    assert getattr(stream_enc, var) == getattr(stream_dec, var)
                pt_dec = b""
                join = b"".join
                for id_ct in stream_enc:
                    problem = (
                        "Invalid packet sizes were allowed."
                    )
                    with Ignore(ValueError, if_else=violation(problem)):
                        stream_dec.buffer(join(id_ct)[:stream_dec.PACKETSIZE - 1])

                    stream_dec.buffer(join(id_ct))
                    for pt in stream_dec:
                        pt_dec += pt
                for id_ct in stream_enc.finalize():
                    stream_dec.buffer(join(id_ct))
                for pt in stream_dec.finalize():
                    pt_dec += pt

                problem = (
                    "Processing was allowed to continue after finalization."
                )
                with Ignore(InterruptedError, if_else=violation(problem)):
                    stream_enc.buffer(pt_enc)
                with Ignore(InterruptedError, if_else=violation(problem)):
                    stream_dec.buffer(id_ct[1])
                assert pt_enc == pt_dec, f"{i=} : plaintext_len={len(pt_enc)} : decrypted_plaintext_len={len(pt_dec)}"

    async def test_async_cipher_decipher_streams_with_varied_data_sizes(
        self
    ) -> None:
        for (config, cipher, salt, aad) in all_ciphers:
            for i in range(0, 512 - config.INNER_HEADER_BYTES - 1, randrange(1, 64)):
                stream_enc = await cipher.astream_encrypt(salt=salt, aad=aad)
                pt_enc = i * b"a"
                await stream_enc.abuffer(pt_enc)

                stream_dec = await cipher.astream_decrypt(
                    salt=stream_enc.salt, aad=stream_enc.aad, iv=stream_enc.iv
                )
                for var in ("salt", "iv", "aad", "PACKETSIZE"):
                    assert getattr(stream_enc, var) == getattr(stream_dec, var)
                pt_dec = b""
                join = b"".join
                async for id_ct in stream_enc:
                    problem = (
                        "Invalid packet sizes were allowed."
                    )
                    with Ignore(ValueError, if_else=violation(problem)):
                        await stream_dec.abuffer(join(id_ct)[:stream_dec.PACKETSIZE - 1])

                    await stream_dec.abuffer(join(id_ct))
                    async for pt in stream_dec:
                        pt_dec += pt
                async for id_ct in stream_enc.afinalize():
                    await stream_dec.abuffer(join(id_ct))
                async for pt in stream_dec.afinalize():
                    pt_dec += pt

                problem = (
                    "Processing was allowed to continue after finalization."
                )
                with Ignore(InterruptedError, if_else=violation(problem)):
                    await stream_enc.abuffer(pt_enc)
                with Ignore(InterruptedError, if_else=violation(problem)):
                    await stream_dec.abuffer(id_ct[1])
                assert pt_enc == pt_dec, f"{i=} : plaintext_len={len(pt_enc)} : decrypted_plaintext_len={len(pt_dec)}"

    async def test_async_encipher_sync_decipher_interop(
        self
    ) -> None:
        for (config, cipher, salt, aad) in all_ciphers:
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
                problem = (
                    "An altered block_id was not detected."
                )
                fake_block_id = xi_mix(block_id + b"\x01", size=len(block_id))
                with Ignore(InvalidBlockID, if_else=violation(problem)) as relay:
                    stream_dec.buffer(fake_block_id + block)
                assert fake_block_id == relay.error.failure_state.block_id
                assert block == relay.error.failure_state.block
                assert 0 == len(relay.error.failure_state.buffer())

                problem = (
                    "An altered block was not detected."
                )
                fake_block = xi_mix(block + b"\x01", size=len(block))
                with Ignore(InvalidBlockID, if_else=violation(problem)) as relay:
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
            assert pt_dec == pt_enc

    async def test_sync_encipher_async_decipher_interop(
        self
    ) -> None:
        for (config, cipher, salt, aad) in all_ciphers:
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
                problem = (
                    "An altered block_id was not detected."
                )
                fake_block_id = xi_mix(block_id + b"\x01", size=len(block_id))
                async with Ignore(InvalidBlockID, if_else=violation(problem)) as relay:
                    await stream_dec.abuffer(fake_block_id + block)
                assert fake_block_id == relay.error.failure_state.block_id
                assert block == relay.error.failure_state.block
                assert 0 == len(relay.error.failure_state.buffer())

                problem = (
                    "An altered block was not detected."
                )
                fake_block = xi_mix(block + b"\x01", size=len(block))
                async with Ignore(InvalidBlockID, if_else=violation(problem)) as relay:
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
            assert pt_dec == pt_enc


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

