# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


async def test_detection_of_ciphertext_modification():
    aciphertext = Ciphertext(await cipher.abytes_encrypt(plaintext_bytes))

    ######
    ###### ciphertext container packs async ciphertexts correctly
    act = b"".join(aciphertext.values())
    assert all(aciphertext.values())
    assert act == b"".join(
        [aciphertext.shmac, aciphertext.salt, aciphertext.iv, aciphertext.ciphertext]
    )

    # async ciphertext doesn't obviously contain plaintext
    for chunk in gentools.data.root(plaintext_bytes, size=10):
        assert chunk not in act
    byte_leakage not in act

    # async decryption of correct data doesn't fail
    assert plaintext_bytes == await cipher.abytes_decrypt(act)

    # sync decryption of async ciphertext doesn't fail
    assert plaintext_bytes == cipher.bytes_decrypt(act)

    ######
    ###### async decryption of altered ciphertext fails
    aict = int.from_bytes(act, BIG)
    context = "Async ciphertext alteration not caught!"
    for abit in range(0, aict.bit_length(), 16):
        with ignore(StreamHMAC.InvalidSHMAC, if_else=violation(context)):
            altered_act = (aict ^ (1 << abit)).to_bytes(len(act), BIG)
            await cipher.abytes_decrypt(altered_act)

    # async decryption of ciphertext lengthened to invalid size fails
    context = "Invalid size lengthened sync ciphertext allowed"
    for extra_bytes in range(1, BLOCKSIZE):
        with ignore(ValueError, if_else=violation(context)):
            await cipher.abytes_decrypt(act + token_bytes(extra_bytes))

    # sync decryption of ciphertext shortened to invalid size fails
    context = "Invalid size shortened sync ciphertext allowed"
    for fewer_bytes in range(1, BLOCKSIZE):
        with ignore(ValueError, if_else=violation(context)):
            await cipher.abytes_decrypt(act[:-fewer_bytes])

    ######
    ###### test the ciphertext container class
    ciphertext = Ciphertext(cipher.bytes_encrypt(plaintext_bytes))

    # ciphertext container packs sync ciphertexts correctly
    ct = b"".join(ciphertext.values())
    assert all(ciphertext.values())
    assert ct == b"".join(
        [ciphertext.shmac, ciphertext.salt, ciphertext.iv, ciphertext.ciphertext]
    )

    # sync ciphertext doesn't obviously contain plaintext
    for chunk in gentools.data.root(plaintext_bytes, size=10):
        assert chunk not in ct
    byte_leakage not in ct

    # sync decryption of correct data doesn't fail
    assert plaintext_bytes == cipher.bytes_decrypt(ct)

    # async decryption of sync ciphertext doesn't fail
    assert plaintext_bytes == await cipher.abytes_decrypt(ct)

    ######
    ###### sync decryption of altered ciphertext fails
    ict = int.from_bytes(ct, BIG)
    context = "Sync ciphertext alteration not caught!"
    for bit in range(0, ict.bit_length(), 16):
        with ignore(StreamHMAC.InvalidSHMAC, if_else=violation(context)):
            altered_ct = (ict ^ (1 << bit)).to_bytes(len(ct), BIG)
            cipher.bytes_decrypt(altered_ct)

    # sync decryption of ciphertext lengthened to invalid size fails
    context = "Invalid size lengthened sync ciphertext allowed"
    for extra_bytes in range(1, BLOCKSIZE):
        with ignore(ValueError, if_else=violation(context)):
            cipher.bytes_decrypt(ct + token_bytes(extra_bytes))

    # sync decryption of ciphertext shortened to invalid size fails
    context = "Invalid size shortened sync ciphertext allowed"
    for fewer_bytes in range(1, BLOCKSIZE):
        with ignore(ValueError, if_else=violation(context)):
            cipher.bytes_decrypt(ct[:-fewer_bytes])


async def aciphertext_stream():
    key_bundle = await KeyAADBundle(key, aad=aad).async_mode()
    shmac = StreamHMAC(key_bundle)._for_encryption()
    datastream = aplaintext_stream(plaintext_bytes)
    cipherstream = abytes_encipher(datastream, shmac=shmac)

    first_ciphertext_block = await cipherstream.asend(None)
    yield key_bundle.salt, key_bundle.iv
    yield (
        await shmac.anext_block_id(first_ciphertext_block),
        first_ciphertext_block,
    )
    async for ciphertext_block in cipherstream:
        yield (
            await shmac.anext_block_id(ciphertext_block),
            ciphertext_block,
        )


def ciphertext_stream():
    key_bundle = KeyAADBundle(key, aad=aad).sync_mode()
    shmac = enc_hmac = StreamHMAC(key_bundle)._for_encryption()
    datastream = plaintext_stream(plaintext_bytes)
    cipherstream = bytes_encipher(datastream, shmac=shmac)

    first_ciphertext_block = cipherstream.send(None)
    yield key_bundle.salt, key_bundle.iv
    yield (
        shmac.next_block_id(first_ciphertext_block),
        first_ciphertext_block,
    )
    for ciphertext_block in cipherstream:
        yield (
            shmac.next_block_id(ciphertext_block),
            ciphertext_block,
        )


async def test_async_block_ids_during_deciphering():
    cipherstream = aciphertext_stream()
    salt, iv = await cipherstream.asend(None)
    key_bundle = await KeyAADBundle(key, salt=salt, aad=aad, iv=iv).async_mode()
    shmac = StreamHMAC(key_bundle)._for_decryption()

    ciphertext = []
    deciphering = abytes_decipher(aunpack(ciphertext), shmac=shmac)

    padded_plaintext = b""
    async for block_id, ciphertext_block in cipherstream:
        await shmac.atest_next_block_id(block_id, ciphertext_block)
        ciphertext.append(ciphertext_block)
        padded_plaintext += await deciphering.asend(None)

        # altering the block_id fails
        context = "Block id was modified without notice!"
        with ignore(StreamHMAC.InvalidBlockID, if_else=violation(context)):
            fake_block_id = await axi_mix(block_id + b"\x01", size=BLOCK_ID_BYTES)
            await shmac.atest_next_block_id(fake_block_id, ciphertext_block)

        # a block_id that is too short fails
        context = "An insufficient size block id was allowed!"
        with ignore(PermissionError, if_else=violation(context)):
            truncated_block_id = block_id[:MIN_BLOCK_ID_BYTES - 1]
            await shmac.atest_next_block_id(truncated_block_id, ciphertext_block)

        # alterting the ciphertext_block fails
        context = "Block was modified without notice!"
        with ignore(StreamHMAC.InvalidBlockID, if_else=violation(context)):
            fake_block = await axi_mix(ciphertext_block + b"\x01", size=BLOCKSIZE)
            await shmac.atest_next_block_id(block_id, fake_block)

    assert plaintext_bytes == await Padding.adepad_plaintext(
        padded_plaintext
    )

    context = "MAC object accessible after finalization!"
    tag = await shmac.afinalize()
    await shmac.atest_shmac(tag)
    with ignore(PermissionError, if_else=violation(context)):
        shmac._mac.digest()


def test_sync_block_ids_during_deciphering():
    stream = ciphertext_stream()
    salt, iv = stream.send(None)
    key_bundle = KeyAADBundle(key, salt=salt, aad=aad, iv=iv).sync_mode()
    shmac = StreamHMAC(key_bundle)._for_decryption()

    ciphertext = []
    deciphering = bytes_decipher(unpack(ciphertext), shmac=shmac)

    padded_plaintext = b""
    for block_id, ciphertext_block in stream:
        shmac.test_next_block_id(block_id, ciphertext_block)
        ciphertext.append(ciphertext_block)
        padded_plaintext += deciphering.send(None)

        # altering the block_id fails
        context = "Block id was modified without notice!"
        with ignore(StreamHMAC.InvalidBlockID, if_else=violation(context)):
            fake_block_id = xi_mix(block_id + b"\x01", size=BLOCK_ID_BYTES)
            shmac.test_next_block_id(fake_block_id, ciphertext_block)

        # a block_id that is too short fails
        context = "An insufficient size block id was allowed!"
        with ignore(PermissionError, if_else=violation(context)):
            truncated_block_id = block_id[:MIN_BLOCK_ID_BYTES - 1]
            shmac.test_next_block_id(truncated_block_id, ciphertext_block)

        # alterting the ciphertext_block fails
        context = "Block was modified without notice!"
        with ignore(StreamHMAC.InvalidBlockID, if_else=violation(context)):
            fake_block = xi_mix(ciphertext_block + b"\x01", size=BLOCKSIZE)
            shmac.test_next_block_id(block_id, fake_block)

    assert plaintext_bytes == Padding.depad_plaintext(padded_plaintext)

    context = "MAC object accessible after finalization!"
    tag = shmac.finalize()
    shmac.test_shmac(tag)
    with ignore(PermissionError, if_else=violation(context)):
        shmac._mac.digest()


def test_sync_cipher_decipher_streams():
    # buffering protocol works for varying sizes
    for i in range(0, 512 - INNER_HEADER_BYTES - 1, unique_range(1, 64)):
        stream_enc = CipherStream(key)
        pt_enc = i * b"a"
        stream_enc.buffer(pt_enc)

        stream_dec = DecipherStream(
            key, salt=stream_enc.salt, aad=stream_enc.aad, iv=stream_enc.iv
        )
        for var in ("salt", "iv", "aad", "PACKETSIZE"):
            assert getattr(stream_enc, var) == getattr(stream_dec, var)
        pt_dec = b""
        join = b"".join
        for id_ct in stream_enc:
            stream_dec.buffer(join(id_ct))
            for pt in stream_dec:
                pt_dec += pt
        for id_ct in stream_enc.finalize():
            stream_dec.buffer(join(id_ct))
        for pt in stream_dec.finalize():
            pt_dec += pt
        assert pt_dec == pt_enc


async def test_async_cipher_decipher_streams():
    # buffering protocol works for varying sizes
    for i in range(0, 512 - INNER_HEADER_BYTES - 1, unique_range(1, 64)):
        stream_enc = await AsyncCipherStream(key, salt=salt, aad=aad)
        pt_enc = i * b"a"
        await stream_enc.abuffer(pt_enc)

        stream_dec = await AsyncDecipherStream(
            key, salt=stream_enc.salt, aad=stream_enc.aad, iv=stream_enc.iv
        )
        for var in ("salt", "iv", "aad", "PACKETSIZE"):
            assert getattr(stream_enc, var) == getattr(stream_dec, var)
        pt_dec = b""
        join = b"".join
        async for id_ct in stream_enc:
            await stream_dec.abuffer(join(id_ct))
            async for pt in stream_dec:
                pt_dec += pt
        async for id_ct in stream_enc.afinalize():
            await stream_dec.abuffer(join(id_ct))
        async for pt in stream_dec.afinalize():
            pt_dec += pt
        assert pt_dec == pt_enc


async def test_async_encipher_sync_decipher_interop():
    # inter-op between async encryption & sync decryption doesn't fail
    stream_enc = await AsyncCipherStream(key, salt=salt, aad=aad)
    pt_enc = plaintext_bytes
    await stream_enc.abuffer(pt_enc)

    stream_dec = DecipherStream(
        key, salt=stream_enc.salt, aad=stream_enc.aad, iv=stream_enc.iv
    )
    for var in ("salt", "iv", "aad", "PACKETSIZE"):
        assert getattr(stream_enc, var) == getattr(stream_dec, var)
    pt_dec = b""
    join = b"".join

    async for block_id, block in stream_enc:
        # the cipher can be resumed after the failure state of an
        # InvalidBlockID exception is recovered & the correct data
        # is supplied to the buffer
        context = "An altered block_id was not detected"
        fake_block_id = xi_mix(block_id + b"\x01", size=len(block_id))
        with ignore(InvalidBlockID, if_else=violation(context)) as relay:
            stream_dec.buffer(fake_block_id + block)
        assert fake_block_id == relay.error.failure_state.block_id
        assert block == relay.error.failure_state.block
        assert 0 == len(relay.error.failure_state.buffer())

        context = "An altered block was not detected"
        fake_block = xi_mix(block + b"\x01", size=len(block))
        with ignore(InvalidBlockID, if_else=violation(context)) as relay:
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


async def test_sync_encipher_async_decipher_interop():
    # inter-op between sync encryption & async decryption doesn't fail
    stream_enc = CipherStream(key)
    pt_enc = plaintext_bytes
    stream_enc.buffer(pt_enc)

    stream_dec = await AsyncDecipherStream(
        key, salt=stream_enc.salt, aad=stream_enc.aad, iv=stream_enc.iv
    )
    for var in ("salt", "iv", "aad", "PACKETSIZE"):
        assert getattr(stream_enc, var) == getattr(stream_dec, var)
    pt_dec = b""
    join = b"".join

    for block_id, block in stream_enc:
        # the cipher can be resumed after the failure state of an
        # InvalidBlockID exception is recovered & the correct data
        # is supplied to the buffer
        context = "An altered block_id was not detected"
        fake_block_id = xi_mix(block_id + b"\x01", size=len(block_id))
        async with aignore(InvalidBlockID, if_else=aviolation(context)) as relay:
            await stream_dec.abuffer(fake_block_id + block)
        assert fake_block_id == relay.error.failure_state.block_id
        assert block == relay.error.failure_state.block
        assert 0 == len(relay.error.failure_state.buffer())

        context = "An altered block was not detected"
        fake_block = xi_mix(block + b"\x01", size=len(block))
        async with aignore(InvalidBlockID, if_else=aviolation(context)) as relay:
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

