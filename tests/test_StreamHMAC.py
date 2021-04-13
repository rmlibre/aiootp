# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from init_tests import *


__all__ = [
    "test_detection_of_ciphertext_modification",
    "test_incomplete_validation",
    "test_block_id",
    "__all__",
]


def test_detection_of_ciphertext_modification():
    CT = CIPHERTEXT
    a_hex = lambda: randoms.choice("0123456789abcdef")
    a_number = lambda: randoms.random_range(1, bits[128])

    aciphertext = run(pad.abytes_encrypt(plaintext_bytes))
    act = [CT, aciphertext[CT][:1], aciphertext[SALT], aciphertext[HMAC]]
    _act = aciphertext[CT]
    _ahmac = aciphertext[HMAC]
    _asalt = aciphertext[SALT]
    _asiv = aciphertext[SIV]
    ciphertext = pad.bytes_encrypt(plaintext_bytes)
    ct = [CT, ciphertext[CT][:1], ciphertext[SALT], ciphertext[HMAC]]
    _ct = ciphertext[CT]
    _hmac = ciphertext[HMAC]
    _salt = ciphertext[SALT]
    _siv = ciphertext[SIV]

    amodified_ciphertexts = dict(
        amodified_ciphertext_0={CT: [], HMAC: _ahmac, SALT: _asalt, SIV: _asiv},
        amodified_ciphertext_1={CT: [_act[0] ^ a_number(), *_act[1:]], HMAC: _ahmac, SALT: _asalt, SIV: _asiv},
        amodified_ciphertext_2={CT: [_act[0] ^ 0b1, *_act[1:]], HMAC: _ahmac, SALT: _asalt, SIV: _asiv},
        amodified_ciphertext_3={CT: [_act[0] + bits[2048], *_act[1:]], HMAC: _ahmac, SALT: _asalt, SIV: _asiv},
        amodified_ciphertext_4={CT: _act, HMAC: "", SALT: _asalt, SIV: _asiv},
        amodified_ciphertext_5={CT: _act, HMAC: hex(int(_ahmac, 16) ^ a_number())[2:], SALT: _asalt, SIV: _asiv},
        amodified_ciphertext_6={CT: _act, HMAC: hex(int(_ahmac, 16) ^ 0b1)[2:], SALT: _asalt, SIV: _asiv},
        amodified_ciphertext_7={CT: _act, HMAC: _ahmac + a_hex(), SALT: _asalt, SIV: _asiv},
        amodified_ciphertext_8={CT: _act, HMAC: _ahmac[:-2], SALT: _asalt, SIV: _asiv},
        amodified_ciphertext_9={CT: _act, HMAC: _ahmac, SALT: "", SIV: _asiv},
        amodified_ciphertext_10={CT: _act, HMAC: _ahmac, SALT: hex(int(_asalt, 16) ^ a_number())[2:], SIV: _asiv},
        amodified_ciphertext_11={CT: _act, HMAC: _ahmac, SALT: hex(int(_asalt, 16) ^ 0b1)[2:], SIV: _asiv},
        amodified_ciphertext_12={CT: _act, HMAC: _ahmac, SALT: _asalt + a_hex(), SIV: _asiv},
        amodified_ciphertext_13={CT: _act, HMAC: _ahmac, SALT: _asalt[:-2], SIV: _asiv},
        amodified_ciphertext_14={CT: _act, HMAC: _ahmac, SALT: _asalt, SIV: ""},
        amodified_ciphertext_15={CT: _act, HMAC: _ahmac, SALT: _asalt, SIV: hex(int(_asiv, 16) ^ a_number())[2:]},
        amodified_ciphertext_16={CT: _act, HMAC: _ahmac, SALT: _asalt, SIV: hex(int(_asiv, 16) ^ 0b1)[2:]},
        amodified_ciphertext_17={CT: _act, HMAC: _ahmac, SALT: _asalt, SIV: _asiv + a_hex()},
        amodified_ciphertext_18={CT: _act, HMAC: _ahmac, SALT: _asalt, SIV: _asiv[:-2]},

    )
    modified_ciphertexts = dict(
        modified_ciphertext_0={CT: [], HMAC: _hmac, SALT: _salt, SIV: _siv},
        modified_ciphertext_1={CT: [_ct[0] ^ a_number(), *_ct[1:]], HMAC: _hmac, SALT: _salt, SIV: _siv},
        modified_ciphertext_2={CT: [_ct[0] ^ 0b1, *_ct[1:]], HMAC: _hmac, SALT: _salt, SIV: _siv},
        modified_ciphertext_3={CT: [_ct[0] + bits[2048], *_ct[1:]], HMAC: _hmac, SALT: _salt, SIV: _siv},
        modified_ciphertext_4={CT: _ct, HMAC: "", SALT: _salt, SIV: _siv},
        modified_ciphertext_5={CT: _ct, HMAC: hex(int(_hmac, 16) ^ a_number())[2:], SALT: _salt, SIV: _siv},
        modified_ciphertext_6={CT: _ct, HMAC: hex(int(_hmac, 16) ^ 0b1)[2:], SALT: _salt, SIV: _siv},
        modified_ciphertext_7={CT: _ct, HMAC: _hmac + a_hex(), SALT: _salt, SIV: _siv},
        modified_ciphertext_8={CT: _ct, HMAC: _hmac[:-2], SALT: _salt, SIV: _siv},
        modified_ciphertext_9={CT: _ct, HMAC: _hmac, SALT: "", SIV: _siv},
        modified_ciphertext_10={CT: _ct, HMAC: _hmac, SALT: hex(int(_salt, 16) ^ a_number())[2:], SIV: _siv},
        modified_ciphertext_11={CT: _ct, HMAC: _hmac, SALT: hex(int(_salt, 16) ^ 0b1)[2:], SIV: _siv},
        modified_ciphertext_12={CT: _ct, HMAC: _hmac, SALT: _salt + a_hex(), SIV: _siv},
        modified_ciphertext_13={CT: _ct, HMAC: _hmac, SALT: _salt[:-2], SIV: _siv},
        modified_ciphertext_14={CT: _ct, HMAC: _hmac, SALT: _salt, SIV: ""},
        modified_ciphertext_15={CT: _ct, HMAC: _hmac, SALT: _salt, SIV: hex(int(_siv, 16) ^ a_number())[2:]},
        modified_ciphertext_16={CT: _ct, HMAC: _hmac, SALT: _salt, SIV: hex(int(_siv, 16) ^ 0b1)[2:]},
        modified_ciphertext_17={CT: _ct, HMAC: _hmac, SALT: _salt, SIV: _siv + a_hex()},
        modified_ciphertext_18={CT: _ct, HMAC: _hmac, SALT: _salt, SIV: _siv[:-2]},
    )
    for name, modified_ciphertext in amodified_ciphertexts.items():
        try:
            mct = [name, modified_ciphertext[CT][:1], modified_ciphertext[SALT], modified_ciphertext[HMAC]]
            pt = run(pad.abytes_decrypt(modified_ciphertext))
        except (ValueError, OverflowError):
            pass
        except Exception as err:
            e = (err, mct, act)
            assert err.__class__ == PermissionError, ("An unexpected error!", e)
        else:
            e = (pt, mct, act)
            raise AssertionError("Modification was not detected!", e)
    for name, modified_ciphertext in modified_ciphertexts.items():
        try:
            mct = [name, modified_ciphertext[CT][:1], modified_ciphertext[SALT], modified_ciphertext[HMAC]]
            pt = pad.bytes_decrypt(modified_ciphertext)
        except (ValueError, OverflowError):
            pass
        except Exception as err:
            e = (err, mct, ct)
            assert err.__class__ == PermissionError, ("An unexpected error!", e)
        else:
            e = (pt, mct, ct)
            raise AssertionError("Modification was not detected!", e)


def test_incomplete_validation():
    hmac_0 = pad.StreamHMAC(salt=salt).for_encryption()
    hmac_1 = pad.StreamHMAC(salt=salt, pid=pid).for_encryption()
    hmac_2 = pad.StreamHMAC(key=csprng(), salt=salt).for_encryption()
    hmacs = [hmac_0, hmac_1, hmac_2]

    digests = []
    adigests = []
    for hmac in hmacs:
        hmac.update(plaintext_bytes)
        run(hmac.aupdate(plaintext_bytes))
        digests.append(hmac.current_digest())
        adigests.append(run(hmac.acurrent_digest()))

    for i, hmac in enumerate(hmacs):
        hmac.test_current_digest(digests[i])
        run(hmac.atest_current_digest(adigests[i]))

        next_index = (i + 1) % len(hmacs)
        try:
            hmac.test_current_digest(digests[next_index])
        except ValueError:
            pass
        else:
            raise AssertionError("Validators don't detect invalid HMACs.")

        try:
            run(hmac.atest_current_digest(adigests[next_index]))
        except ValueError:
            pass
        else:
            raise AssertionError("Validators don't detect invalid HMACs.")


def test_block_id():

    async def aciphertext_stream():
        # Usage Example (Encryption):
        global aenc_hmac
        global adigest

        hmac = aenc_hmac = pad.StreamHMAC(salt=salt, pid=pid).for_encryption()
        adigest = hmac._mac.digest()
        datastream = pad.aplaintext_stream(plaintext_bytes, salt=salt, pid=pid)
        cipherstream = datastream.abytes_encipher(key, salt=salt, pid=pid, validator=hmac)

        first_block = await cipherstream()
        yield salt, hmac.siv
        yield first_block, await hmac.anext_block_id(first_block.to_bytes(256, "big"))
        while True:
            block = await cipherstream()
            yield block, await hmac.anext_block_id(block.to_bytes(256, "big"))

    def ciphertext_stream():
        # Usage Example (Encryption):
        global enc_hmac
        global digest

        hmac = enc_hmac = pad.StreamHMAC(salt=salt, pid=pid).for_encryption()
        digest = hmac._mac.digest()
        datastream = pad.plaintext_stream(plaintext_bytes, salt=salt, pid=pid)
        cipherstream = datastream.bytes_encipher(key, salt=salt, pid=pid, validator=hmac)

        first_block = cipherstream()
        yield salt, hmac.siv
        yield first_block, hmac.next_block_id(first_block.to_bytes(256, "big"))
        while True:
            try:
                block = cipherstream()
            except StopIteration:
                break
            yield block, hmac.next_block_id(block.to_bytes(256, "big"))


    # Usage Example (Decryption):

    stream = ciphertext_stream()
    salt_, siv = stream.send(None)
    hmac = pad.StreamHMAC(salt=salt_, pid=pid, siv=siv).for_decryption()

    ciphertext = []
    deciphering = unpack(ciphertext).bytes_decipher(key, salt=salt_, pid=pid, validator=hmac)

    padded_plaintext = b""
    for block, block_id in stream:
        hmac.test_next_block_id(block_id, block.to_bytes(256, "big"))

        try:
            hmac.test_next_block_id(block_id[:-1], block.to_bytes(256, "big"))
        except ValueError:
            pass
        else:
            raise AssertionError("Block id was modified without notice!")
        try:
            hmac.test_next_block_id(block_id, block.to_bytes(256, "big")[:-1])
        except ValueError:
            pass
        else:
            raise AssertionError("Block was modified without notice!")

        ciphertext.append(block)
        padded_plaintext += deciphering()

    assert plaintext_bytes == pad.io.depad_plaintext(
        padded_plaintext,
        padding_key=pad.padding_key(salt=salt_, pid=pid),
    )


    # Async Usage Example (Decryption):
    stream = aciphertext_stream()
    salt_, siv = run(stream.asend(None))
    hmac = pad.StreamHMAC(salt=salt_, pid=pid, siv=siv).for_decryption()

    ciphertext = []
    deciphering = aunpack(ciphertext).abytes_decipher(key, salt=salt_, pid=pid, validator=hmac)

    padded_plaintext = b""
    while True:
        try:
            block, block_id = run(stream.asend(None))
        except (StopAsyncIteration, RuntimeError):
            break
        run(hmac.atest_next_block_id(block_id, block.to_bytes(256, "big")))

        try:
            run(hmac.atest_next_block_id(block_id[:-1], block.to_bytes(256, "big")))
        except ValueError:
            pass
        else:
            raise AssertionError("Block id was modified without notice!")
        try:
            run(hmac.atest_next_block_id(block_id, block.to_bytes(256, "big")[:-1]))
        except ValueError:
            pass
        else:
            raise AssertionError("Block was modified without notice!")

        ciphertext.append(block)
        padded_plaintext += run(deciphering())

    assert plaintext_bytes == pad.io.depad_plaintext(
        padded_plaintext,
        padding_key=pad.padding_key(salt=salt_, pid=pid),
    )

