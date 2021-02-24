# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from init_tests import *


__all__ = [
    "test_detection_of_ciphertext_modification",
    "test_incomplete_validation",
    "__all__",
]


def test_detection_of_ciphertext_modification():
    HMAC = commons.HMAC
    SALT = commons.SALT
    CT = commons.CIPHERTEXT
    a_hex = lambda: randoms.choice("0123456789abcdef")
    a_number = lambda: randoms.random_range(1, bits[256])

    aciphertext = run(pad.abytes_encrypt(plaintext_bytes))
    _act = aciphertext["ciphertext"]
    _ahmac = aciphertext["hmac"]
    _asalt = aciphertext["salt"]
    ciphertext = pad.bytes_encrypt(plaintext_bytes)
    _ct = ciphertext["ciphertext"]
    _hmac = ciphertext["hmac"]
    _salt = ciphertext["salt"]

    amodified_ciphertexts = dict(
        amodified_ciphertext_0={CT: [], HMAC: _ahmac, SALT: _asalt},
        amodified_ciphertext_1={CT: [_act[0] ^ a_number(), *_act[1:]], HMAC: _ahmac, SALT: _asalt},
        amodified_ciphertext_2={CT: [_act[0] ^ 0b1, *_act[1:]], HMAC: _ahmac, SALT: _asalt},
        amodified_ciphertext_3={CT: [_act[0] + bits[2049], *_act[1:]], HMAC: _ahmac, SALT: _asalt},
        amodified_ciphertext_4={CT: _act, HMAC: "", SALT: _asalt},
        amodified_ciphertext_5={CT: _act, HMAC: hex(int(_ahmac, 16) ^ a_number())[2:], SALT: _asalt},
        amodified_ciphertext_6={CT: _act, HMAC: hex(int(_ahmac, 16) ^ 0b1)[2:], SALT: _asalt},
        amodified_ciphertext_7={CT: _act, HMAC: _ahmac + a_hex(), SALT: _asalt},
        amodified_ciphertext_8={CT: _act, HMAC: _ahmac, SALT: ""},
        amodified_ciphertext_9={CT: _act, HMAC: _ahmac, SALT: hex(int(_asalt, 16) ^ a_number())[2:]},
        amodified_ciphertext_10={CT: _act, HMAC: _ahmac, SALT: hex(int(_asalt, 16) ^ 0b1)[2:]},
        amodified_ciphertext_11={CT: _act, HMAC: _ahmac, SALT: _asalt + a_hex()},
    )
    modified_ciphertexts = dict(
        modified_ciphertext_0={CT: [], HMAC: _hmac, SALT: _salt},
        modified_ciphertext_1={CT: [_ct[0] ^ a_number(), *_ct[1:]], HMAC: _hmac, SALT: _salt},
        modified_ciphertext_2={CT: [_ct[0] ^ 0b1, *_ct[1:]], HMAC: _hmac, SALT: _salt},
        modified_ciphertext_3={CT: [_ct[0] + bits[2049], *_ct[1:]], HMAC: _hmac, SALT: _salt},
        modified_ciphertext_4={CT: _ct, HMAC: "", SALT: _salt},
        modified_ciphertext_5={CT: _ct, HMAC: hex(int(_hmac, 16) ^ a_number())[2:], SALT: _salt},
        modified_ciphertext_6={CT: _ct, HMAC: hex(int(_hmac, 16) ^ 0b1)[2:], SALT: _salt},
        modified_ciphertext_7={CT: _ct, HMAC: _hmac + a_hex(), SALT: _salt},
        modified_ciphertext_8={CT: _ct, HMAC: _hmac, SALT: ""},
        modified_ciphertext_9={CT: _ct, HMAC: _hmac, SALT: hex(int(_salt, 16) ^ a_number())[2:]},
        modified_ciphertext_10={CT: _ct, HMAC: _hmac, SALT: hex(int(_salt, 16) ^ 0b1)[2:]},
        modified_ciphertext_11={CT: _ct, HMAC: _hmac, SALT: _salt + a_hex()},
    )
    for modified_ciphertext in amodified_ciphertexts.values():
        try:
            run(pad.abytes_decrypt(modified_ciphertext))
        except (ValueError, OverflowError):
            pass
        else:
            raise AssertionError("Modification was not detected!")
    for modified_ciphertext in modified_ciphertexts.values():
        try:
            pad.bytes_decrypt(modified_ciphertext)
        except (ValueError, OverflowError):
            pass
        else:
            raise AssertionError("Modification was not detected!")


def test_incomplete_validation():
    hmac_0 = pad.StreamHMAC(salt=salt)
    hmac_1 = pad.StreamHMAC(salt=salt, pid=pid)
    hmac_2 = pad.StreamHMAC(key=csprng(), salt=salt)
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
