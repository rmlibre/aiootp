# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "__all__",
    "test_json_conversion_functions",
]


from init_tests import *


def test_json_conversion_functions():
    aciphertext = run(pad.abytes_encrypt(plaintext_bytes))
    ciphertext = pad.bytes_encrypt(plaintext_bytes)

    aascii_ciphertext = run(pad.io.ajson_to_ascii(json.dumps(aciphertext)))
    ascii_ciphertext = pad.io.json_to_ascii(json.dumps(ciphertext))

    ajson_ciphertext = run(pad.io.aascii_to_json(aascii_ciphertext))
    json_ciphertext = pad.io.ascii_to_json(ascii_ciphertext)

    assert ajson_ciphertext != json_ciphertext
    assert ajson_ciphertext == aciphertext
    assert json_ciphertext == ciphertext
    assert aascii_ciphertext != ascii_ciphertext


    aciphertext_deterministic = run(pad.abytes_encrypt(plaintext_bytes, salt=salt, allow_dangerous_determinism=True))
    ciphertext_deterministic = pad.bytes_encrypt(plaintext_bytes, salt=salt, allow_dangerous_determinism=True)

    aascii_ciphertext_deterministic = run(pad.io.ajson_to_ascii(json.dumps(aciphertext_deterministic)))
    ascii_ciphertext_deterministic = pad.io.json_to_ascii(json.dumps(ciphertext_deterministic))

    ajson_ciphertext_deterministic = run(pad.io.aascii_to_json(aascii_ciphertext_deterministic))
    json_ciphertext_deterministic = pad.io.ascii_to_json(ascii_ciphertext_deterministic)

    assert ajson_ciphertext_deterministic != json_ciphertext_deterministic
    assert ajson_ciphertext_deterministic == aciphertext_deterministic
    assert json_ciphertext_deterministic == ciphertext_deterministic
    assert aascii_ciphertext_deterministic != ascii_ciphertext_deterministic


    padding_key = pad.padding_key(salt=salt, pid=pid)
    padded_plaintext = pad.io.pad_plaintext(plaintext_bytes, padding_key=padding_key)
    apadded_plaintext = run(pad.io.apad_plaintext(plaintext_bytes, padding_key=padding_key))
    hmac = pad.StreamHMAC(salt=salt, pid=pid).for_encryption()
    ahmac = pad.StreamHMAC(salt=salt, pid=pid).for_encryption()
    encipher = data(padded_plaintext).bytes_encipher(key, salt=salt, pid=pid, validator=hmac)
    aencipher = adata(padded_plaintext).abytes_encipher(key, salt=salt, pid=pid, validator=ahmac)
    ciphertext = {
        commons.CIPHERTEXT: [block for block in encipher],
        commons.HMAC: hmac.finalize().hex(),
        commons.SALT: salt,
        commons.SIV: hmac.siv,
    }
    aciphertext = {
        commons.CIPHERTEXT: run(aencipher.alist(mutable=True)),
        commons.HMAC: run(ahmac.afinalize()).hex(),
        commons.SALT: salt,
        commons.SIV: ahmac.siv,
    }
    assert ciphertext == aciphertext

