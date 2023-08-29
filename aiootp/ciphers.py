# This file is part of aiootp:
# an application agnostic — async-compatible — anonymity & cryptography
# library, providing access to high-level Pythonic utilities to simplify
# the tasks of secure data processing, communication & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "AsyncCipherStream",
    "AsyncDecipherStream",
    "Chunky2048",
    "CipherStream",
    "DecipherStream",
]


__doc__ = (
    "A collection of low-level tools & higher level abstractions which "
    "can be used to create custom security tools, or as pre-assembled r"
    "ecipes, including the package's main online salt reuse / misuse re"
    "sistant, tweakable AEAD cipher called `Chunky2048`."
)


from .__ciphers.chunky2048 import *


extras = dict(
    _StreamHMAC=StreamHMAC,
    _SyntheticIV=SyntheticIV,
    AsyncCipherStream=AsyncCipherStream,
    AsyncDecipherStream=AsyncDecipherStream,
    ChaCha20Poly1305=ChaCha20Poly1305,
    Chunky2048=Chunky2048,
    CipherStream=CipherStream,
    DecipherStream=DecipherStream,
    __doc__=__doc__,
    __package__=__package__,
    _abytes_decipher=abytes_decipher,
    _abytes_encipher=abytes_encipher,
    _aplaintext_stream=aplaintext_stream,
    _bytes_decipher=bytes_decipher,
    _bytes_encipher=bytes_encipher,
    _plaintext_stream=plaintext_stream,
)


ciphers = make_module("ciphers", mapping=extras)

