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


__all__ = [
    "Domains",
    "abytes_are_equal",
    "ahash_bytes",
    "bytes_are_equal",
    "hash_bytes",
]


__doc__ = "Data processing & encoding utilities."


from .transform import *
from .canon import *
from .domains import *
from .byte_io import *
from .hashing import *


modules = dict(
    transform=transform,
    canon=canon,
    domains=domains,
    byte_io=byte_io,
    hashing=hashing,
)


module_api = dict(
    ByteIO=ByteIO,
    Domains=Domains,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    abytes_are_equal=abytes_are_equal,
    acanonical_pack=acanonical_pack,
    acanonical_unpack=acanonical_unpack,
    ahash_bytes=ahash_bytes,
    bytes_are_equal=bytes_are_equal,
    canonical_pack=canonical_pack,
    canonical_unpack=canonical_unpack,
    hash_bytes=hash_bytes,
)

