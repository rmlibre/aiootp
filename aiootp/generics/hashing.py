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


__all__ = ["ahash_bytes", "hash_bytes"]


__doc__ = "Canonicalized keyed hashing functions for SHA3 objects."


from hashlib import sha3_512

from aiootp._typing import Typing as t
from aiootp._constants import INT_BYTES, BIG

from .canon import aencode_key, encode_key
from .canon import acanonical_pack, canonical_pack


async def ahash_bytes(
    *collection: bytes,
    hasher: t.Callable[[bytes], t.HasherType] = sha3_512,
    pad: bytes = b"\x00",
    size: t.Optional[int] = None,
    key: bytes = b"",
) -> bytes:
    """
    Joins the `collection` of `bytes`-type objects with a canonical
    encoding & returns the `hasher` object's digest of the encoded
    result.

    `size` may be specified if the `hasher` object's `digest`
    method so requires.

    Returns a keyed-hash if `key` is specified.
    """
    obj = hasher()
    obj.update(
        (await aencode_key(key, obj.block_size, pad=pad) if key else b"")
        + await acanonical_pack(
            (size if size else obj.digest_size).to_bytes(INT_BYTES, BIG),
            *collection,
            blocksize=obj.block_size,
            pad=pad,
        )
    )
    if size:
        return obj.digest(size)
    return obj.digest()


def hash_bytes(
    *collection: bytes,
    hasher: t.Callable[[bytes], t.HasherType] = sha3_512,
    pad: bytes = b"\x00",
    size: t.Optional[int] = None,
    key: bytes = b"",
) -> bytes:
    """
    Joins the `collection` of `bytes`-type objects with a canonical
    encoding & returns the `hasher` object's digest of the encoded
    result.

    `size` may be specified if the `hasher` object's `digest`
    method so requires.

    Returns a keyed-hash if `key` is specified.
    """
    obj = hasher()
    obj.update(
        (encode_key(key, obj.block_size, pad=pad) if key else b"")
        + canonical_pack(
            (size if size else obj.digest_size).to_bytes(INT_BYTES, BIG),
            *collection,
            blocksize=obj.block_size,
            pad=pad,
        )
    )
    if size:
        return obj.digest(size)
    return obj.digest()


module_api = dict(
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    ahash_bytes=ahash_bytes,
    hash_bytes=hash_bytes,
)

