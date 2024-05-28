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


__all__ = ["Domains", "DomainEncoder"]


__doc__ = "Domain separation constants & utilities."


from hashlib import shake_128

from aiootp._typing import Typing as t
from aiootp._constants import misc, DEFAULT_AAD
from aiootp.commons import FrozenInstance

from .hashing import ahash_bytes, hash_bytes


class DomainEncoder(FrozenInstance):
    """
    A base class which enables domain constants to be encoded & created
    for specific use cases.
    """

    __slots__ = ()

    _DOMAIN: bytes = b"domain_constant_encoder"

    @classmethod
    async def aencode_constant(
        cls,
        constant: t.AnyStr,
        size: int = 8,
        *,
        domain: bytes = b"",
        aad: bytes = DEFAULT_AAD,
        pad: bytes = b"\x00",
    ) -> bytes:
        """
        Receives a `str` or `bytes`-type `constant`, encodes & hashes
        it under a `domain`, along with the metadata of the encoding,
        then returns the `size`-byte digest from the `shake_128` XOF.

        These returned values are used by the package as inputs to other
        functions which in turn makes their outputs domain-specific.
        This has various security benefits, such as:

        https://eprint.iacr.org/2010/264.pdf & more recent published
        works show schemes which are not provably secure, may be
        transformable into provably secure schemes just with some
        assumptions that functions which they rely upon happen to be
        domain-specific.
        """
        if constant.__class__ is not bytes:
            constant = constant.encode()
        return await ahash_bytes(
            cls._DOMAIN,
            domain,
            aad,
            constant,
            hasher=shake_128,
            size=size,
            pad=pad,
        )

    @classmethod
    def encode_constant(
        cls,
        constant: t.AnyStr,
        size: int = 8,
        *,
        domain: bytes = b"",
        aad: bytes = DEFAULT_AAD,
        pad: bytes = b"\x00",
    ) -> bytes:
        """
        Receives a `str` or `bytes`-type `constant`, encodes & hashes
        it under a `domain`, along with the metadata of the encoding,
        then returns the `size`-byte digest from the `shake_128` XOF.

        These returned values are used by the package as inputs to other
        functions which in turn makes their outputs domain-specific.
        This has various security benefits, such as:

        https://eprint.iacr.org/2010/264.pdf & more recent published
        works show schemes which are not provably secure, may be
        transformable into provably secure schemes just with some
        assumptions that functions which they rely upon happen to be
        domain-specific.
        """
        if constant.__class__ is not bytes:
            constant = constant.encode()
        return hash_bytes(
            cls._DOMAIN,
            domain,
            aad,
            constant,
            hasher=shake_128,
            size=size,
            pad=pad,
        )


class Domains(DomainEncoder):
    """
    A collection of encoded constants which can augment function inputs
    to make their outputs domain-specific.
    """

    __slots__ = ()

    for name, value in misc.__dict__.items():
        if value.__class__ is str:
            vars()[name] = DomainEncoder.encode_constant(value)

    del name
    del value


module_api = dict(
    DomainEncoder=t.add_type(DomainEncoder),
    Domains=t.add_type(Domains),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

