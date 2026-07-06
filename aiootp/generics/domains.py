# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2026 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


"""
Domain separation constants & utilities.
"""

__all__ = ["Domains", "DomainEncoder"]


from hashlib import shake_128

from aiootp._typing import Typing as t
from aiootp._constants import misc, DEFAULT_AAD
from aiootp.commons import FrozenInstance

from .hashing import ahash_bytes, hash_bytes


class EncodedConstant(bytes):
    """
    Signals that the value for a user-defined constant has already been
    encoded.
    """


class DomainEncoder(FrozenInstance):
    """
    A base class which enables domain constants to be encoded & created
    for specific use cases.
    """

    __slots__ = ()

    _DOMAIN: bytes = b"domain_constant_encoder"
    _SUBCLASS_DOMAIN: bytes = b""
    _DEFAULT_SIZE: int = 8

    _Constant: type = EncodedConstant

    @classmethod
    def _follows_naming_convention(cls, name: str, /) -> bool:
        """
        Determines whether a given attribute `name` follows the class'
        convention for user-defined constants.
        """
        return (
            not name.startswith("_")
            and name.isupper()
            and name.isidentifier()
        )

    @classmethod
    def _has_already_been_encoded(
        cls,
        value: t.AnyStr | _Constant,
        /,
    ) -> bool:
        """
        Returns `True` if the provided `value` is an instance of the
        class' signalling type, which indicates that the value has
        already been encoded.
        """
        return isinstance(value, cls._Constant)

    def __init_subclass__(cls, /, *a: t.Any, **kw: t.Any) -> None:
        """
        Walks a subclass' dictionary to automatically discover & encode
        user-defined constants which follow the class' convention for
        the names of constants.
        """
        super().__init_subclass__(*a, **kw)
        for name, value in cls.__dict__.items():
            follows_name_convention = cls._follows_naming_convention(name)
            is_already_encoded = cls._has_already_been_encoded(value)
            if is_already_encoded or not follows_name_convention:
                continue

            constant = cls.encode_constant(
                value,
                domain=cls._SUBCLASS_DOMAIN,
                size=cls._DEFAULT_SIZE,
            )
            setattr(cls, name, constant)

    @classmethod
    async def aencode_constant(
        cls,
        constant: t.AnyStr,
        size: int = 8,
        *,
        domain: bytes = b"",
        aad: bytes = DEFAULT_AAD,
        pad: bytes = b"\x00",
    ) -> _Constant:
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
        if isinstance(constant, str):
            constant = constant.encode()

        result = await ahash_bytes(
            cls._DOMAIN,
            domain,
            aad,
            constant,
            hasher=shake_128,
            size=size,
            pad=pad,
        )
        return cls._Constant(result)

    @classmethod
    def encode_constant(
        cls,
        constant: t.AnyStr,
        size: int = 8,
        *,
        domain: bytes = b"",
        aad: bytes = DEFAULT_AAD,
        pad: bytes = b"\x00",
    ) -> _Constant:
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
        if isinstance(constant, str):
            constant = constant.encode()

        result = hash_bytes(
            cls._DOMAIN,
            domain,
            aad,
            constant,
            hasher=shake_128,
            size=size,
            pad=pad,
        )
        return cls._Constant(result)


class Domains(DomainEncoder):
    """
    A collection of encoded constants which can augment function inputs
    to make their outputs domain-specific.
    """

    __slots__ = ()

    vars().update(
        (name, value.encode())
        for name, value in misc.__dict__.items()
        if value.__class__ is str
    )


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
