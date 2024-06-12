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


__all__ = ["HashTupleKDF", "DomainKDF"]


__doc__ = (
    "An interface for key derivation that facilitates domain-separation "
    "& canonicalized input processing."
)


from hashlib import shake_128

from aiootp._typing import Typing as t
from aiootp._constants import HASHER_TYPES
from aiootp._exceptions import Issue
from aiootp.commons import FrozenInstance
from aiootp.generics import Domains, ahash_bytes, hash_bytes
from aiootp.generics import acanonical_pack, canonical_pack


class HashTupleKDF(FrozenInstance):
    """
    A base type for passing KDF-related class attributes to subclasses
    in a consistent manner.
    """

    __slots__ = ("_payload",)

    _type: t.Callable[..., t.XOFType]

    def __init_subclass__(cls, *a, salt_label: t.AnyStr, **kw) -> None:
        """
        Ensures subclasses can define custom key & base type hasher
        algorithms within their class bodies & have the blocksizes of
        those objects be recorded by the class correctly during
        definition time.
        """
        super().__init_subclass__(*a, **kw)
        cls._TYPE_BLOCKSIZE: int = cls._type().block_size
        cls._new_payload: t.Callable[[], t.XOFType] = cls._type(
            Domains.encode_constant(salt_label, size=cls._TYPE_BLOCKSIZE)
        ).copy

    def _initialize_payload(
        self, domain: bytes, data: t.Iterable[bytes], *, key: bytes
    ) -> None:
        """
        Canonically encodes then hashes the domain, key & first batch of
        input data to prepare a hashing object that processes all
        additional data & acts as an initial key generator subroutine
        for other key derivation procedures.
        """
        self._payload = self._new_payload()
        self._payload.update(
            hash_bytes(
                Domains.KDF,
                domain,
                *data,
                key=key + domain,
                size=self._payload.block_size,
                hasher=self._type,
            )
        )

    async def _arun_kdf(
        self,
        *data: bytes,
        size: t.Optional[int] = None,
        aad: bytes,
        obj: t.SimpleNamespace,
    ) -> bytes:
        """
        A generic procedure for key derivation using the description of
        a desired hash function, along with an XOF for KDF context
        absorbsion, state memory, & initial key production. The input
        `data`, `aad`, & domain of the KDF are canonically encoded &
        passed through the keyed-hashed under the initial key.
        """
        return await ahash_bytes(
            aad,
            *data,
            size=None if obj.digest_size else size,
            key=self._payload.digest(obj.block_size),
            hasher=obj.factory,
        )

    def _run_kdf(
        self,
        *data: bytes,
        size: t.Optional[int] = None,
        aad: bytes,
        obj: t.SimpleNamespace,
    ) -> bytes:
        """
        A generic procedure for key derivation using the description of
        a desired hash function, along with an XOF for KDF context
        absorbsion, state memory, & initial key production. The input
        `data`, `aad`, & domain of the KDF are canonically encoded &
        passed through the keyed-hashed under the initial key.
        """
        return hash_bytes(
            aad,
            *data,
            size=None if obj.digest_size else size,
            key=self._payload.digest(obj.block_size),
            hasher=obj.factory,
        )


class DomainKDF(HashTupleKDF, salt_label=b"domain_kdf_salt"):
    """
    Creates objects able to derive domain & data-specific keyed hashes.
    Payload updates are automatically canonicalized.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp import DomainKDF


    kdf = DomainKDF(b"ecdhe", session.transcript, key=session.key)

    auth_key = kdf.sha3_512(aad=b"auth-key")
    encryption_key = kdf.sha3_512(aad=b"encryption-key")
    """

    __slots__ = ()

    _type: t.Callable[[bytes], t.XOFType] = shake_128

    def __init__(self, domain: bytes, *data: bytes, key: bytes) -> None:
        """
        Initializes a `domain`-specific KDF with a `key`, & associated
        payload `data`, which is canonically encoded by the class.
        """
        self._initialize_payload(domain, data, key=key)

    def copy(self) -> t.Cls:
        """
        Copies the instance state into a new object which can be updated
        separately in differing contexts.
        """
        kdf = self.__class__.__new__(self.__class__)
        kdf._payload = self._payload.copy()
        return kdf

    async def aupdate(self, *data: bytes) -> t.Self:
        """
        Canonically updates the payload object with additional values.
        Update calls, input data & the order of both, must match exactly
        to create matching KDF states in distinct instances.
        """
        if not data:
            raise Issue.value_must("update data", "not be empty")
        payload = self._payload
        payload.update(
            await acanonical_pack(*data, blocksize=payload.block_size)
        )
        return self

    def update(self, *data: bytes) -> t.Self:
        """
        Canonically updates the payload object with additional values.
        Update calls, input data & the order of both, must match exactly
        to create matching KDF states in distinct instances.
        """
        if not data:
            raise Issue.value_must("update data", "not be empty")
        payload = self._payload
        payload.update(
            canonical_pack(*data, blocksize=payload.block_size)
        )
        return self

    async def asha3_256(
        self, *data: bytes, aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed sha3_256 hash of the instance's state.
        """
        return await self._arun_kdf(
            *data, aad=aad, obj=HASHER_TYPES["sha3_256"]
        )

    def sha3_256(
        self, *data: bytes, aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed sha3_256 hash of the instance's state.
        """
        return self._run_kdf(
            *data, aad=aad, obj=HASHER_TYPES["sha3_256"]
        )

    async def asha3_512(
        self, *data: bytes, aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed sha3_512 hash of the instance's state.
        """
        return await self._arun_kdf(
            *data, aad=aad, obj=HASHER_TYPES["sha3_512"]
        )

    def sha3_512(
        self, *data: bytes, aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed sha3_512 hash of the instance's state.
        """
        return self._run_kdf(
            *data, aad=aad, obj=HASHER_TYPES["sha3_512"]
        )

    async def ashake_128(
        self, *data: bytes, size: int, aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed shake_128 hash of the instance's state.
        """
        return await self._arun_kdf(
            *data, size=size, aad=aad, obj=HASHER_TYPES["shake_128"]
        )

    def shake_128(
        self, *data: bytes, size: int, aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed shake_128 hash of the instance's state.
        """
        return self._run_kdf(
            *data, size=size, aad=aad, obj=HASHER_TYPES["shake_128"]
        )

    async def ashake_256(
        self, *data: bytes, size: int, aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed shake_256 hash of the instance's state.
        """
        return await self._arun_kdf(
            *data, size=size, aad=aad, obj=HASHER_TYPES["shake_256"]
        )

    def shake_256(
        self, *data: bytes, size: int, aad: bytes = b""
    ) -> bytes:
        """
        Return the keyed shake_256 hash of the instance's state.
        """
        return self._run_kdf(
            *data, size=size, aad=aad, obj=HASHER_TYPES["shake_256"]
        )


module_api = dict(
    DomainKDF=t.add_type(DomainKDF),
    HashTupleKDF=t.add_type(HashTupleKDF),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

