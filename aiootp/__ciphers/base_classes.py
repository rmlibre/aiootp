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


from hashlib import shake_128

from aiootp import Domains
from aiootp.__constants import *
from aiootp._typing import Typing as t
from aiootp.commons import Slots
from aiootp.generics import (
    canonical_pack, encode_key, fullblock_ljust, int_as_bytes
)


class KeyedKDF(Slots):
    """
    """

    __slots__ = ("name", "obj", "pad", "offset")

    def __init__(
        self, *, name: str, obj: SHAKE_128_TYPE, pad: bytes, offset: bytes
    ) -> None:
        """
        """
        self.name = name
        self.obj = obj
        self.pad = pad
        self.offset = offset

    def new(self) -> SHAKE_128_TYPE:
        return self.obj.copy()


class CipherKDFs:
    """
    A private type which is responsible for initializing the keystream
    key-derivation & mac objects for the `Chunky2048` cipher.
    """

    __slots__ = ()

    _METADATA: bytes
    _KDF_BASE_FACTORIES: t.Mapping[str, t.Tuple[callable, bytes, bytes]]

    CIPHER_NAME: str
    CONFIG: t.Mapping[str, t.Any]

    @classmethod
    def _create_metadata_constant(cls) -> None:
        # Cause ciphertexts to be unique & plaintexts to be scrambled for
        # any distinct variations of the cipher if the package is modified.
        # IMPORTANT FOR SECURITY. (https://eprint.iacr.org/2016/292.pdf)
        # DO NOT OVERRIDE TO PROVIDE ITER-OP.
        return canonical_pack(
            int_as_bytes(cls.CONFIG.EPOCH_NS, size=16),
            int_as_bytes(cls.CONFIG.BLOCKSIZE, size=2),
            int_as_bytes(cls.CONFIG.BLOCK_ID_BYTES, size=1),
            int_as_bytes(cls.CONFIG.SHMAC_BYTES, size=1),
            int_as_bytes(cls.CONFIG.SALT_BYTES, size=1),
            int_as_bytes(cls.CONFIG.IV_BYTES, size=1),
            int_as_bytes(cls.CONFIG.TIMESTAMP_BYTES, size=1),
            int_as_bytes(cls.CONFIG.SIV_KEY_BYTES, size=2),
            int_as_bytes(cls.CONFIG.MIN_PADDING_BLOCKS, size=2),
            pad=b"",
            int_bytes=1,
        )

    @classmethod
    def _create_base_kdfs(cls) -> None:
        """
        """
        for kdf_name, settings in cls.CONFIG.KDF_SETTINGS.items():
            factory: callable = settings.hasher(
                Domains.encode_constant(
                    f"{kdf_name}_salt",
                    domain=cls.CIPHER_NAME.encode(),
                    aad=cls._METADATA,
                    size=settings.blocksize,
                )
            ).copy
            yield kdf_name, factory, settings.pad, settings.offset

    def __init_subclass__(
        cls, *a, name: str, config: t.Mapping[str, t.Any], **kw
    ) -> None:
        """
        """
        cls.CONFIG = config
        cls.CIPHER_NAME = name
        cls._METADATA = cls._create_metadata_constant()
        cls._KDF_BASE_FACTORIES = SimpleNamespace()
        for kdf_name, factory, pad, offset in cls._create_base_kdfs():
            cls._KDF_BASE_FACTORIES[kdf_name] = (factory, pad, offset)
        super().__init_subclass__(*a, **kw)

    def key_base_kdf(self, kdf_name: str, *, key: bytes) -> None:
        """
        """
        factory, pad, offset = self._KDF_BASE_FACTORIES[kdf_name]
        kdf = KeyedKDF(name=kdf_name, obj=factory(), pad=pad, offset=offset)
        kdf_key = encode_key(key, kdf.obj.block_size, pad=pad)
        kdf.obj.update(kdf_key)
        return kdf

    def randomize_keyed_kdf(
        self, kdf_factory: KeyedKDF, summary: bytes
    ) -> SHAKE_128_TYPE:
        """
        A generalized KDF initializer which works for the seed, left &
        right KDFs, & the StreamHMAC MAC.
        """
        kdf = kdf_factory.new()
        kdf.update(
            fullblock_ljust(summary, kdf.block_size, pad=kdf_factory.pad)
            + kdf_factory.offset
        )
        return kdf

