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


__all__ = ["CipherKDFs", "KeyedCipherKDF", "ShakeConfig"]


__doc__ = "Manager interfaces for cipher KDFs."


from aiootp._typing import Typing as t
from aiootp._constants.misc import MIN_KEY_BYTES
from aiootp._exceptions import KeyAADIssue, Issue
from aiootp.commons import Config, ConfigMap, FrozenInstance
from aiootp.generics import Domains
from aiootp.generics import canonical_pack, encode_key, fullblock_ljust


class ShakeConfig(Config):
    """
    Allows for a domain-separated initialization of a cipher's KDF.
    """

    __slots__ = (
        "name",
        "pad",
        "offset_amount",
        "offset",
        "blocksize",
        "double_blocksize",
        "hasher_type",
        "hasher",
        "factory",
        "key_slice",
    )

    slots_types: t.Mapping[str, type] = dict(
        name=str,
        pad=bytes,
        offset_amount=int,
        offset=bytes,
        blocksize=int,
        double_blocksize=int,
        hasher_type=type,
        hasher=t.Callable,
        factory=t.Callable,
        key_slice=slice,
    )

    def __init__(
        self,
        name: str,
        pad: bytes,
        offset_amount: int,
        hasher: t.Callable,
        key_slice: t.Optional[slice],
    ) -> None:
        self.name = name
        self.pad = pad
        self.offset_amount = offset_amount
        self.offset = offset_amount * pad
        self.hasher = hasher
        self.hasher_type = type(hasher())
        self.blocksize = hasher().block_size
        self.double_blocksize = 2 * self.blocksize
        self.key_slice = key_slice

    def prepare_factory(
        self, config_id: bytes, packed_metadata: bytes
    ) -> t.Self:
        """
        Domain separates each KDF with a unique salt based on the
        relative name of the KDF & the configuration metadata of the
        cipher.
        """
        self.factory = self.hasher(
            Domains.encode_constant(
                f"{self.name}_salt",
                domain=config_id,
                aad=packed_metadata,
                size=self.double_blocksize,
            )
        ).copy
        return self


class KeyedCipherKDF(FrozenInstance):
    """
    Allows the amortization of an initialized cipher's KDF, allowing the
    efficient use of the cipher with arbitrarily large sized keys.
    """

    __slots__ = ("config", "kdf")

    def __init__(self, key: bytes, config: ShakeConfig) -> None:
        self.config = config
        self.kdf = config.factory()
        self.kdf.update(encode_key(key, config.blocksize, pad=config.pad))

    def new_session_copy(self, summary: bytes) -> t.XOFType:
        """
        Returns a copy of the keyed KDF after being initialized with the
        session's `salt`, `aad`, & `iv` canonically encoded into a
        `summary`.
        """
        config = self.config
        session_kdf = self.kdf.copy()
        session_kdf.update(
            fullblock_ljust(summary, config.blocksize, pad=config.pad)
            + config.offset
        )
        return session_kdf


class CipherKDFs(FrozenInstance):
    """
    A private type which is responsible for initializing the keystream
    key-derivation objects for chained sponge ciphers.
    """

    __slots__ = ("config",)

    def test_key_validity(self, key: bytes) -> None:
        """
        Throws exception if `key` violates type & min size requirements.
        """
        if key.__class__ is not bytes:
            raise Issue.value_must_be_type("key", bytes)
        elif len(key) < MIN_KEY_BYTES:
            raise KeyAADIssue.invalid_key_size(len(key), MIN_KEY_BYTES)

    def key_base_kdf(self, name: str, *, key: bytes) -> KeyedCipherKDF:
        """
        Keys & returns an initialized KDF.
        """
        return KeyedCipherKDF(key, self.config.KDF_CONFIGS[name])


module_api = dict(
    CipherKDFs=t.add_type(CipherKDFs),
    KeyedCipherKDF=t.add_type(KeyedCipherKDF),
    ShakeConfig=t.add_type(ShakeConfig),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

