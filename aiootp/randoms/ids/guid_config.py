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


__all__ = ["GUIDConfig"]


__doc__ = "A configuration type for `GUID`."


from hashlib import shake_256

from aiootp._typing import Typing as t
from aiootp._paths import SecurePath, read_salt_file
from aiootp.commons import Config
from aiootp.generics import Domains, hash_bytes


# ensure the device has created a secret static salt for GUIDs
_guid_salt_name = Domains.encode_constant(b"default_guid_salt", size=16)
_guid_salt_path = SecurePath(key=_guid_salt_name, _admin=True)
_guid_salt = read_salt_file(_guid_salt_path)


class GUIDConfig(Config):
    """
    A configuration type for `GUID`.
    """

    __slots__ = (
        "_DEFAULT_KEY",
        "AAD",
        "SIZE",
        "KEY_SIZE",
        "RAW_GUID_CONFIG_ID",
        "PERMUTATION_CONFIG_ID",
        "RawGUID",
        "Permutation",
    )

    slots_types: t.Mapping[str, type] = dict(
        _DEFAULT_KEY=bytes,
        AAD=bytes,
        SIZE=int,
        KEY_SIZE=int,
        RAW_GUID_CONFIG_ID=t.Hashable,
        PERMUTATION_CONFIG_ID=t.Hashable,
        RawGUID=type,
        Permutation=t.PermutationType,
    )

    _DEFAULT_SALT_DOMAIN: t.AnyStr = b"default_guid_salt"

    def _process_raw_guid_config_id(
        self, raw_guid_config_id: t.Optional[t.Hashable]
    ) -> t.Hashable:
        """
        Returns the `RawGUID` config ID if specified. If not, the
        instance's own config ID is assumed to be desired & is returned.
        """
        if raw_guid_config_id is None:
            return self.CONFIG_ID
        else:
            return raw_guid_config_id

    def _process_permutation_config_id(
        self, permutation_config_id: t.Optional[t.Hashable]
    ) -> t.Hashable:
        """
        Returns the permutation config ID if specified. If not, the
        instance's own config ID is assumed to be desired & is returned.
        """
        if permutation_config_id is None:
            return self.CONFIG_ID
        else:
            return permutation_config_id

    def _load_default_key(self) -> bytes:
        """
        Return the static device salt used for GUID creation.
        """
        config_id = repr(self.CONFIG_ID).encode()
        return hash_bytes(
            self._DEFAULT_SALT_DOMAIN,
            config_id,
            self.AAD,
            key=_guid_salt,
            hasher=shake_256,
            size=self.KEY_SIZE,
        )

    def __init__(
        self,
        *,
        config_id: t.Hashable,
        size: int,
        raw_guid_type: type,
        permutation_type: t.PermutationType,
        raw_guid_config_id: t.Optional[t.Hashable] = None,
        permutation_config_id: t.Optional[t.Hashable] = None,
        aad: bytes = b"",
    ) -> None:
        self.CONFIG_ID = config_id
        self.AAD = aad
        self.SIZE = size
        self.KEY_SIZE = permutation_type.key_size(config_id)
        self._DEFAULT_KEY = self._load_default_key()
        self.RAW_GUID_CONFIG_ID = self._process_raw_guid_config_id(
            raw_guid_config_id
        )
        self.PERMUTATION_CONFIG_ID = self._process_permutation_config_id(
            permutation_config_id
        )
        self.RawGUID = raw_guid_type
        self.Permutation = permutation_type


module_api = dict(
    GUIDConfig=t.add_type(GUIDConfig),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

