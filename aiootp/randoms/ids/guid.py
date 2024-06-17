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


__all__ = ["GUID"]


__doc__ = (
    "A type for creating globally unique, pseudo-random identifiers "
    "using bijective, keyed permutations."
)


from aiootp._typing import Typing as t
from aiootp._constants import BIG
from aiootp._exceptions import Issue
from aiootp._permutations import FastAffineXORChain
from aiootp.commons import ConfigMap, FrozenInstance

from .raw_guid import RawGUID, RawGUIDContainer
from .guid_config import GUIDConfig


class GUID(FrozenInstance):
    """
    A class for producing globally unique, pseudo-random identifiers
    that are guaranteed to be unique if all calls occur on a different
    nanosecond & use the same instance `key`. Additionally, any calls
    which utilize the same `key` but a different `node_id` will always
    produce unique outputs from each other, even if they occur on the
    same nanosecond. Outputs are also guaranteed to be unique if no more
    than 256 calls are made each nanosecond from any instance that
    utilizes the same `key` & `node_id`.

    Normal birthday-bound collision probabilities apply when a different
    `key` is used between callers.

    All outputs are masked using a pseudo-random permutation. They can
    be unmasked to reveal the raw GUIDs which by default are sorted by
    their `timestamp`, `node_id`, `ticker`, & `token`, in that order.

    By default 1-byte `node_id`s are supported, allowing 256 distinct
    guaranteed unique callers.

     _____________________________________
    |                                     |
    |   Format Diagram: Default Raw GUID  |
    |_____________________________________|
     __________________________________________________________________
    |                         |                    |         |         |
    |      timestamp (ns)     |       token        | node-id |  ticker |
    |-------------------------|--------------------|---------|---------|
    |         8-bytes         |       6-bytes      |  1-byte |  1-byte |
    |_________________________|____________________|_________|_________|
    |                                                                  |
    |                          16-bytes                                |
    |__________________________________________________________________|

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from io import StringIO
    from aiootp import GUID

    # Simple usage:

    def standard_guid_format(guid: bytes) -> str:
        read = StringIO(guid.hex()).read
        return "-".join(read(section) for section in (8, 4, 4, 4, 12))

    guids = GUID()
    print(standard_guid_format(guids.new()))
    8b36d9e4-cd73-8f67-631a-94e7b088c50a

    # Advanced usage:

    size = 16
    dds = distributed_database_system
    assert len(dds.shared_key) == GUID.key_size(size)
    guids = GUID(key=dds.shared_key, node_id=local_db.id)
    assert len(guids.new()) == size

    for table in local_db.tables:
        for record in table.new_records:
            record.dds_primary_key = guids.new()
            dds.merge(table, record)

    # Unmasking GUIDs

    guids = GUID(node_id=b"\xfc")
    print(guids.read(guids.new()))
    RawGUIDContainer(
        timestamp=b'\x00\xa3\xb9\xc3\xcc\x83CW',
        token=b'\xb4T<\xe7\xc8o',
        node_id=b'\xfc',
        ticker=b'\x01',
    )
    print(guids.read(guids.new()))
    RawGUIDContainer(
        timestamp=b'\x00\xa3\xb9\xc3\xcc\x88\x0f\x99',
        token=b'\xb5~\xf1\xf7\xa4\xab',
        node_id=b'\xfc',
        ticker=b'\x02',
    )
    """

    __slots__ = ("_raw_guid", "_permutation", "config")

    _configs = ConfigMap(
        mapping={
            config_id: GUIDConfig(
                config_id=config_id,
                size=config_id,
                raw_guid_type=RawGUID,
                permutation_type=FastAffineXORChain,
            ) for config_id in range(12, 33)
        },
        config_type=GUIDConfig,
    )

    @classmethod
    def key_size(cls, config_id: t.Hashable) -> bytes:
        """
        Returns the number of bytes a uniform random key needs to be
        to initialize the instance's permutation.
        """
        return cls._configs[config_id].KEY_SIZE

    def _initialize_permutation(self, key: bytes) -> t.PermutationType:
        """
        Returns a bijective, keyed permutation as specified by the
        instance's configuration.
        """
        config_id = self.config.PERMUTATION_CONFIG_ID
        return self.config.Permutation(key=key, config_id=config_id)

    def __init__(
        self,
        *,
        key: t.Optional[bytes] = None,
        node_id: bytes = b"\x00",
        config_id: t.Hashable = 16,
    ) -> None:
        self.config = c = self._configs[config_id]
        key = key if key else c._DEFAULT_KEY
        self._raw_guid = c.RawGUID(node_id=node_id, config_id=config_id)
        self._permutation = self._initialize_permutation(key)

    async def anew(self) -> bytes:
        """
        Returns globally unique identifier that is blinded using a
        bijective, keyed permutation.
        """
        guid = await self._permutation.apermute(
            int.from_bytes(await self._raw_guid.anew(), BIG)
        )
        return guid.to_bytes(self.config.SIZE, BIG)

    def new(self) -> bytes:
        """
        Returns globally unique identifier that is blinded using a
        bijective, keyed permutation.
        """
        return self._permutation.permute(
            int.from_bytes(self._raw_guid.new(), BIG)
        ).to_bytes(self.config.SIZE, BIG)

    async def aread(self, guid: bytes) -> RawGUIDContainer:
        """
        Unblinds a `guid` & returns an object with the secret values
        parsed into it.
        """
        if len(guid) != self.config.SIZE:
            raise Issue.invalid_length("guid", len(guid))
        guid = int.from_bytes(guid, BIG)
        original = await self._permutation.ainvert(guid)
        return await self._raw_guid.aread(
            original.to_bytes(self.config.SIZE, BIG)
        )

    def read(self, guid: bytes) -> RawGUIDContainer:
        """
        Unblinds a `guid` & returns an object with the secret values
        parsed into it.
        """
        if len(guid) != self.config.SIZE:
            raise Issue.invalid_length("guid", len(guid))
        guid = int.from_bytes(guid, BIG)
        original = self._permutation.invert(guid)
        return self._raw_guid.read(original.to_bytes(self.config.SIZE, BIG))


module_api = dict(
    GUID=t.add_type(GUID),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

