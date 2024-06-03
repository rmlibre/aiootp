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


__all__ = ["RawGUID"]


__doc__ = "A type for creating unblinded unique bytes values."


from aiootp._typing import Typing as t
from aiootp._constants import BIG
from aiootp._exceptions import Issue
from aiootp.commons import ConfigMap, FrozenInstance
from aiootp.asynchs import asleep

from .raw_guid_config import RawGUIDConfig, RawGUIDContainer


class RawGUID(FrozenInstance):
    """
    Creates a unique bytes value by combining a timestamp, random bytes,
    an instance-specific node-ID, & an incrementing counter.

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
    """

    __slots__ = ("tick", "node_id", "config")

    _configs = ConfigMap(
        mapping={
            config_id: RawGUIDConfig(
                timestamp_bytes=8,
                prf_bytes=config_id - 10,
                node_id_bytes=1,
                ticker_bytes=1,
                size=config_id,
            ) for config_id in range(12, 33)
        },
        config_type=RawGUIDConfig,
    )

    def _process_node_id(self, node_id: bytes) -> bytes:
        """
        Raises `ValueError` if the specified `node_id` isn't the correct
        length.
        """
        node_id_bytes = self.config.NODE_ID_BYTES
        if len(node_id) != node_id_bytes:
            raise Issue.invalid_length("node_id", node_id_bytes)
        return node_id

    def __init__(
        self, node_id: bytes = b"\x00", *, config_id: t.Hashable = 16
    ) -> None:
        self.config = self._configs[config_id]
        self.node_id = self._process_node_id(node_id)
        self.tick = 0

    def _incremented_tick(self) -> bytes:
        """
        Returns the incremented counter value.
        """
        c = self.config
        object.__setattr__(self, "tick", (self.tick + 1) & c.TICK_DOMAIN)
        return self.tick.to_bytes(c.TICKER_BYTES, BIG)

    async def anew(self) -> bytes:
        """
        Creates an unblinded, raw GUID bytes value.
        """
        await asleep()
        return self.new()

    def new(self) -> bytes:
        """
        Creates an unblinded, raw GUID bytes value.
        """
        config = self.config
        return (
            config.clock.make_timestamp(size=config.TIMESTAMP_BYTES)
            + config.prf(config.PRF_BYTES)
            + self.node_id
            + self._incremented_tick()
        )

    async def aread(self, guid: bytes) -> RawGUIDContainer:
        """
        Parses unblinded, unique bytes values into a mapping.
        """
        await asleep()
        return self.read(guid)

    def read(self, guid: bytes) -> RawGUIDContainer:
        """
        Parses unblinded, unique bytes values into a mapping.
        """
        return RawGUIDContainer(guid, config=self.config)


module_api = dict(
    RawGUID=t.add_type(RawGUID),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

