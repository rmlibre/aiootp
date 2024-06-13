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


from test_initialization import *
from test_Clock import TIME_RESOLUTION

from aiootp.randoms.ids.raw_guid_config import RawGUIDContainer


class TestGUIDConfig:

    async def test_permutation_cid_can_be_specified(self) -> None:
        for permutation_config_id in (14, 15, 17, 20):
            config = t.GUIDConfig(
                config_id=16,
                size=16,
                raw_guid_type=t.RawGUID,
                permutation_type=t.FastAffineXORChain,
                permutation_config_id=permutation_config_id,
            )
            assert permutation_config_id == config.PERMUTATION_CONFIG_ID

    async def test_raw_cid_can_be_specified(self) -> None:
        for raw_guid_config_id in (14, 15, 17, 20):
            config = t.GUIDConfig(
                config_id=16,
                size=16,
                raw_guid_type=t.RawGUID,
                permutation_type=t.FastAffineXORChain,
                raw_guid_config_id=raw_guid_config_id,
            )
            assert raw_guid_config_id == config.RAW_GUID_CONFIG_ID


class TestGUID:

    async def test_unmasking_inverts_the_applied_permutation(self) -> None:
        for size in range(12, 33):
            key = token_bytes(GUID.key_size(size))
            guid = GUID(key=key, config_id=size)

            # ASYNC
            masked_guid = await guid.anew()
            unmasked_guid = await guid.aread(masked_guid)

            reconstructed_rawguid = b"".join(unmasked_guid.values())
            int_reconstructed_rawguid = int.from_bytes(reconstructed_rawguid, BIG)
            permuted_rawguid = await guid._permutation.apermute(int_reconstructed_rawguid)
            assert masked_guid == permuted_rawguid.to_bytes(size, BIG)

            # SYNC
            masked_guid = guid.new()
            unmasked_guid = guid.read(masked_guid)

            reconstructed_rawguid = b"".join(unmasked_guid.values())
            int_reconstructed_rawguid = int.from_bytes(reconstructed_rawguid, BIG)
            permuted_rawguid = guid._permutation.permute(int_reconstructed_rawguid)
            assert masked_guid == permuted_rawguid.to_bytes(size, BIG)

    async def test_raw_guids_sorting(self) -> None:
        runs = 32
        indexes = list(range(runs))
        for size in range(12, 33):
            key = token_bytes(GUID.key_size(size))
            guid = GUID(key=key, config_id=size)
            raw_guids = set(guid.read(guid.new()) for _ in indexes)
            assert runs == len(raw_guids)
            raw_guids_list = sorted(raw_guids)
            for i, raw in enumerate(raw_guids_list):
                assert raw == raw
                if (i < runs - 1):
                    assert raw < raw_guids_list[i + 1]
                else:
                    assert raw > raw_guids_list[i - 1]

    async def test_guid_size_limits(self) -> None:
        problem = (
            "Invalid length GUID was allowed during decoding."
        )
        for size in range(12, 33):
            key = token_bytes(GUID.key_size(size))
            guid = GUID(key=key, config_id=size)
            with Ignore(ValueError, if_else=violation(problem)):
                guid.read(b"\xff" + guid.new())
            with Ignore(ValueError, if_else=violation(problem)):
                RawGUIDContainer(b"\xff" + guid.new(), config=guid.config)
            with Ignore(ValueError, if_else=violation(problem)):
                await guid.aread(b"\xff" + guid.new())

    async def test_node_id_size_limits(self) -> None:
        problem = (
            "An invalid length node ID was allowed."
        )
        for size in range(12, 33):
            key = token_bytes(GUID.key_size(size))
            config = GUID._configs[size]
            rg_config = config.RawGUID._configs[config.RAW_GUID_CONFIG_ID]
            with Ignore(ValueError, if_else=violation(problem)):
                GUID(
                    key=key,
                    config_id=size,
                    node_id=(rg_config.NODE_ID_BYTES + 1) * "ff",
                )

    async def test_guid_uniqueness(self) -> None:
        size = 12
        key = token_bytes(GUID.key_size(size))
        guid = GUID(key=key, config_id=size)

        runs = 2048
        # PROBLEM: Low resolution system clock harms GUID uniqueness guarantees.
        is_os_clock_resolution_issue = lambda relay: (TIME_RESOLUTION >= 1e-04)

        # ASYNC
        guids = {await guid.anew() for _ in range(runs)}
        with Ignore(AssertionError, if_except=is_os_clock_resolution_issue):
            assert runs == len(guids)

        # SYNC
        for _ in range(runs):
            guids.add(guid.new())
        with Ignore(AssertionError, if_except=is_os_clock_resolution_issue):
            assert 2 * runs == len(guids)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

