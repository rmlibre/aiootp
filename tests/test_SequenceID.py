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


class TestSequenceIDConfig:
    kw = dict(config_id=16, permutation_type=t.FastAffineXORChain)

    async def test_permutation_cid_defaults_to_instance_cid(self) -> None:
        config = t.SequenceIDConfig(size=16, **self.kw)
        assert 16 == config.PERMUTATION_CONFIG_ID

    async def test_size_must_be_within_bounded_limits(self) -> None:
        problem = (
            "A size out of bounds was allowed."
        )
        for bad_size in (-1, 0, 4097):
            with Ignore(ValueError, if_else=violation(problem)):
                t.SequenceIDConfig(size=bad_size, **self.kw)


class TestSequenceID:

    async def test_inversion_correctness(self) -> None:
        for n in range(1, 33):
            for index in range(0, 256, 16):
                key = token_bytes(SequenceID.key_size(n))
                sid = SequenceID(key=key, config_id=n)
                aresult = await sid.anew(index)
                result = sid.new(index)
                assert index == await sid.aread(aresult)
                assert index == await sid.aread(result)
                assert index == sid.read(aresult)
                assert index == sid.read(result)

    async def test_range_uniqueness(self) -> None:
        n = 1
        key = token_bytes(SequenceID.key_size(n))
        sid = SequenceID(key=key, config_id=n)

        # the sequence ids produced are unique for every given sequential
        # integer up to the max of the byte domain.
        history = set()
        for index in range(256 ** n):
            result = sid.new(index)
            assert index == sid.read(result)
            assert result not in history, f"{index=}, {n=}"
            history.add(result)

        # assert values wrap after the domain has been exhausted
        assert sid.new(index + 1) in history
        assert sid.new(index + 1) == await sid.anew(index + 1)

    async def test_sizes(self) -> None:

        for n in range(1, 33):
            # the salt must be at least the length of output sizes
            problem = (
                "An invalid key size for a specified config_id was allowed."
            )
            with Ignore(KeyError, ValueError, if_else=violation(problem)):
                sid = SequenceID(
                    key=token_bytes(SequenceID.key_size(n - 1)), config_id=n
                )

            sid = SequenceID(key=token_bytes(SequenceID.key_size(n)), config_id=n)
            # the size of produced sequential ids is the same as the defined
            # size
            result = sid.new(n)
            assert len(result) == n
            assert type(result) is bytes
            assert result == await sid.anew(n)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

