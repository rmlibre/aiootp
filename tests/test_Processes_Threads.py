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


async def aget_ids() -> int:
    from aiootp.asynchs import asleep
    from aiootp.asynchs.threads import get_thread_id
    from aiootp.asynchs.processes import get_process_id

    await asleep()
    return dict(process_id=get_process_id(), thread_id=get_thread_id())


def get_ids() -> int:
    from aiootp.asynchs.threads import get_thread_id
    from aiootp.asynchs.processes import get_process_id

    return dict(process_id=get_process_id(), thread_id=get_thread_id())


class BasicTestSuite:
    _type: type
    _id_name: str

    async def test_anew(self) -> None:
        name = self._id_name

        result = (await self._type.anew(aget_ids))[name]
        assert result > 0
        assert result.__class__ is int
        assert result != (await aget_ids())[name]
        assert result != get_ids()[name]

        result = (await self._type.anew(get_ids))[name]
        assert result > 0
        assert result.__class__ is int
        assert result != get_ids()[name]

    def test_new(self) -> None:
        name = self._id_name

        result = self._type.new(get_ids)[name]
        assert result > 0
        assert result.__class__ is int
        assert result != get_ids()[name]

    async def test_asubmit(self) -> None:
        name = self._id_name
        self._type.reset_pool()

        fut = await self._type.asubmit(aget_ids)
        result = (await fut.aresult())[name]
        assert result == fut.result()[name]
        assert result > 0
        assert result.__class__ is int
        assert result != (await aget_ids())[name]
        assert result != get_ids()[name]

        fut = await self._type.asubmit(get_ids)
        result = (await fut.aresult())[name]
        assert result == fut.result()[name]
        assert result > 0
        assert result.__class__ is int
        assert result != (await aget_ids())[name]
        assert result != get_ids()[name]

    def test_submit(self) -> None:
        name = self._id_name
        self._type.reset_pool()

        fut = self._type.submit(get_ids)
        result = fut.result()[name]
        assert result > 0
        assert result.__class__ is int
        assert result != get_ids()[name]

    async def test_probe_delay_must_be_positive(self) -> None:
        problem = (
            "A non-positive probe_delay was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            await self._type.anew(acsprng, probe_delay=-1)

        with Ignore(ValueError, if_else=violation(problem)):
            self._type.new(csprng, probe_delay=-1)


class TestProcesses(BasicTestSuite):
    _type: type = Processes
    _id_name: str = "process_id"


class TestThreads(BasicTestSuite):
    _type: type = Threads
    _id_name: str = "thread_id"


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

