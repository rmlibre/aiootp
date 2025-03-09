# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2025 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


from conftest import *


INTERFACES = (Processes, Threads)


@pytest.mark.parametrize("interface", INTERFACES)
async def test_anew_workers_have_distinct_ids_from_their_caller(
    interface: t.ConcurrencyInterface,
) -> None:
    amethod = interface.aget_id
    method = interface.get_id

    result = await interface.anew(amethod)
    acaller_id = await amethod()
    caller_id = method()
    assert result > 0
    assert result.__class__ is int
    assert result != acaller_id
    assert result != caller_id
    assert acaller_id == caller_id

    result = await interface.anew(method)
    acaller_id = await amethod()
    caller_id = method()
    assert result > 0
    assert result.__class__ is int
    assert result != acaller_id
    assert result != caller_id
    assert acaller_id == caller_id


@pytest.mark.parametrize("interface", INTERFACES)
async def test_new_workers_have_distinct_ids_from_their_caller(
    interface: t.ConcurrencyInterface,
) -> None:
    amethod = interface.aget_id
    method = interface.get_id

    result = interface.new(method)
    acaller_id = await amethod()
    caller_id = method()
    assert result > 0
    assert result.__class__ is int
    assert result != acaller_id
    assert result != caller_id
    assert acaller_id == caller_id


@pytest.mark.parametrize("interface", INTERFACES)
async def test_asubmit_workers_have_distinct_ids_from_their_caller(
    interface: t.ConcurrencyInterface,
) -> None:
    interface.reset_pool()
    amethod = interface.aget_id
    method = interface.get_id

    fut = await interface.asubmit(amethod)
    result = await fut.aresult()
    acaller_id = await amethod()
    caller_id = method()
    assert result == fut.result()
    assert result > 0
    assert result.__class__ is int
    assert result != acaller_id
    assert result != caller_id
    assert acaller_id == caller_id

    fut = await interface.asubmit(method)
    result = await fut.aresult()
    acaller_id = await amethod()
    caller_id = method()
    assert result == fut.result()
    assert result > 0
    assert result.__class__ is int
    assert result != acaller_id
    assert result != caller_id
    assert acaller_id == caller_id


@pytest.mark.parametrize("interface", INTERFACES)
async def test_submit_workers_have_distinct_ids_from_their_caller(
    interface: t.ConcurrencyInterface,
) -> None:
    interface.reset_pool()
    amethod = interface.aget_id
    method = interface.get_id

    fut = interface.submit(method)
    result = fut.result()
    acaller_id = await amethod()
    caller_id = method()
    assert result > 0
    assert result.__class__ is int
    assert result != acaller_id
    assert result != caller_id
    assert acaller_id == caller_id


@pytest.mark.parametrize("interface", INTERFACES)
async def test_probe_delay_must_be_positive(
    interface: t.ConcurrencyInterface,
) -> None:
    amethod = interface.aget_id
    method = interface.get_id

    problem = (  # fmt: skip
        "A non-positive probe_delay was allowed."
    )
    with Ignore(ValueError, if_else=violation(problem)):
        await interface.anew(amethod, probe_delay=-1)

    with Ignore(ValueError, if_else=violation(problem)):
        interface.new(method, probe_delay=-1)

    with Ignore(ValueError, if_else=violation(problem)):
        await interface.asubmit(amethod, probe_delay=-1)

    with Ignore(ValueError, if_else=violation(problem)):
        interface.submit(method, probe_delay=-1)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
