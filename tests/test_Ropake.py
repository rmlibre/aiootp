# This file is part of tiny_onion, a small-as-possible solution for p2p
# networking over tor v3 onion services.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from init_tests import *


__all__ = [
    "__all__",
    "test_Ropake_exchanges",
]


async def async_registration(async_database):
    db = async_database
    await db.ametatag("client")
    await db.ametatag("server")
    await db.asave()
    async with Ropake.aclient_registration(db.client) as client:
        server = Ropake.aserver_registration(await client(), db.server)  # client sends hello
        await client(await server())  # server sends hello response

    with generics.ignore(StopAsyncIteration):
        await server()  # server finishes authenticating client data

    clients_keys = await client.aresult()
    servers_keys = await server.aresult()
    assert len(clients_keys.key) == 128
    assert len(servers_keys.key) == 128
    assert len(clients_keys.key_id) == 128
    assert len(servers_keys.key_id) == 128
    assert len(clients_keys.session_key) == 128
    assert len(servers_keys.session_key) == 128
    assert clients_keys.namespace == servers_keys.namespace

    await db.asave()
    assert (
        db.client[Ropake.KEY] == db.server[servers_keys.key_id][Ropake.KEY]
    )
    assert (
        Ropake._make_commit(db.client._root_key, db.client[Ropake.SALT])
        == db.server[servers_keys.key_id][Ropake.KEYED_PASSWORD]
    )


def registration(database):
    db = database
    db.load(manifest=True)
    with Ropake.client_registration(db.client) as client:
        server = Ropake.server_registration(client(), db.server)  # client sends hello
        client(server())  # server sends hello response

    with generics.ignore(StopIteration):
        server()  # server finishes authenticating client data

    clients_keys = client.result()
    servers_keys = server.result()
    assert len(clients_keys.key) == 128
    assert len(servers_keys.key) == 128
    assert len(clients_keys.key_id) == 128
    assert len(servers_keys.key_id) == 128
    assert len(clients_keys.session_key) == 128
    assert len(servers_keys.session_key) == 128
    assert clients_keys.namespace == servers_keys.namespace

    db.save()
    assert (
        db.client[Ropake.KEY] == db.server[servers_keys.key_id][Ropake.KEY]
    )
    assert (
        Ropake._make_commit(db.client._root_key, db.client[Ropake.SALT])
        == db.server[servers_keys.key_id][Ropake.KEYED_PASSWORD]
    )


async def async_authentication(async_database):
    db = async_database
    await db.aload(manifest=True)
    async with Ropake.aclient(db.client) as client:
        server = Ropake.aserver(await client(), db.server)  # client sends hello
        await client(await server())  # server sends hello response

    with generics.ignore(StopAsyncIteration):
        await server()  # server finishes authenticating client data

    clients_keys = await client.aresult()
    servers_keys = await server.aresult()
    assert len(clients_keys.key) == 128
    assert len(servers_keys.key) == 128
    assert len(clients_keys.key_id) == 128
    assert len(servers_keys.key_id) == 128
    assert len(clients_keys.session_key) == 128
    assert len(servers_keys.session_key) == 128
    assert clients_keys.namespace == servers_keys.namespace

    await db.asave()
    assert (
        db.client[Ropake.KEY] == db.server[servers_keys.key_id][Ropake.KEY]
    )
    assert (
        Ropake._make_commit(db.client._root_key, db.client[Ropake.SALT])
        == db.server[servers_keys.key_id][Ropake.KEYED_PASSWORD]
    )


def authentication(database):
    db = database
    db.load(manifest=True)
    with Ropake.client(db.client) as client:
        server = Ropake.server(client(), db.server)  # client sends hello
        client(server())  # server sends hello response

    with generics.ignore(StopIteration):
        server()  # server finishes authenticating client data

    clients_keys = client.result()
    servers_keys = server.result()
    assert len(clients_keys.key) == 128
    assert len(servers_keys.key) == 128
    assert len(clients_keys.key_id) == 128
    assert len(servers_keys.key_id) == 128
    assert len(clients_keys.session_key) == 128
    assert len(servers_keys.session_key) == 128
    assert clients_keys.namespace == servers_keys.namespace

    db.save()
    assert (
        db.client[Ropake.KEY] == db.server[servers_keys.key_id][Ropake.KEY]
    )
    assert (
        Ropake._make_commit(db.client._root_key, db.client[Ropake.SALT])
        == db.server[servers_keys.key_id][Ropake.KEYED_PASSWORD]
    )


def test_Ropake_exchanges(database, async_database):
    run(async_registration(async_database))
    registration(database)
    run(async_authentication(async_database))
    authentication(database)

