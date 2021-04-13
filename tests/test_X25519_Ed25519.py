# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from init_tests import *


__all__ = [
    "__all__",
    "test_X25519",
    "test_Ed25519",
]


async def basic_async_tests(tested_class):

    # Testing equality of async constructors
    secret_key_a = await tested_class().agenerate()
    key_a_from_secret_object = await tested_class().aimport_secret_key(secret_key_a.secret_key)
    key_a_from_secret_bytes = await tested_class().aimport_secret_key(secret_key_a.secret_bytes)
    key_a_from_secret_hex = await tested_class().aimport_secret_key(secret_key_a.secret_bytes.hex())

    key_a_from_public_object = await tested_class().aimport_public_key(secret_key_a.public_key)
    key_a_from_public_bytes = await tested_class().aimport_public_key(secret_key_a.public_bytes)
    key_a_from_public_hex = await tested_class().aimport_public_key(secret_key_a.public_bytes.hex())

    assert len(secret_key_a.public_bytes) == 32
    assert len(secret_key_a.secret_bytes) == 32
    assert type(key_a_from_public_object.public_key) == type(key_a_from_secret_object.public_key)
    assert key_a_from_public_bytes.public_bytes == key_a_from_secret_bytes.public_bytes
    assert key_a_from_public_hex.public_bytes.hex() == key_a_from_secret_hex.public_bytes.hex()
    assert secret_key_a.secret_bytes == key_a_from_secret_object.secret_bytes
    assert secret_key_a.secret_bytes == key_a_from_secret_bytes.secret_bytes
    assert secret_key_a.secret_bytes == key_a_from_secret_hex.secret_bytes
    assert secret_key_a.public_bytes == key_a_from_secret_object.public_bytes
    assert secret_key_a.public_bytes == key_a_from_secret_bytes.public_bytes
    assert secret_key_a.public_bytes == key_a_from_secret_hex.public_bytes
    assert not hasattr(key_a_from_public_object, "_secret_key")
    assert not hasattr(key_a_from_public_bytes, "_secret_key")
    assert not hasattr(key_a_from_public_hex, "_secret_key")


def basic_sync_tests(tested_class):

    # Testing equality of sync constructors
    secret_key_b = tested_class().generate()
    key_b_from_secret_object = tested_class().import_secret_key(secret_key_b.secret_key)
    key_b_from_secret_bytes = tested_class().import_secret_key(secret_key_b.secret_bytes)
    key_b_from_secret_hex = tested_class().import_secret_key(secret_key_b.secret_bytes.hex())

    key_b_from_public_object = tested_class().import_public_key(secret_key_b.public_key)
    key_b_from_public_bytes = tested_class().import_public_key(secret_key_b.public_bytes)
    key_b_from_public_hex = tested_class().import_public_key(secret_key_b.public_bytes.hex())

    assert len(secret_key_b.public_bytes) == 32
    assert len(secret_key_b.secret_bytes) == 32
    assert type(key_b_from_public_object.public_key) == type(key_b_from_secret_object.public_key)
    assert key_b_from_public_bytes.public_bytes == key_b_from_secret_bytes.public_bytes
    assert key_b_from_public_hex.public_bytes.hex() == key_b_from_secret_hex.public_bytes.hex()
    assert secret_key_b.secret_bytes == key_b_from_secret_object.secret_bytes
    assert secret_key_b.secret_bytes == key_b_from_secret_bytes.secret_bytes
    assert secret_key_b.secret_bytes == key_b_from_secret_hex.secret_bytes
    assert secret_key_b.public_bytes == key_b_from_secret_object.public_bytes
    assert secret_key_b.public_bytes == key_b_from_secret_bytes.public_bytes
    assert secret_key_b.public_bytes == key_b_from_secret_hex.public_bytes
    assert not hasattr(key_b_from_public_object, "_secret_key")
    assert not hasattr(key_b_from_public_bytes, "_secret_key")
    assert not hasattr(key_b_from_public_hex, "_secret_key")


def test_X25519(database, async_database):
    # Test class constructors
    secret_key_a = run(X25519().agenerate())
    secret_key_b = X25519().generate()
    run(basic_async_tests(X25519))
    basic_sync_tests(X25519)


    # Testing sync protocols
    # 2DH
    peer_key = X25519().generate()
    with secret_key_b.protocols.dh2_client() as client:
        server = peer_key.dh2_server(peer_ephemeral_key=client())
        client(server.exhaust())

    assert client.result().digest() == server.result().digest()

    # 3DH
    with secret_key_b.dh3_client() as client:
        pkB, pkD = client()
        server = peer_key.dh3_server(peer_identity_key=pkB, peer_ephemeral_key=pkD)
        client(server.exhaust())

    assert client.result().digest() == server.result().digest()


    async def testing_async_protocols():

        # 2DH
        peer_key = await X25519().agenerate()
        async with secret_key_b.protocols.adh2_client() as client:
            server = peer_key.adh2_server(peer_ephemeral_key=await client())
            await client(await server.aexhaust())

        assert (await client.aresult()).digest() == (await server.aresult()).digest()

        # 3DH
        async with secret_key_b.adh3_client() as client:
            pkB, pkD = await client()
            server = peer_key.adh3_server(peer_identity_key=pkB, peer_ephemeral_key=pkD)
            await client(await server.aexhaust())

        assert (await client.aresult()).digest() == (await server.aresult()).digest()

    run(testing_async_protocols())


def test_Ed25519(database, async_database):
    # Test class constructors
    secret_key_a = run(Ed25519().agenerate())
    secret_key_b = Ed25519().generate()
    run(basic_async_tests(Ed25519))
    basic_sync_tests(Ed25519)

    async_signature = run(secret_key_a.asign(plaintext_bytes))
    signature = secret_key_b.sign(plaintext_bytes)

    arbitrary_verifier = Ed25519().generate()
    key_a_verifier = run(Ed25519().aimport_public_key(secret_key_a.public_bytes))
    key_b_verifier = Ed25519().import_public_key(secret_key_b.public_bytes)

    run(key_a_verifier.averify(async_signature, plaintext_bytes))
    run(arbitrary_verifier.averify(async_signature, plaintext_bytes, public_key=secret_key_a.public_bytes))

    key_b_verifier.verify(signature, plaintext_bytes)
    arbitrary_verifier.verify(signature, plaintext_bytes, public_key=secret_key_b.public_bytes)

