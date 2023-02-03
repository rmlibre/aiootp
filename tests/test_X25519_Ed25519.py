# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


async def basic_async_tests(tested_class):
    secret_key_a = await tested_class().agenerate()

    # the Curve25519 class handles pulling correct values from the
    # cryptography package
    assert (
        secret_key_a.secret_bytes
        == await secret_key_a._Curve25519.asecret_bytes(secret_key_a.secret_key)
    )
    assert (
        secret_key_a.public_bytes
        == await secret_key_a._Curve25519.apublic_bytes(secret_key_a.public_key)
    )

    context = "an invalid type was allowed to be used to extract secret bytes"
    async with aignore(TypeError, if_else=aviolation(context)):
        await secret_key_a._Curve25519.asecret_bytes(secret_key_a.public_key)

    context = "an invalid type was allowed to be used to extract public bytes"
    async with aignore(TypeError, if_else=aviolation(context)):
        await secret_key_a._Curve25519.apublic_bytes(secret_key_a)

    # Testing equality of async constructors
    key_a_from_secret_object = await tested_class().aimport_secret_key(secret_key_a.secret_key)
    key_a_from_secret_bytes = await tested_class().aimport_secret_key(secret_key_a.secret_bytes)
    key_a_from_secret_hex = await tested_class().aimport_secret_key(secret_key_a.secret_bytes.hex())

    key_a_from_public_object = await tested_class().aimport_public_key(secret_key_a.public_key)
    key_a_from_public_bytes = await tested_class().aimport_public_key(secret_key_a.public_bytes)
    key_a_from_public_hex = await tested_class().aimport_public_key(secret_key_a.public_bytes.hex())

    context = "a falsey value secret key import didn't fail!"
    async with aignore(ValueError, if_else=aviolation(context)):
        await tested_class().aimport_secret_key(None)

    context = "a falsey value public key import didn't fail!"
    async with aignore(ValueError, if_else=aviolation(context)):
        await tested_class().aimport_public_key(None)

    assert len(secret_key_a.public_bytes) == 32
    assert len(secret_key_a.secret_bytes) == 32
    assert type(key_a_from_public_object.public_key) == type(key_a_from_secret_object.public_key)
    assert type(key_a_from_public_object.public_bytes) is bytes
    assert type(key_a_from_public_bytes.public_bytes) is bytes
    assert type(key_a_from_public_hex.public_bytes) is bytes
    assert key_a_from_public_object.public_bytes == key_a_from_secret_object.public_bytes
    assert key_a_from_public_bytes.public_bytes == key_a_from_secret_bytes.public_bytes
    assert key_a_from_public_hex.public_bytes == key_a_from_secret_hex.public_bytes
    assert secret_key_a.secret_bytes == key_a_from_secret_object.secret_bytes
    assert secret_key_a.secret_bytes == key_a_from_secret_bytes.secret_bytes
    assert secret_key_a.secret_bytes == key_a_from_secret_hex.secret_bytes
    assert secret_key_a.public_bytes == key_a_from_secret_object.public_bytes
    assert secret_key_a.public_bytes == key_a_from_secret_bytes.public_bytes
    assert secret_key_a.public_bytes == key_a_from_secret_hex.public_bytes
    assert secret_key_a.secret_bytes != key_a_from_secret_object.public_bytes
    assert not key_a_from_public_object.has_secret_key()
    assert not key_a_from_public_bytes.has_secret_key()
    assert not key_a_from_public_hex.has_secret_key()
    assert key_a_from_public_object.has_public_key()
    assert key_a_from_public_bytes.has_public_key()
    assert key_a_from_public_hex.has_public_key()
    assert secret_key_a.has_secret_key()
    assert secret_key_a.has_public_key()

    context = (
        "Async public key import was allowed when an instance was "
        "already initialized with a key!"
    )
    async with aignore(PermissionError, if_else=aviolation(context)) as relay:
        await secret_key_a.aimport_public_key(secret_key_a.public_bytes)
    assert "is already set" in relay.error.args[0]

    context = (
        "Async secret key import was allowed when an instance was "
        "already initialized with a key!"
    )
    async with aignore(PermissionError, if_else=aviolation(context)) as relay:
        await secret_key_a.aimport_secret_key(secret_key_a.secret_bytes)
    assert "is already set" in relay.error.args[0]


def basic_sync_tests(tested_class):
    secret_key_b = tested_class().generate()

    # the Curve25519 class handles pulling correct values from the
    # cryptography package
    assert (
        secret_key_b.secret_bytes
        == secret_key_b._Curve25519.secret_bytes(secret_key_b.secret_key)
    )
    assert (
        secret_key_b.public_bytes
        == secret_key_b._Curve25519.public_bytes(secret_key_b.public_key)
    )

    context = "an invalid type was allowed to be used to extract secret bytes"
    with ignore(TypeError, if_else=violation(context)):
        secret_key_b._Curve25519.secret_bytes(secret_key_b.public_key)

    context = "an invalid type was allowed to be used to extract public bytes"
    with ignore(TypeError, if_else=violation(context)):
        secret_key_b._Curve25519.public_bytes(secret_key_b)

    # Testing equality of sync constructors
    key_b_from_secret_object = tested_class().import_secret_key(secret_key_b.secret_key)
    key_b_from_secret_bytes = tested_class().import_secret_key(secret_key_b.secret_bytes)
    key_b_from_secret_hex = tested_class().import_secret_key(secret_key_b.secret_bytes.hex())

    key_b_from_public_object = tested_class().import_public_key(secret_key_b.public_key)
    key_b_from_public_bytes = tested_class().import_public_key(secret_key_b.public_bytes)
    key_b_from_public_hex = tested_class().import_public_key(secret_key_b.public_bytes.hex())

    context = "a falsey value secret key import didn't fail!"
    with ignore(ValueError, if_else=violation(context)):
        tested_class().import_secret_key(None)

    context = "a falsey value public key import didn't fail!"
    with ignore(ValueError, if_else=violation(context)):
        tested_class().import_public_key(None)

    assert len(secret_key_b.public_bytes) == 32
    assert len(secret_key_b.secret_bytes) == 32
    assert type(key_b_from_public_object.public_key) == type(key_b_from_secret_object.public_key)
    assert type(key_b_from_public_object.public_bytes) is bytes
    assert type(key_b_from_public_bytes.public_bytes) is bytes
    assert type(key_b_from_public_hex.public_bytes) is bytes
    assert key_b_from_public_object.public_bytes == key_b_from_secret_object.public_bytes
    assert key_b_from_public_bytes.public_bytes == key_b_from_secret_bytes.public_bytes
    assert key_b_from_public_hex.public_bytes == key_b_from_secret_hex.public_bytes
    assert secret_key_b.secret_bytes == key_b_from_secret_object.secret_bytes
    assert secret_key_b.secret_bytes == key_b_from_secret_bytes.secret_bytes
    assert secret_key_b.secret_bytes == key_b_from_secret_hex.secret_bytes
    assert secret_key_b.public_bytes == key_b_from_secret_object.public_bytes
    assert secret_key_b.public_bytes == key_b_from_secret_bytes.public_bytes
    assert secret_key_b.public_bytes == key_b_from_secret_hex.public_bytes
    assert secret_key_b.secret_bytes != key_b_from_secret_object.public_bytes
    assert not key_b_from_public_object.has_secret_key()
    assert not key_b_from_public_bytes.has_secret_key()
    assert not key_b_from_public_hex.has_secret_key()
    assert key_b_from_public_object.has_public_key()
    assert key_b_from_public_bytes.has_public_key()
    assert key_b_from_public_hex.has_public_key()
    assert secret_key_b.has_secret_key()
    assert secret_key_b.has_public_key()

    with ignore(PermissionError) as relay:
        secret_key_b.import_public_key(secret_key_b.public_bytes)
    assert "is already set" in relay.error.args[0]

    with ignore(PermissionError) as relay:
        secret_key_b.import_secret_key(secret_key_b.secret_bytes)
    assert "is already set" in relay.error.args[0]


async def test_X25519(database, async_database):
    # Test class constructors
    secret_key_a = await X25519().agenerate()
    secret_key_b = X25519().generate()

    await basic_async_tests(X25519)
    basic_sync_tests(X25519)

    # exchange methods create shared keys from different instances'
    # public bytes
    shared_key_a = secret_key_a.exchange(secret_key_b.public_bytes)
    shared_key_b = secret_key_b.exchange(secret_key_a.public_bytes)
    assert bytes_are_equal(shared_key_a, shared_key_b)

    shared_key_a = await secret_key_a.aexchange(secret_key_b.public_bytes)
    shared_key_b = await secret_key_b.aexchange(secret_key_a.public_bytes)
    assert await abytes_are_equal(shared_key_a, shared_key_b)

    # exchange methods create shared keys from different instances'
    # public hex
    shared_key_a = secret_key_a.exchange(secret_key_b.public_bytes.hex())
    shared_key_b = secret_key_b.exchange(secret_key_a.public_bytes.hex())
    assert bytes_are_equal(shared_key_a, shared_key_b)

    shared_key_a = await secret_key_a.aexchange(secret_key_b.public_bytes.hex())
    shared_key_b = await secret_key_b.aexchange(secret_key_a.public_bytes.hex())
    assert await abytes_are_equal(shared_key_a, shared_key_b)

    # exchange methods create shared keys from different instances'
    # public key object
    shared_key_a = secret_key_a.exchange(secret_key_b.public_key)
    shared_key_b = secret_key_b.exchange(secret_key_a.public_key)
    assert bytes_are_equal(shared_key_a, shared_key_b)

    shared_key_a = await secret_key_a.aexchange(secret_key_b.public_key)
    shared_key_b = await secret_key_b.aexchange(secret_key_a.public_key)
    assert await abytes_are_equal(shared_key_a, shared_key_b)

    # exchange methods create shared keys from different instances'
    # secret key object
    shared_key_a = secret_key_a.exchange(secret_key_b.secret_key)
    shared_key_b = secret_key_b.exchange(secret_key_a.secret_key)
    assert bytes_are_equal(shared_key_a, shared_key_b)

    shared_key_a = await secret_key_a.aexchange(secret_key_b.secret_key)
    shared_key_b = await secret_key_b.aexchange(secret_key_a.secret_key)
    assert await abytes_are_equal(shared_key_a, shared_key_b)

    # Testing protocols
    # SYNC
    # 2DH
    peer_key = X25519().generate()
    with secret_key_b.dh2_client() as client:
        server = peer_key.dh2_server(peer_ephemeral_key=client())
        client(server.exhaust())

    assert client.result().sha3_512() == server.result().sha3_512()

    # 3DH
    with secret_key_b.dh3_client() as client:
        pkB, pkD = client()
        server = peer_key.dh3_server(peer_identity_key=pkB, peer_ephemeral_key=pkD)
        client(server.exhaust())

    assert client.result().sha3_512() == server.result().sha3_512()


    # ASYNC
    # 2DH
    peer_key = await X25519().agenerate()
    async with secret_key_b.adh2_client() as client:
        server = peer_key.adh2_server(peer_ephemeral_key=await client())
        await client(await server.aexhaust())

    assert (await client.aresult()).sha3_512() == (await server.aresult()).sha3_512()

    # 3DH
    async with secret_key_b.adh3_client() as client:
        pkB, pkD = await client()
        server = peer_key.adh3_server(peer_identity_key=pkB, peer_ephemeral_key=pkD)
        await client(await server.aexhaust())

    assert client.result().sha3_512() == server.result().sha3_512()


async def test_Ed25519(database, async_database):
    # Test class constructors
    secret_key_a = await Ed25519().agenerate()
    secret_key_b = Ed25519().generate()

    await basic_async_tests(Ed25519)
    basic_sync_tests(Ed25519)

    async_signature = await secret_key_a.asign(plaintext_bytes)
    signature = secret_key_b.sign(plaintext_bytes)

    arbitrary_verifier = Ed25519().generate()
    key_a_verifier = await Ed25519().aimport_public_key(secret_key_a.public_bytes)
    key_b_verifier = Ed25519().import_public_key(secret_key_b.public_bytes)

    # async verification succeeds when supplied a correct signature & data
    await key_a_verifier.averify(async_signature, plaintext_bytes)
    await arbitrary_verifier.averify(async_signature, plaintext_bytes, public_key=secret_key_a.public_bytes)

    # async verification succeeds when supplied an incorrect signature & data
    context = "Async verification succeeded for an invalid signature!"
    async with aignore(Ed25519.InvalidSignature, if_else=aviolation(context)):
        await key_a_verifier.averify(token_bytes(len(async_signature)), plaintext_bytes)
    context = "Async verification succeeded for an invalid signature!"
    async with aignore(Ed25519.InvalidSignature, if_else=aviolation(context)):
        await arbitrary_verifier.averify(token_bytes(len(async_signature)), plaintext_bytes, public_key=secret_key_a.public_bytes)

    # sync verification succeeds when supplied a correct signature & data
    key_b_verifier.verify(signature, plaintext_bytes)
    arbitrary_verifier.verify(signature, plaintext_bytes, public_key=secret_key_b.public_bytes)

    # sync verification succeeds when supplied an incorrect signature & data
    context = "Verification succeeded for an invalid signature!"
    with ignore(Ed25519.InvalidSignature, if_else=violation(context)):
        key_a_verifier.verify(token_bytes(len(async_signature)), plaintext_bytes)
    context = "Verification succeeded for an invalid signature!"
    with ignore(Ed25519.InvalidSignature, if_else=violation(context)):
        arbitrary_verifier.verify(token_bytes(len(async_signature)), plaintext_bytes, public_key=secret_key_a.public_bytes)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

