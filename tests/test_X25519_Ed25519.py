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


OTHER_TYPE_MAPPING = {Ed25519.__name__: X25519, X25519.__name__: Ed25519}


async def basic_async_tests(tested_class):
    secret_key_a = await tested_class().agenerate()

    problem = (
        "An invalid type was allowed to be imported as a secret key."
    )
    class_not_being_tested = OTHER_TYPE_MAPPING[tested_class.__name__]
    some_secret_key = class_not_being_tested().generate()
    async with Ignore(TypeError, if_else=violation(problem)):
        await tested_class().aimport_secret_key(some_secret_key.secret_key)
    async with Ignore(TypeError, if_else=violation(problem)):
        await tested_class().aimport_secret_key(some_secret_key.public_key)

    problem = (
        "An invalid type was allowed to be imported as a public key."
    )
    some_public_key = class_not_being_tested().import_public_key(some_secret_key.public_key)
    async with Ignore(TypeError, if_else=violation(problem)):
        await tested_class().aimport_secret_key(some_public_key.public_key)

    # Testing equality of async constructors
    key_a_from_secret_object = await tested_class().aimport_secret_key(secret_key_a.secret_key)
    key_a_from_secret_bytes = await tested_class().aimport_secret_key(secret_key_a.secret_bytes)

    key_a_from_public_object = await tested_class().aimport_public_key(secret_key_a.public_key)
    key_a_from_public_bytes = await tested_class().aimport_public_key(secret_key_a.public_bytes)

    problem = (
        "A falsey value secret key import didn't fail."
    )
    async with Ignore(ValueError, if_else=violation(problem)):
        await tested_class().aimport_secret_key(b"")

    problem = (
        "A non-key type secret key import didn't fail."
    )
    for non_key_type in (None, "", 0):
        async with Ignore(TypeError, if_else=violation(problem)):
            await tested_class().aimport_secret_key(non_key_type)

    problem = (
        "An invalid length secret key import didn't fail."
    )
    for invalid_length in (1, 16, 31, 33, 48, 64):
        async with Ignore(ValueError, if_else=violation(problem)):
            await tested_class().aimport_secret_key(token_bytes(invalid_length))

    problem = (
        "A falsey value public key import didn't fail."
    )
    async with Ignore(ValueError, if_else=violation(problem)):
        await tested_class().aimport_public_key(b"")

    problem = (
        "A non-key type public key import didn't fail."
    )
    for falsey_value in (None, "", 0):
        async with Ignore(TypeError, if_else=violation(problem)):
            await tested_class().aimport_public_key(falsey_value)

    problem = (
        "An invalid length public key import didn't fail."
    )
    for invalid_length in (1, 16, 31, 33, 48, 64):
        async with Ignore(ValueError, if_else=violation(problem)):
            await tested_class().aimport_public_key(token_bytes(invalid_length))

    assert len(secret_key_a.public_bytes) == 32
    assert len(secret_key_a.secret_bytes) == 32
    assert type(key_a_from_public_object.public_key) == type(key_a_from_secret_object.public_key)
    assert type(key_a_from_public_object.public_bytes) is bytes
    assert type(key_a_from_public_bytes.public_bytes) is bytes
    assert key_a_from_public_object.public_bytes == key_a_from_secret_object.public_bytes
    assert key_a_from_public_bytes.public_bytes == key_a_from_secret_bytes.public_bytes
    assert secret_key_a.secret_bytes == key_a_from_secret_object.secret_bytes
    assert secret_key_a.secret_bytes == key_a_from_secret_bytes.secret_bytes
    assert secret_key_a.public_bytes == key_a_from_secret_object.public_bytes
    assert secret_key_a.public_bytes == key_a_from_secret_bytes.public_bytes
    assert secret_key_a.secret_bytes != key_a_from_secret_object.public_bytes
    assert not key_a_from_public_object.has_secret_key()
    assert not key_a_from_public_bytes.has_secret_key()
    assert key_a_from_public_object.has_public_key()
    assert key_a_from_public_bytes.has_public_key()
    assert secret_key_a.has_secret_key()
    assert secret_key_a.has_public_key()

    problem = (
        "Async public key import was allowed when an instance was "
        "already initialized with a key."
    )
    async with Ignore(PermissionError, if_else=violation(problem)):
        await secret_key_a.aimport_public_key(secret_key_a.public_bytes)

    problem = (
        "Async secret key import was allowed when an instance was "
        "already initialized with a key."
    )
    async with Ignore(PermissionError, if_else=violation(problem)):
        await secret_key_a.aimport_secret_key(secret_key_a.secret_bytes)


def basic_sync_tests(tested_class):
    secret_key_b = tested_class().generate()

    # Testing equality of sync constructors
    key_b_from_secret_object = tested_class().import_secret_key(secret_key_b.secret_key)
    key_b_from_secret_bytes = tested_class().import_secret_key(secret_key_b.secret_bytes)

    key_b_from_public_object = tested_class().import_public_key(secret_key_b.public_key)
    key_b_from_public_bytes = tested_class().import_public_key(secret_key_b.public_bytes)

    problem = (
        "A falsey value secret key import didn't fail."
    )
    with Ignore(ValueError, if_else=violation(problem)):
        tested_class().import_secret_key(b"")

    problem = (
        "A non-key type secret key import didn't fail."
    )
    for non_key_type in (None, "", 0):
        with Ignore(TypeError, if_else=violation(problem)):
            tested_class().import_secret_key(non_key_type)

    problem = (
        "An invalid length secret key import didn't fail."
    )
    for invalid_length in (1, 16, 31, 33, 48, 64):
        with Ignore(ValueError, if_else=violation(problem)):
            tested_class().import_secret_key(token_bytes(invalid_length))

    problem = (
        "A falsey value public key import didn't fail."
    )
    with Ignore(ValueError, if_else=violation(problem)):
        tested_class().import_public_key(b"")

    problem = (
        "A non-key type public key import didn't fail."
    )
    for falsey_value in (None, "", 0):
        with Ignore(TypeError, if_else=violation(problem)):
            tested_class().import_public_key(falsey_value)

    problem = (
        "An invalid length public key import didn't fail."
    )
    for invalid_length in (1, 16, 31, 33, 48, 64):
        with Ignore(ValueError, if_else=violation(problem)):
            tested_class().import_public_key(token_bytes(invalid_length))

    assert len(secret_key_b.public_bytes) == 32
    assert len(secret_key_b.secret_bytes) == 32
    assert type(key_b_from_public_object.public_key) == type(key_b_from_secret_object.public_key)
    assert type(key_b_from_public_object.public_bytes) is bytes
    assert type(key_b_from_public_bytes.public_bytes) is bytes
    assert key_b_from_public_object.public_bytes == key_b_from_secret_object.public_bytes
    assert key_b_from_public_bytes.public_bytes == key_b_from_secret_bytes.public_bytes
    assert secret_key_b.secret_bytes == key_b_from_secret_object.secret_bytes
    assert secret_key_b.secret_bytes == key_b_from_secret_bytes.secret_bytes
    assert secret_key_b.public_bytes == key_b_from_secret_object.public_bytes
    assert secret_key_b.public_bytes == key_b_from_secret_bytes.public_bytes
    assert secret_key_b.secret_bytes != key_b_from_secret_object.public_bytes
    assert not key_b_from_public_object.has_secret_key()
    assert not key_b_from_public_bytes.has_secret_key()
    assert key_b_from_public_object.has_public_key()
    assert key_b_from_public_bytes.has_public_key()
    assert secret_key_b.has_secret_key()
    assert secret_key_b.has_public_key()

    problem = (
        "Sync public key import was allowed when an instance was "
        "already initialized with a key."
    )
    with Ignore(PermissionError, if_else=violation(problem)):
        secret_key_b.import_public_key(secret_key_b.public_bytes)

    problem = (
        "Sync secret key import was allowed when an instance was "
        "already initialized with a key."
    )
    with Ignore(PermissionError, if_else=violation(problem)):
        secret_key_b.import_secret_key(secret_key_b.secret_bytes)


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
    # public key object
    shared_key_a = secret_key_a.exchange(secret_key_b.public_key)
    shared_key_b = secret_key_b.exchange(secret_key_a.public_key)
    assert bytes_are_equal(shared_key_a, shared_key_b)

    shared_key_a = await secret_key_a.aexchange(secret_key_b.public_key)
    shared_key_b = await secret_key_b.aexchange(secret_key_a.public_key)
    assert await abytes_are_equal(shared_key_a, shared_key_b)

    # exchange methods create shared keys from different instances'
    # secret key object
    problem = (
        "A secret key was used in an interface expecting a public key."
    )
    with Ignore(TypeError, if_else=violation(problem)):
        secret_key_a.exchange(secret_key_b.secret_key)
    with Ignore(TypeError, if_else=violation(problem)):
        secret_key_b.exchange(secret_key_a.secret_key)

    with Ignore(TypeError, if_else=violation(problem)):
        await secret_key_a.aexchange(secret_key_b.secret_key)
    with Ignore(TypeError, if_else=violation(problem)):
        await secret_key_b.aexchange(secret_key_a.secret_key)


class TestDiffieHellmanProtocols:

    async def test_non_kex_types_throw_error_in_kex_protocol_inits(
        self
    ) -> None:
        problem = (
            "A non-key exchange type was supplied during init & didn't fail."
        )
        for non_key_type in (dict, str, int, bytes, t.Namespace, Ed25519):
            async with Ignore(TypeError, if_else=violation(problem)):
                t.DoubleDiffieHellmanClient(non_key_type, kdf_type=DomainKDF)
            async with Ignore(TypeError, if_else=violation(problem)):
                t.DoubleDiffieHellmanServer(non_key_type(), kdf_type=DomainKDF)
            async with Ignore(TypeError, if_else=violation(problem)):
                t.TripleDiffieHellmanClient(non_key_type(), kdf_type=DomainKDF)
            async with Ignore(TypeError, if_else=violation(problem)):
                t.TripleDiffieHellmanServer(non_key_type(), kdf_type=DomainKDF)

    async def test_non_kdf_types_throw_error_in_kex_protocol_inits(
        self
    ) -> None:
        problem = (
            "A non-KDF type was supplied during init & didn't fail."
        )
        my_identity_key = X25519().generate()
        for non_kdf_type in (dict, str, int, bytes, t.Namespace, Ed25519):
            async with Ignore(TypeError, if_else=violation(problem)):
                t.DoubleDiffieHellmanClient(X25519, kdf_type=non_kdf_type)
            async with Ignore(TypeError, if_else=violation(problem)):
                t.DoubleDiffieHellmanServer(my_identity_key, kdf_type=non_kdf_type)
            async with Ignore(TypeError, if_else=violation(problem)):
                t.TripleDiffieHellmanClient(my_identity_key, kdf_type=non_kdf_type)
            async with Ignore(TypeError, if_else=violation(problem)):
                t.TripleDiffieHellmanServer(my_identity_key, kdf_type=non_kdf_type)

    async def test_async_double_diffie_hellman(self) -> None:
        server_key = await X25519().agenerate()
        client = X25519.dh2_client()
        server = server_key.dh2_server()

        client_ephemeral_key = await client.asend(server_key.public_bytes)
        server_kdf = await server.areceive(client_ephemeral_key)
        server_ephemeral_key = await server.asend()
        client_kdf = await client.areceive(server_ephemeral_key)
        assert client_kdf.sha3_512() == server_kdf.sha3_512()

    async def test_sync_double_diffie_hellman(self) -> None:
        server_key = X25519().generate()
        client = X25519.dh2_client()
        server = server_key.dh2_server()

        client_ephemeral_key = client.send(server_key.public_bytes)
        server_kdf = server.receive(client_ephemeral_key)
        server_ephemeral_key = server.send()
        client_kdf = client.receive(server_ephemeral_key)
        assert client_kdf.sha3_512() == server_kdf.sha3_512()

    async def test_async_triple_diffie_hellman(self) -> None:
        client_key = await X25519().agenerate()
        server_key = await X25519().agenerate()
        client = client_key.dh3_client()
        server = server_key.dh3_server()

        client_identity_key, client_ephemeral_key = await client.asend(server_key.public_bytes)
        server_kdf = await server.areceive(client_identity_key, client_ephemeral_key)
        server_ephemeral_key = await server.asend()
        client_kdf = await client.areceive(server_ephemeral_key)
        assert client_kdf.sha3_512() == server_kdf.sha3_512()

    async def test_sync_triple_diffie_hellman(self) -> None:
        client_key = X25519().generate()
        server_key = X25519().generate()
        client = client_key.dh3_client()
        server = server_key.dh3_server()

        client_identity_key, client_ephemeral_key = client.send(server_key.public_bytes)
        server_kdf = server.receive(client_identity_key, client_ephemeral_key)
        server_ephemeral_key = server.send()
        client_kdf = client.receive(server_ephemeral_key)
        assert client_kdf.sha3_512() == server_kdf.sha3_512()

    async def test_double_diffie_hellman_interop(self) -> None:
        server_key = await X25519().agenerate()
        client = X25519.dh2_client()
        server = server_key.dh2_server()

        client_ephemeral_key = client.send(server_key.public_bytes)
        server_kdf = await server.areceive(client_ephemeral_key)
        server_ephemeral_key = await server.asend()
        client_kdf = client.receive(server_ephemeral_key)
        assert client_kdf.sha3_512() == server_kdf.sha3_512()

        client = X25519.dh2_client()
        server = server_key.dh2_server()

        client_ephemeral_key = await client.asend(server_key.public_bytes)
        server_kdf = server.receive(client_ephemeral_key)
        server_ephemeral_key = server.send()
        client_kdf = await client.areceive(server_ephemeral_key)
        assert client_kdf.sha3_512() == server_kdf.sha3_512()

    async def test_triple_diffie_hellman_interop(self) -> None:
        client_key = await X25519().agenerate()
        server_key = await X25519().agenerate()
        client = client_key.dh3_client()
        server = server_key.dh3_server()

        client_identity_key, client_ephemeral_key = client.send(server_key.public_bytes)
        server_kdf = await server.areceive(client_identity_key, client_ephemeral_key)
        server_ephemeral_key = await server.asend()
        client_kdf = client.receive(server_ephemeral_key)
        assert client_kdf.sha3_512() == server_kdf.sha3_512()

        client = client_key.dh3_client()
        server = server_key.dh3_server()

        client_identity_key, client_ephemeral_key = await client.asend(server_key.public_bytes)
        server_kdf = server.receive(client_identity_key, client_ephemeral_key)
        server_ephemeral_key = server.send()
        client_kdf = await client.areceive(server_ephemeral_key)
        assert client_kdf.sha3_512() == server_kdf.sha3_512()


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
    problem = (
        "Async verification succeeded for an invalid signature."
    )
    async with Ignore(Ed25519.InvalidSignature, if_else=violation(problem)):
        await key_a_verifier.averify(token_bytes(len(async_signature)), plaintext_bytes)
    problem = (
        "Async verification succeeded for an invalid signature."
    )
    async with Ignore(Ed25519.InvalidSignature, if_else=violation(problem)):
        await arbitrary_verifier.averify(token_bytes(len(async_signature)), plaintext_bytes, public_key=secret_key_a.public_bytes)

    # sync verification succeeds when supplied a correct signature & data
    key_b_verifier.verify(signature, plaintext_bytes)
    arbitrary_verifier.verify(signature, plaintext_bytes, public_key=secret_key_b.public_bytes)

    # sync verification succeeds when supplied an incorrect signature & data
    problem = (
        "Verification succeeded for an invalid signature."
    )
    with Ignore(Ed25519.InvalidSignature, if_else=violation(problem)):
        key_a_verifier.verify(token_bytes(len(async_signature)), plaintext_bytes)
    problem = (
        "Verification succeeded for an invalid signature."
    )
    with Ignore(Ed25519.InvalidSignature, if_else=violation(problem)):
        arbitrary_verifier.verify(token_bytes(len(async_signature)), plaintext_bytes, public_key=secret_key_a.public_bytes)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

