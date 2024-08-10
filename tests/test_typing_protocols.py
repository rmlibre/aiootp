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


from collections import deque

from conftest import *

from aiootp._constants.misc import HASHER_TYPES


class BlankType:
    pass


class ProtocolSubTypeTests:
    async def test_issubclass_at_runtime(self) -> None:
        for type_tested in self.types_tested:
            assert issubclass(type_tested, self.protocol)
            assert not issubclass(BlankType, self.protocol)

    async def test_isinstance_at_runtime(self) -> None:
        for instance_tested in self.instances_tested:
            assert isinstance(instance_tested, self.protocol)
            assert not isinstance(BlankType(), self.protocol)


class TestPaddingType(ProtocolSubTypeTests):
    protocol = t.PaddingType
    types_tested = [t.Padding]
    (config, *_) = randoms.choice(all_ciphers)
    instances_tested = [t.Padding(config)]


class TestStreamHMACTypes(ProtocolSubTypeTests):
    protocol = t.StreamHMACType
    types_tested = []
    instances_tested = []
    for _, cipher, *_ in all_ciphers:
        types_tested.append(cipher._StreamHMAC)
        instances_tested.append(cipher.stream_encrypt().shmac)

    async def test_hasattr_on_properties(self) -> None:
        for instance_tested in self.instances_tested:
            hasattr(instance_tested, "result")


class TestSyntheticIVTypes(ProtocolSubTypeTests):
    protocol = t.SyntheticIVType
    types_tested = []
    instances_tested = []
    for _, cipher, *_ in dual_output_ciphers:
        typ = cipher._Junction._SyntheticIV
        types_tested.append(typ)
        instances_tested.append(typ())


class TestAsyncCipherStreamingTypes(ProtocolSubTypeTests):
    protocol = t.AsyncCipherStreamingType
    types_tested = [t.AsyncCipherStream, t.AsyncDecipherStream]
    (config, cipher, salt, _) = randoms.choice(all_ciphers)
    # fmt: off
    instances_tested = [
        run(t.AsyncCipherStream(cipher)),
        run(t.AsyncDecipherStream(
            cipher, salt=salt, iv=csprng(config.IV_BYTES)
        )),
    ]
    # fmt: on


class TestCipherStreamingTypes(ProtocolSubTypeTests):
    protocol = t.CipherStreamingType
    types_tested = [t.CipherStream, t.DecipherStream]
    (config, cipher, salt, _) = randoms.choice(all_ciphers)
    instances_tested = [
        t.CipherStream(cipher),
        t.DecipherStream(cipher, salt=salt, iv=csprng(config.IV_BYTES)),
    ]


class TestCipherInterfaceTypes(ProtocolSubTypeTests):
    protocol = t.CipherInterfaceType
    types_tested = [cipher.__class__ for (_, cipher, *_) in all_ciphers]
    instances_tested = [type_tested(key) for type_tested in types_tested]


class TestConfigTypes(ProtocolSubTypeTests):
    protocol = t.ConfigType
    types_tested = [config.__class__ for (config, *_) in all_ciphers]
    instances_tested = [config for (config, *_) in all_ciphers]


class TestSupportsPopleftTypes(ProtocolSubTypeTests):
    protocol = t.SupportsPopleft
    types_tested = [deque]
    instances_tested = [type_tested([0, 1]) for type_tested in types_tested]


class TestSupportsAppendPopTypes(ProtocolSubTypeTests):
    protocol = t.SupportsAppendPop
    types_tested = [deque, list]
    instances_tested = [type_tested([0, 1]) for type_tested in types_tested]


class TestSupportsAppendPopleftTypes(ProtocolSubTypeTests):
    protocol = t.SupportsAppendPopleft
    types_tested = [deque]
    instances_tested = [type_tested([0, 1]) for type_tested in types_tested]


class TestHasherTypes(ProtocolSubTypeTests):
    protocol = t.HasherType
    types_tested = [
        config.factory().__class__ for config in HASHER_TYPES.values()
    ]
    instances_tested = [
        config.factory() for config in HASHER_TYPES.values()
    ]


class TestXOFTypes(ProtocolSubTypeTests):
    protocol = t.XOFType
    types_tested = [
        config.factory().__class__
        for config in HASHER_TYPES.values()
        if config.factory().digest_size == 0
    ]
    instances_tested = [
        config.factory()
        for config in HASHER_TYPES.values()
        if config.factory().digest_size == 0
    ]


class TestPermutationTypes(ProtocolSubTypeTests):
    protocol = t.PermutationType
    types_tested = [
        t.AffinePermutation,
        t.AffineXORChain,
        t.FastAffineXORChain,
    ]
    instances_tested = [
        type_tested(key=csprng(type_tested.key_size(16)), config_id=16)
        for type_tested in types_tested
    ]


class TestPoolExecutorTypes(ProtocolSubTypeTests):
    protocol = t.PoolExecutorType
    types_tested = [t.Processes._pool.__class__, t.Threads._pool.__class__]
    instances_tested = [t.Processes._pool, t.Threads._pool]


class TestAsyncDatabaseType(ProtocolSubTypeTests):
    protocol = t.AsyncDatabaseType
    types_tested = [AsyncDatabase]
    instances_tested = [
        run(type_tested(key)) for type_tested in types_tested
    ]


class TestDatabaseType(ProtocolSubTypeTests):
    protocol = t.DatabaseType
    types_tested = [Database]
    instances_tested = [type_tested(key) for type_tested in types_tested]


class TestDomainKDFTypes(ProtocolSubTypeTests):
    protocol = t.DomainKDFType
    types_tested = [DomainKDF, t.DBKDF]
    instances_tested = [
        type_tested(b"test-domain", key=key) for type_tested in types_tested
    ]


class TestPublicKeyTypes(ProtocolSubTypeTests):
    protocol = t.PublicKeyType
    instances_tested = [
        typ().generate().public_key for typ in (X25519, Ed25519)
    ]
    types_tested = [
        instance_tested.__class__ for instance_tested in instances_tested
    ]


class TestSecretKeyTypes(ProtocolSubTypeTests):
    protocol = t.SecretKeyType
    instances_tested = [
        typ().generate().secret_key for typ in (X25519, Ed25519)
    ]
    types_tested = [
        instance_tested.__class__ for instance_tested in instances_tested
    ]


class TestAsymmetricKeyTypes(ProtocolSubTypeTests):
    protocol = t.AsymmetricKeyType
    instances_tested = [
        X25519(),
        Ed25519(),
        X25519().generate(),
        Ed25519().generate(),
    ]
    types_tested = [
        instance_tested.__class__ for instance_tested in instances_tested
    ]


class TestSignerTypes(ProtocolSubTypeTests):
    protocol = t.SignerType
    instances_tested = [Ed25519(), Ed25519().generate()]
    types_tested = [
        instance_tested.__class__ for instance_tested in instances_tested
    ]


class TestKeyExchangeTypes(ProtocolSubTypeTests):
    protocol = t.KeyExchangeType
    instances_tested = [X25519(), X25519().generate()]
    types_tested = [
        instance_tested.__class__ for instance_tested in instances_tested
    ]


class TestKeyExchangeProtocolTypes(ProtocolSubTypeTests):
    protocol = t.KeyExchangeProtocolType
    key = X25519()
    instances_tested = [
        X25519.dh2_client(),
        key.dh2_server(),
        key.dh3_client(),
        key.dh3_server(),
    ]
    types_tested = [
        instance_tested.__class__ for instance_tested in instances_tested
    ]


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
