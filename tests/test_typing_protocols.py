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


class ProtocolSubTypeTests:

    async def test_issubclass_at_runtime(self) -> None:
        for type_tested in self.types_tested:
            assert issubclass(type_tested, self.protocol)

    async def test_isinstance_at_runtime(self) -> None:
        for instance_tested in self.instances_tested:
            assert isinstance(instance_tested, self.protocol)


class TestPaddingType(ProtocolSubTypeTests):
    (config, *_) = randoms.choice(all_ciphers)
    protocol = t.PaddingType
    types_tested = [t.Padding]
    instances_tested = [t.Padding(config)]


class TestStreamHMACTypes(ProtocolSubTypeTests):
    protocol = t.StreamHMACType
    types_tested = []
    instances_tested = []
    for (config, cipher, salt, _) in all_ciphers:
        types_tested.append(cipher._StreamHMAC)
        instances_tested.append(cipher.stream_encrypt().shmac)

    async def test_hasattr_on_properties(self) -> None:
        for instance_tested in self.instances_tested:
            hasattr(instance_tested, "result")


class TestSyntheticIVTypes(ProtocolSubTypeTests):
    protocol = t.SyntheticIVType
    types_tested = []
    instances_tested = []
    for (config, cipher, salt, _) in dual_output_ciphers:
        typ = cipher._Junction._SyntheticIV
        types_tested.append(typ)
        instances_tested.append(typ())


class TestAsyncCipherStreamingTypes(ProtocolSubTypeTests):
    (config, cipher, salt, _) = randoms.choice(all_ciphers)
    config = cipher._config
    protocol = t.AsyncCipherStreamingType
    types_tested = [t.AsyncCipherStream, t.AsyncDecipherStream]
    instances_tested = [
        run(t.AsyncCipherStream(cipher)),
        run(t.AsyncDecipherStream(cipher, salt=salt, iv=csprng(config.IV_BYTES))),
    ]


class TestCipherStreamingTypes(ProtocolSubTypeTests):
    (config, cipher, salt, _) = randoms.choice(all_ciphers)
    config = cipher._config
    protocol = t.CipherStreamingType
    types_tested = [t.CipherStream, t.DecipherStream]
    instances_tested = [
        t.CipherStream(cipher),
        t.DecipherStream(cipher, salt=salt, iv=csprng(config.IV_BYTES)),
    ]


class TestCipherInterfaceTypes(ProtocolSubTypeTests):
    protocol = t.CipherInterfaceType
    types_tested = [cipher.__class__ for (_, cipher, *_) in all_ciphers]
    instances_tested = [type_tested(key) for type_tested in types_tested]


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

