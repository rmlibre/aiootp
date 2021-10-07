# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["__all__", "test_misc_functionality"]


from init_tests import *


async def async_tests():
    entropy = await arandom_512(rounds=1)
    assert len(entropy) == 64
    assert entropy.__class__ is bytes

    entropy = await arandom_256(entropy="test", rounds=1)
    assert len(entropy) == 32
    assert entropy.__class__ is bytes

    assert len(await acsprng(None)) == 64
    assert len(await acsprng("test")) == 64

    prime = await randoms.PrimeTools.acreate_prime(128)
    assert prime.bit_length() == 128
    assert randoms.PrimeTools.is_prime(prime)

    prng = randoms.WeakEntropy()
    weak_entropy = await prng.atoken_bytes(128)
    assert len(weak_entropy) == 128
    assert weak_entropy.__class__ is bytes

    uuid_salt = await agenerate_key(size=64)
    uuids = await amake_uuids(size=32, salt=uuid_salt).aprime()
    uuid = await uuids("test@user.org")
    assert uuid == await uuids("test@user.org")
    assert uuid != await uuids("test2@user.org")
    assert len(uuid) == 32
    assert uuid.__class__ is bytes
    assert uuid_salt == await uuids.aresult(exit=True)


def sync_tests():
    entropy = random_512(rounds=1)
    assert len(entropy) == 64
    assert entropy.__class__ is bytes

    entropy = random_256(entropy="test", rounds=1)
    assert len(entropy) == 32
    assert entropy.__class__ is bytes

    assert len(csprng(None)) == 64
    assert len(csprng("test")) == 64

    prime = randoms.PrimeTools.create_prime(128)
    assert prime.bit_length() == 128
    assert randoms.PrimeTools.is_prime(prime)
    assert randoms.PrimeTools.next_prime(prime) > prime
    assert randoms.PrimeTools.prev_prime(prime) < prime

    prng = randoms.WeakEntropy()
    weak_entropy = prng.token_bytes(128)
    assert len(weak_entropy) == 128
    assert weak_entropy.__class__ is bytes

    uuid_salt = generate_key(size=64)
    uuids = make_uuids(size=32, salt=uuid_salt).prime()
    uuid = uuids("test@user.org")
    assert uuid == uuids("test@user.org")
    assert uuid != uuids("test2@user.org")
    assert len(uuid) == 32
    assert uuid_salt == uuids.result(exit=True)


def test_misc_functionality():
    run(async_tests())
    sync_tests()

