# This file is part of aiootp, an asynchronous crypto and anonymity
# library. Home of the Chunky2048 psuedo one-time pad stream cipher.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


async def test_mnemonic():
    phrase6 = b"-".join(mnemonic(key, 6, **passcrypt_settings))
    aphrase6 = b"-".join(await amnemonic(key, 6, **passcrypt_settings))
    assert all((word in WORD_LIST) for word in phrase6.lower().split(b"-"))
    assert phrase6 == aphrase6
    assert len(phrase6.split(b"-")) == 6

    phrase12 = b"-".join(mnemonic(key, 12, **passcrypt_settings)).title()
    aphrase12 = b"-".join(await amnemonic(key, 12, **passcrypt_settings)).title()
    assert all((word in WORD_LIST) for word in phrase12.lower().split(b"-"))
    assert phrase12 == aphrase12
    assert len(phrase12.split(b"-")) == 12


    problem = "Can supply passcrypt settings to sync mnemonic when not given passphrase"
    with ignore(ValueError, if_else=violation(problem)) as relay:
        phrase12 = b"-".join(mnemonic(size=12, **passcrypt_settings)).title()
    assert "parameters are not used" in relay.error.args[0]

    problem = "Can supply passcrypt settings to async mnemonic when not given passphrase"
    with ignore(ValueError, if_else=violation(problem)) as relay:
        aphrase12 = b"-".join(await amnemonic(size=12, **passcrypt_settings)).title()
    assert "parameters are not used" in relay.error.args[0]


    assert mnemonic() != await amnemonic()


async def test_DomainKDF():
    # additional optional data can be added to hashing methods
    kdf = DomainKDF(b"test", key=key)
    test_data = (b"input tests", token_bytes(32), token_bytes(32))

    problem = "empty kdf updates were allowed!"
    with ignore(ValueError, if_else=violation(problem)):
        await kdf.aupdate()
    with ignore(ValueError, if_else=violation(problem)):
        kdf.update()

    # async and sync methods produce the same outputs given the same inputs
    assert kdf.sha3_256(*test_data) == await kdf.asha3_256(*test_data)
    assert kdf.sha3_512(*test_data) == await kdf.asha3_512(*test_data)
    assert kdf.shake_128(32, *test_data) == await kdf.ashake_128(32, *test_data)
    assert kdf.shake_256(32, *test_data) == await kdf.ashake_256(32, *test_data)

    # hashing methods produce different outputs given the different inputs
    assert kdf.sha3_256() != await kdf.asha3_256(*test_data)
    assert kdf.sha3_512() != await kdf.asha3_512(*test_data)
    assert kdf.shake_128(32) != await kdf.ashake_128(32, *test_data)
    assert kdf.shake_256(32) != await kdf.ashake_256(32, *test_data)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

