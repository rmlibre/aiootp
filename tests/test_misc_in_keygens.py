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


    problem = (
        "Can supply passcrypt settings to sync mnemonic when not given "
        "passphrase."
    )
    with Ignore(ValueError, if_else=violation(problem)) as relay:
        phrase12 = b"-".join(mnemonic(size=12, **passcrypt_settings)).title()
    assert "parameters are not used" in relay.error.args[0]

    problem = (
        "Can supply passcrypt settings to async mnemonic when not given "
        "passphrase."
    )
    with Ignore(ValueError, if_else=violation(problem)) as relay:
        aphrase12 = b"-".join(await amnemonic(size=12, **passcrypt_settings)).title()
    assert "parameters are not used" in relay.error.args[0]


    assert mnemonic() != await amnemonic()


class TestDomainKDF:
    aad: bytes = b"associated data..."
    domain: bytes = b"domain..."
    data: bytes = b"data..."
    key: bytes = csprng()

    async def test_update_alters_state_distinctly(self) -> None:
        aupdated_kdf = DomainKDF(self.domain, key=self.key)
        updated_kdf = aupdated_kdf.copy()
        assert await aupdated_kdf.asha3_512(aad=self.aad) == updated_kdf.sha3_512(aad=self.aad)

        initialized_kdf = DomainKDF(self.domain, self.data, key=self.key)

        await aupdated_kdf.aupdate(self.data)
        assert await aupdated_kdf.asha3_512(aad=self.aad) != initialized_kdf.sha3_512(aad=self.aad)

        updated_kdf.update(self.data)
        assert updated_kdf.sha3_512(aad=self.aad) != initialized_kdf.sha3_512(aad=self.aad)



async def test_DomainKDF():
    # additional optional data can be added to hashing methods
    kdf = DomainKDF(b"test", key=key)
    aad = b"testing DomainKDF" + csprng(token_bits(6))
    test_data = (b"input tests", token_bytes(32), token_bytes(32))

    problem = (
        "Empty KDF updates were allowed."
    )
    with Ignore(ValueError, if_else=violation(problem)):
        await kdf.aupdate()
    with Ignore(ValueError, if_else=violation(problem)):
        kdf.update()

    # async and sync methods produce the same outputs given the same inputs
    assert kdf.sha3_256(*test_data) == await kdf.asha3_256(*test_data)
    assert kdf.sha3_512(*test_data) == await kdf.asha3_512(*test_data)
    assert kdf.shake_128(*test_data, size=32) == await kdf.ashake_128(*test_data, size=32)
    assert kdf.shake_256(*test_data, size=32) == await kdf.ashake_256(*test_data, size=32)

    # async and sync methods produce the same outputs given the same aad
    assert kdf.sha3_256(aad=aad) == await kdf.asha3_256(aad=aad)
    assert kdf.sha3_512(aad=aad) == await kdf.asha3_512(aad=aad)
    assert kdf.shake_128(aad=aad, size=32) == await kdf.ashake_128(aad=aad, size=32)
    assert kdf.shake_256(aad=aad, size=32) == await kdf.ashake_256(aad=aad, size=32)

    # hashing methods produce different outputs given the different inputs
    assert kdf.sha3_256() != await kdf.asha3_256(*test_data)
    assert kdf.sha3_512() != await kdf.asha3_512(*test_data)
    assert kdf.shake_128(size=32) != await kdf.ashake_128(*test_data, size=32)
    assert kdf.shake_256(size=32) != await kdf.ashake_256(*test_data, size=32)

    # hashing methods produce different outputs given the different aad
    assert kdf.sha3_256() != await kdf.asha3_256(aad=aad)
    assert kdf.sha3_512() != await kdf.asha3_512(aad=aad)
    assert kdf.shake_128(size=32) != await kdf.ashake_128(aad=aad, size=32)
    assert kdf.shake_256(size=32) != await kdf.ashake_256(aad=aad, size=32)



__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

