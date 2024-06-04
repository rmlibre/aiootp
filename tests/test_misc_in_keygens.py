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


import platform

from test_initialization import *


class TestMnemonics:

    async def test_default_is_random(self) -> None:
        assert mnemonic() != await amnemonic()

    async def test_returns_list_of_bytes_words(self) -> None:
         phrase = mnemonic()
         assert phrase.__class__ is list
         assert all((word.__class__ is bytes) for word in phrase)

         aphrase = await amnemonic()
         assert aphrase.__class__ is list
         assert all((word.__class__ is bytes) for word in aphrase)

    async def test_size_dictates_word_count(self) -> None:
        for size in range(6, 12):
            size_word_phrase = mnemonic(size=size)
            asize_word_phrase = await amnemonic(size=size)
            assert size == len(size_word_phrase)
            assert size == len(asize_word_phrase)

    async def test_using_passphrase_is_deterministic(self) -> None:
        is_mac_os_issue = lambda relay: (platform.system() == "Darwin")

        with Ignore(ConnectionRefusedError, if_except=is_mac_os_issue):
            phrase = mnemonic(passphrase, **passcrypt_settings)
            aphrase = await amnemonic(passphrase, **passcrypt_settings)
            assert all((word in WORD_LIST) for word in phrase)
            assert phrase == aphrase

    async def test_async_parameters_dictate_functionality(self) -> None:
        problem = (
            "Can supply passcrypt settings to async mnemonic when not given "
            "passphrase."
        )
        with Ignore(ValueError, if_else=violation(problem)) as relay:
            await amnemonic(size=12, **passcrypt_settings)
        assert "parameters are not used" in relay.error.args[0]

    async def test_sync_parameters_dictate_functionality(self) -> None:
        problem = (
            "Can supply passcrypt settings to sync mnemonic when not given "
            "passphrase."
        )
        with Ignore(ValueError, if_else=violation(problem)) as relay:
            mnemonic(size=12, **passcrypt_settings)
        assert "parameters are not used" in relay.error.args[0]


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

