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
         assert all((word in WORD_LIST) for word in phrase)
         assert all((word.__class__ is bytes) for word in phrase)

         aphrase = await amnemonic()
         assert aphrase.__class__ is list
         assert all((word in WORD_LIST) for word in aphrase)
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
            assert phrase == aphrase

    async def test_async_parameters_dictate_functionality(self) -> None:
        problem = (
            "Can supply passcrypt settings to async mnemonic when not given "
            "passphrase."
        )
        with Ignore(ValueError, if_else=violation(problem)) as relay:
            await amnemonic(**passcrypt_settings)
        assert "parameters are not used" in relay.error.args[0]

    async def test_sync_parameters_dictate_functionality(self) -> None:
        problem = (
            "Can supply passcrypt settings to sync mnemonic when not given "
            "passphrase."
        )
        with Ignore(ValueError, if_else=violation(problem)) as relay:
            mnemonic(**passcrypt_settings)
        assert "parameters are not used" in relay.error.args[0]


class TestDomainKDF:
    aad: bytes = b"associated data..."
    domain: bytes = b"domain..."
    data: bytes = b"data..."
    inputs: t.Iterable[bytes] = (csprng(), csprng(), csprng())
    key: bytes = csprng()
    kdf: DomainKDF = DomainKDF(domain, data, key=key)

    async def test_empty_updates_arent_allowed(self) -> None:
        problem = (
            "Empty KDF updates were allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            await self.kdf.aupdate()
        with Ignore(ValueError, if_else=violation(problem)):
            self.kdf.update()

    async def test_update_alters_state_distinctly(self) -> None:
        aupdated_kdf = DomainKDF(self.domain, key=self.key)
        updated_kdf = aupdated_kdf.copy()
        assert await aupdated_kdf.asha3_512(aad=self.aad) == updated_kdf.sha3_512(aad=self.aad)

        initialized_kdf = DomainKDF(self.domain, self.data, key=self.key)

        await aupdated_kdf.aupdate(self.data)
        assert await aupdated_kdf.asha3_512(aad=self.aad) != initialized_kdf.sha3_512(aad=self.aad)

        updated_kdf.update(self.data)
        assert updated_kdf.sha3_512(aad=self.aad) != initialized_kdf.sha3_512(aad=self.aad)

    async def test_same_inputs_produce_same_outputs(self) -> None:
        assert self.kdf.sha3_256(*self.inputs) == await self.kdf.asha3_256(*self.inputs)
        assert self.kdf.sha3_512(*self.inputs) == await self.kdf.asha3_512(*self.inputs)
        assert self.kdf.shake_128(*self.inputs, size=32) == await self.kdf.ashake_128(*self.inputs, size=32)
        assert self.kdf.shake_256(*self.inputs, size=32) == await self.kdf.ashake_256(*self.inputs, size=32)

    async def test_same_aad_produces_same_outputs(self) -> None:
        assert self.kdf.sha3_256(aad=self.aad) == await self.kdf.asha3_256(aad=self.aad)
        assert self.kdf.sha3_512(aad=self.aad) == await self.kdf.asha3_512(aad=self.aad)
        assert self.kdf.shake_128(aad=self.aad, size=32) == await self.kdf.ashake_128(aad=self.aad, size=32)
        assert self.kdf.shake_256(aad=self.aad, size=32) == await self.kdf.ashake_256(aad=self.aad, size=32)

    async def test_different_inputs_produce_different_outputs(self) -> None:
        assert self.kdf.sha3_256() != await self.kdf.asha3_256(*self.inputs)
        assert self.kdf.sha3_512() != await self.kdf.asha3_512(*self.inputs)
        assert self.kdf.shake_128(size=32) != await self.kdf.ashake_128(*self.inputs, size=32)
        assert self.kdf.shake_256(size=32) != await self.kdf.ashake_256(*self.inputs, size=32)

    async def test_different_aad_produces_different_outputs(self) -> None:
        assert self.kdf.sha3_256() != await self.kdf.asha3_256(aad=self.aad)
        assert self.kdf.sha3_512() != await self.kdf.asha3_512(aad=self.aad)
        assert self.kdf.shake_128(size=32) != await self.kdf.ashake_128(aad=self.aad, size=32)
        assert self.kdf.shake_256(size=32) != await self.kdf.ashake_256(aad=self.aad, size=32)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

