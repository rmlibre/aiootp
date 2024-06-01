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


import os
import platform

from test_initialization import *


# NOTE: The tests run in alphabetical order, so a Z is prepended to their
#       names. This way time will naturally pass from the start of the
#       tests to the end, eliminating idle waiting time.


class TestZCipherTimeToLive:

    async def test_async_json_decrypt(self):
        problem = (
            "Life-time for async json ciphertext is malfunctioning."
        )
        with Ignore(TimestampExpired, if_else=violation(problem)) as ignored:
            relay = ignored
            await ttl_test_cipher.cipher.ajson_decrypt(
                atest_json_ciphertext, aad=ttl_test_cipher.aad, ttl=1
            )
        assert relay.error.expired_by >= 1

    async def test_sync_json_decrypt(self):
        problem = (
            "Life-time for sync json ciphertext is malfunctioning."
        )
        with Ignore(TimestampExpired, if_else=violation(problem)) as ignored:
            relay = ignored
            ttl_test_cipher.cipher.json_decrypt(
                test_json_ciphertext, aad=ttl_test_cipher.aad, ttl=1
            )
        assert relay.error.expired_by >= 1

    async def test_async_read_token(self):
        problem = (
            "Life-time for async tokens is malfunctioning."
        )
        with Ignore(TimestampExpired, if_else=violation(problem)) as ignored:
            relay = ignored
            await ttl_test_cipher.cipher.aread_token(
                atest_token_ciphertext, aad=ttl_test_cipher.aad, ttl=1
            )
        assert relay.error.expired_by >= 1

    async def test_sync_read_token(self):
        problem = (
            "Life-time for sync tokens is malfunctioning."
        )
        with Ignore(TimestampExpired, if_else=violation(problem)) as ignored:
            relay = ignored
            ttl_test_cipher.cipher.read_token(
                test_token_ciphertext, aad=ttl_test_cipher.aad, ttl=1
            )
        assert relay.error.expired_by >= 1


class TestZPasscryptTimeToLive:

    async def test_async_verfiy_ttl(self):
        problem = (
            "Life-time for async passcrypt hashes are malfunctioning."
        )
        with Ignore(TimestampExpired, if_else=violation(problem)) as ignored:
            relay = ignored
            await Passcrypt.averify(aexpired_passcrypt_hash, passphrase_0, ttl=1)
        assert relay.error.expired_by >= 1

    async def test_sync_verfiy_ttl(self):
        problem = (
            "Life-time for sync passcrypt hashes are malfunctioning."
        )
        with Ignore(TimestampExpired, if_else=violation(problem)) as ignored:
            relay = ignored
            Passcrypt.verify(expired_passcrypt_hash, passphrase_0, ttl=1)
        assert relay.error.expired_by >= 1


class TestZZZExitTests:

    async def test_zzz_exit_tests(self) -> None:
        """
        The test suite doesn't exit on some platforms. This is part of
        troubleshooting resolutions to such cross-platform errors.
        """
        if platform.system() != "Linux":
            os._exit(0)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

