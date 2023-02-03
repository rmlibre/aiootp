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


async def test_xttl_functionality():
    delta = clock.delta(time_start)
    if delta < 2:
        asynchs.sleep(delta)

    # ciphertext verification fails if the hash has expired
    context = "Life-time for sync json ciphertext is malfunctioning."
    with ignore(TimeoutError, TimestampExpired, if_else=violation(context)):
        cipher.json_decrypt(test_json_ciphertext, aad=aad, ttl=1)

    context = "Life-time for async json ciphertext is malfunctioning."
    async with aignore(TimeoutError, TimestampExpired, if_else=aviolation(context)):
        await cipher.ajson_decrypt(atest_json_ciphertext, aad=aad, ttl=1)

    context = "Life-time for sync tokens is malfunctioning."
    with ignore(TimeoutError, TimestampExpired, if_else=violation(context)):
        cipher.read_token(test_token_ciphertext, aad=aad, ttl=1)

    context = "Life-time for async tokens is malfunctioning."
    async with aignore(TimeoutError, TimestampExpired, if_else=aviolation(context)):
        await cipher.aread_token(atest_token_ciphertext, aad=aad, ttl=1)


    # passcrypt verification fails if the hash has expired
    context = "Life-time for sync passcrypt hashes are malfunctioning."
    with ignore(TimeoutError, TimestampExpired, if_else=violation(context)):
        Passcrypt.verify(expired_passcrypt_hash, passphrase_0, ttl=1)

    context = "Life-time for async passcrypt hashes are malfunctioning."
    async with aignore(TimeoutError, TimestampExpired, if_else=aviolation(context)):
        await Passcrypt.averify(aexpired_passcrypt_hash, passphrase_0, ttl=1)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

