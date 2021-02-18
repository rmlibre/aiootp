# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from init_tests import *


__all__ = [
    "test_apasscrypt",
    "test_passcrypt",
    "test_passcrypts_equality",
    "test_passcrypt_generators",
    "test_apasscrypt_generators",
    "__all__",
]


def test_passcrypt():
    for password in passwords:
        for salt in salts:
            passcrypt_passwords.append(
                passcrypt(password, salt, **passcrypt_settings)
            )


def test_apasscrypt():
    for password in passwords:
        for salt in salts:
            apasscrypt_passwords.append(
                run(apasscrypt(password, salt, **passcrypt_settings))
            )


def test_passcrypts_equality():
    assert passcrypt_passwords == apasscrypt_passwords


async def async_generator_run():
    async for _ in adata(plaintext_bytes).apasscrypt(**passcrypt_settings)[0]:
        pass


def test_apasscrypt_generators():
    run(async_generator_run())


def test_passcrypt_generators():
    for _ in data(plaintext_string).passcrypt(**passcrypt_settings)[0]:
        pass

