# This file is part of tiny_onion, a small-as-possible solution for p2p
# networking over tor v3 onion services.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#          © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from init_tests import *


__all__ = [
    "test_apasscrypt",
    "test_passcrypt",
    "test_passcrypts_equality",
    "__all__",
]


password_0 = csprng()
password_1 = randoms.urandom(256)
password_2 = dict(some_data=list(password_1))
passwords = [password_0, password_1, password_2]


salt_0 = csprng()
salt_1 = randoms.urandom(256)
salt_2 = dict(some_data=list(password_1))
salts = [salt_0, salt_1, salt_2]


settings = dict(kb=256, cpu=2, hardness=256)


passcrypt_passwords = []
apasscrypt_passwords = []


def test_passcrypt():
    for password in passwords:
        for salt in salts:
            passcrypt_passwords.append(
                passcrypt(password, salt, **settings)
            )


def test_apasscrypt():
    for password in passwords:
        for salt in salts:
            apasscrypt_passwords.append(
                run(apasscrypt(password, salt, **settings))
            )


def test_passcrypts_equality():
    assert passcrypt_passwords == apasscrypt_passwords

