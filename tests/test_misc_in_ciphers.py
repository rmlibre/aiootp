# This file is part of tiny_onion, a small-as-possible solution for p2p
# networking over tor v3 onion services.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "__all__",
    "test_key_limits",
    "test_keys_limits",
    "test_datastream_limits",
    "test_missing_Passcrypt_lines",
]


from init_tests import *


ainvalid_size_datastream = adata(plaintext_string, size=257).aascii_to_int()
invalid_size_datastream = data(plaintext_string, size=257).ascii_to_int()


def test_datastream_limits():
    try:
        run(pad.axor(ainvalid_size_datastream, key=akeys())[100]())
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        pad.xor(invalid_size_datastream, key=keys())[100]()
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        run(pad.abytes_xor(ainvalid_size_datastream, key=abytes_keys())[100]())
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        pad.bytes_xor(invalid_size_datastream, key=bytes_keys())[100]()
    except ValueError:
        pass
    else:
        raise AssertionError


def test_keys_limits():
    try:
        run(akeys(key=None)[100]())
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        keys(key=None)[100]()
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        run(abytes_keys(key=None)[100]())
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        bytes_keys(key=None)[100]()
    except ValueError:
        pass
    else:
        raise AssertionError


def test_key_limits():
    try:
        run(pad.apadding_key(key=None))
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        pad.padding_key(key=None)
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        run(pad.apadding_key(salt=None))
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        pad.padding_key(salt=None)
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        run(pad.apadding_key(salt=csprng()))
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        pad.padding_key(salt=csprng())
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        run(pad.apadding_key(salt=csprbg()))
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        pad.padding_key(salt=csprbg())
    except ValueError:
        pass
    else:
        raise AssertionError


def test_missing_Passcrypt_lines():
    pcrypt = Passcrypt()
    pcrypt(key, salt, **passcrypt_settings)
    pcrypt._passcrypt(key, salt, **passcrypt_settings)
    run(pcrypt(key, salt, aio=True, **passcrypt_settings))
    run(pcrypt._apasscrypt(key, salt, **passcrypt_settings))

    try:
        run(pcrypt(None, salt, aio=True, **passcrypt_settings))
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        pcrypt(key, None, **passcrypt_settings)
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        run(pcrypt(key, salt, aio=True, kb=255, hardness=256))
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        pcrypt(key, salt, kb=256, hardness=255)
    except ValueError:
        pass
    else:
        raise AssertionError

    try:
        pcrypt(key, salt, kb=256, cpu=1, hardness=256)
    except ValueError:
        pass
    else:
        raise AssertionError
