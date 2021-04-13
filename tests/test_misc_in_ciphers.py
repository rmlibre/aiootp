# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
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
        keystream = akeys(key, salt=salt)
        validator = StreamHMAC(key, salt=salt).for_encryption()
        run(pad.axor(ainvalid_size_datastream, key=keystream, validator=validator)[100]())
    except ValueError as e:
        pass
    else:
        raise AssertionError("A cipher block exceeded 256 bytes", e)

    try:
        keystream = keys(key, salt=salt)
        validator = StreamHMAC(key, salt=salt).for_encryption()
        pad.xor(invalid_size_datastream, key=keystream, validator=validator)[100]()
    except ValueError as e:
        pass
    else:
        raise AssertionError("A cipher block exceeded 256 bytes", e)

    try:
        run(ainvalid_size_datastream.areset())
        keystream = abytes_keys(key, salt=salt)
        validator = StreamHMAC(key, salt=salt).for_encryption()
        run(pad.abytes_xor(ainvalid_size_datastream, key=keystream, validator=validator)[100]())
    except ValueError as e:
        pass
    else:
        raise AssertionError("A cipher block exceeded 256 bytes", e)

    try:
        invalid_size_datastream.reset()
        keystream = bytes_keys(key, salt=salt)
        validator = StreamHMAC(key, salt=salt).for_encryption()
        pad.bytes_xor(invalid_size_datastream, key=keystream, validator=validator)[100]()
    except ValueError as e:
        pass
    else:
        raise AssertionError("A cipher block exceeded 256 bytes", e)


def test_keys_limits():
    try:
        run(akeys(key=None)[100]())
    except ValueError as e:
        pass
    else:
        raise AssertionError("A falsey key was used", e)

    try:
        keys(key=None)[100]()
    except ValueError as e:
        pass
    else:
        raise AssertionError("A falsey key was used", e)

    try:
        run(abytes_keys(key=None)[100]())
    except ValueError as e:
        pass
    else:
        raise AssertionError("A falsey key was used", e)

    try:
        bytes_keys(key=None)[100]()
    except ValueError as e:
        pass
    else:
        raise AssertionError("A falsey key was used", e)


def test_key_limits():
    try:
        run(pad.apadding_key(key=None, salt=salt))
    except ValueError as e:
        pass
    else:
        raise AssertionError("A falsey key was used", e)

    try:
        pad.padding_key(key=None, salt=salt)
    except ValueError as e:
        pass
    else:
        raise AssertionError("A falsey key was used", e)

    try:
        run(pad.apadding_key(salt=None))
    except ValueError as e:
        pass
    else:
        raise AssertionError("A falsey salt was used", e)

    try:
        pad.padding_key(salt=None)
    except ValueError as e:
        pass
    else:
        raise AssertionError("A falsey salt was used", e)

    try:
        run(pad.apadding_key(salt=csprng()))
    except ValueError as e:
        pass
    else:
        raise AssertionError("Salt isn't a 32 byte hex string", e)

    try:
        pad.padding_key(salt=csprng())
    except ValueError as e:
        pass
    else:
        raise AssertionError("Salt isn't a 32 byte hex string", e)

    try:
        run(pad.apadding_key(salt=csprbg()))
    except ValueError as e:
        pass
    else:
        raise AssertionError("Salt isn't a 32 byte hex string", e)

    try:
        pad.padding_key(salt=csprbg())
    except ValueError as e:
        pass
    else:
        raise AssertionError("Salt isn't a 32 byte hex string", e)


def test_missing_Passcrypt_lines():
    pcrypt = Passcrypt(**passcrypt_settings)
    pcrypt.new(key, salt)
    pcrypt._passcrypt(key, salt, **passcrypt_settings)
    run(pcrypt.anew(key, salt))
    run(pcrypt._apasscrypt(key, salt, **passcrypt_settings))

    try:
        run(pcrypt.anew(None, salt))
    except ValueError as e:
        pass
    else:
        raise AssertionError("Empty password was allowed.", e)

    try:
        pcrypt.new(key, None)
    except ValueError as e:
        pass
    else:
        raise AssertionError("Empty salt was allowed.", e)

    try:
        run(pcrypt.anew(key, salt, kb=255, hardness=256))
    except ValueError as e:
        pass
    else:
        raise AssertionError("A `kb` cost below 256 was allowed.", e)

    try:
        pcrypt.new(key, salt, kb=256, hardness=255)
    except ValueError as e:
        pass
    else:
        raise AssertionError("A `hardness` below 256 was allowed.", e)

    try:
        pcrypt.new(key, salt, kb=256, cpu=1, hardness=256)
    except ValueError as e:
        pass
    else:
        raise AssertionError("A `cpu` cost below 2 was allowed.", e)

