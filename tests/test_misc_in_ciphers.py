# This file is part of aiootp, an asynchronous pseudo one-time pad based
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


ainvalid_size_datastream = adata(plaintext_bytes, size=257)
invalid_size_datastream = data(plaintext_bytes, size=257)


def test_datastream_limits():
    akey_bundle = run(KeyAADBundle(key=key, salt=salt, aad=aad, allow_dangerous_determinism=True).async_mode())
    key_bundle = KeyAADBundle(key=key, salt=salt, aad=aad, allow_dangerous_determinism=True).sync_mode()
    try:
        run(ainvalid_size_datastream.areset())
        keystream = abytes_keys.root(akey_bundle)
        validator = StreamHMAC(akey_bundle).for_encryption()
        run(ciphers._abytes_xor(ainvalid_size_datastream, key=akey_bundle._keystream, validator=validator)[100]())
    except ValueError as e:
        pass
    else:
        raise AssertionError("A cipher block exceeded 256 bytes", e)

    try:
        invalid_size_datastream.reset()
        keystream = bytes_keys(key_bundle)
        validator = StreamHMAC(key_bundle).for_encryption()
        ciphers._bytes_xor(invalid_size_datastream, key=key_bundle._keystream, validator=validator)[100]()
    except ValueError as e:
        pass
    else:
        raise AssertionError("A cipher block exceeded 256 bytes", e)


def test_keys_limits():
    try:
        key_bundle = KeyAADBundle(key=None)
        assert not key_bundle.key
    except AssertionError as e:
        pass
    else:
        raise AssertionError("A falsey key was not overridden", e)

    try:
        KeyAADBundle(key=csprng().hex())
    except TypeError as e:
        pass
    else:
        raise AssertionError("Non-bytes key was allowed", e)


def test_key_limits():
    try:
        KeyAADBundle(salt=csprng().hex())
    except TypeError as e:
        pass
    else:
        raise AssertionError("Non-bytes salt was allowed", e)

    try:
        KeyAADBundle(salt=csprng())
    except ValueError as e:
        pass
    else:
        raise AssertionError("Invalid length salt was allowed", e)


def test_missing_Passcrypt_lines():
    pcrypt = Passcrypt(**passcrypt_settings)
    pcrypt._passcrypt(key, salt, **passcrypt_settings)
    run(pcrypt._apasscrypt(key, salt, **passcrypt_settings))

    try:
        run(pcrypt.anew(b"", salt))
    except ValueError as e:
        pass
    else:
        raise AssertionError("Empty passphrase was allowed.", e)

    try:
        run(pcrypt.anew(None, salt))
    except TypeError as e:
        pass
    else:
        raise AssertionError("Non-bytes passphrase was allowed.", e)

    try:
        pcrypt.new(key, b"")
    except ValueError as e:
        pass
    else:
        raise AssertionError("Empty salt was allowed.", e)

    try:
        pcrypt.new(key, None)
    except TypeError as e:
        pass
    else:
        raise AssertionError("Non-bytes salt was allowed.", e)

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

