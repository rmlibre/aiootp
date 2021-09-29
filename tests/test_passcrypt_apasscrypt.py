# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from init_tests import *


__all__ = [
    "test_metadata_hashes",
    "test_passcrypts_equality",
    "test_passcrypt_generators",
    "test_apasscrypt_generators",
    "__all__",
]


def test_metadata_hashes():
    passphrase = b"a generic passphrase 123456"
    pcrypt = Passcrypt(**passcrypt_settings)
    araw_metadata_hash = run(pcrypt.ahash_passphrase_raw(passphrase))
    raw_metadata_hash = pcrypt.hash_passphrase_raw(passphrase)
    ametadata_hash = run(pcrypt.ahash_passphrase(passphrase))
    metadata_hash = pcrypt.hash_passphrase(passphrase)

    assert raw_metadata_hash != araw_metadata_hash
    assert metadata_hash != ametadata_hash

    assert type(araw_metadata_hash) == bytes
    assert len(araw_metadata_hash) == 106
    assert len(araw_metadata_hash) == len(araw_metadata_hash)
    assert type(raw_metadata_hash) == bytes
    assert len(raw_metadata_hash) == 106
    assert len(raw_metadata_hash) == len(araw_metadata_hash)

    assert type(ametadata_hash) == bytes
    assert len(ametadata_hash) == 148
    assert len(ametadata_hash) == len(ametadata_hash)
    assert type(metadata_hash) == bytes
    assert len(metadata_hash) == 148
    assert len(metadata_hash) == len(ametadata_hash)

    table = list(Tables.URL_SAFE.encode())
    assert b"%3D%3D" == metadata_hash[-6:]
    for char in set(metadata_hash[:-6]):
        assert char in table

    assert b"%3D%3D" == ametadata_hash[-6:]
    for char in set(ametadata_hash[:-6]):
        assert char in table

    kb = int.from_bytes(raw_metadata_hash[:4], "big")
    cpu = int.from_bytes(raw_metadata_hash[4:6], "big")
    hardness = int.from_bytes(raw_metadata_hash[6:10], "big")
    metadata_settings = Namespace(kb=kb, cpu=cpu, hardness=hardness)
    salt = raw_metadata_hash[10:42]
    hash_check = pcrypt.new(passphrase, salt, **metadata_settings)
    assert hash_check == raw_metadata_hash[42:]

    kb = int.from_bytes(araw_metadata_hash[:4], "big")
    cpu = int.from_bytes(araw_metadata_hash[4:6], "big")
    hardness = int.from_bytes(araw_metadata_hash[6:10], "big")
    ametadata_settings = Namespace(kb=kb, cpu=cpu, hardness=hardness)
    salt = araw_metadata_hash[10:42]
    ahash_check = run(pcrypt.anew(passphrase, salt, **ametadata_settings))
    assert ahash_check == araw_metadata_hash[42:]

    assert passcrypt_settings == {**metadata_settings}
    assert {**metadata_settings} == {**ametadata_settings}

    pcrypt.verify(metadata_hash, passphrase)
    run(pcrypt.averify(ametadata_hash, passphrase))
    pcrypt.verify_raw(raw_metadata_hash, passphrase)
    run(pcrypt.averify_raw(araw_metadata_hash, passphrase))


def test_passcrypts_equality():
    assert passcrypt_passphrases == apasscrypt_passphrases


async def async_generator_run():
    async for _ in adata(plaintext_bytes).apasscrypt(**passcrypt_settings)[0]:
        pass


def test_apasscrypt_generators():
    run(async_generator_run())


def test_passcrypt_generators():
    for _ in data(plaintext_bytes).passcrypt(**passcrypt_settings)[0]:
        pass

