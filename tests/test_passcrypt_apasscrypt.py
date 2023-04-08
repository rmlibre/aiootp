# This file is part of aiootp, an asynchronous crypto and anonymity
# library. Home of the Chunky2048 psuedo one-time pad stream cipher.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


async def test_metadata_hashes():
    passphrase = b"a generic passphrase 123456"
    pcrypt = Passcrypt(**passcrypt_settings)
    ametadata_hash = await pcrypt.ahash_passphrase(passphrase)
    metadata_hash = pcrypt.hash_passphrase(passphrase)


    # unique hashes are created
    assert metadata_hash != ametadata_hash


    # bytes are produced
    assert type(ametadata_hash) == bytes
    assert type(metadata_hash) == bytes


    # no difference in length between async & sync
    assert len(ametadata_hash) == len(ametadata_hash)
    assert len(metadata_hash) == len(ametadata_hash)


    # reconstructing a hash from specification works in sync
    pcrypt_hash = PasscryptHash().import_hash(metadata_hash)
    hash_check = Passcrypt.new(
        passphrase,
        pcrypt_hash.salt,
        aad=pcrypt_hash.timestamp,
        mb=pcrypt_hash.mb,
        cpu=pcrypt_hash.cpu,
        cores=pcrypt_hash.cores,
        tag_size=pcrypt_hash.tag_size,
    )
    assert pcrypt_hash.tag_size == len(hash_check)
    assert hash_check == metadata_hash[-pcrypt_hash.tag_size:]
    assert hash_check == await Passcrypt.anew(
        passphrase,
        pcrypt_hash.salt,
        aad=pcrypt_hash.timestamp,
        mb=pcrypt_hash.mb,
        cpu=pcrypt_hash.cpu,
        cores=pcrypt_hash.cores,
        tag_size=pcrypt_hash.tag_size,
    )


    # reconstructing a hash from specification works in async
    apcrypt_hash = PasscryptHash().import_hash(ametadata_hash)
    ahash_check = await Passcrypt.anew(
        passphrase,
        apcrypt_hash.salt,
        aad=apcrypt_hash.timestamp,
        mb=apcrypt_hash.mb,
        cpu=apcrypt_hash.cpu,
        cores=apcrypt_hash.cores,
        tag_size=apcrypt_hash.tag_size,
    )
    assert apcrypt_hash.tag_size == len(ahash_check)
    assert ahash_check == ametadata_hash[-apcrypt_hash.tag_size:]
    assert ahash_check == Passcrypt.new(
        passphrase,
        apcrypt_hash.salt,
        aad=apcrypt_hash.timestamp,
        mb=apcrypt_hash.mb,
        cpu=apcrypt_hash.cpu,
        cores=apcrypt_hash.cores,
        tag_size=apcrypt_hash.tag_size,
    )


    # verification passes
    pcrypt.verify(metadata_hash, passphrase)
    await pcrypt.averify(ametadata_hash, passphrase)


    # verification fails given a different passphrase
    context = "An invalid passphrase passed sync verification!"
    with ignore(Passcrypt.InvalidPassphrase, if_else=violation(context)):
        pcrypt.verify(metadata_hash, passphrase + b"\x00")

    context = "An invalid passphrase passed async verification!"
    with ignore(Passcrypt.InvalidPassphrase, if_else=violation(context)):
        await pcrypt.averify(ametadata_hash, passphrase + b"\x00")


    # mb resource limits are respected
    mb_allowed = passcrypt_settings.mb
    context = f"The `mb` was allowed to exceed the resource limit of {mb_allowed - 1}"
    with ignore(ResourceWarning, if_else=violation(context)):
        pcrypt.verify(metadata_hash, passphrase, mb_allowed=range(1, mb_allowed - 1))

    context = f"The `mb` was allowed to fall below the resource limit of {mb_allowed + 1}"
    with ignore(ResourceWarning, if_else=violation(context)):
        pcrypt.verify(metadata_hash, passphrase, mb_allowed=range(mb_allowed + 1, mb_allowed + 2))


    # cpu resource limits are respected
    cpu_allowed = passcrypt_settings.cpu
    context = f"The `cpu` was allowed to exceed the resource limit of {cpu_allowed - 1}"
    with ignore(ResourceWarning, if_else=violation(context)):
        pcrypt.verify(metadata_hash, passphrase, cpu_allowed=range(256, cpu_allowed - 1))

    context = f"The `cpu` was allowed to fall below the resource limit of {cpu_allowed + 1}"
    with ignore(ResourceWarning, if_else=violation(context)):
        pcrypt.verify(metadata_hash, passphrase, cpu_allowed=range(cpu_allowed + 1, 257))


    # cores resource limits are respected
    cores_allowed = passcrypt_settings.cores
    context = f"The `cores` was allowed to exceed the resource limit of {cores_allowed - 1}"
    with ignore(ResourceWarning, if_else=violation(context)):
        pcrypt.verify(metadata_hash, passphrase, cores_allowed=range(256, cores_allowed - 1))

    context = f"The `cores` was allowed to fall below the resource limit of {cores_allowed + 1}"
    with ignore(ResourceWarning, if_else=violation(context)):
        pcrypt.verify(metadata_hash, passphrase, cores_allowed=range(cores_allowed + 1, 257))


    # test vectors are recreated correctly
    # test vector #0
    assert passcrypt_test_vector_0.hash_passphrase_result == (
        passcrypt_test_vector_0.timestamp
        + (passcrypt_test_vector_0.mb - 1).to_bytes(MB_BYTES, BIG)
        + (passcrypt_test_vector_0.cpu - 1).to_bytes(CPU_BYTES, BIG)
        + (passcrypt_test_vector_0.cores - 1).to_bytes(CORES_BYTES, BIG)
        + (passcrypt_test_vector_0.salt_size - 1).to_bytes(SALT_SIZE_BYTES, BIG)
        + passcrypt_test_vector_0.salt
        + passcrypt_test_vector_0.tag
    )
    assert passcrypt_test_vector_0.tag == Passcrypt.new(
        passcrypt_test_vector_0.passphrase,
        passcrypt_test_vector_0.salt,
        aad=passcrypt_test_vector_0.timestamp,
        mb=passcrypt_test_vector_0.mb,
        cpu=passcrypt_test_vector_0.cpu,
        cores=passcrypt_test_vector_0.cores,
        tag_size=passcrypt_test_vector_0.tag_size,
    )
    Passcrypt.verify(
        passcrypt_test_vector_0.hash_passphrase_result,
        passcrypt_test_vector_0.passphrase,
    )

    # test vector #1
    assert passcrypt_test_vector_1.hash_passphrase_result == (
        passcrypt_test_vector_1.timestamp
        + (passcrypt_test_vector_1.mb - 1).to_bytes(MB_BYTES, BIG)
        + (passcrypt_test_vector_1.cpu - 1).to_bytes(CPU_BYTES, BIG)
        + (passcrypt_test_vector_1.cores - 1).to_bytes(CORES_BYTES, BIG)
        + (passcrypt_test_vector_1.salt_size - 1).to_bytes(SALT_SIZE_BYTES, BIG)
        + passcrypt_test_vector_1.salt
        + passcrypt_test_vector_1.tag
    )
    assert passcrypt_test_vector_1.tag == Passcrypt.new(
        passcrypt_test_vector_1.passphrase,
        passcrypt_test_vector_1.salt,
        aad=passcrypt_test_vector_1.timestamp + passcrypt_test_vector_1.aad,
        mb=passcrypt_test_vector_1.mb,
        cpu=passcrypt_test_vector_1.cpu,
        cores=passcrypt_test_vector_1.cores,
        tag_size=passcrypt_test_vector_1.tag_size,
    )
    Passcrypt.verify(
        passcrypt_test_vector_1.hash_passphrase_result,
        passcrypt_test_vector_1.passphrase,
        aad=passcrypt_test_vector_1.aad,
    )

    # test vector #2
    assert passcrypt_test_vector_2.hash_passphrase_result == (
        passcrypt_test_vector_2.timestamp
        + (passcrypt_test_vector_2.mb - 1).to_bytes(MB_BYTES, BIG)
        + (passcrypt_test_vector_2.cpu - 1).to_bytes(CPU_BYTES, BIG)
        + (passcrypt_test_vector_2.cores - 1).to_bytes(CORES_BYTES, BIG)
        + (passcrypt_test_vector_2.salt_size - 1).to_bytes(SALT_SIZE_BYTES, BIG)
        + passcrypt_test_vector_2.salt
        + passcrypt_test_vector_2.tag
    )
    assert passcrypt_test_vector_2.tag == Passcrypt.new(
        passcrypt_test_vector_2.passphrase,
        passcrypt_test_vector_2.salt,
        aad=passcrypt_test_vector_2.timestamp + passcrypt_test_vector_2.aad,
        mb=passcrypt_test_vector_2.mb,
        cpu=passcrypt_test_vector_2.cpu,
        cores=passcrypt_test_vector_2.cores,
        tag_size=passcrypt_test_vector_2.tag_size,
    )
    Passcrypt.verify(
        passcrypt_test_vector_2.hash_passphrase_result,
        passcrypt_test_vector_2.passphrase,
        aad=passcrypt_test_vector_2.aad,
    )

    # test vector #3
    assert passcrypt_test_vector_3.hash_passphrase_result == (
        passcrypt_test_vector_3.timestamp
        + (passcrypt_test_vector_3.mb - 1).to_bytes(MB_BYTES, BIG)
        + (passcrypt_test_vector_3.cpu - 1).to_bytes(CPU_BYTES, BIG)
        + (passcrypt_test_vector_3.cores - 1).to_bytes(CORES_BYTES, BIG)
        + (passcrypt_test_vector_3.salt_size - 1).to_bytes(SALT_SIZE_BYTES, BIG)
        + passcrypt_test_vector_3.salt
        + passcrypt_test_vector_3.tag
    )
    assert passcrypt_test_vector_3.tag == Passcrypt.new(
        passcrypt_test_vector_3.passphrase,
        passcrypt_test_vector_3.salt,
        aad=passcrypt_test_vector_3.timestamp + passcrypt_test_vector_3.aad,
        mb=passcrypt_test_vector_3.mb,
        cpu=passcrypt_test_vector_3.cpu,
        cores=passcrypt_test_vector_3.cores,
        tag_size=passcrypt_test_vector_3.tag_size,
    )
    Passcrypt.verify(
        passcrypt_test_vector_3.hash_passphrase_result,
        passcrypt_test_vector_3.passphrase,
        aad=passcrypt_test_vector_3.aad,
    )


async def test_missing_passcrypt_lines():
    s = dict(aad=b"", mb=MIN_MB, cpu=MIN_CPU, cores=MIN_CORES, tag_size=MIN_TAG_SIZE)
    PasscryptSession = Passcrypt._passcrypt.__annotations__["session"]


    # empty passphrase byte-strings are not allowed
    context = "Empty passphrase was allowed."
    with ignore(ValueError, if_else=violation(context)):
        PasscryptSession(b"", salt, **s)

    with ignore(ValueError, if_else=violation(context)):
        Passcrypt.new(b"", salt, **s)

    async with aignore(ValueError, if_else=aviolation(context)):
        await Passcrypt.anew(b"", salt, **s)


    # passphrases below the minimum length are not allowed
    context = "A below minimum length passphrase was allowed."
    with ignore(ValueError, if_else=violation(context)):
        PasscryptSession((MIN_PASSPHRASE_BYTES - 1) * b"p", salt, **s)

    with ignore(ValueError, if_else=violation(context)):
        Passcrypt.new((MIN_PASSPHRASE_BYTES - 1) * b"p", salt, **s)

    async with aignore(ValueError, if_else=aviolation(context)):
        await Passcrypt.anew((MIN_PASSPHRASE_BYTES - 1) * b"p", salt, **s)


    # passphrases must be bytes
    context = "Non-bytes passphrase was allowed."
    with ignore(TypeError, if_else=violation(context)):
        PasscryptSession("a string passphrase", salt, **s)

    with ignore(TypeError, if_else=violation(context)):
        Passcrypt.new("a string passphrase", salt, **s)

    async with aignore(TypeError, if_else=aviolation(context)):
        await Passcrypt.anew("a string passphrase", salt, **s)


    # falsey salts are not allowed in methods which do not auto-generate
    # salts
    context = "Empty salt was allowed."
    with ignore(ValueError, if_else=violation(context)):
        PasscryptSession(key, salt=b"", **s)

    with ignore(ValueError, if_else=violation(context)):
        Passcrypt.new(key, salt=b"", **s)

    async with aignore(ValueError, if_else=aviolation(context)):
        await Passcrypt.anew(key, salt=b"", **s)


    # salts must be bytes
    context = "Non-bytes salt was allowed."
    with ignore(TypeError, if_else=violation(context)):
        PasscryptSession(key, "a string salt here", **s)

    with ignore(TypeError, if_else=violation(context)):
        Passcrypt.new(key, "a string salt here", **s)

    async with aignore(TypeError, if_else=aviolation(context)):
        await Passcrypt.anew(key, "a string salt here", **s)


    # aad values must be bytes
    context = "A non-bytes type `aad` was allowed."
    with ignore(TypeError, if_else=violation(context)):
        PasscryptSession(key, salt, **{**s, "aad": "some string aad"})

    with ignore(TypeError, if_else=violation(context)):
        Passcrypt.new(key, salt, **{**s, "aad": None})

    async with aignore(TypeError, if_else=aviolation(context)):
        await Passcrypt.anew(key, salt, **{**s, "aad": "some string aad"})


    # the mb cost must be at least the default minimum
    context = "A `mb` cost below the minimum was allowed."
    with ignore(ValueError, if_else=violation(context)):
        PasscryptSession(key, salt, **{**s, "mb": MIN_MB - 1})

    with ignore(ValueError, if_else=violation(context)):
        Passcrypt.new(key, salt, **{**s, "mb": MIN_MB - 1})

    async with aignore(ValueError, if_else=aviolation(context)):
        await Passcrypt.anew(key, salt, **{**s, "mb": MIN_MB - 1})


    # the cpu cost must be at least the default minimum
    context = "A `cpu` cost below the minimum was allowed."
    with ignore(ValueError, if_else=violation(context)):
        PasscryptSession(key, salt, **{**s, "cpu": MIN_CPU - 1})

    with ignore(ValueError, if_else=violation(context)):
        Passcrypt.new(key, salt, **{**s, "cpu": MIN_CPU - 1})

    async with aignore(ValueError, if_else=aviolation(context)):
        await Passcrypt.anew(key, salt, **{**s, "cpu": MIN_CPU - 1})


    # the cores cost must be at least the default minimum
    context = "A `cores` cost below the minimum was allowed."
    with ignore(ValueError, if_else=violation(context)):
        PasscryptSession(key, salt, **{**s, "cores": MIN_CORES - 1})

    with ignore(ValueError, if_else=violation(context)):
        Passcrypt.new(key, salt, **{**s, "cores": MIN_CORES - 1})

    async with aignore(ValueError, if_else=aviolation(context)):
        await Passcrypt.anew(key, salt, **{**s, "cores": MIN_CORES - 1})


    # the tag_size must be at least the default minimum
    context = "A `tag_size` below the minimum was allowed."
    with ignore(ValueError, if_else=violation(context)):
        PasscryptSession(key, salt, **{**s, "tag_size": MIN_TAG_SIZE - 1})

    with ignore(ValueError, if_else=violation(context)):
        Passcrypt.new(key, salt, **{**s, "tag_size": MIN_TAG_SIZE - 1})

    async with aignore(ValueError, if_else=aviolation(context)):
        await Passcrypt.anew(key, salt, **{**s, "tag_size": MIN_TAG_SIZE - 1})


    assert len(Passcrypt._passcrypt(PasscryptSession(key, salt, **s))) == MIN_TAG_SIZE


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

