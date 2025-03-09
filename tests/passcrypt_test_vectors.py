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


from aiootp.commons.namespaces import OpenNamespace


passcrypt_test_vector_0 = OpenNamespace(
    mb=2,
    cpu=2,
    cores=2,
    tag_size=257,
    salt_size=256,
    aad=b"",
    timestamp=bytes.fromhex("000a59139c603129"),
    passphrase=b"test vector passphrase I",
    salt=bytes.fromhex(
        "b3c100b7670ef0c9e15bf877a80d78342ab1f6039511d8444ef82ee9f185fd"
        "ff3bebf168f4af41c5d735a2a6a19c8aab2d142353e307968d9d65e33c9424"
        "a51e0b70c4415723d5c72267cd992fd51141c2ce6ae94ccff9945d1b222fc0"
        "0be81504032ab3e51d0ed617d51fee6cfd5c5302bbd7ada60e0f3d45d631f6"
        "a7c4dc47517f20659a1c00f0f371d8a2e09bb247d4493502b4460f3826a094"
        "ac50faa39b8473629ae782d7fb3bb6c69dfaf68a52f06bc3f92d5c88d99a1f"
        "064d377dd894ee14993cf4d72cd78a4401d519a78fca5b2d7b4b6557e75507"
        "ab94021f2fcb29a10d87c0deca93607e339c1dd67d2db939ee926028712073"
        "bff2135410a51bb2"
    ),
    tag=bytes.fromhex(
        "4b3b9a627021735a7a0c2f595bab62135b2fb918711309da9e98e5336fa18a"
        "394e165a9d2a00750d4fd52d4e26562f44d1850327e7e583f1f69b35ea4483"
        "3f00efc01cdfebfeca15f09e377a786ce4a3efa8b0e945f4b07a420bc2c878"
        "c6f29bd2e0dd6156a9575450c913722606cf03bb2f9a951e384e17638a3b16"
        "0cb88199a7c3f099e7be390101e1933662c523e1cd61ba78d77a15607a1b3f"
        "7ec2f53486c8537fccba1da9fff7aac32c65170237b429de52a9f596cc8ea9"
        "95a877503ffd6e04caaef3ceacc1cdc0828243e37d82d263517f5336567a19"
        "54e5515a7a33a820f620b118b74c7089ec1f7c00207659b9b5a737db7cb1ca"
        "aaa01a51b2b8641014"
    ),
    hash_passphrase_result=bytes.fromhex(
        "000a59139c6031290000010101ffb3c100b7670ef0c9e15bf877a80d78342a"
        "b1f6039511d8444ef82ee9f185fdff3bebf168f4af41c5d735a2a6a19c8aab"
        "2d142353e307968d9d65e33c9424a51e0b70c4415723d5c72267cd992fd511"
        "41c2ce6ae94ccff9945d1b222fc00be81504032ab3e51d0ed617d51fee6cfd"
        "5c5302bbd7ada60e0f3d45d631f6a7c4dc47517f20659a1c00f0f371d8a2e0"
        "9bb247d4493502b4460f3826a094ac50faa39b8473629ae782d7fb3bb6c69d"
        "faf68a52f06bc3f92d5c88d99a1f064d377dd894ee14993cf4d72cd78a4401"
        "d519a78fca5b2d7b4b6557e75507ab94021f2fcb29a10d87c0deca93607e33"
        "9c1dd67d2db939ee926028712073bff2135410a51bb24b3b9a627021735a7a"
        "0c2f595bab62135b2fb918711309da9e98e5336fa18a394e165a9d2a00750d"
        "4fd52d4e26562f44d1850327e7e583f1f69b35ea44833f00efc01cdfebfeca"
        "15f09e377a786ce4a3efa8b0e945f4b07a420bc2c878c6f29bd2e0dd6156a9"
        "575450c913722606cf03bb2f9a951e384e17638a3b160cb88199a7c3f099e7"
        "be390101e1933662c523e1cd61ba78d77a15607a1b3f7ec2f53486c8537fcc"
        "ba1da9fff7aac32c65170237b429de52a9f596cc8ea995a877503ffd6e04ca"
        "aef3ceacc1cdc0828243e37d82d263517f5336567a1954e5515a7a33a820f6"
        "20b118b74c7089ec1f7c00207659b9b5a737db7cb1caaaa01a51b2b8641014"
    ),
)


passcrypt_test_vector_1 = OpenNamespace(
    mb=3,
    cpu=3,
    cores=3,
    tag_size=32,
    salt_size=10,
    aad=b"testvector",
    timestamp=bytes.fromhex("000a59328da314c9"),
    passphrase=b"test vector passphrase II",
    salt=bytes.fromhex("ca926bc906fa14b886eb"),
    tag=bytes.fromhex(
        "597dd54fabbeddd3605b3c2bd4ac2c476ac457978ddabf31ccd4a3b8f33942e8"
    ),
    hash_passphrase_result=bytes.fromhex(
        "000a59328da314c9000002020209ca926bc906fa14b886eb597dd54fabbedd"
        "d3605b3c2bd4ac2c476ac457978ddabf31ccd4a3b8f33942e8"
    ),
)


passcrypt_test_vector_2 = OpenNamespace(
    mb=4,
    cpu=4,
    cores=4,
    tag_size=16,
    salt_size=4,
    aad=b"core_cache_change",
    timestamp=bytes.fromhex("000a59529a517df8"),
    passphrase=b"test vector passphrase III",
    salt=bytes.fromhex("80345361"),
    tag=bytes.fromhex("4a9f3a8ad7b60afcdc2400fd3e0f3ff4"),
    hash_passphrase_result=bytes.fromhex(
        "000a59529a517df8000003030303803453614a9f3a8ad7b60afcdc2400fd3e"
        "0f3ff4"
    ),
)


passcrypt_test_vector_3 = OpenNamespace(
    mb=1,
    cpu=5,
    cores=5,
    tag_size=24,
    salt_size=8,
    aad=bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
        "1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d"
        "3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c"
        "5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b"
        "7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a"
        "9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9"
        "babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8"
        "d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7"
        "f8f9fafbfcfdfeff"
    ),
    timestamp=bytes.fromhex("000a59a53cfe5ecd"),
    passphrase=b"test vector passphrase IIII",
    salt=bytes.fromhex("fbd2ee954afb48c3"),
    tag=bytes.fromhex("527a0138c531ea8c027fcad351fd11674c686a16265b5368"),
    hash_passphrase_result=bytes.fromhex(
        "000a59a53cfe5ecd000000040407fbd2ee954afb48c3527a0138c531ea8c02"
        "7fcad351fd11674c686a16265b5368"
    ),
)
