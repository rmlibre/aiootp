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


import multiprocessing


try:
    multiprocessing.set_start_method("fork", force=True)
except ValueError:
    multiprocessing.set_start_method("spawn", force=True)
multiprocessing.freeze_support()


import sys
import json
import pytest
import hashlib
import builtins
from pathlib import Path
from functools import partial
from hashlib import sha3_256, sha3_512, shake_128, shake_256


_PACKAGE_PATH = str(Path(__file__).absolute().parent.parent)
sys.path.insert(0, _PACKAGE_PATH)


import aiootp
from aiootp import *
from aiootp._paths import *
from aiootp._typing import *
from aiootp._constants.misc import *
from aiootp._constants.datasets import *
from aiootp._exceptions import *
from aiootp._gentools import aunpack, unpack, batch, abatch
from aiootp._permutations import *
from aiootp._debug_control import DebugControl
from aiootp.commons.slots import Slots, FrozenSlots
from aiootp.commons.namespaces import Namespace, OpenNamespace
from aiootp.commons.configs import Config, ConfigMap
from aiootp.asynchs import Processes, Threads, Clock
from aiootp.asynchs import run, asleep, get_process_id, get_thread_id
from aiootp.generics import *
from aiootp.generics import ByteIO
from aiootp.generics.canon import acanonical_pack, canonical_pack
from aiootp.generics.canon import acanonical_unpack, canonical_unpack
from aiootp.generics.canon import aencode_key, encode_key
from aiootp.generics.transform import axi_mix, xi_mix
from aiootp.randoms import *
from aiootp.randoms.simple import *
from aiootp.ciphers import Ciphertext, Padding


# Use enable_debugging method to run tests in debug mode. May cause noticable slowdown.
DebugControl.disable_debugging()


# create static values for this test session
t = Typing

violation = lambda problem: lambda relay: raise_exception(AssertionError(f"{problem} : {repr(relay)}"))


class MemoizedCipher(FrozenSlots):
    __slots__ = ("config", "cipher", "salt", "aad")

    def __init__(self, cipher_type: type) -> None:
        self.config = cipher_type._config
        self.cipher = cipher_type(key=key)
        self.salt = csprng(self.config.SALT_BYTES)
        self.aad = f"testing {self.config.NAME}".encode()

    def __iter__(
        self
    ) -> t.Generator[
        None, t.Union[t.ConfigType, t.CipherInterfaceType, bytes], None
    ]:
        yield self.config
        yield self.cipher
        yield self.salt
        yield self.aad


key = csprng(168)
dual_output_ciphers = [MemoizedCipher(Chunky2048)]
shake_permute_ciphers = [MemoizedCipher(Slick256)]
all_ciphers = [*dual_output_ciphers, *shake_permute_ciphers]
dual_output_cipher_names = [
    conf.NAME for (conf, _,_,_) in dual_output_ciphers
]
shake_permute_cipher_names = [
    conf.NAME for (conf, _,_,_) in shake_permute_ciphers
]


chunky2048_test_vector_0 = OpenNamespace(
    plaintext=(
        b"it is not a doctrine to be preached, but a deed to be done."
    ),
    key=bytes.fromhex(
        "54868dc506d99611adb67f1b41eda44fd7151e135860a6d791cad6df6715bd"
        "5204713bc2b064e88a429b93aaa282d9cc7c0c5cdaaffb65cc268b7acedd5e"
        "531a"
    ),
    shmac=bytes.fromhex(
        "f791571464dd45754e16d8e6dea2f1a05204dca2510589be012bc5117dfd98"
        "e8"
    ),
    salt=bytes.fromhex(
        "cf3761d57860bdbc"
    ),
    iv=bytes.fromhex(
        "e09d2eee03ae82e6"
    ),
    aad=b"test_vector_I",
    ciphertext=bytes.fromhex(
        "1ce9033362f402390f872fa4f20de14d8a13f32f3906dd302a275b2c62f9f5"
        "f1a8ddb61871a2bab61dffaa2b414c2ca68601a61d9670a944619fc5105469"
        "b95e63c494326678e865a751d2ab0cac40439aa51cec3a8aa9e4cf0255ea96"
        "659a4cce41e2c8dac09f97d5bb05efb39bcf6043c6cd18364f0ecc0c721160"
        "e8204e333b1e336c55bd9a09ba1c0ce08805cc924c1925ad238b785ad17e6c"
        "064b2fe8676dc2fff3a3a895381cbf8d5aa04970c4f210ae323a5274c8f703"
        "4167ba0f7042e17d748d68327d2219c83bf4e4fb9f5d36c0b0c5ca661db09c"
        "b887d2bd39589d2e12f7a799b2e3e1cad7a7dbfd4c9d1a46de6ed5e51d7561"
        "70de526f4c4fa9fb"
    ),
)


slick256_test_vector_0 = OpenNamespace(
    plaintext=(
        b"it is not a doctrine to be preached, but a deed to be done."
    ),
    key=bytes.fromhex(
        "54868dc506d99611adb67f1b41eda44fd7151e135860a6d791cad6df6715bd"
        "5204713bc2b064e88a429b93aaa282d9cc7c0c5cdaaffb65cc268b7acedd5e"
        "531a"
    ),
    shmac=bytes.fromhex(
        "5e6011b3b1ae4314b4192a1e6a18b2ca8130bc5cafcd7287"
    ),
    salt=bytes.fromhex(
        "cf3761d57860bdbc"
    ),
    iv=bytes.fromhex(
        "dda31acd46832df9"
    ),
    aad=b"test_vector_I",
    ciphertext=bytes.fromhex(
        "f73e7361a73af3eeabc88247555e06fc5bdaea10482c8351eab3ee9cfcc6fe"
        "f678b1171e6458fcef3d27896bee262769a742f8ffce51cd44db2a8e5673f4"
        "5770df4b907683c881049f15a92bed514613378ec4beb07766e809b5f68e1e"
        "326bc7"
    ),
)


passphrase_0 = csprng()
passphrase_1 = randoms.token_bytes(32)
passphrases = [passphrase_0, passphrase_1]

salt_0 = csprng()
salt_1 = randoms.token_bytes(32)
salts = [salt_0, salt_1]

passcrypt_settings = OpenNamespace(mb=1, cpu=1, cores=1)

tag = "testing"
atag = "a" + tag
metatag = "clients"
ametatag = "a" + metatag

username = b"test suite"
passphrase = b"terrible low entropy passphrase"
PROFILE = dict(username=username, passphrase=passphrase, salt=salt_0, aad=b"testing passcrypt")
LOW_PASSCRYPT_SETTINGS = OpenNamespace(mb=1, cpu=1, cores=1)
PROFILE_AND_SETTINGS = {**PROFILE, **LOW_PASSCRYPT_SETTINGS}

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
        "597dd54fabbeddd3605b3c2bd4ac2c476ac457978ddabf31ccd4a3b8f33942"
        "e8"
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

byte_leakage = 16 * b"\x00"
string_leakage = 16 * "0".encode()
plaintext_bytes = b"\xff" + 256 * b"\x00"
plaintext_string = "f" + 256 * "0"
test_data = {
    "floats": 10000.243,
    "ints": list(range(-16, 16, 8)),
    "dicts": {"testing": {}},
    "lists": 4 * [[]],
    "strings": "testing...",
    "nul": None,
    "bools": [True, False],
}
atest_data = test_data.copy()


# Creating timestamped values early so later testing has to wait less time
ttl_test_cipher = choice(all_ciphers)
atest_json_ciphertext = run(ttl_test_cipher.cipher.ajson_encrypt(atest_data, aad=ttl_test_cipher.aad))
test_json_ciphertext = ttl_test_cipher.cipher.json_encrypt(test_data, aad=ttl_test_cipher.aad)
atest_token_ciphertext = run(ttl_test_cipher.cipher.amake_token(plaintext_bytes, aad=ttl_test_cipher.aad))
test_token_ciphertext = ttl_test_cipher.cipher.make_token(plaintext_bytes, aad=ttl_test_cipher.aad)

async def make_async_ttl_cipher_stream() -> t.Tuple[t.AsyncCipherStream, bytes]:
    stream = await ttl_test_cipher.cipher.astream_encrypt(
        salt=ttl_test_cipher.salt, aad=ttl_test_cipher.aad
    )
    await stream.abuffer(plaintext_bytes)
    ciphertext = b"".join([
        (block_id + block) async for block_id, block in stream
    ])
    ciphertext += b"".join([
        (block_id + block) async for block_id, block in stream.afinalize()
    ])
    return stream, ciphertext

attl_cipher_stream, attl_stream_ciphertext = run(make_async_ttl_cipher_stream())

ttl_cipher_stream = ttl_test_cipher.cipher.stream_encrypt(
    salt=ttl_test_cipher.salt, aad=ttl_test_cipher.aad
)
ttl_cipher_stream.buffer(plaintext_bytes)
ttl_stream_ciphertext = b"".join(
    (block_id + block) for block_id, block in ttl_cipher_stream.finalize()
)

light_pcrypt = Passcrypt(mb=1, cpu=1, cores=1, tag_size=32)
aexpired_passcrypt_hash = run(light_pcrypt.ahash_passphrase(passphrase_0))
expired_passcrypt_hash = light_pcrypt.hash_passphrase(passphrase_0)

clock = Clock(SECONDS, epoch=EPOCH_NS)
ns_clock = Clock(NANOSECONDS, epoch=EPOCH_NS)
time_start = clock.make_timestamp()


@pytest.fixture(scope="session")
def database():
    print("setup".center(15, "-"))

    db = Database(key=key, preload=True)
    db.save_database()
    yield db

    print("teardown".center(18, "-"))
    db.delete_database()


@pytest.fixture(scope="session")
def async_database():
    print("setup".center(15, "-"))

    db = run(AsyncDatabase(key=key, preload=True))
    yield db

    print("teardown".center(18, "-"))
    run(db.adelete_database())


@pytest.fixture(scope="function")
def path():
    file_path = Path("byte_io_testing_path.txt").absolute()

    if not file_path.is_file():
        file_path.write_bytes(b"")

    yield file_path

    if file_path.is_file():
        file_path.unlink()


class ExampleConfig(Config):
    __slots__ = ("NUMBER", "STRING")

    slots_types = dict(NUMBER=int, STRING=str)

    def __init__(self, number: int, string: str) -> None:
        self.NUMBER = number
        self.STRING = string


@pytest.fixture(scope="function")
def config():
    yield ExampleConfig(number=420, string="word")


@pytest.fixture(scope="function")
def mapping():
    yield ConfigMap(config_type=ExampleConfig)


__all__ = [n for n in globals() if not n.startswith("_")]

