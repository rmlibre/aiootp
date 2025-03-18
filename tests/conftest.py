# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2025 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


import sys
import json
import pytest
import hashlib
import builtins
import platform
from pathlib import Path
from functools import partial
from itertools import permutations as perm, combinations as comb
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from hypothesis import settings, given, strategies as st


settings.register_profile("default", max_examples=10)
settings.load_profile("default")


_PACKAGE_PATH = str(Path(__file__).absolute().parent.parent)
sys.path.insert(0, _PACKAGE_PATH)


import aiootp
from aiootp import *
from aiootp._paths import *
from aiootp._paths import DatabasePath
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
from aiootp.asynchs import run, asleep, sleep, get_process_id, get_thread_id
from aiootp.generics import *
from aiootp.generics import ByteIO
from aiootp.generics.canon import acanonical_pack, canonical_pack
from aiootp.generics.canon import acanonical_unpack, canonical_unpack
from aiootp.generics.canon import aencode_key, encode_key
from aiootp.generics.transform import axi_mix, xi_mix
from aiootp.randoms import *
from aiootp.randoms.simple import *
from aiootp.ciphers import Ciphertext, Padding


from hypothesis_strategies import identifiers
from chunky_2048_test_vectors import chunky2048_test_vector_0
from slick_256_test_vectors import slick256_test_vector_0
from passcrypt_test_vectors import (
    passcrypt_test_vector_0,
    passcrypt_test_vector_1,
    passcrypt_test_vector_2,
    passcrypt_test_vector_3,
)


# Use enable_debugging method to run tests in debug mode. May cause noticable slowdown.
DebugControl.disable_debugging()


# create static values for this test session
t = Typing


test_path = Path(__file__).parent.parent
violation = lambda problem: lambda relay: raise_exception(
    AssertionError(f"{problem} : {relay!r}")
)


class MemoizedCipher(FrozenSlots):
    __slots__ = ("config", "cipher", "salt", "aad")

    def __init__(self, cipher_type: type) -> None:
        self.config = cipher_type._config
        self.cipher = cipher_type(key=key)
        self.salt = csprng(self.config.SALT_BYTES)
        self.aad = f"testing {self.config.NAME}".encode()

    def __iter__(
        self,
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
dual_output_cipher_names = [conf.NAME for (conf, *_) in dual_output_ciphers]
shake_permute_cipher_names = [
    conf.NAME for (conf, *_) in shake_permute_ciphers
]


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
PROFILE = dict(
    username=username,
    passphrase=passphrase,
    salt=salt_0,
    aad=b"testing passcrypt",
)
LOW_PASSCRYPT_SETTINGS = OpenNamespace(mb=1, cpu=1, cores=1)
PROFILE_AND_SETTINGS = {**PROFILE, **LOW_PASSCRYPT_SETTINGS}


byte_leakage = 16 * b"\x00"
string_leakage = 16 * b"0"
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
atest_json_ciphertext = run(
    ttl_test_cipher.cipher.ajson_encrypt(
        atest_data, aad=ttl_test_cipher.aad
    )
)
test_json_ciphertext = ttl_test_cipher.cipher.json_encrypt(
    test_data, aad=ttl_test_cipher.aad
)
atest_token_ciphertext = run(
    ttl_test_cipher.cipher.amake_token(
        plaintext_bytes, aad=ttl_test_cipher.aad
    )
)
test_token_ciphertext = ttl_test_cipher.cipher.make_token(
    plaintext_bytes, aad=ttl_test_cipher.aad
)


async def make_async_ttl_cipher_stream() -> t.Tuple[
    t.AsyncCipherStream, bytes
]:
    stream = await ttl_test_cipher.cipher.astream_encrypt(
        salt=ttl_test_cipher.salt, aad=ttl_test_cipher.aad
    )
    await stream.abuffer(plaintext_bytes)
    ciphertext = b"".join(
        [(block_id + block) async for block_id, block in stream.afinalize()]
    )
    return stream, ciphertext


attl_cipher_stream, attl_stream_ciphertext = run(
    make_async_ttl_cipher_stream()
)

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
def database() -> Database:
    db = Database(key=key, preload=True)
    db.save_database()
    yield db

    db.delete_database()


@pytest.fixture(scope="session")
def async_database() -> AsyncDatabase:
    db = run(AsyncDatabase(key=key, preload=True))
    yield db

    run(db.adelete_database())


@pytest.fixture
def path() -> Path:
    file_path = Path("byte_io_testing_path.txt").absolute()

    if not file_path.is_file():
        file_path.write_bytes(b"")

    yield file_path

    if file_path.is_file():
        file_path.unlink()


@pytest.fixture
def salt_path() -> Path:
    parent_dir = DatabasePath() / "secure"
    file_path = parent_dir / "salt_testing_path.txt"

    yield file_path

    if file_path.is_file():
        file_path.chmod(0o600)
        file_path.unlink()


class ExampleConfig(Config):
    __slots__ = ("NUMBER", "STRING")

    slots_types = dict(NUMBER=int, STRING=str)

    def __init__(self, number: int, string: str) -> None:
        self.NUMBER = number
        self.STRING = string


@pytest.fixture
def config() -> ExampleConfig:
    return ExampleConfig(number=420, string="word")


@pytest.fixture
def mapping() -> ConfigMap:
    return ConfigMap(config_type=ExampleConfig)


@pytest.fixture(scope="session")
def pkg_context() -> Namespace:
    context = OpenNamespace(
        test_path=test_path,
        signing_key=PackageSigner.generate_signing_key(),
    )
    context.signer_init = OpenNamespace(
        package=aiootp.__package__,
        version=aiootp.__version__,
        author=aiootp.__author__,
        license=aiootp.__license__,
        description=aiootp.__doc__,
        date=Clock(DAYS, epoch=0).time(),
        build_number=0,
    )
    context.signer_db_init = OpenNamespace(
        username=b"test_username",
        salt=token_bytes(64),
        passphrase=token_bytes(64),
        path=DatabasePath(),
        **LOW_PASSCRYPT_SETTINGS,
    )
    context.update(**context.signer_init, **context.signer_db_init)
    filename_sheet = """
    include tests/conftest.py
    include tests/test_ByteIO.py
    include tests/test_Database_AsyncDatabase.py
    include tests/test_Passcrypt.py
    include tests/test_StreamHMAC.py
    include tests/test_X25519_Ed25519.py
    include tests/all_aiootp_tests.py
    include tests/all_ciphers_tests.py
    include tests/all_generics_tests.py
    include tests/test_high_level_encryption.py
    include tests/test_misc_in_ciphers.py
    include tests/test_misc_in_generics.py
    include tests/test_misc_in_randoms.py
    include tests/all_randoms_tests.py
    """.strip().split("\n")
    context.files = [
        test_path / line.strip().split(" ")[-1] for line in filename_sheet
    ]
    return context


@pytest.fixture(scope="session")
def pkg_signer(pkg_context: Namespace) -> PackageSigner:
    signer = PackageSigner(**pkg_context.signer_init)
    is_mac_os_issue = lambda _: (platform.system() == "Darwin")
    while True:
        sleep(0.001)
        with Ignore(ConnectionRefusedError, if_except=is_mac_os_issue):
            signer.connect_to_secure_database(**pkg_context.signer_db_init)
            break

    signer.update_signing_key(pkg_context.signing_key)
    for path in pkg_context.files:
        with path.open("rb") as source_file:
            signer.add_file(str(path), source_file.read())

    signer.sign_package()
    yield signer
    signer.db.delete_database()


@pytest.fixture(scope="session")
def pkg_verifier(pkg_signer: PackageSigner) -> PackageVerifier:
    public_bytes = pkg_signer.signing_key.public_bytes
    return PackageVerifier(public_bytes, path=test_path)


__all__ = [n for n in globals() if not n.startswith("_")]
