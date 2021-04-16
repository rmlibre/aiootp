# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


import json
from os import linesep
from pathlib import Path
from getpass import getpass
from hashlib import sha256, sha512
from collections import defaultdict
from setuptools import setup, find_packages

from aiootp import __package__, __version__, __license__
from aiootp import Ed25519, Database, passcrypt, asynchs, sha_256


description = (
    "aiootp - an asynchronous pseudo-one-time-pad based crypto and "
    "anonymity library."
)


with open("PREADME.rst", "r") as preadme:
    long_description = preadme.read()


with open("FAQ.rst", "r") as faq:
    long_description += faq.read()


with open("CHANGES.rst", "r") as changelog:
    long_description += changelog.read()


with open("README.rst", "w+") as readme:
    readme.write(long_description)


with open("MANIFEST.in", "r") as manifest:
    filename_sheet = manifest.read().split(linesep)


checksums = defaultdict(dict)
for line in filename_sheet:
    if (
        ".png" in line
        or  "CHECKSUM" in line
        or "SIGNATURES" in line
        or not line.startswith("include")
    ):
        continue

    name = line.split(" ")[-1]
    with open(Path(name), "r") as source_file:
        source = source_file.read().encode()
        checksums["sha512"][name] = sha512(source).hexdigest()
        checksums["sha256"][name] = sha256(source).hexdigest()


with open("CHECKSUMS.txt", "w+") as checksums_txt:
    package_checksums = json.dumps(dict(checksums), indent=4)
    checksums_txt.write(package_checksums)

    with open("sha512_ROOT_CHECKSUM.txt", "w+") as root_hash_512:
        sha512sum = sha512(package_checksums.encode()).digest()
        root_hash_512.write(sha512sum.hex())

    with open("sha256_ROOT_CHECKSUM.txt", "w+") as root_hash_256:
        sha256sum = sha256(package_checksums.encode()).digest()
        root_hash_256.write(sha256sum.hex())

    name = __package__.encode()
    version = __version__.encode()
    date = asynchs.this_day().to_bytes(8, "big")
    if getpass("Sign Package ? y/N\n").lower().strip().startswith("y"):

        db = Database(
            passcrypt(getpass("Database key ?\n"), getpass("Salt ?\n")),
            directory=getpass("Identity Key Directory ?\n"),
        )
        presigned_keys = db["presigned_ephemeral_keys"]
        if presigned_keys:
            version = db["version"].encode()
            date = db["date"].to_bytes(8, "big")
            identity_hex = db["identity_key_public"]
            identity_key = Ed25519().import_public_key(identity_hex)
            ephemeral_hex = presigned_keys.pop()
            signed_ephemeral_key = db[sha_256(ephemeral_hex)]
            ephemeral_key = Ed25519().import_secret_key(ephemeral_hex)
            scope = [name, version, date, ephemeral_key.public_bytes]
            del db["ephemeral_key_secret"]
            assert signed_ephemeral_key
            assert ephemeral_hex not in db["presigned_ephemeral_keys"]
        else:
            identity_hex = db["identity_key_secret"]
            identity_key = Ed25519().import_secret_key(identity_hex)
            ephemeral_key = Ed25519().generate()
            scope = [name, version, date, ephemeral_key.public_bytes]
            signed_ephemeral_key = identity_key.sign(b"||".join(scope)).hex()
            db["ephemeral_key_secret"] = ephemeral_key.secret_bytes.hex()

        identity_key.verify(
            bytes.fromhex(signed_ephemeral_key), b"||".join(scope)
        )
        proof = dict(
            identity_key=identity_key.public_bytes.hex(),
            pgp_signed_identity_key=db["pgp_attestation"],
            name=name.decode(),
            date=int.from_bytes(date, "big"),
            version=version.decode(),
            ephemeral_key=ephemeral_key.public_bytes.hex(),
            signed_ephemeral_key=signed_ephemeral_key,
            checksums_txt_sha256=sha256sum.hex(),
            checksums_txt_sha512=sha512sum.hex(),
            signed_sha256sum=ephemeral_key.sign(sha256sum).hex(),
            signed_sha512sum=ephemeral_key.sign(sha512sum).hex(),
        )
        db["ephemeral_key_public"] = ephemeral_key.public_bytes.hex()
        db["proof"] = proof
        db.save()

        with open("SIGNATURES.txt", "w+") as attestation:
            attestation.write(json.dumps(proof, indent=4))


setup(
    name=__package__,
    license=__license__,
    version=__version__,
    description=description,
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://twitter.com/aiootp",
    author="Gonzo Investigative Journalism Agency, LLC",
    author_email="gonzo.development@protonmail.ch",
    maintainer="Gonzo Investigative Journalism Agency, LLC",
    maintainer_email="gonzo.development@protonmail.ch",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.6",
    tests_require=["pytest>=6.2.2"],
    install_requires=[
        "sympy>=1.7.1",
        "aiofiles>=0.6.0",
        "async_lru>=1.0.2",
        "cryptography>=3.4.6",
    ],
    classifiers=[
        "Framework :: AsyncIO",
        "Natural Language :: English",
        "Development Status :: 4 - Beta",
        "Operating System :: Unix",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: Linux",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Database",
        "Topic :: Utilities",
        "Topic :: Communications",
        "Topic :: Software Development",
        "Topic :: Communications :: Chat",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries",
        "Topic :: Scientific/Engineering :: Mathematics",
        "Programming Language :: Python :: 3.6",
        "Intended Audience :: Developers",
        "Intended Audience :: Legal Industry",
        "Intended Audience :: Science/Research",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU Affero General Public License v3",
    ],
    keywords=" ".join(
        [
            "xor key salt pepper nonce",
            "AEAD auth authenticated authentication",
            "shmac hmac nmac mac digest integrity",
            "infosec opsec appsec",
            "stream cipher chunky2048 chunky",
            "encrypt plaintext",
            "decrypt ciphertext",
            "passcrypt passphrase",
            "password based derivation function",
            "ropake 3dh 2dh 25519 x25519 ed25519 curve25519",
            "db database store",
            "user uuid unique",
            "transparent encryption decryption",
            "chunky chunky2048 Chunky2048 indistinguishable",
            "pseudo one time pad onetimepad",
            "domain-specific kdf separation",
            "bits 256 512 1024 2048 4096",
            "hash sha sha3 sha-3 keccak",
            "ephemeral byte entropy",
            "PRF PRG RNG PRNG CSPRNG",
            "cryptographically secure",
            "random number generator",
            "bitwise operations",
            "information cyber security",
            "chosen attack",
            "resistance resistant",
            "anonymous anonymity",
            "symmetric asymmetric",
            "communications utilities",
            "simple clean code",
            "crypto cryptology cryptography",
            "beta testing",
            "data science processing",
            "await async asyncio",
            "coroutine coroutines comprehension",
        ]
    ),
) if __name__ == "__main__" else 0

