# This file is part of aiootp, an asynchronous one-time-pad based crypto
# and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigatory Journalism Agency, LLC
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

from aiootp import Ed25519, Database, passcrypt, asynchs


description = """
aiootp - an asynchronous one-time-pad based crypto and anonymity library.
""".replace(
    "\n", ""
)


with open("PREADME.rst", "r") as preadme:
    long_description = preadme.read()


with open("CHANGES.rst", "r") as changelog:
    long_description += f"{4 * linesep}{changelog.read()}"


with open("README.rst", "w+") as readme:
    readme.write(long_description)


with open("MANIFEST.in", "r") as manifest:
    filename_sheet = manifest.read().split(linesep)


checksums = defaultdict(dict)
for line in filename_sheet:
    if (
        "CHECKSUM" in line
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
    package_checksums = json.dumps(dict(checksums))
    checksums_txt.write(package_checksums)

    with open("sha512_ROOT_CHECKSUM.txt", "w+") as root_hash_512:
        sha512sum = sha512(package_checksums.encode()).digest()
        root_hash_512.write(sha512sum.hex())

    with open("sha256_ROOT_CHECKSUM.txt", "w+") as root_hash_256:
        sha256sum = sha256(package_checksums.encode()).digest()
        root_hash_256.write(sha256sum.hex())

    if getpass("Sign Package ? y/N\n").lower().startswith("y"):

        db = Database(
            passcrypt(getpass("Database key ?\n"), getpass("Salt ?\n")),
            directory=getpass("Identity Key Directory ?\n"),
        )

        name = b"aiootp"
        version = b"0.17.0"
        date = asynchs.this_second().to_bytes(8, "big")
        presigned_keys = db["presigned_ephemeral_keys"]
        if presigned_keys:
            version = db["version"].encode()
            date = db["date"].to_bytes(8, "big")
            ephemeral_hex = presigned_keys.pop()
            signed_ephemeral_key = db[identity_hex]
            ephemeral_key = Ed25519().import_secret_key(ephemeral_hex)
            identity_hex = db["identity_key_public"]
            identity_key = Ed25519().import_public_key(identity_hex)
            assert signed_ephemeral_key
            assert ephemeral_hex not in db["presigned_ephemeral_keys"]
        else:
            ephemeral_key = Ed25519().generate()
            identity_hex = db["identity_key_secret"]
            identity_key = Ed25519().import_secret_key(identity_hex)
            scope = [name, version, date, ephemeral_key.public_bytes]
            signed_ephemeral_key = identity_key.sign(b"||".join(scope)).hex()

        db["ephemeral_key"] = ephemeral_key.secret_bytes.hex()
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
        db["proof"] = proof
        db.save()

        with open("SIGNATURES.txt", "w+") as attestation:
            attestation.write(json.dumps(proof))


setup(
    name="aiootp",
    license="AGPLv3",
    version=version.decode(),
    description=description,
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/rmlibre/aiootp",
    author="Gonzo Investigatory Journalism Agency, LLC",
    author_email="gonzo.development@protonmail.ch",
    maintainer="Gonzo Investigatory Journalism Agency, LLC",
    maintainer_email="gonzo.development@protonmail.ch",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.6",
    tests_require=["pytest"],
    install_requires=[
        "sympy",
        "aiofiles",
        "pybase64",
        "async_lru",
        "aioitertools",
        "cryptography",
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
            "encrypt",
            "decrypt",
            "encryption",
            "decryption",
            "one",
            "one-time",
            "onetimepad",
            "onetime pad",
            "one-time-pad",
            "256",
            "512",
            "xor",
            "sha",
            "key",
            "hash",
            "uuid",
            "bits",
            "2048",
            "4096",
            "sha3",
            "sha-3",
            "await",
            "async",
            "RNG",
            "PRNG",
            "CSPRNG",
            "crypto",
            "entropy",
            "asyncio",
            "bitwise",
            "security",
            "ephemeral",
            "integrity",
            "utilities",
            "anonymous",
            "anonymity",
            "symmetric",
            "simple code",
            "cryptography",
            "beta testing",
            "communications",
            "data processing",
            "transparent database",
            "random number generator",
            "coroutine",
            "coroutines",
            "comprehension",
        ]
    ),
) if __name__ == "__main__" else 0
