# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


import json
from getpass import getpass
from setuptools import setup, find_packages

from aiootp import __doc__
from aiootp import __author__, __license__, __package__, __version__
from aiootp import PackageSigner, PackageVerifier


with open("PREADME.rst", "r") as preadme:
    long_description = preadme.read()


with open("FAQ.rst", "r") as faq:
    long_description += faq.read()


with open("CHANGES.rst", "r") as changelog:
    long_description += changelog.read()


with open("README.rst", "w+") as readme:
    readme.write(long_description)


if getpass("sign package? y/N\n").lower().strip().startswith("y"):

    signer = PackageSigner(
        package=__package__,
        version=__version__,
        author=__author__,
        license=__license__,
        description=__doc__,
        build_number=int(getpass("build number:\n")),
    )
    signer.connect_to_secure_database(
        passphrase=getpass("database key:\n"),
        salt=getpass("database salt:\n"),
        directory=getpass("secure directory:\n"),
    )

    with open("MANIFEST.in", "r") as manifest:
        filename_sheet = manifest.read().strip().split("\n")

    for line in filename_sheet:
        line = line.strip()
        if "SIGNATURE" in line or not line.startswith("include"):
            continue
        filename = line.split(" ")[-1]
        with open(filename, "rb") as source_file:
            signer.add_file(filename, source_file.read())

    signer.sign_package()
    signer.db.save_database()
    summary = signer.summarize()
    verifier = PackageVerifier(signer.signing_key.public_bytes)
    verifier.verify_summary(summary)
    with open("SIGNATURE.txt", "w+") as attestation:
        attestation.write(json.dumps(summary, indent=4))


setup(
    name=__package__,
    license=__license__,
    version=__version__,
    description=__doc__,
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
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: Database",
        "Topic :: Utilities",
        "Topic :: Communications",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development",
        "Topic :: Communications :: Chat",
        "Topic :: Communications :: Email",
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
            "xor key salt pepper nonce aad",
            "AEAD auth authenticated authentication",
            "shmac hmac nmac mac digest integrity",
            "infosec opsec appsec",
            "stream cipher chunky2048 chunky",
            "encrypt plaintext",
            "decrypt ciphertext",
            "passcrypt passphrase",
            "password based derivation function",
            "ropake 3dh 2dh 25519 x25519 ed25519 curve25519",
            "diffie hellman sign signature verify verification",
            "db database store",
            "user uuid unique",
            "transparent encryption decryption",
            "chunky chunky2048 Chunky2048 indistinguishable",
            "pseudo one time pad onetimepad",
            "domain-specific kdf separation",
            "bits 256 512 1024 2048 4096",
            "hash sha sha3 sha-3 keccak",
            "ephemeral byte entropy",
            "PRF PRG PRP RNG PRNG CSPRNG",
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

