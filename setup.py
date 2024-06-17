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


import json
from getpass import getpass
from setuptools import setup, find_packages

from aiootp import (
    __doc__,
    __license__,
    __package__,
    __version__,
    __author__,
)
from aiootp import PackageSigner, PackageVerifier


with open("README.rst", "r") as readme:
    long_description = readme.read()


if __name__ != "__main__":
    pass
elif getpass("sign package? (y/N) ").lower().strip().startswith("y"):

    with open("SIGNATURE.txt", "r") as sig:
        scope = json.loads(sig.read())[PackageSigner._SCOPE]
        print("current version:", __version__)
        print(f"current build: {scope['build_number']}\n")

    signer = PackageSigner(
        package=__package__,
        version=__version__,
        author=__author__,
        license=__license__,
        description=__doc__,
        build_number=int(getpass("build number: ")),
    )
    signer.connect_to_secure_database(
        username=getpass("database username: ").encode(),
        passphrase=getpass("database key: ").encode(),
        salt=getpass("database salt: ").encode(),
        path=getpass("secure directory: "),
    )

    if getpass("is the signing key already saved on this device? (Y/n) ").lower().strip().startswith("n"):
        signer.update_signing_key(bytes.fromhex(getpass("signing key: ").strip()))

    while getpass("update public credentials? (y/N) ").lower().strip().startswith("y"):
        signer.update_public_credentials(
            **{getpass("name: ").strip(): getpass("value: ")}
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
    verifier = PackageVerifier(signer.signing_key.public_bytes, path="")
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
    python_requires=">=3.8",
    tests_require=["pytest>=8.1.1", "pytest-asyncio>=0.23.6"],
    install_requires=["aiofiles>=23.2.1", "cryptography>=42.0.8"],
    options={"bdist_wheel": {"python_tag": "py38.py39.py310.py311.py312"}},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Framework :: AsyncIO",
        "Framework :: IPython",
        "Framework :: Jupyter",
        "Framework :: Pytest",
        "Natural Language :: English",
        "Operating System :: Other OS",
        "Operating System :: Unix",
        "Operating System :: MacOS",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: BSD",
        "Operating System :: POSIX :: Linux",
        "Operating System :: OS Independent",
        "Operating System :: Microsoft :: Windows",
        "Topic :: System",
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: Database",
        "Topic :: Education",
        "Topic :: Utilities",
        "Topic :: Communications",
        "Topic :: Office/Business",
        "Topic :: Text Processing",
        "Topic :: System :: Archiving",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development",
        "Topic :: System :: Networking",
        "Topic :: System :: Filesystems",
        "Topic :: Communications :: Chat",
        "Topic :: Scientific/Engineering",
        "Topic :: Communications :: Email",
        "Topic :: Security :: Cryptography",
        "Topic :: Office/Business :: Financial",
        "Topic :: Communications :: File Sharing",
        "Topic :: System :: Distributed Computing",
        "Topic :: System :: Software Distribution",
        "Topic :: System :: Systems Administration",
        "Topic :: Software Development :: Libraries",
        "Topic :: Scientific/Engineering :: Mathematics",
        "Topic :: Office/Business :: Financial :: Investment",
        "Topic :: Office/Business :: Financial :: Accounting",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Typing :: Typed",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Intended Audience :: Education",
        "Intended Audience :: Developers",
        "Intended Audience :: Legal Industry",
        "Intended Audience :: Other Audience",
        "Intended Audience :: Science/Research",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: Healthcare Industry",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Telecommunications Industry",
        "Intended Audience :: Financial and Insurance Industry",
        "License :: OSI Approved :: GNU Affero General Public License v3",
    ],
    keywords=" ".join(
        [
            "xor key salt pepper nonce aad iv siv resuse misuse",
            "fully context committing commitment",
            "online AEAD auth authenticated authentication",
            "shmac hmac nmac mac digest integrity",
            "infosec opsec appsec privacy engineering",
            "stream block cipher permutation chunky2048 slick256",
            "encrypt plaintext",
            "decrypt ciphertext",
            "passcrypt passphrase PBKDF",
            "password based derivation function",
            "3dh 2dh 25519 x25519 ed25519 curve25519",
            "diffie hellman sign signature verify verification",
            "db database value store",
            "user uuid unique guid global",
            "transparent encryption decryption",
            "indistinguishable indistinguishability",
            "pseudo one time pad onetimepad",
            "canonical canonicalization domain separation KDF",
            "bit bits 64 128 256 512 1024 2048 4096",
            "hash sha sha3 sha-3 keccak",
            "ephemeral byte entropy",
            "PRF PRG PRP RNG PRNG CSPRNG",
            "cryptographically secure",
            "random number generator",
            "bitwise operations",
            "IND CCA CPA RUP",
            "information cyber security",
            "active passive adaptive chosen attack",
            "resistance resistant tweak tweakable",
            "anonymous anonymity pseudonymous",
            "symmetric asymmetric",
            "communications utilities",
            "simple clean code",
            "crypto cryptology cryptography cryptanalysis",
            "beta testing",
            "data science multi processing threading",
            "await async asyncio parallel concurrency",
            "coroutine coroutines asynchronous asynchrony",
        ]
    ),
) if __name__ == "__main__" else 0

