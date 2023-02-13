# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
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


with open("PREADME.rst", "r") as preadme:
    long_description = preadme.read()


with open("FAQ.rst", "r") as faq:
    long_description += faq.read()


with open("CHANGES.rst", "r") as changelog:
    long_description += changelog.read()


with open("README.rst", "w+") as readme:
    readme.write(long_description)


if getpass("sign package? (y/N) ").lower().strip().startswith("y"):

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
        signer.update_signing_key(getpass("signing key: ").strip())

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
    python_requires=">=3.7",
    tests_require=["pytest>=7.2.0", "pytest-asyncio>=0.20.0"],
    install_requires=["aiofiles>=0.6.0", "cryptography>=3.4.6"],
    options={"bdist_wheel": {"python_tag": "py3"}},
    classifiers=[
        "Framework :: AsyncIO",
        "Framework :: IPython",
        "Framework :: Jupyter",
        "Framework :: Pytest",
        "Natural Language :: English",
        "Development Status :: 4 - Beta",
        "Operating System :: Unix",
        "Operating System :: MacOS",
        "Operating System :: POSIX",
        "Operating System :: Other OS",
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
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
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
            "AEAD auth authenticated authentication",
            "shmac hmac nmac mac digest integrity",
            "infosec opsec appsec",
            "stream cipher chunky2048 chunky",
            "encrypt plaintext",
            "decrypt ciphertext",
            "passcrypt passphrase",
            "password based derivation function",
            "3dh 2dh 25519 x25519 ed25519 curve25519",
            "diffie hellman sign signature verify verification",
            "db database store",
            "user uuid unique guid global",
            "transparent encryption decryption",
            "Chunky2048 indistinguishable",
            "pseudo one time pad onetimepad",
            "domain-specific kdf separation",
            "bits 64 128 256 512 1024 2048 4096",
            "hash sha sha3 sha-3 keccak",
            "ephemeral byte entropy",
            "PRF PRG PRP RNG PRNG CSPRNG",
            "cryptographically secure",
            "random number generator",
            "bitwise operations",
            "information cyber security",
            "chosen attack",
            "resistance resistant tweak tweakable",
            "anonymous anonymity pseudonymous",
            "symmetric asymmetric",
            "communications utilities",
            "simple clean code",
            "crypto cryptology cryptography",
            "beta testing",
            "data science processing",
            "await async asyncio parallel concurrency",
            "coroutine coroutines comprehension",
        ]
    ),
) if __name__ == "__main__" else 0

