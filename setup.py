# This file is part of aiootp, an asynchronous one-time-pad based crypto
# and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


import json
from os import linesep
from pathlib import Path
from hashlib import sha256, sha512
from collections import defaultdict
from setuptools import setup, find_packages


description = """
aiootp - an asynchronous one-time-pad based crypto and anonymity library.
""".replace("\n", "")


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
    if "CHECKSUM" in line or not line.startswith("include"):
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
        sha512sum = sha512(package_checksums.encode()).hexdigest()
        root_hash_512.write(sha512sum)

    with open("sha256_ROOT_CHECKSUM.txt", "w+") as root_hash_256:
        sha256sum = sha256(package_checksums.encode()).hexdigest()
        root_hash_256.write(sha256sum)


setup(
    name="aiootp",
    license="AGPLv3",
    version="0.9.0",
    description=description,
    long_description=long_description,
    url="https://github.com/rmlibre/aiootp",
    author="Gonzo Investigatory Journalism Agency, LLC",
    author_email="gonzo.development@protonmail.ch",
    maintainer="Gonzo Investigatory Journalism Agency, LLC",
    maintainer_email="gonzo.development@protonmail.ch",
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
    include_package_data=True,
    install_requires=[
        "sympy",
        "aiofiles",
        "pybase64",
        "async_lru",
        "aioitertools",
        "asyncio_contextmanager",
    ],
    tests_require=["pytest"],
    packages=find_packages(),
) if __name__ == "__main__" else 0

