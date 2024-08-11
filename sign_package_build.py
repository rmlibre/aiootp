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


"""
A script to run the package signer over the build.
"""

import json
from pathlib import Path
from getpass import getpass

from aiootp import (
    __doc__,
    __license__,
    __package__,
    __version__,
    __author__,
)
from aiootp import PackageSigner, PackageVerifier


if __name__ == "__main__" and getpass(
    "sign package? (y/N) "
).lower().strip().startswith("y"):
    with Path("SIGNATURE.txt").open("r") as sig:
        scope = json.loads(sig.read())[PackageSigner._SCOPE]
        print("current version:", __version__)
        print(f"current build: {scope['build_number']}\n")

    signer = PackageSigner(
        package=__package__,
        version=__version__,
        author=__author__,
        license=__license__,
        description=__doc__,
        build_number=getpass("build number: "),
    )
    signer.connect_to_secure_database(
        username=getpass("database username: ").encode(),
        passphrase=getpass("database key: ").encode(),
        salt=getpass("database salt: ").encode(),
        path=getpass("secure directory: "),
    )

    if (
        getpass("is the signing key already saved on this device? (Y/n) ")
        .lower()
        .strip()
        .startswith("n")
    ):
        signer.update_signing_key(
            bytes.fromhex(getpass("signing key: ").strip())
        )

    while (
        getpass("update public credentials? (y/N) ")
        .lower()
        .strip()
        .startswith("y")
    ):
        signer.update_public_credentials(
            **{getpass("name: ").strip(): getpass("value: ")}
        )

    with Path("MANIFEST.in").open("r") as manifest:
        filename_sheet = manifest.read().strip().split("\n")

    for line in filename_sheet:
        line = line.strip()
        if "SIGNATURE" in line or not line.startswith("include"):
            continue
        filename = line.split(" ")[-1]
        with Path(filename).open("rb") as source_file:
            signer.add_file(filename, source_file.read())

    signer.sign_package()
    summary = signer.summarize()
    verifier = PackageVerifier(signer.signing_key.public_bytes, path="")
    verifier.verify_summary(summary)
    with Path("SIGNATURE.txt").open("w+") as attestation:
        attestation.write(json.dumps(summary, indent=4))
