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
from shlex import quote, split
from subprocess import check_output

from aiootp import (
    __doc__,
    __license__,
    __package__,
    __version__,
    __author__,
    __PUBLIC_ED25519_KEY__ as aiootp_signing_key,
)
from aiootp import PackageSigner, PackageVerifier


if __name__ != "__main__":
    pass
elif getpass("sign package? (y/N) ").lower().strip().startswith("y"):
    with Path("SIGNATURE.txt").open("r") as sig:
        scope = json.loads(sig.read())[PackageSigner._SCOPE]
        print("current version:", __version__)
        print(f"current build: {scope['build_number']}\n")

    git_branch = next(
        line.strip().split()[-1]
        for line in check_output(split("git branch")).decode().split("\n")
        if line.startswith("*")
    )
    if f"* {git_branch}" not in check_output(split("git branch")).decode():
        raise ValueError(f"The value {git_branch=} is invalid.")

    signer = PackageSigner(
        package=__package__,
        version=__version__,
        author=__author__,
        license=__license__,
        description=__doc__,
        git_branch=git_branch,
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

    git_branch_tree = check_output(
        split(f"git ls-tree --full-tree -r {quote(git_branch)}")
    )
    for line in git_branch_tree.decode().strip().split("\n"):
        filename = line.strip().split("\t")[-1].strip()
        if not filename or "SIGNATURE" in filename:
            continue
        with Path(filename).open("rb") as source_file:
            signer.add_file(filename, source_file.read())

    signer.sign_package()
    summary = signer.summarize()
    verifier = PackageVerifier(bytes.fromhex(aiootp_signing_key), path="")
    verifier.verify_summary(summary)
    with Path("SIGNATURE.txt").open("w+") as attestation:
        attestation.write(json.dumps(summary, indent=4))
elif getpass("verify package? (y/N) ").lower().strip().startswith("y"):
    with Path("SIGNATURE.txt").open("r") as attestation:
        summary = json.loads(attestation.read())
    verifier = PackageVerifier(bytes.fromhex(aiootp_signing_key), path="")
    verifier.verify_summary(summary)
