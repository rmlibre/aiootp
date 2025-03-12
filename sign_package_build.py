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


"""
A script to package build data for verification, or for a request of
signature from the package signer service via a local socket.

 _____________________________________
|                                     |
|            Usage Example:           |
|_____________________________________|

Terminal #1:

~$ source <path/to/secrets/env/file.sh>
~$ uv run sign_package_service.py  # CLI that awaits requests

Terminal #2:

~$ source <path/to/secrets/env/file.sh>
~$ uv run sign_package_build.py  # CLI to request a new signature
"""

import json
import socket
from shlex import split
from pathlib import Path
from getpass import getpass
from subprocess import check_output
from contextlib import contextmanager

from aiootp import (
    __doc__,
    __license__,
    __package__,
    __version__,
    __author__,
    __PUBLIC_ED25519_KEY__,
)
from aiootp import PackageSigner, PackageVerifier
from aiootp._typing import Typing as t
from aiootp.generics import canonical_pack

from sign_package_service import PORT, TTL, HEADER_SLICE
from sign_package_service import buffer_send, buffer_recv
from sign_package_service import Cipher, current_transmit_key


HOST: str = "localhost"
SEND_AAD: bytes = b"build_signature_request"
RECV_AAD: bytes = b"provided_build_signature"
SIGNING_KEY: bytes = bytes.fromhex(__PUBLIC_ED25519_KEY__)


MANIFEST_EXCLUDES: t.Set[str] = {
    ".github/",
    "aiootp/db/",
    "aiootp/tor/",
}
DYNAMIC_FILES: t.Set[str] = {
    (MANIFEST_FILENAME := "MANIFEST.in"),
    (SIGNATURE_FILENAME := "SIGNATURE.txt"),
}


Hasher: t.HasherType = PackageSigner._Hasher


def discover_git_branch_tree() -> t.Tuple[str, str]:
    """
    Calls & parses git responses to determine the current branch or ref
    name, & an enumeration of all the filenames tracked in the repo.

    Returns the str git branch & str list of branch & staged filenames.
    """
    branch_command = split("git rev-parse --abbrev-ref HEAD")
    git_branch = check_output(branch_command).strip()
    if b"* " + git_branch not in check_output(split("git branch")):
        print(f"\nNOTICE: {git_branch=} isn't an existing branch.")

    branch_tree_command = split("git ls-files --cached")
    git_branch_tree = check_output(branch_tree_command).strip()
    return git_branch.decode(), git_branch_tree.decode()


def update_scope_prompt(branch: str) -> t.Dict[str, t.JSONSerializable]:
    """
    Gathers package metadata to be added into the signature context, &
    offers the option via CLI to update the build number.

    Returns the metadata as a JSON object-like dict.
    """
    print(f"\ncurrent version: {__version__}")

    if (old_signature_file := Path(SIGNATURE_FILENAME)).is_file():
        old_signature = json.loads(old_signature_file.read_bytes())
        old_scope = old_signature[PackageSigner._SCOPE]
        old_build_number = old_scope["build_number"]
        print(f"current build: {old_build_number}\n")

    return dict(
        package=__package__,
        version=__version__,
        author=__author__,
        license=__license__,
        description=__doc__,
        git_branch=branch,
        build_number=getpass("build number: ") or old_build_number,
    )


def discover_file_inventory(
    git_branch_tree: str,
) -> t.Tuple[bytes, t.Dict[str, str]]:
    """
    Dynamically reconstructs the Python 'MANIFEST.in' from the git file
    list, excluding external data directories. The appropriate filenames
    are bundled along with their source data's hexdigests into a dict to
    be sent over to the signing service.

    Returns the new manifest file, and the bundled file metadata.
    """
    manifest = ""
    files = {}

    for line in git_branch_tree.split("\n"):
        if not (filename := line.strip()):
            continue
        if all((part not in filename) for part in MANIFEST_EXCLUDES):
            manifest += f"include {filename}\n"
        if filename not in DYNAMIC_FILES:
            hashed_file = Hasher(Path(filename).read_bytes())
            files[filename] = hashed_file.hexdigest()

    manifest = manifest.encode()
    files[MANIFEST_FILENAME] = Hasher(manifest).hexdigest()
    return manifest, files


@contextmanager
def start_client(host: str = HOST, port: int = PORT) -> socket.socket:
    """
    Wraps a new client socket at `host`:`port` in a context guaranteed
    to close the channel when the context ends.

    Yields the new client socket.
    """
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(TTL)
        client.connect((host, port))
        yield client
    finally:
        client.close()


def send_request(
    client: socket.socket,
    cipher: t.CipherInterfaceType,
    scope: t.Dict[str, t.JSONSerializable],
    files: t.Dict[str, str],
) -> bytes:
    """
    Wraps the package `scope` & `files` metadata within authenticated
    encryption from the `cipher`, & sends the ciphertext request over
    the `client` socket to the service.

    Returns the request ciphertext header, which is used later to bind
    the service response ciphertext to the current request.
    """
    signing_request = canonical_pack(
        json.dumps(scope).encode(), json.dumps(files).encode()
    )
    request = cipher.bytes_encrypt(signing_request, aad=SEND_AAD)
    buffer_send(client, request)
    return request[HEADER_SLICE]


def recv_response(
    client: socket.socket, cipher: t.CipherInterfaceType, header: bytes
) -> bytes:
    """
    Receives a service response from the `client` socket, then decrypts
    & authenticates the ciphertext with the `cipher`.

    Returns the resulting signed package summary.
    """
    recv_length = int.from_bytes(buffer_recv(client, 8), "big")
    response = buffer_recv(client, recv_length)
    aad = canonical_pack(RECV_AAD, header)
    return cipher.bytes_decrypt(response, aad=aad, ttl=TTL)


def request_package_summary_signature(
    get_transmit_key: t.Callable[..., bytes],
) -> bytes:
    """
    Bundles the package metadata & requests a signature from the signing
    service over a socket connection. The channel's integrity is ensured
    by the key returned from the `get_transmit_key` callable argument.

    Returns the resulting signed package summary.
    """
    git_branch, git_branch_tree = discover_git_branch_tree()

    scope = update_scope_prompt(git_branch)
    manifest, files = discover_file_inventory(git_branch_tree)

    Path(MANIFEST_FILENAME).write_bytes(manifest)

    with start_client() as client:
        cipher = Cipher(get_transmit_key())
        header = send_request(client, cipher, scope, files)
        return recv_response(client, cipher, header)


if __name__ != "__main__":
    pass
elif not getpass("\nsign package? (Y/n) ").lower().strip().startswith("n"):
    summary = request_package_summary_signature(
        get_transmit_key=current_transmit_key
    )
    PackageVerifier(SIGNING_KEY, path="").verify_summary(summary)
    Path(SIGNATURE_FILENAME).write_bytes(summary)
elif not getpass("verify package? (Y/n) ").lower().strip().startswith("n"):
    summary = Path(SIGNATURE_FILENAME).read_bytes()
    PackageVerifier(SIGNING_KEY, path="").verify_summary(summary)
