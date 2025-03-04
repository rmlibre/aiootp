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
A script to run a service that signs build data sent via local socket
requests.

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

import io
import os
import json
import socket
from getpass import getpass

from aiootp import __package__, __version__
from aiootp import Chunky2048 as Cipher
from aiootp import PackageSigner
from aiootp._typing import Typing as t
from aiootp.generics import canonical_pack, canonical_unpack


HOST: str = "localhost"
PORT: int = 13120
TTL: float = 2.0
EXIT_TTL: float = 7200.0
MAX_BUFFER: int = 8192
RECV_AAD: bytes = b"build_signature_request"
SEND_AAD: bytes = b"provided_build_signature"
HEADER_SLICE: slice = Cipher._config.HEADER_SLICE


_KEY_NEGOTIATION_FEATURE_FLAG: bool = False


def current_transmit_key(
    channel: t.Optional[socket.socket] = None, context: t.Any = None
) -> bytes:
    """
    Supports future key rotation implementations by querying for the
    transmission key at the start of each signature request.

    Returns the current bytes-type key.

    **Under Development**: Key negotiation may be implemented in future.
    The parameters signal this possibility, but are currently unused.
    """
    if _KEY_NEGOTIATION_FEATURE_FLAG and (channel or context):
        raise NotImplementedError("Key negotiation not available.")
    return bytes.fromhex(os.getenv("_TRANSMIT_KEY"))


def update_signing_key_prompt(signer: PackageSigner) -> None:
    """
    Provides a CLI flow to optionally insert the hex package signing key
    into the package signer's database.
    """
    if (
        getpass("is the signing key already saved on this device? (Y/n) ")
        .lower()
        .strip()
        .startswith("n")
    ):
        signer.update_signing_key(
            bytes.fromhex(getpass("signing key: ").strip())
        )


def update_public_credentials_prompt(signer: PackageSigner) -> None:
    """
    Provides a CLI flow to optionally insert the {str_name: str_value}
    public credentials into the package signer's database.
    """
    while (
        getpass("update public credentials? (y/N) ")
        .lower()
        .strip()
        .startswith("y")
    ):
        signer.update_public_credentials(
            **{getpass("name: ").strip(): getpass("value: ")}
        )


def make_signer_object() -> PackageSigner:
    """
    Provides a CLI flow to unlock the package signer's database, &
    optionally insert missing or outdated values to be included in
    signature contexts.

    Returns the package signer object.
    """
    signer = PackageSigner(package=__package__, version=__version__)
    signer.connect_to_secure_database(
        username=getpass("database username: ").encode(),
        passphrase=getpass("database key: ").encode(),
        salt=getpass("database salt: ").encode(),
        path=getpass("secure directory: "),
    )
    update_signing_key_prompt(signer)
    update_public_credentials_prompt(signer)
    return signer


def buffer_recv(channel: socket.socket, size: int) -> bytes:
    """
    A reliable method of ingesting exactly `size` number of bytes from a
    socket `channel`.

    Returns the received bytes.
    """
    index = 0
    buffer = io.BytesIO()
    while index < size:
        delta = buffer.write(channel.recv(min(size - index, MAX_BUFFER)))
        if not delta:
            raise ConnectionAbortedError("The channel has been closed.")
        index += delta
        buffer.seek(index)
    buffer.seek(0)
    return buffer.read()


def buffer_send(channel: socket.socket, data: bytes) -> int:
    """
    A reliable method of sending all of the `data` bytes through a
    socket `channel` while still enforcing a max buffer size.

    Returns the int number of bytes which were sent.
    """
    size = len(data)
    channel.sendall(size.to_bytes(8, "big"))
    buffer = io.BytesIO(data)
    while chunk := buffer.read(MAX_BUFFER):
        channel.sendall(chunk)
    return size


def get_and_parse_request(
    channel: socket.socket, cipher: t.CipherInterfaceType
) -> t.Tuple[bytes, t.Dict[str, t.JSONSerializable], t.Dict[str, str]]:
    """
    Authenticates the received request data from a `channel` using a
    transmission key shared between the service & the requester.

    Returns the relevant parsed parts of the request.
    """
    recv_length = int.from_bytes(buffer_recv(channel, 8), "big")
    request = buffer_recv(channel, recv_length)
    signing_request = cipher.bytes_decrypt(request, aad=RECV_AAD, ttl=TTL)
    scope, files = canonical_unpack(signing_request)
    return request[HEADER_SLICE], json.loads(scope), json.loads(files)


def produce_signed_summary(
    signer: t.PackageSigner,
    scope: t.Dict[str, t.JSONSerializable],
    files: t.Dict[str, str],
) -> bytes:
    """
    Ingests the package `scope` & `files` metadata into the `signer`.

    Returns the JSON serialized signed bytes-type summary.
    """
    signer.__init__(**scope)
    signer.files.update(files)
    signer.sign_package()
    return json.dumps(signer.summarize(), indent=4).encode()


def send_packaged_response(
    channel: socket.socket,
    cipher: t.CipherInterfaceType,
    header: bytes,
    summary: bytes,
) -> int:
    """
    Sends the requested context data & signature `summary` through the
    `channel` to the requester, within a transcript-specific ciphertext.

    Returns the number of bytes which were sent.
    """
    aad = canonical_pack(SEND_AAD, header)
    response = cipher.bytes_encrypt(summary, aad=aad)
    return buffer_send(channel, response)


def signing_service_loop(
    signer: PackageSigner,
    server: socket.socket,
    get_transmit_key: t.Callable[..., bytes],
) -> None:
    """
    Awaits & fulfills authentic signature requests sent over a socket.
    """
    while True:
        try:
            channel, _ = server.accept()
        except TimeoutError:
            break
        try:
            channel.settimeout(TTL)
            cipher = Cipher(get_transmit_key())

            header, scope, files = get_and_parse_request(channel, cipher)
            if scope["package"] != __package__:
                raise ValueError("Invalid context switch.")

            summary = produce_signed_summary(signer, scope, files)
            send_packaged_response(channel, cipher, header, summary)
        except (SystemExit, KeyboardInterrupt):
            break
        except (ConnectionResetError, TimeoutError) as e:
            print(f"Connection issue encountered: {e!r}")
        except (TypeError, ValueError, json.JSONDecodeError) as e:
            print(f"Message issue encountered: {e!r}")
        except (Cipher.InvalidSHMAC, Cipher.TimestampExpired) as e:
            print(f"Invalid request received: {e!r}")
        finally:
            channel.close()


def run_signing_service(
    host: str = HOST,
    port: int = PORT,
    *,
    get_transmit_key: t.Callable[..., bytes],
) -> None:
    """
    Binds the signing service to a socket at the `host` and `port`,
    where it will receive signature requests & authenticate them with
    the symmetric key returned from the `get_transmit_key` callable
    argument.
    """
    signer = make_signer_object()
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(EXIT_TTL)
        server.bind((host, port))
        server.listen(1)
        signing_service_loop(signer, server, get_transmit_key)
    finally:
        server.close()


if __name__ == "__main__":
    run_signing_service(get_transmit_key=current_transmit_key)
