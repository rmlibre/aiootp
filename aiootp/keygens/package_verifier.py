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


__all__ = ["PackageVerifier"]


__doc__ = (
    "An interface for verfying the authenticity of software package "
    "hashes & signatures."
)


import json
from pathlib import Path
from hashlib import sha384

from aiootp._typing import Typing as t
from aiootp._constants import CHECKSUM, CHECKSUMS, SIGNATURE, SIGNING_KEY
from aiootp._exceptions import Issue, PackageSignerIssue, InvalidSignature
from aiootp.generics import bytes_are_equal

from .curve_25519 import Ed25519


class PackageVerifier:
    """
    Provides an intuitive API for verifying package summaries produced
    by `PackageSigner` objects.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp import PackageVerifier

    verifier = PackageVerifier(public_signing_key, path="")
    verifier.verify_summary(package_signature_summary)
    """

    __slots__ = (
        "_path",
        "_checksum",
        "_signature",
        "_signing_key",
        "_summary_dictionary",
    )

    _Hasher: t.Callable[[bytes], t.HasherType] = sha384
    _Signer: type = Ed25519

    _CHECKSUM: str = CHECKSUM
    _CHECKSUMS: str = CHECKSUMS
    _SIGNATURE: str = SIGNATURE
    _SIGNING_KEY: str = SIGNING_KEY

    InvalidSignature: type = InvalidSignature

    def __init__(
        self,
        public_signing_key: t.Union[bytes, t.PublicKeyType, t.SignerType],
        *,
        path: t.OptionalPathStr = None,
        verify_files: bool = True,
    ) -> None:
        """
        Receives the bytes type public signing key a user expects a
        package to be signed by, & stores it within the instance. The
        `path` keyword argument is the root location where all of the
        source files can be reached via the relative paths of the files
        declared in the summary. If instead the source files will not be
        checked for validity & only the validity of the signature will
        be assertained, the `verify_files` keyword can be set falsey.
        """
        if public_signing_key.__class__ is not self._Signer:
            key = public_signing_key
            self._signing_key = self._Signer().import_public_key(key)
        else:
            self._signing_key = public_signing_key
        if verify_files:
            self._path = Path(path).absolute()
        elif path is not None:
            raise Issue.unused_parameters("path", "not verifying files")

    @property
    def _summary_bytes(self) -> bytes:
        """
        Returns the UTF-8 encoded JSON package signature summary sans
        the package checksum & signature for hashing.
        """
        return json.dumps(self._summary_dictionary).encode()

    def _import_summary(
        self, summary: t.Dict[str, t.JSONSerializable]
    ) -> None:
        """
        Verifies the package summary checksum & stores its values within
        the instance.
        """
        summary = self._summary_dictionary = {**summary}
        self._checksum = bytes.fromhex(summary.pop(self._CHECKSUM))
        self._signature = bytes.fromhex(summary.pop(self._SIGNATURE))
        if self._Hasher(self._summary_bytes).digest() != self._checksum:
            raise Issue.invalid_value("package summary checksum")

    def _verify_file_checksums(self, summary: dict) -> None:
        """
        Verifies the files declared in the summary by loading them from
        the filesystem & calculating their digests for a match.
        """
        path = self._path
        files = summary[self._CHECKSUMS]
        for file_path, purported_hexdigest in files.items():
            purported_digest = bytes.fromhex(purported_hexdigest)
            with open(path / file_path, "rb") as source_file:
                digest = self._Hasher(source_file.read()).digest()
                if not bytes_are_equal(purported_digest, digest):
                    raise PackageSignerIssue.invalid_file_digest(file_path)

    def verify_summary(
        self,
        summary: t.Union[
            t.Dict[str, t.JSONSerializable], t.JSONDeserializable
        ],
    ) -> None:
        """
        Verifies the purported checksum of a package summary & the
        signature of the checksum.
        """
        if summary.__class__ is not dict:
            summary = json.loads(summary)
        purported_signing_key = bytes.fromhex(summary[self._SIGNING_KEY])
        if purported_signing_key != self._signing_key.public_bytes:
            raise Issue.invalid_value("summary's public signing key")
        self._import_summary(summary)
        if hasattr(self, "_path"):
            self._verify_file_checksums(summary)
        self._signing_key.verify(self._signature, self._checksum)


module_api = dict(
    PackageVerifier=t.add_type(PackageVerifier),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

