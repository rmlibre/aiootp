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


__all__ = [
    "PackageSigner",
    "PackageSignerFiles",
    "PackageSignerScope",
    "PackageVerifier",
]


__doc__ = (
    "Interfaces for signing software packages & verfying their "
    "authenticity."
)


import json
from pathlib import Path
from hashlib import sha384
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey, Ed25519PrivateKey
)

from aiootp._typing import Typing as t
from aiootp._constants import DAYS
from aiootp._constants import CHECKSUM, CHECKSUMS, PUBLIC_CREDENTIALS
from aiootp._constants import SCOPE, SIGNATURE, SIGNING_KEY, VERSIONS
from aiootp._exceptions import Issue, PackageSignerIssue, InvalidSignature
from aiootp.asynchs import Clock
from aiootp.generics import Domains, canonical_pack, bytes_are_equal
from aiootp.databases import Database

from .curve_25519 import Ed25519


class PackageSignerScope(t.OpenNamespace):
    """
    Stores user-defined scope values of a package signing session.
    """

    def __init__(
        self,
        *,
        package: str,
        version: str,
        date: int,
        **extras: t.Dict[str, t.JSONSerializable],
    ) -> None:
        self.__dict__.update(extras)
        self.package = package
        self.version = version
        self.date = date


class PackageSignerFiles(t.OpenNamespace):
    """
    Stores the filename, hashing object key-value pairs of a package
    signing session.
    """


class PackageSigner:
    """
    Provides an intuitive API for users to sign their own packages.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    import json
    from getpass import getpass
    from aiootp import PackageSigner

    signer = PackageSigner(
        package=__package__,
        version=__version__,
        author=__author__,
        license=__license__,
    )
    signer.connect_to_secure_database(
        passphrase=getpass("database passphrase: "),
        salt=getpass("database salt: "),
        path=getpass("secure directory: "),
    )

    with open("MANIFEST.in", "r") as manifest:
        filename_sheet = manifest.read().split("\n")

    for line in filename_sheet:
        if not line.startswith("include"):
            continue
        filename = line.strip().split(" ")[-1]
        with open(filename, "rb") as source_file:
            signer.add_file(filename, source_file.read())

    signer.sign_package()
    signer.db.save_database()
    package_signature_summary = signer.summarize()
    """

    __slots__ = ("_db", "_scope", "files")

    _Database: type = Database
    _Hasher: t.Callable[[bytes], t.HasherType] = sha384
    _Signer: type = Ed25519

    _CHECKSUM: str = CHECKSUM
    _CHECKSUMS: str = CHECKSUMS
    _CLASS: str = "PackageSigner"
    _PUBLIC_CREDENTIALS: str = PUBLIC_CREDENTIALS
    _SCOPE: str = SCOPE
    _SIGNATURE: str = SIGNATURE
    _SIGNING_KEY: str = SIGNING_KEY
    _VERSIONS: str = VERSIONS

    _clock: t.ClockType = Clock(DAYS, epoch=0)

    InvalidSignature: type = InvalidSignature

    @classmethod
    def _database_template(cls) -> t.Dict[str, t.Union[str, t.JSONObject]]:
        """
        Returns the default instance package database values for
        initializing new databases.
        """
        return {
            cls._SIGNING_KEY: "",
            cls._VERSIONS: {},
            cls._PUBLIC_CREDENTIALS: {},
        }

    @classmethod
    def generate_signing_key(cls) -> t.SecretSignerType:
        """
        Generates a new `Ed25519` secret signing key object.
        """
        return cls._Signer().generate()

    def __init__(
        self,
        package: str,
        version: str,
        date: t.Optional[int] = None,
        **scopes: t.JSONObject,
    ) -> None:
        """
        Sets the instance's package scope attributes & default file
        checksums container.
        """
        self.files = PackageSignerFiles()
        self._scope = PackageSignerScope(
            package=package,
            version=version,
            date=date if date else self._clock.time(),
            **scopes,
        )

    def __repr__(self) -> str:
        """
        Displays the instance's declared scope.
        """
        cls = self.__class__.__qualname__
        return str(f"{cls}({self._scope})")

    @property
    def _public_credentials(self) -> t.JSONObject:
        """
        Returns public credentials from the instance's secure database.
        """
        return self.db[self._scope.package][self._PUBLIC_CREDENTIALS]

    @property
    def signing_key(self) -> t.SecretSignerType:
        """
        Returns the package's secret signing key from the instance's
        encrypted database in an `Ed25519` object.
        """
        package = self._scope.package
        aad = canonical_pack(Domains.PACKAGE_SIGNER, package.encode())
        encrypted_key = self.db[package][self._SIGNING_KEY]
        if not encrypted_key:
            raise PackageSignerIssue.signing_key_hasnt_been_set()
        key = self.db.read_token(encrypted_key, aad=aad)
        return self._Signer().import_secret_key(key)

    @property
    def db(self) -> t.DatabaseType:
        """
        Returns the instance's database object, or alerts the user to
        connect to a secure database if it isn't yet set.
        """
        try:
            return self._db
        except AttributeError:
            raise PackageSignerIssue.must_connect_to_secure_database()

    @property
    def _checksums(self) -> t.Dict[str, str]:
        """
        Returns the instance's package filenames & their hexdigests in
        a JSON ready dictionary.
        """
        return {
            filename: hasher.hexdigest()
            for filename, hasher in sorted(self.files.items())
        }

    @property
    def _summary(self) -> t.JSONObject:
        """
        Collects the instance's package file checksums, names, public
        credentials, version scopes & the package's public signing key
        into a json-ready dictionary.
        """
        return {
            self._CHECKSUMS: {
                filename: hexdigest
                for filename, hexdigest in self._checksums.items()
            },
            self._PUBLIC_CREDENTIALS: {
                name: credential
                for name, credential in sorted(
                    self._public_credentials.items()
                )
            },
            self._SCOPE: {
                name: value for name, value in sorted(self._scope.items())
            },
            self._SIGNING_KEY: self.signing_key.public_bytes.hex(),
        }

    @property
    def _checksum(self) -> bytes:
        """
        Returns the digest of the current package summary.
        """
        return self._Hasher(json.dumps(self._summary).encode()).digest()

    @property
    def _signature(self) -> bytes:
        """
        Returns the stored package summary signature.
        """
        try:
            versions = self.db[self._scope.package][self._VERSIONS]
            return bytes.fromhex(versions[self._scope.version])
        except KeyError:
            raise PackageSignerIssue.package_hasnt_been_signed()

    def connect_to_secure_database(
        self,
        *secret_credentials: bytes,
        username: bytes,
        passphrase: bytes,
        salt: bytes = b"",
        path: t.OptionalPathStr = None,
        **passcrypt_settings,
    ) -> "self":
        """
        Opens an encrypted database connection using the Passcrypt
        passphrase-based key derivation function, a `passphrase` & any
        available additional credentials a user may have. If a database
        doesn't already exist, then a new one is created with default
        values.
        """
        self._db = self._Database.generate_profile(
            self._CLASS.encode(),
            *secret_credentials,
            username=username,
            passphrase=passphrase,
            salt=salt,
            path=path,
            **passcrypt_settings,
        )
        try:
            self.db.query_tag(self._scope.package, cache=True)
        except LookupError:
            self.db[self._scope.package] = self._database_template()
        finally:
            return self

    def update_scope(self, **scopes) -> "self":
        """
        Updates the package scopes to qualify the package signature of
        the current package version within the instance.
        """
        self._scope.__dict__.update(scopes)
        return self

    def update_public_credentials(
        self, **credentials: t.Dict[str, t.JSONSerializable]
    ) -> "self":
        """
        Updates the public credentials to be associated with the package
        signature & stores them in the instance's database cache. The
        database must be saved separately to save them to disk.
        """
        package = self._scope.package
        self.db[package][self._PUBLIC_CREDENTIALS].update(credentials)
        return self

    def update_signing_key(
        self, signing_key: t.Union[str, bytes, t.SecretSignerType, Ed25519],
    ) -> "self":
        """
        Updates the package's secret signing key as an encrypted token
        within the instance's database cache. The database must be saved
        separately to save the encrypted signing key to disk.
        """
        if signing_key.__class__ is not self._Signer:
            signing_key = self._Signer().import_secret_key(signing_key)
        package = self._scope.package
        aad = canonical_pack(Domains.PACKAGE_SIGNER, package.encode())
        self.db[package][self._SIGNING_KEY] = self.db.make_token(
            signing_key.secret_bytes, aad=aad
        ).decode()
        return self

    def add_file(self, filename: str, file_data: bytes) -> "self":
        """
        Stores a `filename` & the hash object of the file's bytes type
        contents in the instance's `files` attribute mapping.
        """
        self.files[filename] = self._Hasher(file_data)
        return self

    def sign_package(self) -> "self":
        """
        Signs the package summary checksum & stores it in the instance's
        secure database cache. The database must be saved separately to
        save the signature to disk.
        """
        checksum = self._checksum
        self.db[self._scope.package][self._VERSIONS].update(
            {self._scope.version: self.signing_key.sign(checksum).hex()}
        )
        return self

    def summarize(self) -> t.Dict[str, t.JSONSerializable]:
        """
        Assures the stored package checksum signature matches the
        current checksum of the package summary. If valid, the summary
        is returned along with the package checksum & its signature in
        a dictionary.
        """
        checksum = self._checksum
        signature = self._signature
        signing_key = self.signing_key
        try:
            signing_key.verify(signature, checksum)
        except self.InvalidSignature:
            raise PackageSignerIssue.out_of_sync_package_signature()
        return {
            self._CHECKSUM: checksum.hex(),
            **self._summary,
            self._SIGNATURE: signature.hex(),
        }


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
        public_signing_key: t.Union[
            str, bytes, t.PublicSignerType, t.SignerType
        ],
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
    PackageSigner=t.add_type(PackageSigner),
    PackageSignerFiles=t.add_type(PackageSignerFiles),
    PackageSignerScope=t.add_type(PackageSignerScope),
    PackageVerifier=t.add_type(PackageVerifier),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

