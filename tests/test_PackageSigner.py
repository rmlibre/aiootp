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


import platform

from test_initialization import *

from aiootp._paths import DatabasePath
from aiootp.asynchs import sleep
from aiootp.keygens.passcrypt.config import passcrypt_spec


def test_sign_and_verify():
    try:
        test_key = token_bytes(64)
        test_salt = token_bytes(64)
        test_directory = DatabasePath()

        signer = PackageSigner(
            package=aiootp.__package__,
            version=aiootp.__version__,
            author=aiootp.__author__,
            license=aiootp.__license__,
            description=aiootp.__doc__,
        )
        signer.update_scope(build_number=0)
        _repr = repr(signer)
        assert all(name in _repr for name in signer._scope)

        problem = (
            "Allowed to retrieve a signature before connecting to the "
            "database."
        )
        with Ignore(RuntimeError, if_else=violation(problem)):
            signer._signature

        is_mac_os_issue = lambda relay: (platform.system() == "Darwin")
        while True:
            sleep(0.001)
            with Ignore(ConnectionRefusedError, if_except=is_mac_os_issue):
                signer.connect_to_secure_database(
                    username=b"test_username",
                    passphrase=test_key,
                    salt=test_salt,
                    path=test_directory,
                    mb=passcrypt_spec.MIN_MB,
                    cpu=1,
                )
                break
        signer.update_public_credentials(x25519_public_key=aiootp.__PUBLIC_X25519_KEY__)

        problem = (
            "Allowed to retrieve a signing key before its creation."
        )
        with Ignore(LookupError, if_else=violation(problem)):
            signer.signing_key

        problem = (
            "Allowed to retrieve a signature before signing."
        )
        with Ignore(RuntimeError, if_else=violation(problem)):
            signer._signature

        test_signing_key = signer.generate_signing_key()

        # update_signing_key expects a str, bytes, Ed25519PrivateKey or an Ed25519 object
        signer.update_signing_key(test_signing_key)
        signer.update_signing_key(signer.signing_key.secret_key)
        signer.update_signing_key(signer.signing_key.secret_bytes)

        problem = (
            "A type other than str, bytes, Ed25519PrivateKey or an "
            "Ed25519 object was allowed for update_signing_key."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            signer.update_signing_key(bytearray(signer.signing_key.secret_bytes))

        filename_sheet = """
        include tests/test_initialization.py
        include tests/test_aiootp.py
        include tests/test_generics.py
        include tests/test_ByteIO.py
        include tests/test_misc_in_generics.py
        include tests/test_randoms.py
        include tests/test_misc_in_randoms.py
        include tests/test_ciphers.py
        include tests/test_Database_AsyncDatabase.py
        include tests/test_StreamHMAC.py
        include tests/test_X25519_Ed25519.py
        include tests/test_high_level_encryption.py
        include tests/test_misc_in_ciphers.py
        include tests/test_Passcrypt.py
        """.strip().split("\n")

        test_path = Path(__file__).parent.parent
        for line in filename_sheet:
            filename = line.strip().split(" ")[-1]
            with open(test_path / filename, "rb") as source_file:
                file_data = source_file.read()
                signer.add_file(filename, file_data)

                # added file hashes are available from the files attribute
                # by their filename
                assert filename in signer.files
                assert signer.files[filename].digest() != signer._Hasher().digest()
                assert signer.files[filename].digest() == signer._Hasher(file_data).digest()

        signer.sign_package()
        summary = signer.summarize()

        # The package verifier successfully verifies a correct summary
        verifier = PackageVerifier(signer.signing_key.public_bytes, path=test_path)
        verifier.verify_summary(summary)

        # Package verifier can also accept an Ed25519 object
        verifier = PackageVerifier(
            Ed25519().import_public_key(signer.signing_key.public_key), path=test_path
        )
        verifier.verify_summary(summary)

        # summarize calls produce the same summaries if the signer object
        # has not been modified
        assert summary == signer.summarize()

        # summary checksum alteration fails
        summary["checksum"] = summary["checksum"][::-1]
        problem = (
            "Summary alteration uncaught."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            verifier.verify_summary(summary)

        # returning the checksum to the original value succeeds
        summary["checksum"] = summary["checksum"][::-1]
        verifier.verify_summary(summary)

        # a json summary also works
        verifier.verify_summary(json.dumps(summary))

        # altering the signature does not work
        problem = (
            "Signature alteration went uncaught."
        )
        with Ignore(verifier.InvalidSignature, if_else=violation(problem)):
            fake_summary = {**summary, "signature": token_bytes(64).hex()}
            verifier.verify_summary(fake_summary)

        # the signing key in the summary is the hex representation of the
        # signing objects public key
        assert len(summary["signing_key"]) == 64
        assert summary["signing_key"] == signer.signing_key.public_bytes.hex()

        # altering the signing key fails
        summary["signing_key"] = X25519().generate().public_bytes.hex()
        problem = (
            "Changed signing_key went uncaught."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            verifier.verify_summary(summary)

        # returning to the original signing key succeeds
        summary["signing_key"] = test_signing_key.public_bytes.hex()
        verifier.verify_summary(summary)

        # changing the signature is detected during summarization
        VERSION = signer._scope.version
        VERSIONS = signer._VERSIONS
        PACKAGE = signer._scope.package
        signature = signer.db[PACKAGE][VERSIONS][VERSION]
        signer.db[PACKAGE][VERSIONS][VERSION] = token_bytes(32).hex()
        problem = (
            "Altered signature not detected during summarization."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            signer.summarize()

        # returning the signature works
        signer.db[PACKAGE][VERSIONS][VERSION] = signature
        signer.summarize()

        # verifier detects wrong file digest
        signer.sign_package()
        summary = signer.summarize()
        filename = list(summary[CHECKSUMS])[-1]
        summary[CHECKSUMS][filename] = signer._Hasher().hexdigest()
        problem = (
            "An invalid file digest wasn't detected."
        )
        with Ignore(InvalidDigest, if_else=violation(problem)):
            verifier._verify_file_checksums(summary)

        # verifier throws error if path is specified without also
        # specifying direct file validation.
        problem = (
            "A verifier was initialized with conflicting flags."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            PackageVerifier(
                signer.signing_key.public_bytes,
                path=test_path,
                verify_files=False,
            )
    finally:
        signer.db.delete_database()


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

