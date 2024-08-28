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


from conftest import *


class TestPackageVerifier:
    async def test_path_needed_to_verify_file_hashes(
        self, pkg_signer: PackageSigner
    ) -> None:
        problem = (  # fmt: skip
            "The default `verify_files=True` was allowed to initialize "
            "without specifying a relative directory to locate files."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            PackageVerifier(pkg_signer.signing_key.public_bytes)

        verifier = PackageVerifier(
            pkg_signer.signing_key.public_bytes, verify_files=False
        )
        verifier.verify_summary(pkg_signer.summarize())

    async def test_if_path_given_verify_files_must_be_true(
        self, pkg_context: Namespace, pkg_signer: PackageSigner
    ) -> None:
        problem = (  # fmt: skip
            "A verifier was initialized with conflicting flags."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            PackageVerifier(
                pkg_signer.signing_key.public_bytes,
                path=pkg_context.test_path,
                verify_files=False,
            )

    async def test_verifier_detects_wrong_file_digest(
        self, pkg_context: Namespace, pkg_signer: PackageSigner
    ) -> None:
        verifier = PackageVerifier(
            pkg_signer.signing_key.public_bytes, path=pkg_context.test_path
        )
        summary = pkg_signer.summarize()
        filename = randoms.choice(list(summary[CHECKSUMS]))
        summary[CHECKSUMS][filename] = pkg_signer._Hasher().hexdigest()
        problem = (  # fmt: skip
            f"An invalid digest for file {filename=} wasn't detected."
        )
        with Ignore(InvalidDigest, if_else=violation(problem)):
            verifier._verify_file_checksums(summary)

    async def test_signing_key_input_acceptable_types(
        self, pkg_context: Namespace, pkg_signer: PackageSigner
    ) -> None:
        summary = pkg_signer.summarize()
        public_keys = [
            Ed25519().import_public_key(pkg_signer.signing_key.public_key),
            pkg_signer.signing_key.public_key,
            pkg_signer.signing_key.public_bytes,
        ]
        for key in public_keys:
            verifier = PackageVerifier(key, path=pkg_context.test_path)
            verifier.verify_summary(summary)

    async def test_altering_signing_key_fails(
        self,
        pkg_signer: PackageSigner,
        pkg_verifier: PackageVerifier,
    ) -> None:
        summary = pkg_signer.summarize()
        summary["signing_key"] = X25519().generate().public_bytes.hex()
        problem = (  # fmt: skip
            "An altered `signing_key` went uncaught."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            pkg_verifier.verify_summary(summary)

        # returning to the original signing key succeeds
        summary["signing_key"] = pkg_signer.signing_key.public_bytes.hex()
        pkg_verifier.verify_summary(summary)

    async def test_altering_checksum_fails(
        self,
        pkg_signer: PackageSigner,
        pkg_verifier: PackageVerifier,
    ) -> None:
        summary = pkg_signer.summarize()
        summary["checksum"] = summary["checksum"][::-1]
        problem = (  # fmt: skip
            "Summary alteration uncaught."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            pkg_verifier.verify_summary(summary)

        # returning the checksum to the original value succeeds
        summary["checksum"] = summary["checksum"][::-1]
        pkg_verifier.verify_summary(summary)

        # a json summary also works
        pkg_verifier.verify_summary(json.dumps(summary))


class TestPackageSigner:
    async def test_changing_signature_detected_during_summarization(
        self, pkg_context: Namespace, pkg_signer: PackageSigner
    ) -> None:
        PACKAGE = pkg_context.package
        VERSIONS = pkg_signer._VERSIONS
        VERSION = pkg_context.version
        signature = pkg_signer.db[PACKAGE][VERSIONS][VERSION]
        pkg_signer.db[PACKAGE][VERSIONS][VERSION] = token_bytes(64).hex()

        problem = (  # fmt: skip
            "Altered signature not detected during summarization."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            pkg_signer.summarize()

        # returning the signature works
        pkg_signer.db[PACKAGE][VERSIONS][VERSION] = signature
        pkg_signer.summarize()

    async def test_signing_key_in_summary_is_hex_public_key(
        self, pkg_signer: PackageSigner
    ) -> None:
        summary = pkg_signer.summarize()
        assert len(summary["signing_key"]) == 64
        assert (
            summary["signing_key"]
            == pkg_signer.signing_key.public_bytes.hex()
        )

    async def test_altering_the_signature_summary_fails(
        self, pkg_context: Namespace, pkg_signer: PackageSigner
    ) -> None:
        summary = pkg_signer.summarize()
        verifier = PackageVerifier(
            pkg_signer.signing_key.public_bytes, path=pkg_context.test_path
        )

        problem = (  # fmt: skip
            "Signature alteration went uncaught."
        )
        with Ignore(verifier.InvalidSignature, if_else=violation(problem)):
            fake_summary = {**summary, "signature": token_bytes(64).hex()}
            verifier.verify_summary(fake_summary)

    async def test_unmodified_signer_summary_is_deterministic(
        self, pkg_signer: PackageSigner
    ) -> None:
        summary = pkg_signer.summarize()
        for _ in range(2):
            assert summary == pkg_signer.summarize()
            assert json.dumps(summary) == json.dumps(pkg_signer.summarize())
            assert summary == json.loads(json.dumps(pkg_signer.summarize()))

    async def test_scope_items_show_in_repr(
        self, pkg_context: Namespace, pkg_signer: PackageSigner
    ) -> None:
        _repr = repr(pkg_signer)
        assert all(
            f"{name}={pkg_context[name]!r}" in _repr
            for name in pkg_signer._scope
        )

    @given(
        build_number=st.one_of(
            st.none(),
            st.booleans(),
            st.integers(),
            st.floats(),  # if nan, can't directly check equality
            st.text(),
        ).filter(lambda x: x != 0)
    )
    async def test_scope_updates_when_instructed(
        self,
        pkg_context: Namespace,
        pkg_signer: PackageSigner,
        build_number: t.Hashable,
    ) -> None:
        old_number = pkg_context.build_number
        assert 2 == len({pkg_signer._scope.build_number, build_number})
        assert 1 == len({pkg_signer._scope.build_number, old_number})
        pkg_signer.update_scope(build_number=build_number)
        assert 1 == len({pkg_signer._scope.build_number, build_number})
        pkg_signer.sign_package()

        pkg_signer.update_scope(build_number=old_number)
        assert 1 == len({pkg_signer._scope.build_number, old_number})
        pkg_signer.sign_package()

    async def test_file_hashes_are_stored_after_being_added(
        self,
        pkg_context: Namespace,
        pkg_signer: PackageSigner,
        pkg_verifier: PackageVerifier,
    ) -> None:
        pkg_signer.sign_package()
        pkg_verifier.verify_summary(summary := pkg_signer.summarize())
        signer = PackageSigner(**pkg_context.signer_init)
        signer.connect_to_secure_database(**pkg_context.signer_db_init)
        signer.update_signing_key(pkg_signer.signing_key)
        assert signer.db._root_filename == pkg_signer.db._root_filename
        for index, path in enumerate(pkg_context.files, start=1):
            filename = str(path)
            file_data = path.read_bytes()
            signer.add_file(filename, file_data)
            assert index == len(signer.files)
            assert filename in signer.files
            assert (
                signer.files[filename].digest() != signer._Hasher().digest()
            )
            assert (
                signer.files[filename].digest()
                == signer._Hasher(file_data).digest()
            )
        assert len(signer.files) == len(pkg_context.files)
        signer.sign_package()
        pkg_verifier.verify_summary(new_summary := signer.summarize())
        assert summary == new_summary

    async def test_cant_retrieve_signing_key_prior_to_setting(
        self, pkg_context: Namespace, pkg_signer: PackageSigner
    ) -> None:
        signing_key = pkg_signer.signing_key
        pkg_signer.db[pkg_context.package]["versions"] = {}
        try:
            problem = (  # fmt: skip
                "Allowed to retrieve a signing key before its creation."
            )
            del pkg_signer.db[pkg_context.package]["signing_key"]
            assert not hasattr(pkg_signer, "signing_key")
            pkg_signer.db[pkg_context.package]["signing_key"] = ""
            assert not hasattr(pkg_signer, "signing_key")
            with Ignore(t.SigningKeyNotSet, if_else=violation(problem)):
                assert pkg_signer.signing_key
        finally:
            pkg_signer.update_signing_key(signing_key)
            pkg_signer.sign_package()

    async def test_update_signing_key_interface_changes_signing_key(
        self, pkg_context: Namespace, pkg_signer: PackageSigner
    ) -> None:
        summary = pkg_signer.summarize()
        signing_key = pkg_signer.signing_key
        try:
            new_signing_key = pkg_signer.generate_signing_key()
            pkg_signer.update_signing_key(new_signing_key)
            pkg_signer.sign_package()
            new_summary = pkg_signer.summarize()
            verifier = PackageVerifier(
                new_signing_key, path=pkg_context.test_path
            )
            assert summary["signing_key"] != new_summary["signing_key"]
            assert (
                signing_key.public_bytes
                != pkg_signer.signing_key.public_bytes
            )
            verifier.verify_summary(new_summary)
        finally:
            pkg_signer.update_signing_key(signing_key)
            pkg_signer.sign_package()

    async def test_update_signing_key_interface_acceptable_types(
        self, pkg_signer: PackageSigner
    ) -> None:
        # update_signing_key expects a bytes, Ed25519PrivateKey or an Ed25519 object
        pkg_signer.update_signing_key(pkg_signer.signing_key)
        pkg_signer.update_signing_key(pkg_signer.signing_key.secret_key)
        pkg_signer.update_signing_key(pkg_signer.signing_key.secret_bytes)

        problem = (  # fmt: skip
            "A type other than bytes, Ed25519PrivateKey or an "
            "Ed25519 object was allowed for update_signing_key."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            pkg_signer.update_signing_key(
                bytearray(pkg_signer.signing_key.secret_bytes)
            )
        with Ignore(TypeError, if_else=violation(problem)):
            pkg_signer.update_signing_key(
                pkg_signer.signing_key.secret_bytes.hex()
            )

    async def test_cant_retrieve_signature_prior_to_signing(
        self, pkg_context: Namespace, pkg_signer: PackageSigner
    ) -> None:
        del pkg_signer.db[pkg_context.package]["versions"][
            pkg_context.version
        ]
        problem = (  # fmt: skip
            "Allowed to retrieve a signature before signing."
        )
        assert not hasattr(pkg_signer, "_signature")
        with Ignore(t.PackageNotSigned, if_else=violation(problem)):
            assert pkg_signer._signature
        pkg_signer.sign_package()
        assert pkg_signer._signature

    async def test_update_public_credentials_updates_state(
        self, pkg_signer: PackageSigner
    ) -> None:
        public_credentials = pkg_signer.db["aiootp"]["public_credentials"]
        summary = pkg_signer.summarize()
        assert not public_credentials
        assert "x25519_public_key" not in public_credentials
        pkg_signer.update_public_credentials(
            x25519_public_key=aiootp.__PUBLIC_X25519_KEY__
        )
        pkg_signer.sign_package()
        new_summary = pkg_signer.summarize()
        assert summary != new_summary
        assert public_credentials
        assert (
            aiootp.__PUBLIC_X25519_KEY__
            == public_credentials["x25519_public_key"]
        )

    def test_database_must_be_connected_to_retrieve_signer_state(
        self, pkg_context: Namespace
    ) -> None:
        signer = PackageSigner(**pkg_context.signer_init)
        problem = (  # fmt: skip
            "Allowed to retrieve database states before connecting to the "
            "database."
        )
        assert not hasattr(signer, "_db")
        with Ignore(t.DatabaseNotConnected, if_else=violation(problem)):
            assert signer.db


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
