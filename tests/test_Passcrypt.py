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


from test_initialization import *

from aiootp._constants.misc import B_TO_MB_RATIO
from aiootp.keygens.passcrypt import PasscryptHash
from aiootp.keygens.passcrypt.sessions_manager import PasscryptProcesses
from aiootp.keygens.passcrypt.config import passcrypt_spec as config


PasscryptSession = t.PasscryptSession


class TestPasscryptMetadataHashes:
    passphrase = b"a generic passphrase 123456"
    pcrypt = Passcrypt(**passcrypt_settings, tag_size=16)
    config = pcrypt._config
    ametadata_hash = run(pcrypt.ahash_passphrase(passphrase))
    metadata_hash = pcrypt.hash_passphrase(passphrase)

    async def test_hashes_are_unique(self) -> None:
        tag_slice = slice(-self.pcrypt._settings.tag_size, None)
        assert self.metadata_hash != self.ametadata_hash
        assert self.metadata_hash[tag_slice] != self.ametadata_hash[tag_slice]

    async def test_hashes_are_bytes(self) -> None:
        assert type(self.ametadata_hash) == bytes
        assert type(self.metadata_hash) == bytes

    async def test_async_hash_reconstruction(self) -> None:
        apcrypt_hash = PasscryptHash(
            config=self.config
        ).import_hash(self.ametadata_hash)
        ahash_check = await self.pcrypt.anew(
            self.passphrase, apcrypt_hash.salt, aad=apcrypt_hash.timestamp
        )
        assert apcrypt_hash.tag_size == len(ahash_check)
        assert ahash_check == self.ametadata_hash[-apcrypt_hash.tag_size:]
        assert ahash_check == self.pcrypt.new(
            self.passphrase, apcrypt_hash.salt, aad=apcrypt_hash.timestamp
        )
        assert {**apcrypt_hash} == dict(
            timestamp=apcrypt_hash.timestamp,
            mb=apcrypt_hash.mb,
            cpu=apcrypt_hash.cpu,
            cores=apcrypt_hash.cores,
            salt=apcrypt_hash.salt,
            tag=apcrypt_hash.tag,
        )
        assert self.ametadata_hash == (
            apcrypt_hash.timestamp
            + (apcrypt_hash.mb - 1).to_bytes(config.MB_BYTES, BIG)
            + (apcrypt_hash.cpu - 1).to_bytes(config.CPU_BYTES, BIG)
            + (apcrypt_hash.cores - 1).to_bytes(config.CORES_BYTES, BIG)
            + (len(apcrypt_hash.salt) - 1).to_bytes(config.SALT_SIZE_BYTES, BIG)
            + apcrypt_hash.salt
            + apcrypt_hash.tag
        )

    async def test_sync_hash_reconstruction(self) -> None:
        pcrypt_hash = PasscryptHash(
            config=self.config
        ).import_hash(self.metadata_hash)
        hash_check = self.pcrypt.new(
            self.passphrase, pcrypt_hash.salt, aad=pcrypt_hash.timestamp
        )
        assert pcrypt_hash.tag_size == len(hash_check)
        assert hash_check == self.metadata_hash[-pcrypt_hash.tag_size:]
        assert hash_check == await self.pcrypt.anew(
            self.passphrase, pcrypt_hash.salt, aad=pcrypt_hash.timestamp
        )
        assert {**pcrypt_hash} == dict(
            timestamp=pcrypt_hash.timestamp,
            mb=pcrypt_hash.mb,
            cpu=pcrypt_hash.cpu,
            cores=pcrypt_hash.cores,
            salt=pcrypt_hash.salt,
            tag=pcrypt_hash.tag,
        )
        assert self.metadata_hash == (
            pcrypt_hash.timestamp
            + (pcrypt_hash.mb - 1).to_bytes(config.MB_BYTES, BIG)
            + (pcrypt_hash.cpu - 1).to_bytes(config.CPU_BYTES, BIG)
            + (pcrypt_hash.cores - 1).to_bytes(config.CORES_BYTES, BIG)
            + (len(pcrypt_hash.salt) - 1).to_bytes(config.SALT_SIZE_BYTES, BIG)
            + pcrypt_hash.salt
            + pcrypt_hash.tag
        )

    async def test_verify_methods_detect_correct_passphrase(self) -> None:
        await Passcrypt.averify(
            self.ametadata_hash, self.passphrase, config=self.config
        )
        Passcrypt.verify(
            self.metadata_hash, self.passphrase, config=self.config
        )

    async def test_wrong_passphrase_fails_async(self) -> None:
        problem = (
            "An invalid passphrase passed async verification."
        )
        with Ignore(Passcrypt.InvalidPassphrase, if_else=violation(problem)):
            await Passcrypt.averify(
                self.ametadata_hash,
                self.passphrase + b"\x00",
                config=self.config,
            )

    async def test_wrong_passphrase_fails_sync(self) -> None:
        problem = (
            "An invalid passphrase passed sync verification."
        )
        with Ignore(Passcrypt.InvalidPassphrase, if_else=violation(problem)):
            Passcrypt.verify(
                self.metadata_hash,
                self.passphrase + b"\x00",
                config=self.config,
            )

    async def test_async_mb_resource_limitations(self) -> None:
        mb_allowed = passcrypt_settings.mb
        problem = (
            "The `mb` was allowed to exceed the resource limit of "
            f"{mb_allowed - 1}."
        )
        with Ignore(ResourceWarning, if_else=violation(problem)):
            await Passcrypt.averify(
                self.ametadata_hash,
                self.passphrase,
                mb_allowed=range(1, mb_allowed - 1),
                config=self.config,
            )

        problem = (
            "The `mb` was allowed to fall below the resource limit of "
            f"{mb_allowed + 1}."
        )
        with Ignore(ResourceWarning, if_else=violation(problem)):
            await Passcrypt.averify(
                self.ametadata_hash,
                self.passphrase,
                mb_allowed=range(mb_allowed + 1, mb_allowed + 2),
                config=self.config,
            )

    async def test_sync_mb_resource_limitations(self) -> None:
        mb_allowed = passcrypt_settings.mb
        problem = (
            "The `mb` was allowed to exceed the resource limit of "
            f"{mb_allowed - 1}."
        )
        with Ignore(ResourceWarning, if_else=violation(problem)):
            Passcrypt.verify(
                self.metadata_hash,
                self.passphrase,
                mb_allowed=range(1, mb_allowed - 1),
                config=self.config,
            )

        problem = (
            "The `mb` was allowed to fall below the resource limit of "
            f"{mb_allowed + 1}."
        )
        with Ignore(ResourceWarning, if_else=violation(problem)):
            Passcrypt.verify(
                self.metadata_hash,
                self.passphrase,
                mb_allowed=range(mb_allowed + 1, mb_allowed + 2),
                config=self.config,
            )

    async def test_async_cpu_resource_limitations(self) -> None:
        cpu_allowed = passcrypt_settings.cpu
        problem = (
            "The `cpu` was allowed to exceed the resource limit of "
            f"{cpu_allowed - 1}."
        )
        with Ignore(ResourceWarning, if_else=violation(problem)):
            await Passcrypt.averify(
                self.ametadata_hash,
                self.passphrase,
                cpu_allowed=range(256, cpu_allowed - 1),
                config=self.config,
            )

        problem = (
            "The `cpu` was allowed to fall below the resource limit of "
            f"{cpu_allowed + 1}."
        )
        with Ignore(ResourceWarning, if_else=violation(problem)):
            await Passcrypt.averify(
                self.ametadata_hash,
                self.passphrase,
                cpu_allowed=range(cpu_allowed + 1, 257),
                config=self.config,
            )

    async def test_sync_cpu_resource_limitations(self) -> None:
        cpu_allowed = passcrypt_settings.cpu
        problem = (
            "The `cpu` was allowed to exceed the resource limit of "
            f"{cpu_allowed - 1}."
        )
        with Ignore(ResourceWarning, if_else=violation(problem)):
            Passcrypt.verify(
                self.metadata_hash,
                self.passphrase,
                cpu_allowed=range(256, cpu_allowed - 1),
                config=self.config,
            )

        problem = (
            "The `cpu` was allowed to fall below the resource limit of "
            f"{cpu_allowed + 1}."
        )
        with Ignore(ResourceWarning, if_else=violation(problem)):
            Passcrypt.verify(
                self.metadata_hash,
                self.passphrase,
                cpu_allowed=range(cpu_allowed + 1, 257),
                config=self.config,
            )

    async def test_async_cores_resource_limitations(self) -> None:
        cores_allowed = passcrypt_settings.cores
        problem = (
            "The `cores` was allowed to exceed the resource limit of "
            f"{cores_allowed - 1}."
        )
        with Ignore(ResourceWarning, if_else=violation(problem)):
            await Passcrypt.averify(
                self.ametadata_hash,
                self.passphrase,
                cores_allowed=range(256, cores_allowed - 1),
                config=self.config,
            )

        problem = (
            "The `cores` was allowed to fall below the resource limit of "
            f"{cores_allowed + 1}."
        )
        with Ignore(ResourceWarning, if_else=violation(problem)):
            await Passcrypt.averify(
                self.ametadata_hash,
                self.passphrase,
                cores_allowed=range(cores_allowed + 1, 257),
                config=self.config,
            )

    async def test_sync_cores_resource_limitations(self) -> None:
        cores_allowed = passcrypt_settings.cores
        problem = (
            "The `cores` was allowed to exceed the resource limit of "
            f"{cores_allowed - 1}."
        )
        with Ignore(ResourceWarning, if_else=violation(problem)):
            Passcrypt.verify(
                self.metadata_hash,
                self.passphrase,
                cores_allowed=range(256, cores_allowed - 1),
                config=self.config,
            )

        problem = (
            "The `cores` was allowed to fall below the resource limit of "
            f"{cores_allowed + 1}."
        )
        with Ignore(ResourceWarning, if_else=violation(problem)):
            Passcrypt.verify(
                self.metadata_hash,
                self.passphrase,
                cores_allowed=range(cores_allowed + 1, 257),
                config=self.config,
            )


class TestPasscryptTestVectors:

    def accrue_failures(self, index: int, failures: t.List[Exception]) -> None:
        return lambda relay: failures.append((index, relay.error)) or True

    async def test_declared_algorithm_example_results(self) -> None:
        example_results = (
            passcrypt_test_vector_0,
            passcrypt_test_vector_1,
            passcrypt_test_vector_2,
            passcrypt_test_vector_3,
        )
        failures = []
        for index, result in enumerate(example_results):
            with Ignore(
                AssertionError, if_except=self.accrue_failures(index, failures)
            ):
                await self.examples_match_derivation(result)
        assert not any(failures)

    async def examples_match_derivation(self, result) -> None:
        assert result.hash_passphrase_result == (
            result.timestamp
            + (result.mb - 1).to_bytes(config.MB_BYTES, BIG)
            + (result.cpu - 1).to_bytes(config.CPU_BYTES, BIG)
            + (result.cores - 1).to_bytes(config.CORES_BYTES, BIG)
            + (result.salt_size - 1).to_bytes(config.SALT_SIZE_BYTES, BIG)
            + result.salt
            + result.tag
        )
        pcrypt = Passcrypt(
            mb=result.mb,
            cpu=result.cpu,
            cores=result.cores,
            tag_size=result.tag_size,
        )
        assert result.tag == pcrypt.new(
            result.passphrase,
            result.salt,
            aad=result.timestamp + result.aad,
        )
        await Passcrypt.averify(
            result.hash_passphrase_result,
            result.passphrase,
            aad=result.aad,
            config=pcrypt._config,
        )


class TestPasscryptInputsOutputs:
    pcrypt = Passcrypt(
        mb=config.MIN_MB,
        cpu=config.MIN_CPU,
        cores=config.MIN_CORES,
        tag_size=config.MIN_TAG_SIZE,
        salt_size=config.MIN_SALT_SIZE,
    )
    salt = csprng(config.MIN_SALT_SIZE)
    object.__delattr__(pcrypt._settings, "salt_size")
    config = pcrypt._config
    settings = dict(**pcrypt._settings, config=pcrypt._config)

    async def test_empty_passphrase_isnt_allowed(self) -> None:
        problem = (
            "Empty passphrase was allowed."
        )
        with Ignore(Passcrypt.ImproperPassphrase, if_else=violation(problem)):
            PasscryptSession(b"", self.salt, aad=b"", **self.settings)

        with Ignore(Passcrypt.ImproperPassphrase, if_else=violation(problem)):
            self.pcrypt.new(b"", self.salt)

        async with Ignore(Passcrypt.ImproperPassphrase, if_else=violation(problem)):
            await self.pcrypt.anew(b"", self.salt)

    async def test_min_passphrase_length(self) -> None:
        problem = (
            "A below minimum length passphrase was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            PasscryptSession(
                (config.MIN_PASSPHRASE_BYTES - 1) * b"p",
                self.salt,
                **self.settings,
            )

        with Ignore(ValueError, if_else=violation(problem)):
            self.pcrypt.new((config.MIN_PASSPHRASE_BYTES - 1) * b"p", self.salt)

        async with Ignore(ValueError, if_else=violation(problem)):
            await self.pcrypt.anew((config.MIN_PASSPHRASE_BYTES - 1) * b"p", self.salt)

    async def test_passphrase_must_be_bytes(self) -> None:
        problem = (
            "Non-bytes passphrase was allowed."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            PasscryptSession(
                "a string passphrase", self.salt, **self.settings
            )

        with Ignore(TypeError, if_else=violation(problem)):
            self.pcrypt.new("a string passphrase", self.salt)

        with Ignore(TypeError, if_else=violation(problem)):
            self.pcrypt.new(None, self.salt)

        with Ignore(TypeError, if_else=violation(problem)):
            self.pcrypt.new(12345, self.salt)

        async with Ignore(TypeError, if_else=violation(problem)):
            await self.pcrypt.anew("a string passphrase", self.salt)

    async def test_falsey_salts_not_allowed(self) -> None:
        problem = (
            "Empty salt was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            PasscryptSession(key, salt=b"", **self.settings)

        with Ignore(ValueError, if_else=violation(problem)):
            self.pcrypt.new(key, salt=b"")

        async with Ignore(ValueError, if_else=violation(problem)):
            await self.pcrypt.anew(key, salt=b"")

    async def test_salt_must_be_bytes(self) -> None:
        problem = (
            "Non-bytes salt was allowed."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            PasscryptSession(key, "a string salt here", **self.settings)

        with Ignore(TypeError, if_else=violation(problem)):
            self.pcrypt.new(key, "a string salt here")

        with Ignore(TypeError, if_else=violation(problem)):
            self.pcrypt.new(key, None)

        with Ignore(TypeError, if_else=violation(problem)):
            self.pcrypt.new(key, 123456)

        async with Ignore(TypeError, if_else=violation(problem)):
            await self.pcrypt.anew(key, "a string salt here")

    async def test_aad_must_be_bytes(self) -> None:
        problem = (
            "A non-bytes type `aad` was allowed."
        )
        with Ignore(TypeError, if_else=violation(problem)):
            PasscryptSession(
                key, self.salt, aad="some string aad", **self.settings
            )

        with Ignore(TypeError, if_else=violation(problem)):
            self.pcrypt.new(key, self.salt, aad=None)

        with Ignore(TypeError, if_else=violation(problem)):
            self.pcrypt.new(key, self.salt, aad=12345)

        with Ignore(TypeError, if_else=violation(problem)):
            await self.pcrypt.anew(key, self.salt, aad="some string aad")

    async def test_mb_must_be_int(self) -> None:
        assert isinstance(PasscryptIssue.invalid_mb(2.2), TypeError)
        assert isinstance(PasscryptIssue.invalid_mb("2"), TypeError)
        assert isinstance(PasscryptIssue.invalid_mb(None), TypeError)

    async def test_min_mb(self) -> None:
        problem = (
            "A `mb` cost below the minimum was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            Passcrypt(
                mb=self.config.MIN_MB - 1,
                cpu=self.config.MIN_CPU,
                cores=self.config.MIN_CORES,
                tag_size=self.config.MIN_TAG_SIZE,
                salt_size=self.config.MIN_SALT_SIZE,
            )

    async def test_max_mb(self) -> None:
        problem = (
            "A `mb` cost above the minimum was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            Passcrypt(
                mb=self.config.MAX_MB + 1,
                cpu=self.config.MIN_CPU,
                cores=self.config.MIN_CORES,
                tag_size=self.config.MIN_TAG_SIZE,
                salt_size=self.config.MIN_SALT_SIZE,
            )

    async def test_cpu_must_be_int(self) -> None:
        assert isinstance(PasscryptIssue.invalid_cpu(2.2), TypeError)
        assert isinstance(PasscryptIssue.invalid_cpu("2"), TypeError)
        assert isinstance(PasscryptIssue.invalid_cpu(None), TypeError)

    async def test_min_cpu(self) -> None:
        problem = (
            "A `cpu` cost below the minimum was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            Passcrypt(
                mb=self.config.MIN_MB,
                cpu=self.config.MIN_CPU - 1,
                cores=self.config.MIN_CORES,
                tag_size=self.config.MIN_TAG_SIZE,
                salt_size=self.config.MIN_SALT_SIZE,
            )

    async def test_max_cpu(self) -> None:
        problem = (
            "A `cpu` cost above the minimum was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            Passcrypt(
                mb=self.config.MIN_MB,
                cpu=self.config.MAX_CPU + 1,
                cores=self.config.MIN_CORES,
                tag_size=self.config.MIN_TAG_SIZE,
                salt_size=self.config.MIN_SALT_SIZE,
            )

    async def test_cores_must_be_int(self) -> None:
        assert isinstance(PasscryptIssue.invalid_cores(2.2), TypeError)
        assert isinstance(PasscryptIssue.invalid_cores("2"), TypeError)
        assert isinstance(PasscryptIssue.invalid_cores(None), TypeError)

    async def test_min_cores(self) -> None:
        problem = (
            "A `cores` cost below the minimum was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            Passcrypt(
                mb=self.config.MIN_MB,
                cpu=self.config.MIN_CPU,
                cores=self.config.MIN_CORES - 1,
                tag_size=self.config.MIN_TAG_SIZE,
                salt_size=self.config.MIN_SALT_SIZE,
            )

    async def test_max_cores(self) -> None:
        problem = (
            "A `cores` cost above the minimum was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            Passcrypt(
                mb=self.config.MIN_MB,
                cpu=self.config.MIN_CPU,
                cores=self.config.MAX_CORES + 1,
                tag_size=self.config.MIN_TAG_SIZE,
                salt_size=self.config.MIN_SALT_SIZE,
            )

    async def test_tag_size_must_be_int(self) -> None:
        assert isinstance(PasscryptIssue.invalid_tag_size(2.2), TypeError)
        assert isinstance(PasscryptIssue.invalid_tag_size("2"), TypeError)
        assert isinstance(PasscryptIssue.invalid_tag_size(None), TypeError)

    async def test_min_tag_size(self) -> None:
        problem = (
            "A `tag_size` below the minimum was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            Passcrypt(
                mb=self.config.MIN_MB,
                cpu=self.config.MIN_CPU,
                cores=self.config.MIN_CORES,
                tag_size=self.config.MIN_TAG_SIZE - 1,
                salt_size=self.config.MIN_SALT_SIZE,
            )

    async def test_salt_size_must_be_int(self) -> None:
        assert isinstance(PasscryptIssue.invalid_salt_size(2.2), TypeError)
        assert isinstance(PasscryptIssue.invalid_salt_size("2"), TypeError)
        assert isinstance(PasscryptIssue.invalid_salt_size(None), TypeError)

    async def test_min_salt_size(self) -> None:
        problem = (
            "A `salt_size` below the minimum was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            Passcrypt(
                mb=self.config.MIN_MB,
                cpu=self.config.MIN_CPU,
                cores=self.config.MIN_CORES,
                tag_size=self.config.MIN_TAG_SIZE,
                salt_size=self.config.MIN_SALT_SIZE - 1,
            )

    async def test_max_salt_size(self) -> None:
        problem = (
            "A `salt_size` above the minimum was allowed."
        )
        with Ignore(ValueError, if_else=violation(problem)):
            Passcrypt(
                mb=self.config.MIN_MB,
                cpu=self.config.MIN_CPU,
                cores=self.config.MIN_CORES,
                tag_size=self.config.MIN_TAG_SIZE,
                salt_size=self.config.MAX_SALT_SIZE + 1,
            )

    async def test_inner_work_memory_output_size(self) -> None:
        assert len(
            PasscryptProcesses._passcrypt(
                PasscryptSession(key, self.salt, **self.settings)
            )
        ) == SHAKE_128_BLOCKSIZE


class TestPasscryptConcurrencyInterface:
    pcrypt = Passcrypt(**passcrypt_settings, tag_size=32)

    async def test_async_broken_pool_is_restarted(self) -> None:
        problem = (
            "The algorithm wasn't halted by a broken process pool."
        )
        Processes._pool._broken = True
        with Ignore(RuntimeError, if_else=violation(problem)):
            await self.pcrypt.ahash_passphrase(passphrase)
        assert not Processes._pool._broken

    async def test_sync_broken_pool_is_restarted(self) -> None:
        problem = (
            "The algorithm wasn't halted by a broken process pool."
        )
        Processes._pool._broken = True
        with Ignore(RuntimeError, if_else=violation(problem)):
            self.pcrypt.hash_passphrase(passphrase)
        assert not Processes._pool._broken


class TestPasscryptSession:

    class MockLengthOfDataExperimentsOnRam:

        def __init__(self) -> None:
            self.total_data_ingested = 0

        def __getitem__(self, slice_of_data: slice) -> int:
            start = 0 if slice_of_data.start is None else slice_of_data.start
            stop = 0 if slice_of_data.stop is None else slice_of_data.stop
            return abs(stop - start)

        def extend(self, size_of_data: int) -> None:
            self.total_data_ingested += size_of_data

    class MockLengthOfDataExperimentsOnProof:

        def __init__(self) -> None:
            self.total_data_ingested = 0
            self.total_data_output = 0

        def update(self, size_of_data: int) -> None:
            self.total_data_ingested += size_of_data

        def digest(self, size_of_data: int) -> int:
            self.total_data_output += size_of_data
            return size_of_data

    class MockSelf(t.Namespace):

        def __setattr__(self, name: str, value: t.Any) -> None:
            if name == "ram" and name in self:
                pass
            else:
                object.__setattr__(self, name, value)

    async def test_allocate_ram_can_handle_above_max_sha3_output_size(
        self
    ) -> None:
        max_size = (B_TO_MB_RATIO * 512 - 1)
        multiples_of_max_size = 3
        mock_ram = self.MockLengthOfDataExperimentsOnRam()
        mock_proof = self.MockLengthOfDataExperimentsOnProof()
        mock_self = self.MockSelf(
            ram=mock_ram,
            proof=mock_proof,
            total_size=max_size * multiples_of_max_size,
        )
        PasscryptSession.allocate_ram(mock_self)
        assert mock_self.total_size == mock_ram.total_data_ingested
        assert mock_self.total_size == mock_proof.total_data_output
        assert 168 * multiples_of_max_size == mock_proof.total_data_ingested


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

