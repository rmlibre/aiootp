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


import warnings

from aiootp import _paths as p

from conftest import *


KEY = token_bytes(32)
SALT = token_bytes(32)


def is_windows_limitation(_: Ignore) -> bool:
    """
    On Windows, ``os.chmod(path, 0o000)`` doesn't deny reading attempts
    the way Unix-like systems do.

    This function raises the intended PermissionError if reading wasn't
    denied & the tests are being run on an OS which shouldn't have this
    Windows limitation.
    """
    if platform.system() != "Windows":
        raise PermissionError("Set permissions allowed reading.")

    warnings.warn(
        "NOTICE: File permissions on Windows don't deny reading of "
        "sensitive files, like random seed & salt files, as Unix-like "
        "systems do when os.chmod(path, 0o000) is used."
    )


class TestDeniableFilename:
    """
    Tests for the hash to shrunken filename functionalities.
    """

    @pytest.mark.parametrize("size", [*range(-28, 33, 5)])
    async def test_async_size_arg_must_be_between_1_and_16_inclusive(
        self, size: int
    ) -> None:
        try:
            await p.adeniable_filename(KEY, size=size)
        except ValueError:
            assert (size > 16) or (size < 1)
        else:
            assert 16 >= size >= 1

    @pytest.mark.parametrize("size", [*range(-28, 33, 5)])
    async def test_size_arg_must_be_between_1_and_16_inclusive(
        self, size: int
    ) -> None:
        try:
            p.deniable_filename(KEY, size=size)
        except ValueError:
            assert (size > 16) or (size < 1)
        else:
            assert 16 >= size >= 1

    @pytest.mark.parametrize("size", [4, 8])
    @pytest.mark.parametrize("key_length", [*range(0, 33, 8)])
    async def test_async_key_length_must_be_at_least_double_size_arg(
        self, key_length: int, size: int
    ) -> None:
        key = token_bytes(key_length)

        try:
            await p.adeniable_filename(key, size=size)
        except ValueError:
            assert key_length < 2 * size
        else:
            assert key_length >= 2 * size

    @pytest.mark.parametrize("size", [4, 8])
    @pytest.mark.parametrize("key_length", [*range(0, 33, 8)])
    async def test_key_length_must_be_at_least_double_size_arg(
        self, key_length: int, size: int
    ) -> None:
        key = token_bytes(key_length)

        try:
            p.deniable_filename(key, size=size)
        except ValueError:
            assert key_length < 2 * size
        else:
            assert key_length >= 2 * size


class TestMakeSaltFile:
    """
    Tests for the making protected salt file functionalities.
    """

    async def test_async_given_salt_is_persisted(
        self, salt_path: t.Path
    ) -> None:
        await p._amake_salt_file(salt_path, salt=SALT)
        salt_path.chmod(0o600)

        assert SALT == salt_path.read_bytes()

    async def test_given_salt_is_persisted(self, salt_path: t.Path) -> None:
        p._make_salt_file(salt_path, salt=SALT)
        salt_path.chmod(0o600)

        assert SALT == salt_path.read_bytes()

    async def test_async_new_salt_is_created(
        self, salt_path: t.Path
    ) -> None:
        await p._amake_salt_file(salt_path)
        salt_path.chmod(0o600)

        salt = salt_path.read_bytes()
        assert len(salt) == 32
        assert len(set(salt)) >= 16

    async def test_new_salt_is_created(self, salt_path: t.Path) -> None:
        p._make_salt_file(salt_path)
        salt_path.chmod(0o600)

        salt = salt_path.read_bytes()
        assert len(salt) == 32
        assert len(set(salt)) >= 16

    @pytest.mark.parametrize("size", [*range(16, 49, 8)])
    async def test_async_salt_must_be_at_least_32_bytes(
        self, salt_path: t.Path, size: int
    ) -> None:
        salt = token_bytes(size)

        try:
            await p._amake_salt_file(salt_path, salt=salt)
        except ValueError:
            assert size < 32
        else:
            assert size >= 32

    @pytest.mark.parametrize("size", [*range(16, 49, 8)])
    async def test_salt_must_be_at_least_32_bytes(
        self, salt_path: t.Path, size: int
    ) -> None:
        salt = token_bytes(size)

        try:
            p._make_salt_file(salt_path, salt=salt)
        except ValueError:
            assert size < 32
        else:
            assert size >= 32

    async def test_async_no_read_permissions_set_after_creation(
        self, salt_path: t.Path
    ) -> None:
        await p._amake_salt_file(salt_path)

        with Ignore(PermissionError, if_else=is_windows_limitation):
            salt_path.read_bytes()

    async def test_no_read_permissions_set_after_creation(
        self, salt_path: t.Path
    ) -> None:
        p._make_salt_file(salt_path)

        with Ignore(PermissionError, if_else=is_windows_limitation):
            salt_path.read_bytes()

    async def test_async_no_write_permissions_set_after_creation(
        self, salt_path: t.Path
    ) -> None:
        await p._amake_salt_file(salt_path)

        problem = (  # fmt: skip
            "Set permissions allowed writing."
        )
        with Ignore(PermissionError, if_else=violation(problem)):
            salt_path.write_bytes(SALT)

    async def test_no_write_permissions_set_after_creation(
        self, salt_path: t.Path
    ) -> None:
        p._make_salt_file(salt_path)

        problem = (  # fmt: skip
            "Set permissions allowed writing."
        )
        with Ignore(PermissionError, if_else=violation(problem)):
            salt_path.write_bytes(SALT)


class TestReadSaltFile:
    """
    Tests for the reading protected salt file functionalities.
    """

    async def test_async_read_doesnt_automate_creation(
        self, salt_path: t.Path
    ) -> None:
        problem = (  # fmt: skip
            "Reading non-existant salt file didn't raise error."
        )
        with Ignore(FileNotFoundError, if_else=violation(problem)):
            await p._aread_salt_file(salt_path)

    async def test_read_doesnt_automate_creation(
        self, salt_path: t.Path
    ) -> None:
        problem = (  # fmt: skip
            "Reading non-existant salt file didn't raise error."
        )
        with Ignore(FileNotFoundError, if_else=violation(problem)):
            p._read_salt_file(salt_path)

    @pytest.mark.parametrize("size", [*range(16, 49, 8)])
    async def test_async_salt_must_be_at_least_32_bytes(
        self, salt_path: t.Path, size: int
    ) -> None:
        salt_path.write_bytes(token_bytes(size))
        salt_path.chmod(0o000)

        try:
            await p._aread_salt_file(salt_path)
        except ValueError:
            assert size < 32
        else:
            assert size >= 32

    @pytest.mark.parametrize("size", [*range(16, 49, 8)])
    async def test_salt_must_be_at_least_32_bytes(
        self, salt_path: t.Path, size: int
    ) -> None:
        salt_path.write_bytes(token_bytes(size))
        salt_path.chmod(0o000)

        try:
            p._read_salt_file(salt_path)
        except ValueError:
            assert size < 32
        else:
            assert size >= 32

    async def test_async_no_read_permissions_set_after_reading(
        self, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        await p._aread_salt_file(salt_path)

        with Ignore(PermissionError, if_else=is_windows_limitation):
            salt_path.read_bytes()

    async def test_no_read_permissions_set_after_reading(
        self, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        p._read_salt_file(salt_path)

        with Ignore(PermissionError, if_else=is_windows_limitation):
            salt_path.read_bytes()

    async def test_async_no_write_permissions_set_after_reading(
        self, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        await p._aread_salt_file(salt_path)

        problem = (  # fmt: skip
            "Set permissions allowed reading."
        )
        with Ignore(PermissionError, if_else=violation(problem)):
            salt_path.write_bytes(SALT)

    async def test_no_write_permissions_set_after_reading(
        self, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        p._read_salt_file(salt_path)

        problem = (  # fmt: skip
            "Set permissions allowed reading."
        )
        with Ignore(PermissionError, if_else=violation(problem)):
            salt_path.write_bytes(SALT)


class TestUpdateSaltFile:
    """
    Tests for the updating protected salt file functionalities.
    """

    async def test_async_new_salt_is_created(
        self, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        new_salt = token_bytes(32)
        await p._aupdate_salt_file(salt_path, salt=new_salt)

        salt_path.chmod(0o600)
        assert new_salt == salt_path.read_bytes()

    async def test_new_salt_is_created(self, salt_path: t.Path) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        new_salt = token_bytes(32)
        p._update_salt_file(salt_path, salt=new_salt)

        salt_path.chmod(0o600)
        assert new_salt == salt_path.read_bytes()

    @pytest.mark.parametrize("size", [*range(16, 49, 8)])
    async def test_async_salt_must_be_at_least_32_bytes(
        self, salt_path: t.Path, size: int
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        try:
            await p._aupdate_salt_file(salt_path, salt=csprng(size))
        except ValueError:
            assert size < 32
        else:
            assert size >= 32

    @pytest.mark.parametrize("size", [*range(16, 49, 8)])
    async def test_salt_must_be_at_least_32_bytes(
        self, salt_path: t.Path, size: int
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        try:
            p._update_salt_file(salt_path, salt=csprng(size))
        except ValueError:
            assert size < 32
        else:
            assert size >= 32

    async def test_async_no_read_permissions_set_after_updating(
        self, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        await p._aupdate_salt_file(salt_path, salt=token_bytes(32))

        with Ignore(PermissionError, if_else=is_windows_limitation):
            salt_path.read_bytes()

    async def test_no_read_permissions_set_after_updating(
        self, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        p._update_salt_file(salt_path, salt=token_bytes(32))

        with Ignore(PermissionError, if_else=is_windows_limitation):
            salt_path.read_bytes()

    async def test_async_no_write_permissions_set_after_updating(
        self, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        await p._aupdate_salt_file(salt_path, salt=token_bytes(32))

        problem = (  # fmt: skip
            "Set permissions allowed writing."
        )
        with Ignore(PermissionError, if_else=violation(problem)):
            salt_path.write_bytes(SALT)

    async def test_no_write_permissions_set_after_updating(
        self, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        p._update_salt_file(salt_path, salt=token_bytes(32))

        problem = (  # fmt: skip
            "Set permissions allowed writing."
        )
        with Ignore(PermissionError, if_else=violation(problem)):
            salt_path.write_bytes(SALT)


class TestDeleteSaltFile:
    """
    Tests for the deleting protected salt file functionalities.
    """

    async def test_async_file_is_removed(self, salt_path: t.Path) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        await p._adelete_salt_file(salt_path)

        assert not salt_path.is_file()
        assert not salt_path.is_dir()

    async def test_file_is_removed(self, salt_path: t.Path) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        p._delete_salt_file(salt_path)

        assert not salt_path.is_file()
        assert not salt_path.is_dir()


class TestSecureSaltPath:
    """
    Tests for the protected salt file interface functionalities.
    """

    async def test_async_default_secure_path(self) -> None:
        path = p.DatabasePath() / "secure"

        result = p.SecureSaltPath(key=KEY)

        assert str(path) == str(result.parent)

    async def test_default_secure_path(self) -> None:
        path = p.DatabasePath() / "secure"

        result = p.SecureSaltPath(key=KEY)

        assert str(path) == str(result.parent)

    async def test_async_default_secure_admin_path(self) -> None:
        path = (p.DatabasePath() / "secure") / "_admin"

        result = await p.AsyncSecureSaltPath(key=KEY, _admin=True)

        assert str(path) == str(result.parent)

    async def test_default_secure_admin_path(self) -> None:
        path = (p.DatabasePath() / "secure") / "_admin"

        result = p.SecureSaltPath(key=KEY, _admin=True)

        assert str(path) == str(result.parent)

    async def test_async_same_keys_derive_same_paths(self) -> None:
        result_0 = await p.AsyncSecureSaltPath(key=KEY)
        result_1 = await p.AsyncSecureSaltPath(key=KEY)

        assert str(result_0) == str(result_1)

    async def test_same_keys_derive_same_paths(self) -> None:
        result_0 = p.SecureSaltPath(key=KEY)
        result_1 = p.SecureSaltPath(key=KEY)

        assert str(result_0) == str(result_1)

    async def test_async_same_keys_derive_same_admin_paths(self) -> None:
        result_0 = await p.AsyncSecureSaltPath(key=KEY, _admin=True)
        result_1 = await p.AsyncSecureSaltPath(key=KEY, _admin=True)

        assert str(result_0) == str(result_1)

    async def test_same_keys_derive_same_admin_paths(self) -> None:
        result_0 = p.SecureSaltPath(key=KEY, _admin=True)
        result_1 = p.SecureSaltPath(key=KEY, _admin=True)

        assert str(result_0) == str(result_1)

    async def test_zzz_ensure_test_files_are_removed(self) -> None:
        path = await p.AsyncSecureSaltPath(key=KEY)
        path.is_file() and path.unlink()

        path = p.SecureSaltPath(key=KEY)
        path.is_file() and path.unlink()

        path = await p.AsyncSecureSaltPath(key=KEY, _admin=True)
        path.is_file() and path.unlink()

        path = p.SecureSaltPath(key=KEY, _admin=True)
        path.is_file() and path.unlink()


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
