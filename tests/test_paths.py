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


class Targets(t.NamedTuple):
    """
    A container for distinct target test functions.
    """

    asynch: t.Callable[..., t.Awaitable[t.Any]]
    synch: t.Callable[..., t.Any]


class TargetRunner:
    """
    A runner base class for this file's unit tests.
    """

    targets: Targets

    async def run(self, target, *a: t.Any, **kw: t.Any) -> t.Any:
        if target is self.targets.asynch:
            return await target(*a, **kw)
        else:
            return target(*a, **kw)


class TestDeniableFilename(TargetRunner):
    """
    Tests for the hash to shrunken filename functionalities.
    """

    targets = Targets(
        asynch=p.adeniable_filename,
        synch=p.deniable_filename,
    )

    @pytest.mark.parametrize("size", [*range(-28, 33, 5)])
    @pytest.mark.parametrize("target", targets)
    async def test_size_arg_must_be_between_1_and_16_inclusive(
        self, target, size: int
    ) -> None:
        try:
            await self.run(target, KEY, size=size)
        except ValueError:
            assert (size > 16) or (size < 1)
        else:
            assert 16 >= size >= 1

    @pytest.mark.parametrize("size", [4, 8])
    @pytest.mark.parametrize("key_length", [*range(0, 33, 8)])
    @pytest.mark.parametrize("target", targets)
    async def test_key_length_must_be_at_least_double_size_arg(
        self, target, key_length: int, size: int
    ) -> None:
        key = token_bytes(key_length)

        try:
            await self.run(target, key, size=size)
        except ValueError:
            assert key_length < 2 * size
        else:
            assert key_length >= 2 * size


class TestMakeSaltFile(TargetRunner):
    """
    Tests for the making protected salt file functionalities.
    """

    targets = Targets(
        asynch=p._amake_salt_file,
        synch=p._make_salt_file,
    )

    @pytest.mark.parametrize("target", targets)
    async def test_given_salt_is_persisted(
        self, target, salt_path: t.Path
    ) -> None:
        await self.run(target, salt_path, salt=SALT)

        salt_path.chmod(0o600)

        assert SALT == salt_path.read_bytes()

    @pytest.mark.parametrize("target", targets)
    async def test_new_salt_is_created(
        self, target, salt_path: t.Path
    ) -> None:
        await self.run(target, salt_path)

        salt_path.chmod(0o600)

        salt = salt_path.read_bytes()
        assert len(salt) == 32
        assert len(set(salt)) >= 16

    @pytest.mark.parametrize("size", [*range(16, 49, 8)])
    @pytest.mark.parametrize("target", targets)
    async def test_salt_must_be_at_least_32_bytes(
        self, target, salt_path: t.Path, size: int
    ) -> None:
        salt = token_bytes(size)

        try:
            await self.run(target, salt_path, salt=salt)
        except ValueError:
            assert size < 32
        else:
            assert size >= 32

    @pytest.mark.parametrize("target", targets)
    async def test_no_read_permissions_set_after_creation(
        self, target, salt_path: t.Path
    ) -> None:
        await self.run(target, salt_path)

        with Ignore(PermissionError, if_else=is_windows_limitation):
            salt_path.read_bytes()

    @pytest.mark.parametrize("target", targets)
    async def test_no_write_permissions_set_after_creation(
        self, target, salt_path: t.Path
    ) -> None:
        await self.run(target, salt_path)

        problem = (  # fmt: skip
            "Set permissions allowed writing."
        )
        with Ignore(PermissionError, if_else=violation(problem)):
            salt_path.write_bytes(SALT)


class TestReadSaltFile(TargetRunner):
    """
    Tests for the reading protected salt file functionalities.
    """

    targets = Targets(
        asynch=p._aread_salt_file,
        synch=p._read_salt_file,
    )

    @pytest.mark.parametrize("target", targets)
    async def test_read_doesnt_automate_creation(
        self, target, salt_path: t.Path
    ) -> None:
        problem = (  # fmt: skip
            "Reading non-existant salt file didn't raise error."
        )
        with Ignore(FileNotFoundError, if_else=violation(problem)):
            await self.run(target, salt_path)

    @pytest.mark.parametrize("size", [*range(16, 49, 8)])
    @pytest.mark.parametrize("target", targets)
    async def test_salt_must_be_at_least_32_bytes(
        self, target, salt_path: t.Path, size: int
    ) -> None:
        salt_path.write_bytes(token_bytes(size))
        salt_path.chmod(0o000)

        try:
            await self.run(target, salt_path)
        except ValueError:
            assert size < 32
        else:
            assert size >= 32

    @pytest.mark.parametrize("target", targets)
    async def test_no_read_permissions_set_after_reading(
        self, target, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        await self.run(target, salt_path)

        with Ignore(PermissionError, if_else=is_windows_limitation):
            salt_path.read_bytes()

    @pytest.mark.parametrize("target", targets)
    async def test_no_write_permissions_set_after_reading(
        self, target, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        await self.run(target, salt_path)

        problem = (  # fmt: skip
            "Set permissions allowed writing."
        )
        with Ignore(PermissionError, if_else=violation(problem)):
            salt_path.write_bytes(SALT)

    @pytest.mark.parametrize("target", targets)
    async def test_retrieves_persisted_salt(
        self, target, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        assert SALT == await self.run(target, salt_path)


class TestUpdateSaltFile(TargetRunner):
    """
    Tests for the updating protected salt file functionalities.
    """

    targets = Targets(
        asynch=p._aupdate_salt_file,
        synch=p._update_salt_file,
    )

    @pytest.mark.parametrize("target", targets)
    async def test_new_salt_is_created(
        self, target, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        new_salt = token_bytes(32)
        await self.run(target, salt_path, salt=new_salt)

        salt_path.chmod(0o600)
        assert new_salt == salt_path.read_bytes()

    @pytest.mark.parametrize("size", [*range(16, 49, 8)])
    @pytest.mark.parametrize("target", targets)
    async def test_salt_must_be_at_least_32_bytes(
        self, target, salt_path: t.Path, size: int
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        try:
            await self.run(target, salt_path, salt=csprng(size))
        except ValueError:
            assert size < 32
        else:
            assert size >= 32

    @pytest.mark.parametrize("target", targets)
    async def test_no_read_permissions_set_after_updating(
        self, target, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        await self.run(target, salt_path, salt=token_bytes(32))

        with Ignore(PermissionError, if_else=is_windows_limitation):
            salt_path.read_bytes()

    @pytest.mark.parametrize("target", targets)
    async def test_no_write_permissions_set_after_updating(
        self, target, salt_path: t.Path
    ) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        await self.run(target, salt_path, salt=token_bytes(32))

        problem = (  # fmt: skip
            "Set permissions allowed writing."
        )
        with Ignore(PermissionError, if_else=violation(problem)):
            salt_path.write_bytes(SALT)


class TestDeleteSaltFile(TargetRunner):
    """
    Tests for the deleting protected salt file functionalities.
    """

    targets = Targets(
        asynch=p._adelete_salt_file,
        synch=p._delete_salt_file,
    )

    @pytest.mark.parametrize("target", targets)
    async def test_file_is_removed(self, target, salt_path: t.Path) -> None:
        salt_path.write_bytes(SALT)
        salt_path.chmod(0o000)

        await self.run(target, salt_path)

        assert not salt_path.is_file()
        assert not salt_path.is_dir()


class AdminContext(dict):
    """
    A container for admin data needed by the test target.
    """


class UserContext(dict):
    """
    A container for user data needed by the test target.
    """


class TargetContexts(t.NamedTuple):
    """
    A container for distinct data contexts needed by the test target.
    """

    admin_ctx: AdminContext
    user_ctx: UserContext


class TestSecureSaltPath(TargetRunner):
    """
    Tests for the protected salt file path interface functionalities.
    """

    kwargs = TargetContexts(
        admin_ctx=AdminContext(key=KEY, _admin=True),
        user_ctx=UserContext(key=KEY),
    )

    targets = Targets(
        asynch=p.AsyncSecureSaltPath,
        synch=p.SecureSaltPath,
    )

    @pytest.mark.parametrize("target", targets)
    async def test_default_secure_path(self, target) -> None:
        path = p.DatabasePath() / "secure"

        result = await self.run(target, **self.kwargs.user_ctx)

        assert str(path) == str(result.parent)

    @pytest.mark.parametrize("target", targets)
    async def test_default_secure_admin_path(self, target) -> None:
        path = (p.DatabasePath() / "secure") / "_admin"

        result = await self.run(target, **self.kwargs.admin_ctx)

        assert str(path) == str(result.parent)

    @pytest.mark.parametrize("kw", kwargs)
    @pytest.mark.parametrize("target", targets)
    async def test_zzz_remove_test_files(self, target, kw) -> None:
        path = await self.run(target, **kw)

        if path.is_file():
            path.chmod(0o600)
            path.unlink()


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
