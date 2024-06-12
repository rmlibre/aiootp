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


__all__ = ["AsyncProfileTokens", "ProfileTokens"]


__doc__ = (
    "A type deriving database keys from passphrases using the passcrypt, "
    "memory-hard hashing function."
)


from hashlib import sha3_512

from aiootp._typing import Typing as t
from aiootp._constants import MIN_KEY_BYTES
from aiootp._gentools import aunpack
from aiootp._paths import Path, AsyncSecurePath, SecurePath
from aiootp._paths import aread_salt_file, read_salt_file
from aiootp.asynchs import asleep
from aiootp.commons import FrozenSlots
from aiootp.generics import ahash_bytes, hash_bytes
from aiootp.keygens import Passcrypt

from .dbdomains import DBDomains


class AsyncProfileTokens(FrozenSlots):
    """
    Efficiently stores AsyncDatabase & Database profile token values
    which are used to more safely construct databases from potentially
    low entropy passphrases.
    """

    __slots__ = ("_gist", "_salt", "_salt_path", "login_key", "profile")

    def __init__(self) -> None:
        pass

    @classmethod
    async def _asummon_device_salt(cls, path: t.PathStr) -> bytes:
        """
        Generates a salt which is unique for each unique `path`
        directory that is given to this method. This is a static salt
        which provides an initial form of randomization to cryptographic
        material for all profiles saved under that directory.
        """
        salt_path = await AsyncSecurePath(
            path, key=DBDomains.DEVICE_SALT, _admin=True
        )
        return await aread_salt_file(salt_path)

    async def _asummon_profile_salt(
        self, path: t.PathStr
    ) -> t.Tuple[t.Path, bytes]:
        """
        Creates or loads a salt value saved on the user filesystem to
        help add more entropy to their key derivation functions when
        preparing to open a profile database.
        """
        salt_path = await AsyncSecurePath(path, key=self._gist)
        salt = await aread_salt_file(salt_path)
        return salt_path, salt

    async def _agenerate_profile_login_key(
        self, passphrase: bytes, **passcrypt_settings
    ) -> bytes:
        """
        Combines the output of the expensive key derivation functions &
        the salt stored on the filesystem gathered in preparation to
        safely open a profile database.
        """
        pcrypt = Passcrypt(tag_size=MIN_KEY_BYTES, **passcrypt_settings)
        return await pcrypt.anew(
            passphrase=await ahash_bytes(
                DBDomains.TMP_PREKEY,
                self._salt,
                self._gist,
                key=passphrase,
                hasher=sha3_512,
            ),
            salt=self._salt,
            aad=DBDomains.PROFILE_LOGIN_KEY,
        )

    async def agenerate(
        self,
        *credentials: bytes,
        username: bytes,
        passphrase: bytes,
        salt: bytes,
        aad: bytes,
        path: t.PathStr,
        **passcrypt_settings,
    ) -> t.Self:
        """
        Runs a very expensive key derivation function to build keys
        for users to open a database with only access to potentially
        weakly entropic credentials & the filesystem.
        """
        device_salt = await self._asummon_device_salt(path=path)
        self._gist = await ahash_bytes(
            DBDomains.GIST,
            device_salt,
            salt,
            aad,
            username,
            *credentials,
            key=device_salt,
            hasher=sha3_512,
        )
        self._salt_path, self._salt = await self._asummon_profile_salt(
            path=path
        )
        self.login_key = await self._agenerate_profile_login_key(
            passphrase, **passcrypt_settings
        )
        return self

    async def acleanup(self) -> None:
        """
        Removes cryptographic material from the object after use.
        """
        await asleep()
        object.__delattr__(self, "_gist")
        object.__delattr__(self, "_salt")
        object.__delattr__(self, "login_key")


class ProfileTokens(FrozenSlots):
    """
    Efficiently stores AsyncDatabase & Database profile token values
    which are used to more safely construct databases from potentially
    low entropy passphrases.
    """

    __slots__ = ("_gist", "_salt", "_salt_path", "login_key", "profile")

    def __init__(self) -> None:
        pass

    @classmethod
    def _summon_device_salt(cls, path: t.PathStr) -> bytes:
        """
        Generates a salt which is unique for each unique `path`
        directory that is given to this method. This is a static salt
        which provides an initial form of randomization to cryptographic
        material for all profiles saved under that directory.
        """
        salt_path = SecurePath(path, key=DBDomains.DEVICE_SALT, _admin=True)
        return read_salt_file(salt_path)

    def _summon_profile_salt(
        self, path: t.PathStr
    ) -> t.Tuple[t.Path, bytes]:
        """
        Creates or loads a salt value saved on the user filesystem to
        help add more entropy to their key derivation functions when
        preparing to open a profile database.
        """
        salt_path = SecurePath(path, key=self._gist)
        salt = read_salt_file(salt_path)
        return salt_path, salt

    def _generate_profile_login_key(
        self, passphrase: bytes, **passcrypt_settings
    ) -> bytes:
        """
        Combines the output of the expensive key derivation functions &
        the salt stored on the filesystem gathered in preparation to
        safely open a profile database.
        """
        pcrypt = Passcrypt(tag_size=MIN_KEY_BYTES, **passcrypt_settings)
        return pcrypt.new(
            passphrase=hash_bytes(
                DBDomains.TMP_PREKEY,
                self._salt,
                self._gist,
                key=passphrase,
                hasher=sha3_512,
            ),
            salt=self._salt,
            aad=DBDomains.PROFILE_LOGIN_KEY,
        )

    def generate(
        self,
        *credentials: bytes,
        username: bytes,
        passphrase: bytes,
        salt: bytes,
        aad: bytes,
        path: t.PathStr,
        **passcrypt_settings,
    ) -> t.Self:
        """
        Runs a very expensive key derivation function to build keys
        for users to open a database with only access to potentially
        weakly entropic credentials & the filesystem.
        """
        device_salt = self._summon_device_salt(path=path)
        self._gist = hash_bytes(
            DBDomains.GIST,
            device_salt,
            salt,
            aad,
            username,
            *credentials,
            key=device_salt,
            hasher=sha3_512,
        )
        self._salt_path, self._salt = self._summon_profile_salt(path=path)
        self.login_key = self._generate_profile_login_key(
            passphrase, **passcrypt_settings
        )
        return self

    def cleanup(self) -> None:
        """
        Removes cryptographic material from the object after use.
        """
        object.__delattr__(self, "_gist")
        object.__delattr__(self, "_salt")
        object.__delattr__(self, "login_key")


module_api = dict(
    AsyncProfileTokens=t.add_type(AsyncProfileTokens),
    ProfileTokens=t.add_type(ProfileTokens),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

