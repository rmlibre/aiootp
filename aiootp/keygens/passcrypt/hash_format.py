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


__all__ = ["PasscryptResources", "PasscryptHash"]


__doc__ = "Composed passcrypt hash logic, formatting, & parsing types."


from io import BytesIO

from aiootp._typing import Typing as t
from aiootp._constants import BIG, MB, CPU, CORES
from aiootp._exceptions import PasscryptIssue, raise_exception
from aiootp.commons import FrozenSlots, OpenFrozenSlots

from .config import passcrypt_spec


class PasscryptResources(OpenFrozenSlots):
    """
    Efficiently stores the resource values located in the header of a
    `Passcrypt` hash.
    """

    __slots__ = ("mb", "cpu", "cores")

    def __init__(self, mb: int, cpu: int, cores: int) -> None:
        self.mb = mb
        self.cpu = cpu
        self.cores = cores


class PasscryptHash(FrozenSlots):
    """
    Efficiently stores `Passcrypt` session values to be encoded into &
    safely decoded from formatted `Passcrypt` hashes.
    """

    __slots__ = ("timestamp", "mb", "cpu", "cores", "salt", "tag", "config")

    _MAPPED_ATTRIBUTES: t.Tuple[str] = (
        "timestamp", "mb", "cpu", "cores", "salt", "tag"
    )

    def __init__(
        self,
        *,
        timestamp: t.Optional[bytes] = None,
        mb: t.Optional[int] = None,
        cpu: t.Optional[int] = None,
        cores: t.Optional[int] = None,
        salt: t.Optional[bytes] = None,
        tag: t.Optional[bytes] = None,
        config: t.ConfigType = passcrypt_spec,
    ) -> None:
        """
        Populates the instance state from the provided session values
        which are composable into a `Passcrypt` hash.
        """
        object.__setattr__(self, "config", config)
        if any((timestamp, mb, cpu, cores, salt, tag)):
            config.validate_settings(
                mb=mb,
                cpu=cpu,
                cores=cores,
                tag_size=len(tag),
                salt_size=len(salt),
            )
            self.timestamp = timestamp
            self.mb = mb
            self.cpu = cpu
            self.cores = cores
            self.salt = salt
            self.tag = tag

    def __iter__(self) -> t.Generator[str, None, None]:
        yield from self._MAPPED_ATTRIBUTES

    @property
    def salt_size(self) -> t.Optional[int]:
        """
        Returns the length of the `salt` value stored in the instance
        state. If the `salt` has not been set, returns `None`.
        """
        salt = getattr(self, "salt", None)
        return len(salt) if salt else None

    @property
    def tag_size(self) -> t.Optional[int]:
        """
        Returns the length of the `tag` value stored in the instance
        state. If the `tag` has not been set, returns `None`.
        """
        tag = getattr(self, "tag", None)
        return len(tag) if tag else None

    def import_hash(self, passcrypt_hash: bytes) -> t.Self:
        """
        Populates the instance state from the decoded values represented
        in the bytes-type `passcrypt_hash`. These hashes contain the
        inputs & parameters of a `Passcrypt` session.
        """
        config = self.config
        to_int = int.from_bytes
        read = BytesIO(passcrypt_hash).read
        self.__init__(
            timestamp=read(config.TIMESTAMP_BYTES),
            mb=to_int(read(config.MB_BYTES), BIG) + 1,
            cpu=to_int(read(config.CPU_BYTES), BIG) + 1,
            cores=to_int(read(config.CORES_BYTES), BIG) + 1,
            salt=read(to_int(read(config.SALT_SIZE_BYTES), BIG) + 1),
            tag=read(),
        )
        return self

    def export_hash(self) -> bytes:
        """
        Returns the composed `Passcrypt` hash from the instance state.
        """
        config = self.config
        passcrypt_hash = (
            self.timestamp,
            (self.mb - 1).to_bytes(config.MB_BYTES, BIG),
            (self.cpu - 1).to_bytes(config.CPU_BYTES, BIG),
            (self.cores - 1).to_bytes(config.CORES_BYTES, BIG),
            (self.salt_size - 1).to_bytes(config.SALT_SIZE_BYTES, BIG),
            self.salt,
            self.tag,
        )
        return b"".join(passcrypt_hash)

    def in_allowed_ranges(
        self, mb_allowed: range, cpu_allowed: range, cores_allowed: range
    ) -> bool:
        """
        Procs a `ResourceWarning` exception if any of the range objects
        passed into the method do not contain the value which is set for
        its specified difficulty setting.

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import Passcrypt

        allowed_resource_consumption = dict(
            mb_allowed=range(16, 256),  # Less than 256 MiB allowed
            cpu_allowed=range(2, 8),    # Less than 8 complexity allowed
            cores_allowed=range(1, 5),  # Less than 5 processes allowed
        )

        try:
            Passcrypt.verify(hashed_pw, pw, **allowed_resource_consumption)
        except ResourceWarning as danger:
            admin.log(danger)
            hard_limits_exceeded = (
                danger.requested_resources.mb > 512
                or danger.requested_resources.cpu > 11
                or danger.requested_resources.cores > 8
            )
            below_security_guidelines = (
                danger.requested_resources.mb < 16
                or danger.requested_resources.cpu < 2
            )
            if hard_limits_exceeded:
                raise danger
            elif below_security_guidelines:
                raise PermissionError("Minimum hash difficulty unmet.")
            Passcrypt.verify(hashed_pw, pw)
        """
        proc = raise_exception
        exc = PasscryptIssue.untrusted_resource_consumption
        header = PasscryptResources(self.mb, self.cpu, self.cores)
        self.mb in mb_allowed or proc(exc(MB, header))
        self.cpu in cpu_allowed or proc(exc(CPU, header))
        self.cores in cores_allowed or proc(exc(CORES, header))
        return True


module_api = dict(
    PasscryptHash=t.add_type(PasscryptHash),
    PasscryptResources=t.add_type(PasscryptResources),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

