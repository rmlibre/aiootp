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


__all__ = ["PasscryptConfig", "passcrypt_spec"]


__doc__ = "Passcrypt configuration logic & constants."


from hashlib import shake_128

from aiootp._typing import Typing as t
from aiootp._constants import INT_BYTES, BIG
from aiootp._constants import NANOSECONDS, SAFE_TIMESTAMP_BYTES, EPOCH_NS
from aiootp._exceptions import PasscryptIssue, Metadata
from aiootp.asynchs import Clock
from aiootp.commons import Config
from aiootp.generics import canonical_pack


class PasscryptConfig(Config):
    """
    Specifies the configuration for `Passcrypt`.
    """

    __slots__ = (
        "CORES_BYTES",
        "CORES_RESOURCE_SAFETY_RANGE",
        "CORES_SLICE",
        "CPU_BYTES",
        "CPU_RESOURCE_SAFETY_RANGE",
        "CPU_SLICE",
        "CPU_TO_DIGEST_PAIRS_PER_ROW_RATIO",
        "DEFAULT_CORES",
        "DEFAULT_CPU",
        "DEFAULT_MB",
        "DEFAULT_SCHEMA_SALT_SIZE",
        "EPOCH_NS",
        "HEADER_BYTES",
        "HEADER_SLICE",
        "MAX_CORES",
        "MAX_CPU",
        "MAX_MB",
        "MAX_SALT_SIZE",
        "MB_BYTES",
        "MB_RESOURCE_SAFETY_RANGE",
        "MB_SLICE",
        "MIN_CORES",
        "MIN_CPU",
        "MIN_MB",
        "MIN_PASSPHRASE_BYTES",
        "MIN_SALT_SIZE",
        "MIN_SCHEMA_BYTES",
        "MIN_TAG_SIZE",
        "PACKED_METADATA",
        "PASSCRYPT_PAD",
        "SALT_SIZE_BYTES",
        "SALT_SIZE_SLICE",
        "TIME_UNIT",
        "TIMESTAMP_BYTES",
        "TIMESTAMP_SLICE",
        "clock",
    )

    slots_types: t.Mapping[str, type] = dict(
        CONFIG_ID=t.Hashable,
        CORES_BYTES=int,
        CORES_RESOURCE_SAFETY_RANGE=range,
        CORES_SLICE=slice,
        CPU_BYTES=int,
        CPU_RESOURCE_SAFETY_RANGE=range,
        CPU_SLICE=slice,
        CPU_TO_DIGEST_PAIRS_PER_ROW_RATIO=int,
        DEFAULT_CORES=int,
        DEFAULT_CPU=int,
        DEFAULT_MB=int,
        DEFAULT_SCHEMA_SALT_SIZE=int,
        EPOCH_NS=int,
        HEADER_BYTES=int,
        HEADER_SLICE=slice,
        MAX_CORES=int,
        MAX_CPU=int,
        MAX_MB=int,
        MAX_SALT_SIZE=int,
        MB_BYTES=int,
        MB_RESOURCE_SAFETY_RANGE=range,
        MB_SLICE=slice,
        MIN_CORES=int,
        MIN_CPU=int,
        MIN_MB=int,
        MIN_PASSPHRASE_BYTES=int,
        MIN_SALT_SIZE=int,
        MIN_SCHEMA_BYTES=int,
        MIN_TAG_SIZE=int,
        PACKED_METADATA=bytes,
        PASSCRYPT_PAD=bytes,
        SALT_SIZE_BYTES=int,
        SALT_SIZE_SLICE=slice,
        TIME_UNIT=str,
        TIMESTAMP_BYTES=int,
        TIMESTAMP_SLICE=slice,
        clock=t.ClockType,
    )

    def __init__(
        self,
        *,
        config_id: t.Hashable,
        min_passphrase_bytes: int,
        passcrypt_pad: bytes,
        epoch_ns: int = EPOCH_NS,
    ) -> None:
        self.MIN_CORES = 1
        self.MAX_CORES = 256
        self.DEFAULT_CORES = 4
        self.CORES_BYTES = 1
        self.MIN_CPU = 1
        self.MAX_CPU = 256
        self.DEFAULT_CPU = 1
        self.CPU_TO_DIGEST_PAIRS_PER_ROW_RATIO = 2
        self.CPU_BYTES = 1
        self.MIN_MB = 1
        self.MAX_MB = 256 ** 3
        self.DEFAULT_MB = 64
        self.MB_BYTES = 3
        self.MIN_SALT_SIZE = 4
        self.MAX_SALT_SIZE = 256
        self.DEFAULT_SCHEMA_SALT_SIZE = 8
        self.SALT_SIZE_BYTES = 1
        self.MIN_TAG_SIZE = 16
        self.TIME_UNIT = NANOSECONDS
        self.TIMESTAMP_BYTES = SAFE_TIMESTAMP_BYTES
        self.CONFIG_ID = config_id
        self.EPOCH_NS = epoch_ns
        self.MIN_PASSPHRASE_BYTES = min_passphrase_bytes
        self.PASSCRYPT_PAD = passcrypt_pad
        self._initialize_dynamic_values()
        self._construct_metadata_constant()

    def _initialize_dynamic_values(self) -> None:
        """
        Uses the specified constants to build dependent configuration
        constants & objects.
        """
        self.HEADER_BYTES = (
            self.TIMESTAMP_BYTES
            + self.MB_BYTES
            + self.CPU_BYTES
            + self.CORES_BYTES
            + self.SALT_SIZE_BYTES
        )
        self.HEADER_SLICE = slice(0, self.HEADER_BYTES, 1)
        self.TIMESTAMP_SLICE = slice(0, self.TIMESTAMP_BYTES, 1)
        self.MB_SLICE = slice(
            self.TIMESTAMP_BYTES, self.TIMESTAMP_BYTES + self.MB_BYTES, 1
        )
        self.MB_RESOURCE_SAFETY_RANGE = range(self.MIN_MB, 512)
        self.CPU_SLICE = slice(
            self.TIMESTAMP_BYTES + self.MB_BYTES,
            self.TIMESTAMP_BYTES + self.MB_BYTES + self.CPU_BYTES,
            1,
        )
        self.CPU_RESOURCE_SAFETY_RANGE = range(self.MIN_CPU, 33)
        self.CORES_SLICE = slice(
            self.TIMESTAMP_BYTES + self.MB_BYTES + self.CPU_BYTES,
            self.TIMESTAMP_BYTES
            + self.MB_BYTES
            + self.CPU_BYTES
            + self.CORES_BYTES,
            1,
        )
        self.CORES_RESOURCE_SAFETY_RANGE = range(self.MIN_CORES, 9)
        self.SALT_SIZE_SLICE = slice(
            self.TIMESTAMP_BYTES
            + self.MB_BYTES
            + self.CPU_BYTES
            + self.CORES_BYTES,
            self.HEADER_BYTES,
            1,
        )
        self.MIN_SCHEMA_BYTES = (
            self.HEADER_BYTES + self.MIN_SALT_SIZE + self.MIN_TAG_SIZE
        )
        self.clock = Clock(self.TIME_UNIT, epoch=self.EPOCH_NS)

    def _construct_metadata_constant(self) -> None:
        """
        Causes hashes to be distinct for distinct configurations.

        IMPORTANT FOR SECURITY.
        See:
        https://eprint.iacr.org/2016/292.pdf
        https://csrc.nist.gov/csrc/media/Events/2023/third-workshop-on-
            block-cipher-modes-of-operation/documents/accepted-papers/
            Flexible%20Authenticated%20Encryption.pdf

        DO NOT OVERRIDE TO PROVIDE ITER-OP.
        """
        self.PACKED_METADATA = canonical_pack(
            self.CONFIG_ID,
            str(self.CORES_RESOURCE_SAFETY_RANGE).encode(),
            str(self.CORES_SLICE).encode(),
            str(self.CPU_RESOURCE_SAFETY_RANGE).encode(),
            str(self.CPU_SLICE).encode(),
            self.CPU_TO_DIGEST_PAIRS_PER_ROW_RATIO.to_bytes(INT_BYTES, BIG),
            self.DEFAULT_CORES.to_bytes(INT_BYTES, BIG),
            self.DEFAULT_CPU.to_bytes(INT_BYTES, BIG),
            self.DEFAULT_MB.to_bytes(INT_BYTES, BIG),
            self.DEFAULT_SCHEMA_SALT_SIZE.to_bytes(INT_BYTES, BIG),
            self.EPOCH_NS.to_bytes(16, BIG),
            str(self.HEADER_SLICE).encode(),
            self.MAX_CORES.to_bytes(INT_BYTES, BIG),
            self.MAX_CPU.to_bytes(INT_BYTES, BIG),
            self.MAX_MB.to_bytes(INT_BYTES, BIG),
            self.MAX_SALT_SIZE.to_bytes(INT_BYTES, BIG),
            self.MB_BYTES.to_bytes(INT_BYTES, BIG),
            str(self.MB_RESOURCE_SAFETY_RANGE).encode(),
            str(self.MB_SLICE).encode(),
            self.MIN_CORES.to_bytes(INT_BYTES, BIG),
            self.MIN_CPU.to_bytes(INT_BYTES, BIG),
            self.MIN_MB.to_bytes(INT_BYTES, BIG),
            self.MIN_PASSPHRASE_BYTES.to_bytes(INT_BYTES, BIG),
            self.MIN_SALT_SIZE.to_bytes(INT_BYTES, BIG),
            self.MIN_SCHEMA_BYTES.to_bytes(INT_BYTES, BIG),
            self.MIN_TAG_SIZE.to_bytes(INT_BYTES, BIG),
            self.PASSCRYPT_PAD,
            str(self.SALT_SIZE_SLICE).encode(),
            self.TIME_UNIT.encode(),
            str(self.TIMESTAMP_SLICE).encode(),
            int_bytes=1,
        )

    def is_passphrase(self, passphrase: bytes) -> bool:
        return (
            (passphrase.__class__ is bytes)
            and (len(passphrase) >= self.MIN_PASSPHRASE_BYTES)
        )

    def is_salt(self, salt: bytes) -> bool:
        length_limits = range(self.MIN_SALT_SIZE, self.MAX_SALT_SIZE + 1)
        return (salt.__class__ is bytes) and (len(salt) in length_limits)

    def is_aad(self, aad: bytes):
        return (aad.__class__ is bytes)

    def is_mb(self, mb: int) -> bool:
        mb_limits = range(self.MIN_MB, self.MAX_MB + 1)
        return (mb.__class__ is int) and (mb in mb_limits)

    def is_cpu(self, cpu: int) -> bool:
        cpu_limits = range(self.MIN_CPU, self.MAX_CPU + 1)
        return (cpu.__class__ is int) and (cpu in cpu_limits)

    def is_cores(self, cores: int) -> bool:
        cores_limits = range(self.MIN_CORES, self.MAX_CORES + 1)
        return (cores.__class__ is int) and (cores in cores_limits)

    def is_tag_size(self, tag_size: int) -> bool:
        tag_size_is_int = tag_size.__class__ is int
        return (tag_size_is_int) and (tag_size >= self.MIN_TAG_SIZE)

    def is_salt_size(self, salt_size: int) -> bool:
        salt_size_is_int = salt_size.__class__ is int
        salt_size_limits = range(self.MIN_SALT_SIZE, self.MAX_SALT_SIZE + 1)
        return salt_size_is_int and (salt_size in salt_size_limits)

    def validate_inputs(
        self, passphrase: bytes, salt: bytes, aad: bytes
    ) -> None:
        """
        Makes sure `passphrase`, `salt`, & `aad` are to specification.
        Throws `ValueError` or `TypeError` accordingly if not.
        """
        if not self.is_passphrase(passphrase):
            raise PasscryptIssue.improper_passphrase(Metadata(passphrase))
        elif not self.is_salt(salt):
            raise PasscryptIssue.improper_salt(Metadata(salt))
        elif not self.is_aad(aad):
            raise PasscryptIssue.improper_aad()

    def validate_settings(
        self,
        mb: int,
        cpu: int,
        cores: int,
        tag_size: int,
        salt_size: int,
    ) -> None:
        """
        Ensures the `mb`, `cpu`, `cores`, `tag_size`, & `salt_size`
        values are to specification. Throws `ValueError` or `TypeError`
        accordingly if not.
        """
        if not self.is_mb(mb):
            raise PasscryptIssue.invalid_mb(mb)
        elif not self.is_cpu(cpu):
            raise PasscryptIssue.invalid_cpu(cpu)
        elif not self.is_cores(cores):
            raise PasscryptIssue.invalid_cores(cores)
        elif not self.is_tag_size(tag_size):
            raise PasscryptIssue.invalid_tag_size(tag_size)
        elif not self.is_salt_size(salt_size):
            raise PasscryptIssue.invalid_salt_size(salt_size)


passcrypt_spec = PasscryptConfig(
    config_id=b"Passcrypt", min_passphrase_bytes=12, passcrypt_pad=b"\xf2"
)


module_api = dict(
    PasscryptConfig=t.add_type(PasscryptConfig),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    passcrypt_spec=passcrypt_spec,
)

