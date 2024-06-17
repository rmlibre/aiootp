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


__all__ = ["PasscryptSession"]


__doc__ = "Initializer for the `Passcrypt` proof object."


import math
from hashlib import shake_128

from aiootp._typing import Typing as t
from aiootp._constants import B_TO_MB_RATIO, DEFAULT_AAD
from aiootp._constants import INT_BYTES, BIG, SHAKE_128_BLOCKSIZE
from aiootp._exceptions import Issue, PasscryptIssue
from aiootp._exceptions import Metadata
from aiootp.commons import FrozenSlots, FrozenInstance, OpenNamespace
from aiootp.generics import Domains, ahash_bytes, hash_bytes
from aiootp.generics import canonical_pack, bytes_are_equal
from aiootp.randoms import acsprng, csprng

from .config import passcrypt_spec


class PasscryptSession(FrozenInstance):
    """
    Hanldes the initialization of running the `Passcrypt` hashing
    algorithm with sets of given user parameters.
    """

    __slots__ = (
        "passphrase",
        "salt",
        "aad",
        "mb",
        "cpu",
        "cores",
        "tag_size",
        "row_size",
        "rows",
        "total_size",
        "ram",
        "proof",
        "config",
    )

    _new_passcrypt_proof_kdf: t.Callable[[], t.XOFType] = shake_128(
        Domains.encode_constant(
            b"passcrypt_proof_kdf_salt",
            domain=Domains.PASSCRYPT,
            size=SHAKE_128_BLOCKSIZE,
        )
    ).copy

    def __init__(
        self,
        passphrase: bytes,
        salt: bytes,
        *,
        mb: int,
        cpu: int,
        cores: int,
        tag_size: int,
        config: t.ConfigType,
        aad: bytes = DEFAULT_AAD,

    ) -> None:
        """
        Efficiently stores user parameters.
        """
        self.config = config
        config.validate_inputs(passphrase=passphrase, salt=salt, aad=aad)
        config.validate_settings(
            mb=mb,
            cpu=cpu,
            cores=cores,
            tag_size=tag_size,
            salt_size=len(salt),
        )
        self.passphrase = passphrase
        self.salt = salt
        self.aad = aad
        self.mb = mb
        self.cpu = cpu
        self.cores = cores
        self.tag_size = tag_size

    def __iter__(
        self,
    ) -> t.Generator[t.Union[bytearray, t.Callable, int], None, None]:
        """
        Dumps the set of relevant parameters & function pointers for the
        `Passcrypt` worker. Gives the session a cleaner interface.
        """
        yield from (
            self.ram,
            self.proof.update,
            self.proof.digest,
            self.row_size,
            self.total_size,
        )

    def _hash_session_parameters(self) -> bytes:
        """
        Returns a 336-byte hash of the session's canonically encoded
        parameters.
        """
        return hash_bytes(
            Domains.PASSCRYPT,
            self.config.PACKED_METADATA,
            self.salt,
            self.aad,
            self.mb.to_bytes(INT_BYTES, BIG),
            self.cpu.to_bytes(INT_BYTES, BIG),
            self.cores.to_bytes(INT_BYTES, BIG),
            self.tag_size.to_bytes(INT_BYTES, BIG),
            key=self.passphrase + self.salt + self.aad,
            hasher=shake_128,
            size=336,
            pad=self.config.PASSCRYPT_PAD,
        )

    def prepare_session(self) -> t.Self:
        """
        Canonically hash the parameters to the function & calculate the
        dimensionality of the cache from the given settings.
        """
        rounds = max(
            (1, self.cpu // self.config.CPU_TO_DIGEST_PAIRS_PER_ROW_RATIO)
        )
        self.rows = math.ceil((B_TO_MB_RATIO * self.mb) / (336 * rounds))
        self.row_size = 336 * rounds
        self.total_size = self.row_size * self.rows
        parameters = self._hash_session_parameters()
        self.proof = self._new_passcrypt_proof_kdf()
        self.proof.update(parameters)
        return self

    def allocate_ram(self) -> t.Self:
        """
        Builds a virtual 2d memory cache out of a 1d bytearray to do
        efficient & in-place memory overwrites of segments of the cache
        with new proofs-of-work as the `Passcrypt` algorithm runs to
        completion.

        The bytearray is traversed to simulate the dimensionality of a
        columns=2*rounds, rows=ceil((1024*1024*mb) / (2*168*rounds)),
        2d array, where the unit measure for the width of one column is
        168-bytes (one digest from the `shake_128` `proof` object), &
        rounds=max([1, cpu // 2]).

        This procedure is designed to build the initial cache as fast as
        possible using the C implementation of `hashlib.shake_128` to
        better equalize the execution time between users & their
        adversaries. Quickly building the initial cache to the full size
        of the desired `mb` memory cost is also intended to reduce the
        inefficiencies of doing any resizing of the cache once the
        algorithm begins. This too is the main motivating factor for the
        size of each row being an equal multiple of 336, as it allows
        cache traversal & insertions without needing to plan separately
        for how to treat insertions once the end of a row is reached.
        """
        self.ram = bytearray()
        size = self.total_size
        max_size = (B_TO_MB_RATIO * 512) - 1  # 512MiB, max digest size
        while size > max_size:                # of shake_128 in python
            self.ram.extend(self.proof.digest(max_size))
            self.proof.update(self.ram[-168:])
            size -= max_size
        if size:
            self.ram.extend(self.proof.digest(size))
            self.proof.update(self.ram[-168:])
        return self


module_api = dict(
    PasscryptSession=t.add_type(PasscryptSession),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

