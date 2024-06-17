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


__all__ = ["Passcrypt", "PasscryptSettings"]


__doc__ = (
    "An interface for the passcrypt memory-hard passphrase hashing "
    "function."
)


from hashlib import shake_128

from aiootp._typing import Typing as t
from aiootp._constants import NS_TO_S_RATIO, DEFAULT_AAD, DEFAULT_TTL
from aiootp._exceptions import Issue, PasscryptIssue, TimestampExpired
from aiootp._exceptions import InvalidPassphrase, ImproperPassphrase
from aiootp._gentools import abytes_range, bytes_range
from aiootp.asynchs import Processes
from aiootp.commons import OpenFrozenSlots, FrozenInstance
from aiootp.generics import Domains
from aiootp.generics import ahash_bytes, hash_bytes, bytes_are_equal
from aiootp.randoms import acsprng, csprng

from .config import passcrypt_spec
from .hash_format import PasscryptHash
from .session_init import PasscryptSession
from .sessions_manager import PasscryptProcesses


class PasscryptSettings(OpenFrozenSlots):
    """
    Efficiently stores the resource values located in the header of a
    `Passcrypt` hash.
    """

    __slots__ = ("mb", "cpu", "cores", "tag_size", "salt_size")

    _MAPPED_ATTRIBUTES: t.Tuple[str] = __slots__

    def __init__(
        self,
        *,
        mb: int,
        cpu: int,
        cores: int,
        tag_size: int,
        salt_size: int,
        config: t.ConfigType = passcrypt_spec,
    ) -> None:
        self.mb = mb
        self.cpu = cpu
        self.cores = cores
        self.tag_size = tag_size
        self.salt_size = salt_size
        config.validate_settings(**self)


class Passcrypt(FrozenInstance):
    """
    This class is used to implement an Argon2i-like passphrase-based
    key derivation function that's designed to be resistant to cache-
    timing side-channel attacks & time-memory trade-offs.

    It uses a passphrase-keyed scanning function which sequentially
    passes over unique memory caches requiring a tunable amount of
    difficulty, which is designed here to be very intuitive.

    This scheme is secret independent with regard to how it chooses to
    pass over memory. Through proofs of work & memory, it ensures an
    attacker attempting to crack a passphrase hash cannot complete the
    algorithm substantially faster by storing more memory than what's
    already necessary, or with substantially less memory, by dropping
    cache entries, without drastically increasing the computational
    cost.

    The algorithm initializes all of the columns for the cache using a
    single `shake_128` object after being fed the passphrase, salt, aad
    & all of the parameters. The number of columns is computed
    dynamically to reach the specified memory cost considering that each
    row will hold 2 * max([1, cpu // 2]) digests of 168-bytes. This
    allows the cache to be efficiently allocated up front, benefiting
    further by not needing to resize the memory cache throughout the
    running of the algorithm.

    The sequential passes involve a current row index, the index of the
    row which is the reflection of the first across the cache, & a
    current offset into a row which are multiples of 336 (two digests).
    The index & reflection pointers interleave each other, hashing rows
    with the same object as they scan, & overwriting the 168-byte digest
    / piece of cache at the offset they're pointing to after each hash.

     _____________________________________
    |                                     |
    |    Algorithm Diagram: Side-View     |
    |_____________________________________|

           ___________________ # of rows ___________________
          |                                                 |
          |              initial memory cache               |
          |  row  # of columns == 2 * max([1, cpu // 2])    |
          |   |   # of rows == ⌈1024*1024*mb/168*columns⌉   |
          v   v                                             v
    column|---'-----------------------------------------'---| the initial cache
    column|---'-----------------------------------------'---| of size ~`mb` is
    column|---'-----------------------------------------'---| built very quickly
    column|---'-----------------------------------------'---| using SHAKE-128.
    column|---'-----------------------------------------'---| each (row, column)
    column|---'-----------------------------------------'---| coordinate holds
    column|---'-----------------------------------------'---| one element of
    column|---'-----------------------------------------'---| 168-bytes.
                                                        ^
                                                        |
                           reflection                  row
                          <-   |
          |--------------------'-------'--------------------| each row is
          |--------------------'-------'--------------------| hashed then has
          |--------------------'-------'--------------------| a new 168-byte
          |--------------------'-------'--------------------| digest overwrite
          |--------------------'-------'--------------------| the current pointer
          |--------------------'-------'--------------------| in an alternating
          |--------------------Xxxxxxxx'xxxxxxxxxxxxxxxxxxxx| sequence, first at
          |oooooooooooooooooooo'oooooooO--------------------| the index, then at
                                       |   ->                 its reflection.
                                     index


          |--'-------------------------------------------'--| this continues
          |--'-------------------------------------------'--| until the entire
          |--'-------------------------------------------Xxx| cache has been
          |ooO-------------------------------------------'--| overwritten.
          |xx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'xx| a single `shake_128`
          |oo'ooooooooooooooooooooooooooooooooooooooooooo'oo| object (H) is used
          |xx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'xx| to do all of the
          |oo'ooooooooooooooooooooooooooooooooooooooooooo'oo| hashing.
             |   ->                                 <-   |
           index                                     reflection


          |xxxxxxxxxxx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx| finally, the whole
          |ooooooooooo'ooooooooooooooooooooooooooooooooooooo| cache is quickly
          |xxxxxxxxxxx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx| hashed `cpu` + 2
          |ooooooooooo'ooooooooooooooooooooooooooooooooooooo| number of times.
          |Fxxxxxxxxxx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx| after each pass an
          |foooooooooo'ooooooooooooooooooooooooooooooooooooo| 84-byte digest (F)
          |fxxxxxxxxxx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx| is inserted into the
          |foooooooooo'ooooooooooooooooooooooooooooooooooooo| cache, ruling out
                      |   ->                                  hashing state cycles.
                      | hash cpu + 2 # of times               Then a `tag_size`-
                      v                                       byte tag is output.
           H.update(cache)

          tag = H.digest(tag_size)

         _____________________________________
        |                                     |
        |   Format Diagram: Passcrypt Hash    |
        |_____________________________________|
         ______________________________________________________________
        |                                    |                         |
        |               Header               |          Body           |
        |-------|-------|------|------|------|--------|----------------|
        | time  |  mb   | cpu  | cores| Slen |  salt  |      tag       |
        |  8-   |  3-   |  1-  |  1-  |  1-  |  Slen- |     >=16-      |
        | bytes | bytes | byte | byte | byte |  bytes |     bytes      |
        |_______|_______|______|______|______|________|________________|
        |                                                              |
        |                          >=34-bytes                          |
        |______________________________________________________________|

         _____________________________________
        |                                     |
        |            Usage Example:           |
        |_____________________________________|

        from aiootp import Passcrypt, Domains
        from getpass import getpass


        Passcrypt.PEPPER = bytes.fromhex(getpass("hexidecimal pepper: "))
        pcrypt = Passcrypt(mb=128)

        # registration ->

        un = getpass("username: ").encode() + Domains.USERNAME
        pw = getpass("passphrase: ").encode() + Domains.PASSPHRASE

        pw_hash = pcrypt.hash_passphrase(pw, aad=un, mb=128)


        # a login attempt ->

        un = getpass("username: ").encode() + Domains.USERNAME
        pw = getpass("passphrase: ").encode() + Domains.PASSPHRASE

        try:
            Passcrypt.verify(pw_hash, pw, aad=un, ttl=24 * 3600)
        except Passcrypt.InvalidPassphrase as auth_fail:
            app.post_mortem(error=auth_fail)
        except Passcrypt.TimestampExpired as expired_hash:
            # 24-hour registration expired
            app.post_mortem(error=expired_hash)
    """

    __slots__ = ("_settings", "_config")

    _PasscryptProcesses: type = PasscryptProcesses
    _PasscryptSettings: type = PasscryptSettings

    # An operator of a passphrase database may add a static secret value
    # to the class, referred to as a `pepper`. That value can be set in
    # this variable & will then augment all hashes produced by the class
    # with that additional secret entropy. The operator is in charge of
    # storing this value securely so it can be reused when the program
    # restarts. This value SHOULD NOT be stored in the same database
    # where the hashes are stored.
    PEPPER: bytes = b""

    TimestampExpired = TimestampExpired
    InvalidPassphrase = InvalidPassphrase
    ImproperPassphrase = ImproperPassphrase

    def __init__(
        self,
        *,
        tag_size: int,
        mb: int = passcrypt_spec.DEFAULT_MB,
        cpu: int = passcrypt_spec.DEFAULT_CPU,
        cores: int = passcrypt_spec.DEFAULT_CORES,
        salt_size: int = passcrypt_spec.DEFAULT_SCHEMA_SALT_SIZE,
        config: t.ConfigType = passcrypt_spec,
    ) -> None:
        """
        Stores user-defined settings.
        """
        self._config = config
        self._settings = self._PasscryptSettings(
            mb=mb,
            cpu=cpu,
            cores=cores,
            tag_size=tag_size,
            salt_size=salt_size,
            config=config,
        )

    async def anew(
        self, passphrase: bytes, salt: bytes, *, aad: bytes = DEFAULT_AAD
    ) -> bytes:
        """
        Returns just the `tag_size`-byte hash of the `passphrase`
        when processed with the given `salt`, `aad` & difficulty
        settings.

        NOTICE: The passcrypt algorithm can be highly memory intensive.
        These resources may not be freed up, & often are not, because of
        python quirks around memory management. To force the release of
        these resources, we run the function in another process which
        guarantees the release.
        """
        try:
            sessions = await self._PasscryptProcesses().aspawn(
                passphrase=passphrase,
                salt=salt,
                aad=aad,
                pepper=self.PEPPER,
                mb=self._settings.mb,
                cpu=self._settings.cpu,
                cores=self._settings.cores,
                tag_size=self._settings.tag_size,
                config=self._config,
            )
            return await ahash_bytes(
                *[await session.aresult() for session in sessions],
                size=self._settings.tag_size,
                hasher=shake_128,
                key=await sessions[0].aresult(),
            )
        except Exception as error:
            if Processes._pool._broken:
                Processes.reset_pool()
                raise Issue.broken_pool_restarted() from error
            raise error

    def new(
        self, passphrase: bytes, salt: bytes, *, aad: bytes = DEFAULT_AAD
    ) -> bytes:
        """
        Returns just the `tag_size`-byte hash of the `passphrase`
        when processed with the given `salt`, `aad` & difficulty
        settings.

        NOTICE: The passcrypt algorithm can be highly memory intensive.
        These resources may not be freed up, & often are not, because of
        python quirks around memory management. To force the release of
        these resources, we run the function in another process which
        guarantees the release.
        """
        try:
            sessions = self._PasscryptProcesses().spawn(
                passphrase=passphrase,
                salt=salt,
                aad=aad,
                pepper=self.PEPPER,
                mb=self._settings.mb,
                cpu=self._settings.cpu,
                cores=self._settings.cores,
                tag_size=self._settings.tag_size,
                config=self._config,
            )
            return hash_bytes(
                *[session.result() for session in sessions],
                size=self._settings.tag_size,
                hasher=shake_128,
                key=sessions[0].result(),
            )
        except Exception as error:
            if Processes._pool._broken:
                Processes.reset_pool()
                raise Issue.broken_pool_restarted() from error
            raise error

    async def ahash_passphrase(
        self, passphrase: bytes, *, aad: bytes = DEFAULT_AAD
    ) -> bytes:
        """
        Returns the passcrypt difficulty settings, salt & hash of the
        `passphrase` in a single raw bytes sequence for convenient
        storage. The salt here is automatically generated.

        `passphrase`: A 12-byte or greater entropic value that
                contains the user's desired entropy & cryptographic
                strength. A passphrase is ideally a compilation of
                words, symbols & numbers which are easy for the user to
                remember, but difficult for anyone else to guess even if
                they know precise details about who the user is & their
                characteristics / tendencies.

        `aad`: An arbitrary bytes value a user decides to categorize
                the hash with. It is authenticated as associated data &
                safely permutes hashes created with different `aad`.

        NOTICE: The passcrypt algorithm can be highly memory intensive.
        These resources may not be freed up, & often are not, because of
        python quirks around memory management. To force the release of
        these resources, we run the function in another process which
        guarantees the release.
        """
        timestamp = await self._config.clock.amake_timestamp()
        salt = await acsprng(self._settings.salt_size)
        tag = await self.anew(passphrase, salt, aad=timestamp + aad)
        return PasscryptHash(
            timestamp=timestamp,
            mb=self._settings.mb,
            cpu=self._settings.cpu,
            cores=self._settings.cores,
            salt=salt,
            tag=tag,
            config=self._config,
        ).export_hash()

    def hash_passphrase(
        self, passphrase: bytes, *, aad: bytes = DEFAULT_AAD
    ) -> bytes:
        """
        Returns the passcrypt difficulty settings, salt & hash of the
        `passphrase` in a single raw bytes sequence for convenient
        storage. The salt here is automatically generated.

        `passphrase`: A 12-byte or greater entropic value that
                contains the user's desired entropy & cryptographic
                strength. A passphrase is ideally a compilation of
                words, symbols & numbers which are easy for the user to
                remember, but difficult for anyone else to guess even if
                they know precise details about who the user is & their
                characteristics / tendencies.

        `aad`: An arbitrary bytes value a user decides to categorize
                the hash with. It is authenticated as associated data &
                safely permutes hashes created with different `aad`.

        NOTICE: The passcrypt algorithm can be highly memory intensive.
        These resources may not be freed up, & often are not, because of
        python quirks around memory management. To force the release of
        these resources, we run the function in another process which
        guarantees the release.
        """
        timestamp = self._config.clock.make_timestamp()
        salt = csprng(self._settings.salt_size)
        tag = self.new(passphrase, salt, aad=timestamp + aad)
        return PasscryptHash(
            timestamp=timestamp,
            mb=self._settings.mb,
            cpu=self._settings.cpu,
            cores=self._settings.cores,
            salt=salt,
            tag=tag,
            config=self._config,
        ).export_hash()

    @classmethod
    async def averify(
        cls,
        composed_passcrypt_hash: bytes,
        passphrase: bytes,
        *,
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
        mb_allowed: range = passcrypt_spec.MB_RESOURCE_SAFETY_RANGE,
        cpu_allowed: range = passcrypt_spec.CPU_RESOURCE_SAFETY_RANGE,
        cores_allowed: range = passcrypt_spec.CORES_RESOURCE_SAFETY_RANGE,
        config: t.ConfigType = passcrypt_spec,
    ) -> None:
        """
        Verifies that a supplied `passphrase` was indeed used to build
        the `composed_passcrypt_hash`.

        `aad`: An arbitrary bytes value a user decides to categorize
                the hash with. It is authenticated as associated data &
                safely permutes hashes created with different `aad`.

        `ttl`: An amount of seconds which dictate the allowable age of
                a `composed_passcrypt_hash`. The associated timestamp,
                which is attached to the hash, helps ensure the tag is
                unique by separating each tag created across time into
                distinct domains.

        `mb_allowed`: A `builtins.range` object which includes all
                allowable values for the `mb` (Mebibyte) resource cost.
                Raises `ResourceWarning` if the `mb` specified in the
                provided hash falls outside of that range.

        `cpu_allowed`: A `builtins.range` object which includes all
                allowable values for the `cpu` resource cost. Raises
                `ResourceWarning` if the `cpu` specified in the provided
                hash falls outside of that range.

        `cores_allowed`: A `builtins.range` object which includes all
                allowable values for the `cores` resource cost. Raises
                `ResourceWarning` if the `cores` specified in the
                provided hash falls outside of that range.
        """
        parts = PasscryptHash(
            config=config
        ).import_hash(composed_passcrypt_hash)
        await config.clock.atest_timestamp(
            parts.timestamp, ttl * NS_TO_S_RATIO
        )
        parts.in_allowed_ranges(mb_allowed, cpu_allowed, cores_allowed)
        self = cls(
            mb=parts.mb,
            cpu=parts.cpu,
            cores=parts.cores,
            tag_size=parts.tag_size,
            config=config,
        )
        untrusted_hash = await self.anew(
            passphrase, parts.salt, aad=parts.timestamp + aad
        )
        if not bytes_are_equal(untrusted_hash, parts.tag):
            raise PasscryptIssue.verification_failed()

    @classmethod
    def verify(
        cls,
        composed_passcrypt_hash: bytes,
        passphrase: bytes,
        *,
        aad: bytes = DEFAULT_AAD,
        ttl: int = DEFAULT_TTL,
        mb_allowed: range = passcrypt_spec.MB_RESOURCE_SAFETY_RANGE,
        cpu_allowed: range = passcrypt_spec.CPU_RESOURCE_SAFETY_RANGE,
        cores_allowed: range = passcrypt_spec.CORES_RESOURCE_SAFETY_RANGE,
        config: t.ConfigType = passcrypt_spec,
    ) -> None:
        """
        Verifies that a supplied `passphrase` was indeed used to build
        the `composed_passcrypt_hash`.

        `aad`: An arbitrary bytes value a user decides to categorize
                the hash with. It is authenticated as associated data &
                safely permutes hashes created with different `aad`.

        `ttl`: An amount of seconds which dictate the allowable age of
                a `composed_passcrypt_hash`. The associated timestamp,
                which is attached to the hash, helps ensure the tag is
                unique by separating each tag created across time into
                distinct domains.

        `mb_allowed`: A `builtins.range` object which includes all
                allowable values for the `mb` (Mebibyte) resource cost.
                Raises `ResourceWarning` if the `mb` specified in the
                provided hash falls outside of that range.

        `cpu_allowed`: A `builtins.range` object which includes all
                allowable values for the `cpu` resource cost. Raises
                `ResourceWarning` if the `cpu` specified in the provided
                hash falls outside of that range.

        `cores_allowed`: A `builtins.range` object which includes all
                allowable values for the `cores` resource cost. Raises
                `ResourceWarning` if the `cores` specified in the
                provided hash falls outside of that range.
        """
        parts = PasscryptHash(
            config=config
        ).import_hash(composed_passcrypt_hash)
        config.clock.test_timestamp(parts.timestamp, ttl * NS_TO_S_RATIO)
        parts.in_allowed_ranges(mb_allowed, cpu_allowed, cores_allowed)
        self = cls(
            mb=parts.mb,
            cpu=parts.cpu,
            cores=parts.cores,
            tag_size=parts.tag_size,
            config=config,
        )
        untrusted_hash = self.new(
            passphrase, parts.salt, aad=parts.timestamp + aad
        )
        if not bytes_are_equal(untrusted_hash, parts.tag):
            raise PasscryptIssue.verification_failed()


module_api = dict(
    PasscryptSettings=t.add_type(PasscryptSettings),
    Passcrypt=t.add_type(Passcrypt),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

