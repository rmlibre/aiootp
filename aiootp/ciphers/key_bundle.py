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


__all__ = ["KeyAADBundle", "KeyAADMode", "KeyAADRegisters", "SaltAADIV"]


__doc__ = "Types to manage bundled cipher session values."


from secrets import token_bytes

from aiootp._typing import Typing as t
from aiootp._constants import DEFAULT_AAD, ASYNC, SYNC
from aiootp._exceptions import Issue, KeyAADIssue
from aiootp.commons import FrozenInstance, FrozenSlots, OpenFrozenSlots
from aiootp.generics import canonical_pack

from .cipher_kdfs import CipherKDFs


class SaltAADIV(FrozenSlots):
    """
    Creates efficient containers for salt, aad, IV value bundles.
    """

    __slots__ = ("salt", "aad", "iv", "config", "iv_is_fresh")

    _MAPPED_ATTRIBUTES: t.Tuple[str] = ("salt", "aad", "iv")

    def __init__(
        self,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
        iv: t.Optional[bytes] = None,
        *,
        config: t.ConfigType,
    ) -> None:
        self.config = config
        self.salt = salt if salt else token_bytes(self.config.SALT_BYTES)
        self.aad = aad
        self.iv = self._process_iv(iv)
        self._test_salt_aad_iv(self.salt, self.aad, self.iv)

    def __iter__(self) -> t.Generator[str, None, None]:
        yield from self._MAPPED_ATTRIBUTES

    def _process_iv(self, iv: bytes) -> bytes:
        """
        Creating a new random IV during encryption ensures the user
        cannot accidentally prevent the derived key material from being
        fresh. A flag allows improper usage to be acted upon downstream.
        """
        if iv is None:
            self.iv_is_fresh = True
            return token_bytes(self.config.IV_BYTES)
        else:
            self.iv_is_fresh = False
            return iv

    def _test_salt_aad_iv(
        self, salt: bytes, aad: bytes, iv: bytes
    ) -> None:
        """
        Validates the ephemeral `salt`, `aad` authenticated associated
        data, & the random `iv` for a package cipher.
        """
        config = self.config
        if salt.__class__ is not bytes:
            raise Issue.value_must_be_type("salt", bytes)
        elif len(salt) != config.SALT_BYTES:
            raise KeyAADIssue.invalid_salt_size(config.SALT_BYTES)
        elif aad.__class__ is not bytes:
            raise Issue.value_must_be_type("aad", bytes)
        elif iv.__class__ is not bytes:
            raise Issue.value_must_be_type("iv", bytes)
        elif len(iv) != config.IV_BYTES:
            raise Issue.invalid_length("iv", config.IV_BYTES)


class KeyAADRegisters(FrozenSlots):
    """
    Efficiently stores objects which help to enforce the limited usage
    of a `KeyAADBundle` object for a single encryption / decryption
    round.
    """

    __slots__ = ("keystream", "shmac")

    def register(self, name: str, value: t.Any) -> None:
        setattr(self, name, value)


class KeyAADMode(OpenFrozenSlots):
    """
    Helps guide users towards correct usage of `KeyAADBundle` objects in
    ciphers by enforcing that they are set to async or sync key
    derivation modes when using them in those contexts.
    """

    __slots__ = ("_mode",)

    def __eq__(self, mode: str) -> bool:
        """
        The object can directly be compared to the string `mode` from
        within the runtime of an async & sync contexts. Procs an error
        if the mode has not been set.
        """
        return self.mode == mode

    @property
    def mode(self) -> str:
        """
        Procs an error if the mode has not been set.
        """
        try:
            return self._mode
        except AttributeError as error:
            raise KeyAADIssue.no_kdf_mode_declared() from error

    def set_async_mode(self) -> None:
        """
        Sets the object's mode to signal async key derivation is needed.
        """
        self._mode = ASYNC

    def set_sync_mode(self) -> None:
        """
        Sets the object's mode to signal sync key derivation is needed.
        """
        self._mode = SYNC

    def validate(self) -> None:
        """
        Procs an error if the mode has not been set, else returns `None`.
        """
        return self.mode and None


class KeyAADBundle:
    """
    A low-level interface for managing a key, salt, iv & authenticated
    associated data bundle which is to be used for ONLY ONE encryption.
    """

    __slots__ = (
        "_kdfs",
        "_session",
        "_bundle",
        "_mode",
        "_registers",
        "config",
    )

    _Session: type
    _Mode: type = KeyAADMode
    _Registers: type = KeyAADRegisters
    _SaltAADIV: type = SaltAADIV

    def __init__(
        self,
        kdfs: CipherKDFs,
        *,
        salt: t.Optional[bytes] = None,
        aad: bytes = DEFAULT_AAD,
        iv: t.Optional[bytes] = None,
    ) -> None:
        """
        Stores the `salt`, `aad` & `iv` & initializes the session KDFs
        for this permutation of the values.

        The `iv` should only be passed when the bundle is to be used for
        decryption.
        """
        if not issubclass(kdfs.__class__, CipherKDFs):
            raise Issue.value_must_be_type("kdfs", CipherKDFs)
        self.config = kdfs.config
        self._kdfs = kdfs
        self._session = self._Session()
        self._mode = self._Mode()
        self._registers = self._Registers()
        self._bundle = self._SaltAADIV(
            salt=salt,
            aad=aad,
            iv=iv,
            config=self.config,
        )
        self._initialize_session()

    def __iter__(self) -> t.Iterable[bytes]:
        """
        Yields the instance's salt, authenticated associated data, &
        the IV.
        """
        yield self._bundle.salt
        yield self._bundle.aad
        yield self._bundle.iv

    def _initialize_session(self) -> None:
        """
        Initializes cipher KDFs with a canonicalized session summary.
        """
        session = self._session
        summary = canonical_pack(*self, int_bytes=4)
        for kdf_name, kdf_session_copy in self._kdfs.new_session(summary):
            setattr(session, kdf_name, kdf_session_copy)

    def _register_shmac(self, shmac) -> None:
        """
        Registers the shmac which will be tied to the instance for a
        single run of the cipher. Reusing an instance for multiple
        cipher calls is NOT SAFE, & is disallowed by this registration.
        """
        if hasattr(self._registers, "shmac"):
            raise KeyAADIssue.shmac_already_registered()
        self._registers.register("shmac", shmac)

    @property
    def salt(self) -> bytes:
        """
        Returns a [pseudo]random salt that may be supplied by the user.
        By default it's sent in the clear attached to the ciphertext.
        Thus it may simplify implementing efficient features, such as
        search or routing, though care must still be taken when
        considering how leaking such metadata may be harmful. Keeping
        this value constant is strongly discouraged, though the salt
        misuse-reuse resistance of the cipher extends up to
        ~256**(len(iv)/2 + len(siv_key)/2) encryptions/second.
        """
        return self._bundle.salt

    @property
    def aad(self) -> bytes:
        """
        An arbitrary bytes value that a user decides to categorize
        keystreams. It is authenticated as associated data & safely
        differentiates keystreams as a tweak when it's unique for
        each permutation of `key`, `salt`, & `iv`.
        """
        return self._bundle.aad

    @property
    def _iv_given_by_user(self) -> bool:
        """
        Returns a boolean flag to determine inappropriate usage of the
        IV.
        """
        return not self._bundle.iv_is_fresh

    @property
    def iv(self) -> bytes:
        """
        An ephemeral, uniform, random value that's generated by
        the encryption algorithm. Ensures salt misue / reuse
        security even if the `key`, `salt`, & `aad` are the same for
        ~256**(len(iv)/2 + len(siv_key)/2) encryptions/second.
        """
        return self._bundle.iv

    @property
    def _shmac_kdf(self) -> t.XOFType:
        """
        Returns the XOF object used by the `StreamHMAC` class.
        """
        return self._session.shmac_kdf


module_api = dict(
    KeyAADBundle=t.add_type(KeyAADBundle),
    KeyAADMode=t.add_type(KeyAADMode),
    KeyAADRegisters=t.add_type(KeyAADRegisters),
    SaltAADIV=t.add_type(SaltAADIV),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

