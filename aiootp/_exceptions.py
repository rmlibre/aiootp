# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "CiphertextIssue",
    "DatabaseIssue",
    "Issue",
    "KeyAADIssue",
    "PackageSignerIssue",
    "PasscryptIssue",
    "PlaintextIssue",
    "SHMACIssue",
]


__doc__ = (
    "Organizes the package's exceptions in declarative classes & method"
    "s on those classes."
)


import typing


class Issue:
    """
    A class to help with the readability of raising general issues with
    more precise error messages for users.
    """

    __slots__ = []

    _INVALID_VALUE: str = "Invalid NAME!"
    _INVALID_LENGTH: str = "len(NAME) != LENGTH."
    _VALUE_MUST: str = "The NAME value must CONTEXT."
    _MUST_SET_VALUE: str = "Must set NAME for CONTEXT."
    _NO_VALUE_SPECIFIED: str = "No NAME was specified."
    _VALUE_MUST_BE_VALUE: str = "The NAME value must be a VALUE."
    _STREAM_IS_EMPTY: str = "An invalid emtpy stream was provided."
    _VALUE_MUST_BE_TYPE: str = "The NAME value must be a TYPE object."
    _VALUE_ALREADY_SET: str = "The OBJECT is already set to CONTEXT."
    _EXCEEDED_BLOCKSIZE: str = "Data block MUST NOT exceed 256 bytes."
    _CANT_OVERWRITE_EXISTING_ATTRIBUTE: str = (
        "Can't overwrite the existing NAME attribute."
    )
    _INVALID_BLOCKSIZE: str = (
        "An invalid block of SIZE bytes was produced. Blocks must be DE"
        "FAULT bytes."
    )
    _UNSAFE_DETERMINISM: str = (
        "Must enable dangerous determinism to use a custom salt. Provid"
        "ing both a key & salt risks key reuse."
    )

    @classmethod
    def invalid_value(cls, name: str, problem: str = ""):
        issue = cls._INVALID_VALUE.replace("NAME", name)
        if problem:
            issue = f"{issue} The {name} shouldn't be {problem}."
        return ValueError(issue)

    @classmethod
    def invalid_length(cls, name: str, length: int):
        issue = cls._INVALID_LENGTH.replace("NAME", name)
        return ValueError(issue.replace("LENGTH", repr(length)))

    @classmethod
    def value_must(cls, name: str, context: typing.Any):
        issue = cls._VALUE_MUST.replace("NAME", name)
        return ValueError(issue.replace("CONTEXT", str(context)))

    @classmethod
    def must_set_value(cls, name: str, context: str):
        issue = cls._MUST_SET_VALUE.replace("NAME", name)
        return ValueError(issue.replace("CONTEXT", context))

    @classmethod
    def no_value_specified(cls, name: str):
        return ValueError(cls._NO_VALUE_SPECIFIED.replace("NAME", name))

    @classmethod
    def value_must_be_value(cls, name: str, value: typing.Any):
        issue = cls._VALUE_MUST_BE_VALUE.replace("NAME", name)
        return ValueError(issue.replace("VALUE", repr(value)))

    @classmethod
    def stream_is_empty(cls):
        return ValueError(cls._STREAM_IS_EMPTY)

    @classmethod
    def value_must_be_type(cls, name: str, clss: typing.Any):
        issue = cls._VALUE_MUST_BE_TYPE.replace("NAME", name)
        return TypeError(issue.replace("TYPE", repr(clss)))

    @classmethod
    def value_already_set(cls, obj: str, context: str):
        issue = cls._VALUE_ALREADY_SET.replace("OBJECT", obj)
        return PermissionError(issue.replace("CONTEXT", context))

    @classmethod
    def exceeded_blocksize(cls):
        return ValueError(cls._EXCEEDED_BLOCKSIZE)

    @classmethod
    def cant_overwrite_existing_attribute(cls, name: str):
        issue = cls._CANT_OVERWRITE_EXISTING_ATTRIBUTE
        return ValueError(issue.replace("NAME", name))

    @classmethod
    def invalid_blocksize(cls, size: int):
        from .commons import BLOCKSIZE

        issue = cls._INVALID_BLOCKSIZE.replace("SIZE", str(size))
        return ValueError(issue.replace("DEFAULT", str(BLOCKSIZE)))

    @classmethod
    def unsafe_determinism(cls):
        return PermissionError(cls._UNSAFE_DETERMINISM)


class KeyAADIssue:
    """
    A class to help with the readability of raising issues related to
    `Chunky2048` `keys`, `salt` & `aad` values with more precise error
    messages for users.
    """

    __slots__ = []

    _INVALID_KEY: str = "The ``key`` must be at least 32 bytes."
    _INVALID_SALT: str = "The ``salt`` must be a 24-byte value."
    _MODE_ISNT_CORRECT: str = (
        "The KDF mode must be set to MODE to use MODE key derivation."
    )
    _NO_KDF_MODE_DECLARED: str = (
        "KeyAADBundle objects need to be set to either sync or async mo"
        "des prior to querying their derived keys."
    )
    _KEYSTREAM_ALREADY_REGISTERED: str = (
        "This KeyAADBundle object was registered for use by another key"
        "stream. Create a new bundle with fresh randomness instead."
    )
    _VALIDATOR_ALREADY_REGISTERED: str = (
        "This KeyAADBundle object was registered for use by another val"
        "idator object. Create a new bundle with fresh randomness inste"
        "ad."
    )
    _MUST_CREATE_A_NEW_OBJECT_EXPLICITLY: str = (
        "Cipher contexts are more safely changed by explicitly creating"
        " a new key bundle instance with different values than by chang"
        "ing the NAME value of an existing instance."
    )

    @classmethod
    def invalid_key(cls):
        return ValueError(cls._INVALID_KEY)

    @classmethod
    def invalid_salt(cls):
        return ValueError(cls._INVALID_SALT)

    @classmethod
    def mode_isnt_correct(cls, mode: str):
        return ValueError(cls._MODE_ISNT_CORRECT.replace("MODE", mode))

    @classmethod
    def no_kdf_mode_declared(cls):
        return RuntimeError(cls._NO_KDF_MODE_DECLARED)

    @classmethod
    def keystream_already_registered(cls):
        return PermissionError(cls._KEYSTREAM_ALREADY_REGISTERED)

    @classmethod
    def validator_already_registered(cls):
        return PermissionError(cls._VALIDATOR_ALREADY_REGISTERED)

    @classmethod
    def must_create_a_new_object_explicitly(cls, name: str):
        issue = cls._MUST_CREATE_A_NEW_OBJECT_EXPLICITLY
        return PermissionError(issue.replace("NAME", name))


class SHMACIssue:
    """
    A class to help with the readability of raising issues related to
    `StreamHMAC` values & processes with more precise error messages for
    users.
    """

    __slots__ = []

    _NO_CIPHER_MODE_DECLARED: str = "No cipher mode has been declared."
    _ALREADY_FINALIZED: str = "The validator has already been finalized."
    _USE_FINAL_RESULT: str = (
        _ALREADY_FINALIZED + " Use the final result instead."
    )
    _VALIDATION_INCOMPLETE: str = (
        "Can't produce a result before finalization."
    )
    _INVALID_SIV_USAGE: str = (
        "The ``siv`` must be manually passed into the validator during "
        "*decryption*."
    )
    _BLOCK_ID_IS_TOO_BIG: str = (
        "A block id of SIZE bytes is too big. It can be at most MAX byt"
        "es."
    )
    _BLOCK_ID_IS_TOO_SMALL: str = (
        "A block id of SIZE bytes is too small. It must be at least "
        "MINIMUM bytes to securely authenticate a block."
    )

    @classmethod
    def no_cipher_mode_declared(cls):
        return PermissionError(cls._NO_CIPHER_MODE_DECLARED)

    @classmethod
    def already_finalized(cls):
        return PermissionError(cls._ALREADY_FINALIZED)

    @classmethod
    def use_final_result_instead(cls):
        return PermissionError(cls._USE_FINAL_RESULT)

    @classmethod
    def validation_incomplete(cls):
        return PermissionError(cls._VALIDATION_INCOMPLETE)

    @classmethod
    def invalid_siv_usage(cls):
        return PermissionError(cls._INVALID_SIV_USAGE)

    @classmethod
    def block_id_is_too_big(size: int):
        from .commons import MAX_BLOCK_ID_BYTES as MAX

        issue = cls._BLOCK_ID_IS_TOO_BIG.replace("SIZE", str(size))
        return PermissionError(issue.replace("MAX", str(MAX)))

    @classmethod
    def block_id_is_too_small(cls, size: int):
        from .commons import MINIMUM_BLOCK_ID_BYTES as MINIMUM

        issue = cls._BLOCK_ID_IS_TOO_SMALL.replace("SIZE", str(size))
        return PermissionError(issue.replace("MINIMUM", str(MINIMUM)))


class CiphertextIssue:
    """
    A class to help with the readability of raising issues related to
    processing & validating ciphertexts.
    """

    __slots__ = []

    _INVALID_CIPHERTEXT_LENGTH: str = (
        "The given ciphertext of length SIZE is not a multiple of the b"
        "locksize minus the header bytes."
    )

    @classmethod
    def invalid_ciphertext_length(cls, size: int):
        issue = cls._INVALID_CIPHERTEXT_LENGTH
        return ValueError(issue.replace("SIZE", str(size)))


class PlaintextIssue:
    """
    A class to help with the readability of raising issues related to
    processing & validating plaintexts.
    """

    __slots__ = []

    _TIMESTAMP_EXPIRED: str = "Timestamp expired by <SECONDS> seconds."
    _INVALID_TIMESTAMP_FORMAT: str = (
        "Invalid timestamp format! It must be 8 bytes long."
    )

    @classmethod
    def timestamp_expired(cls, seconds_expired: int):
        issue = cls._TIMESTAMP_EXPIRED
        return TimeoutError(issue.replace("SECONDS", str(seconds_expired)))

    @classmethod
    def invalid_timestamp_format(cls):
        return ValueError(cls._INVALID_TIMESTAMP_FORMAT)


class PasscryptIssue:
    """
    A class to help with the readability of raising issues related to
    `Passcrypt` values & processes with more precise error messages for
    users.
    """

    __slots__ = []

    _INVALID_KB: str = "kb:KB must be int >= 256 and < 2**32"
    _INVALID_CPU: str = "cpu:CPU must be int >= 2 and < 65536"
    _INVALID_HARDNESS: str = (
        "hardness:HARDNESS must be int >= 256 and < 2**32"
    )

    @classmethod
    def invalid_hardness(cls, hardness: int):
        issue = cls._INVALID_HARDNESS
        return ValueError(issue.replace("HARDNESS", str(hardness)))

    @classmethod
    def invalid_cpu(cls, cpu: int):
        return ValueError(cls._INVALID_CPU.replace("CPU", str(cpu)))

    @classmethod
    def invalid_kb(cls, kb: int):
        return ValueError(cls._INVALID_KB.replace("KB", str(kb)))


class DatabaseIssue:
    """
    A class to help with the readability of raising issues related to
    `AsyncDatabase` & `Database` values & processes with more precise
    error messages for users.
    """

    __slots__ = []

    _INVALID_WRITE_ATTEMPT: str = "Invalid write attempted."
    _FILE_NOT_FOUND: str = "The NAME filename was not located."
    _NO_EXISTING_METATAG: str = "No metatag database named TAG."
    _MISSING_PROFILE: str = "Profile doesn't exist or is corrupt."
    _TAG_FILE_DOESNT_EXIST: str = "The TAG tag file doesn't exist."
    _KEY_HAS_BEEN_DELETED: str = "The database keys have been deleted."
    _CANT_DELETE_MAINTENANCE_FILES: str = "Can't delete maintenance files."

    @classmethod
    def invalid_write_attempt(cls):
        return PermissionError(cls._INVALID_WRITE_ATTEMPT)

    @classmethod
    def file_not_found(cls, filename: str):
        issue = cls._FILE_NOT_FOUND
        return LookupError(issue.replace("NAME", repr(filename)))

    @classmethod
    def no_existing_metatag(cls, tag: str):
        issue = cls._NO_EXISTING_METATAG
        return LookupError(issue.replace("TAG", repr(tag)))

    @classmethod
    def missing_profile(cls):
        return LookupError(cls._MISSING_PROFILE)

    @classmethod
    def tag_file_doesnt_exist(cls, tag: str):
        issue = cls._TAG_FILE_DOESNT_EXIST
        return LookupError(issue.replace("TAG", repr(tag)))

    @classmethod
    def key_has_been_deleted(cls):
        return PermissionError(cls._KEY_HAS_BEEN_DELETED)

    @classmethod
    def cant_delete_maintenance_files(cls):
        return PermissionError(cls._CANT_DELETE_MAINTENANCE_FILES)


class PackageSignerIssue:
    """
    A class to help with the readability of raising issues related to
    `PackageSigner` values & processes with more precise error messages
    for users.
    """

    __slots__ = []

    _PACKAGE_HASNT_BEEN_SIGNED: str = (
        "The package must be signed before querying its signature."
    )
    _SIGNING_KEY_HASNT_BEEN_SET: str = (
        "The `PackageSigner` instance's signing key hasn't been set."
    )
    _OUT_OF_SYNC_PACKAGE_SIGNATURE: str = (
        "The calculated package signature is out of sync with the curre"
        "nt checksum of the package summary."
    )
    _MUST_CONNECT_TO_SECURE_DATABASE: str = (
        "Must first connect to the package signing session's secure dat"
        "abase before it can be updated or queried."
    )

    @classmethod
    def package_hasnt_been_signed(cls):
        return RuntimeError(cls._PACKAGE_HASNT_BEEN_SIGNED)

    @classmethod
    def must_connect_to_secure_database(cls):
        return RuntimeError(cls._MUST_CONNECT_TO_SECURE_DATABASE)

    @classmethod
    def out_of_sync_package_signature(cls):
        return ValueError(cls._OUT_OF_SYNC_PACKAGE_SIGNATURE)

    @classmethod
    def signing_key_hasnt_been_set(cls):
        return LookupError(cls._SIGNING_KEY_HASNT_BEEN_SET)

