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


__all__ = [
    "AuthenticationFailed",
    "CanonicalEncodingError",
    "CanonicalIssue",
    "CipherStreamIssue",
    "DatabaseIssue",
    "Ignore",
    "ImproperPassphrase",
    "InvalidBlockID",
    "InvalidCiphertextSize",
    "InvalidDigest",
    "InvalidPassphrase",
    "InvalidSHMAC",
    "InvalidSignature",
    "Issue",
    "KeyAADIssue",
    "Metadata",
    "PackageSignerIssue",
    "PasscryptIssue",
    "ReturnValue",
    "SHMACIssue",
    "TimestampExpired",
    "TypeUncheckableAtRuntime",
    "UndefinedRequiredAttributes",
    "raise_exception",
]


__doc__ = (
    "Organizes the package's exceptions in declarative & expressive "
    "classes & methods."
)


import json
import asyncio
from pathlib import Path
from cryptography.exceptions import InvalidSignature

from ._typing import Typing as t


def raise_exception(obj: Exception, /) -> None:
    """
    Simply provides a callable which raises `obj` turning the raise
    statement into an expression.
    """
    raise obj


class Metadata:
    """
    Creates efficient containers for the generic metadata of values.
    This is used so that potentially sensitive values can be analyzed
    while keeping the raw values from being passed around or displayed
    in error outputs.
    """

    __slots__ = ("size", "type")

    def __init__(self, value: t.Any, /) -> None:
        self.type = value.__class__
        self.size = len(value) if hasattr(value, "__len__") else None


class Ignore:
    """
    Allows specialized surpressing & handling of exceptions.
     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    with Ignore(TypeError):
        c = None + "Hello"
        # exception within context is surpressed if it's a `TypeError`

    Or, dynamically choose which exceptions to catch, and call custom
    cleanup code.

    def cleanup(relay: Ignore) -> bool:
        if issubclass(relay.error.__class__, PermissionError):
            return False
        else:
            db.save_database()
            return True

    with Ignore(IOError, PermissionError) as relay:
        relay.except_code = cleanup
        # Analogous to `with Ignore(IOError, if_except=cleanup):`
        # Runs `cleanup` if the specified type of error is raised. If
        # `cleanup` returns `True` the exception is surpressed.

        relay.else_code = cleanup
        # Analogous to `with Ignore(IOError, if_else=cleanup):`
        # Runs `cleanup` if no exception is raised in the context.

        relay.finally_code = cleanup
        # Analogous to `with Ignore(IOError, finally_run=cleanup):`
        # Always runs `cleanup` at the end of the context.

    async def acleanup(relay: Ignore) -> bool:
        ...

    async with Ignore(IOError, PermissionError, if_except=acleanup):
        ...
    """

    __slots__ = (
        "ignored_exceptions",
        "except_code",
        "else_code",
        "finally_code",
        "bus",
        "error",
        "traceback",
    )

    class _PlaceholderHandler:
        """
        Stand-in handler when one isn't specified.
        """

        def __await__(self, /) -> t.Self:
            yield
            return self

        def __call__(self, /, *a, **kw) -> t.Self:
            return self

        def __bool__(self, /) -> bool:
            return True

    def __init__(
        self,
        /,
        *exceptions: Exception,
        if_except: t.Optional[t.Callable[[t.Self], t.Any]] = None,
        if_else: t.Optional[t.Callable[[t.Self], t.Any]] = None,
        finally_run: t.Optional[t.Callable[[t.Self], t.Any]] = None,
    ) -> None:
        placeholder = self._PlaceholderHandler()
        self.ignored_exceptions = exceptions
        self.except_code = (
            placeholder if if_except is None else if_except
        )
        self.else_code = (
            placeholder if if_else is None else if_else
        )
        self.finally_code = (
            placeholder if finally_run is None else finally_run
        )
        self.bus = t.Namespace()
        self.error = None
        self.traceback = None

    def __repr__(self, /) -> str:
        return repr(getattr(self, "error", None))

    async def __aenter__(self, /) -> t.Self:
        """
        Open an async context.
        """
        await asyncio.sleep(0)
        return self

    def __enter__(self, /) -> t.Self:
        """
        Open a sync context.
        """
        return self

    async def __aexit__(
        self,
        /,
        exc_type: t.Optional[type] = None,
        exc_value: t.Optional[Exception] = None,
        traceback: t.Optional[t.TracebackType] = None,
    ) -> bool:
        """
        Allows the controlled handling of raised exceptions within the
        context. If an exception specified by the instance is raised,
        the `if_except` method must return a `bool`: returning `True`
        surpresses the propagation of the exception, returning `False`
        does not.
        """
        try:
            if exc_type is None:
                await self.else_code(self)
            else:
                self.error = exc_value
                self.traceback = traceback
                if issubclass(exc_type, self.ignored_exceptions):
                    return await self.except_code(self)
                else:
                    raise exc_value
        finally:
            await self.finally_code(self)

    def __exit__(
        self,
        /,
        exc_type: t.Optional[type] = None,
        exc_value: t.Optional[Exception] = None,
        traceback: t.Optional[t.TracebackType] = None,
    ) -> bool:
        """
        Allows the controlled handling of raised exceptions within the
        context. If an exception specified by the instance is raised,
        the `if_except` method must return a `bool`: returning `True`
        surpresses the propagation of the exception, returning `False`
        does not.
        """
        try:
            if exc_type is None:
                self.else_code(self)
            else:
                self.error = exc_value
                self.traceback = traceback
                if issubclass(exc_type, self.ignored_exceptions):
                    return self.except_code(self)
                else:
                    raise exc_value
        finally:
            self.finally_code(self)


class CanonicalEncodingError(ValueError):
    """
    An exception raised when a discrepancy is detected between the
    metadata declarations of canonically encoded data & the data itself.
    """


class ReturnValue(UserWarning):
    """
    An exception used by `Comprende` to proagate intended user return
    values from async or sync generators & coroutines to calling code.
    """


class TimestampExpired(TimeoutError):
    """
    An exception raised when an encountered timestamp is older than the
    current time minus a validation method's `ttl` parameter.
    """

    _DEFAULT_MESSAGE: str = "Timestamp expired by <TIME> UNITS."

    def __init__(self, units: str, expired_by: int, /) -> None:
        self.units = units
        self.expired_by = expired_by
        message = self._DEFAULT_MESSAGE.replace("UNITS", repr(units))
        super().__init__(message.replace("TIME", repr(expired_by)))


class AuthenticationFailed(ValueError):
    """
    A base exception class for varying kinds of authentication failures.
    """


class InvalidBlockID(AuthenticationFailed):
    """
    An exception raised when a received `block_id` & `ciphertext_block`
    pair are invalidated by a `StreamHMAC` object.
    """


class InvalidSHMAC(AuthenticationFailed):
    """
    An exception raised when at the end of processing a stream of
    ciphertext, a `shmac` tag is invalidated by the `StreamHMAC` object.
    """


class InvalidDigest(AuthenticationFailed):
    """
    An exception raised when a purported checksum of data does not match
    the calculated checksum.
    """


class InvalidPassphrase(AuthenticationFailed):
    """
    An exception raised when the validation of a supplied passphrase
    fails.
    """


class ImproperPassphrase(ValueError):
    """
    If the passphrase supplied is either not bytes or not long enough
    this exception is raised.
    """


class UndefinedRequiredAttributes(AttributeError):
    """
    Captures the undefined attribute names within the raised exception.
    """

    __slots__ = ("undefined_attributes",)

    _MESSAGE_TEMPLATE: str = (
        "The following required attributes remained undefined after "
        "object initialization: UNDEFINED_ATTRIBUTES."
    )

    def __init__(self, /, *undefined_attributes: str) -> None:
        self.undefined_attributes = undefined_attributes
        super().__init__(
            self
            ._MESSAGE_TEMPLATE
            .replace("UNDEFINED_ATTRIBUTES", repr(undefined_attributes))
        )


class InvalidCiphertextSize(ValueError):
    """
    Thrown with the invalid size stored in an attribute.
    """

    __slots__ = ("size",)

    _MESSAGE_TEMPLATE: str = (
        "The given ciphertext length of SIZE isn't a valid size."
    )

    def __init__(self, size: int, /) -> None:
        self.size = size
        super().__init__(self._MESSAGE_TEMPLATE.replace("SIZE", repr(size)))


class TypeUncheckableAtRuntime(TypeError):
    """
    Some types, like those which use square brackets in their definition,
    cannot be checked with `isinstance`. This exception is raised when
    such types are defined on variables which need to be type-checked at
    runtime.
    """

    _MESSAGE_TEMPLATE: str = (
        "The NAME variable's type was declared using VALUE_TYPE, which "
        "isn't checkable at runtime. Perhaps use a `Protocol` decorated "
        "with `@typing.runtime_checkable` instead?"
    )

    def __init__(self, name: str, value_type: type, /) -> None:
        self.name = name
        self.value_type = value_type
        super().__init__(
            self
            ._MESSAGE_TEMPLATE
            .replace("NAME", repr(name))
            .replace("VALUE_TYPE", repr(value_type))
        )


class Issue:
    """
    A class to help with the readability of raising general issues with
    more precise error messages for users.
    """

    __slots__ = ()

    _INVALID_VALUE: str = "Invalid NAME!"
    _INVALID_LENGTH: str = "len(NAME) != LENGTH."
    _VALUE_MUST: str = "The NAME value must CONTEXT."
    _MUST_SET_VALUE: str = "Must set NAME for CONTEXT."
    _STREAM_IS_EMPTY: str = "An invalid emtpy stream was provided."
    _VALUE_ALREADY_SET: str = "The OBJECT is already set to CONTEXT."
    _VALUE_MUST_BE_TYPE: str = "The NAME value must be a TYPE object."
    _VALUE_MUST_BE_SUBTYPE: str = (
        "The NAME value must match or subclass TYPE."
    )
    _EXCEEDED_BLOCKSIZE: str = (
        "Data block MUST NOT exceed BLOCKSIZE bytes."
    )
    _CANT_REASSIGN_ATTRIBUTE: str = (
        "Can't re-assign the existing NAME attribute."
    )
    _CANT_DEASSIGN_ATTRIBUTE : str = (
        "Can't de-assign the existing NAME attribute."
    )
    _UNUSED_PARAMETERS: str = (
        "The PARAMETERS parameters are not used when CONTEXT."
    )
    _BROKEN_POOL_RESTARTED: str = (
        "The process pool was broken & has now been restarted. Try again."
    )

    @classmethod
    def invalid_value(cls, name: str, problem: str = "", /) -> ValueError:
        issue = cls._INVALID_VALUE.replace("NAME", name)
        if problem:
            issue = f"{issue} The {name} can't be {problem}."
        return ValueError(issue)

    @classmethod
    def invalid_length(cls, name: str, length: int, /) -> ValueError:
        issue = cls._INVALID_LENGTH.replace("NAME", name)
        return ValueError(issue.replace("LENGTH", repr(length)))

    @classmethod
    def value_must(cls, name: str, context: t.Any, /) -> ValueError:
        issue = cls._VALUE_MUST.replace("NAME", repr(name))
        return ValueError(issue.replace("CONTEXT", str(context)))

    @classmethod
    def must_set_value(cls, name: str, context: str, /) -> ValueError:
        issue = cls._MUST_SET_VALUE.replace("NAME", repr(name))
        return ValueError(issue.replace("CONTEXT", str(context)))

    @classmethod
    def stream_is_empty(cls, /) -> ValueError:
        return ValueError(cls._STREAM_IS_EMPTY)

    @classmethod
    def value_already_set(
        cls, obj: str, context: str, /
    ) -> PermissionError:
        issue = cls._VALUE_ALREADY_SET.replace("OBJECT", str(obj))
        return PermissionError(issue.replace("CONTEXT", str(context)))

    @classmethod
    def value_must_be_type(cls, name: str, clss: t.Any, /) -> TypeError:
        issue = cls._VALUE_MUST_BE_TYPE.replace("NAME", repr(name))
        return TypeError(issue.replace("TYPE", repr(clss)))

    @classmethod
    def value_must_be_subtype(cls, name: str, clss: t.Any, /) -> TypeError:
        issue = cls._VALUE_MUST_BE_SUBTYPE.replace("NAME", repr(name))
        return TypeError(issue.replace("TYPE", repr(clss)))

    @classmethod
    def exceeded_blocksize(cls, blocksize: int, /) -> OverflowError:
        issue = cls._EXCEEDED_BLOCKSIZE
        return OverflowError(issue.replace("BLOCKSIZE", repr(blocksize)))

    @classmethod
    def cant_reassign_attribute(cls, name: str, /) -> PermissionError:
        issue = cls._CANT_REASSIGN_ATTRIBUTE
        return PermissionError(issue.replace("NAME", repr(name)))

    @classmethod
    def cant_deassign_attribute(cls, name: str, /) -> PermissionError:
        issue = cls._CANT_DEASSIGN_ATTRIBUTE
        return PermissionError(issue.replace("NAME", repr(name)))

    @classmethod
    def unused_parameters(
        cls, params: t.Any, context: str, /
    ) -> ValueError:
        issue = cls._UNUSED_PARAMETERS.replace("PARAMETERS", repr(params))
        return ValueError(issue.replace("CONTEXT", str(context)))

    @classmethod
    def broken_pool_restarted(cls, /) -> RuntimeError:
        return RuntimeError(cls._BROKEN_POOL_RESTARTED)  # pragme: no cover


class CanonicalIssue:
    """
    A class to help with the readability of raising issues related to
    the canonicalized packing of bytes data with more precise error
    messages for users.
    """

    __slots__ = ()

    _INFLATED_SIZE_DECLARATION: str = (
        "More items to unpack than data permits!"
    )
    _ITEM_LENGTH_MISMATCH: str = (
        "The measured length of the canonically encoded item does not "
        "match its declared length."
    )
    _INVALID_PADDING: str = (
        "Invalid canonical encoding padding detected!"
    )
    _DATA_LENGTH_BLOCKSIZE_MISMATCH: str = (
        "Multiple of data length != declared blocksize!"
    )
    _MISSING_METADATA_ITEMS: str = (
        "The encoding lead to an unpacked data result without its "
        "required blocksize / pad declarations."
    )

    @classmethod
    def item_length_mismatch(cls, /) -> CanonicalEncodingError:
        return CanonicalEncodingError(cls._ITEM_LENGTH_MISMATCH)

    @classmethod
    def inflated_size_declaration(cls, /) -> CanonicalEncodingError:
        return CanonicalEncodingError(cls._INFLATED_SIZE_DECLARATION)

    @classmethod
    def invalid_padding(cls, /) -> CanonicalEncodingError:
        return CanonicalEncodingError(cls._INVALID_PADDING)

    @classmethod
    def data_length_blocksize_mismatch(cls, /) -> CanonicalEncodingError:
        return CanonicalEncodingError(cls._DATA_LENGTH_BLOCKSIZE_MISMATCH)

    @classmethod
    def missing_metadata_items(cls, /) -> CanonicalEncodingError:
        return CanonicalEncodingError(cls._MISSING_METADATA_ITEMS)


class KeyAADIssue:
    """
    A class to help with the readability of raising issues related to
    `Chunky2048` `keys`, `salt`, & `aad` values with more precise error
    messages for users.
    """

    __slots__ = ()

    _INVALID_KEY_SIZE: str = (
        "`key` was KEY_SIZE bytes, but must be at least MIN_SIZE bytes."
    )
    _INVALID_SALT_SIZE: str = (
        "The `salt` must be a SALT_SIZE-byte value."
    )
    _ALREADY_REGISTERED: str = (
        "The shmac has already been registered."
    )
    _MODE_ISNT_CORRECT: str = (
        "The KDF mode must be set to MODE to use MODE key derivation."
    )
    _NO_KDF_MODE_DECLARED: str = (
        "KeyAADBundle objects need to be set to either sync or async "
        "modes prior to querying their derived keys."
    )

    @classmethod
    def invalid_key_size(cls, size: int, min_size: int, /) -> ValueError:
        issue = cls._INVALID_KEY_SIZE.replace("MIN_SIZE", repr(min_size))
        return ValueError(issue.replace("KEY_SIZE", repr(size)))

    @classmethod
    def invalid_salt_size(cls, size: int, /) -> ValueError:
        issue = cls._INVALID_SALT_SIZE
        return ValueError(issue.replace("SALT_SIZE", repr(size)))

    @classmethod
    def shmac_already_registered(cls, /) -> PermissionError:
        return PermissionError(cls._ALREADY_REGISTERED)

    @classmethod
    def mode_isnt_correct(cls, mode: str, /) -> ValueError:
        issue = cls._MODE_ISNT_CORRECT.replace("MODE", repr(mode))
        return ValueError(issue)

    @classmethod
    def no_kdf_mode_declared(cls, /) -> RuntimeError:
        return RuntimeError(cls._NO_KDF_MODE_DECLARED)


class SHMACIssue:
    """
    A class to help with the readability of raising issues related to
    `StreamHMAC` values & processes with more precise error messages for
    users.
    """

    __slots__ = ()

    _NO_CIPHER_MODE_DECLARED: str = "No cipher mode has been declared."
    _ALREADY_FINALIZED: str = "The validator has already been finalized."
    _VALIDATION_INCOMPLETE: str = (
        "Can't produce a result before finalization."
    )
    _INVALID_IV_USAGE: str = (
        "The `iv` must be manually passed into the validator during "
        "*decryption*, & only during decryption."
    )
    _BLOCK_ID_IS_TOO_SMALL: str = (
        "A block id of SIZE bytes is too small. It must be at least "
        "MIN bytes to securely authenticate a block."
    )
    _BLOCK_ID_IS_TOO_BIG: str = (
        "A block id of SIZE bytes is too big. It can be at most MAX "
        "bytes."
    )
    _INVALID_SHMAC: str = (
        "Invalid StreamHMAC hash for the given ciphertext."
    )
    _INVALID_BLOCK_ID: str = (
        "Invalid next block ID hash of the supplied ciphertext block."
    )

    @classmethod
    def no_cipher_mode_declared(cls, /) -> PermissionError:
        return PermissionError(cls._NO_CIPHER_MODE_DECLARED)

    @classmethod
    def already_finalized(cls, /) -> PermissionError:
        return PermissionError(cls._ALREADY_FINALIZED)

    @classmethod
    def validation_incomplete(cls, /) -> PermissionError:
        return PermissionError(cls._VALIDATION_INCOMPLETE)

    @classmethod
    def invalid_iv_usage(cls, /) -> PermissionError:
        return PermissionError(cls._INVALID_IV_USAGE)

    @classmethod
    def block_id_is_too_small(
        cls, size: int, min_size: int, /
    ) -> PermissionError:
        issue = cls._BLOCK_ID_IS_TOO_SMALL.replace("SIZE", repr(size))
        issue = issue.replace("MIN", repr(min_size))
        return PermissionError(issue)

    @classmethod
    def block_id_is_too_big(
        cls, size: int, max_size: int, /
    ) -> PermissionError:
        issue = cls._BLOCK_ID_IS_TOO_BIG.replace("SIZE", repr(size))
        issue = issue.replace("MAX", repr(max_size))
        return PermissionError(issue)

    @classmethod
    def invalid_shmac(cls, /) -> InvalidSHMAC:
        return InvalidSHMAC(cls._INVALID_SHMAC)

    @classmethod
    def invalid_block_id(cls, /) -> InvalidBlockID:
        return InvalidBlockID(cls._INVALID_BLOCK_ID)


class CipherStreamIssue:
    """
    A class to help with the readability of raising issues related to
    `(Async)CipherStream` & `(Async)DecipherStream` values & processes
    with more precise error messages for users.
    """

    __slots__ = ()

    _STREAM_HAS_BEEN_CLOSED: str = (
        "The stream has been closed. Cannot add more `data` to the "
        "buffer of an already closed stream."
    )

    @classmethod
    def stream_has_been_closed(cls, /) -> InterruptedError:
        return InterruptedError(cls._STREAM_HAS_BEEN_CLOSED)


class PasscryptIssue:
    """
    A class to help with the readability of raising issues related to
    `Passcrypt` values & processes with more precise error messages for
    users.
    """

    __slots__ = ()

    _IMPROPER_PASSPHRASE: str = (
        "The given passphrase is too short, at least NEED more characters "
        "need to be added. \nTry using aiootp.mnemonic, it can help in "
        "generating a strong passphrase.\n"
        " _____________________________________\n"
        "|                                     |\n"
        "|            Usage Example:           |\n"
        "|_____________________________________|\n\n"
        "my_new_passphrase = b'-'.join(aiootp.mnemonic())\n\n"
        "print(my_new_passphrase)\n"
        "b'review-letter-blast-giant-connect-ring-balcony-frown'"
    )
    _IMPROPER_SALT: str = (
        "len(salt) must be >= MIN_SALT_SIZE and <= MAX_SALT_SIZE"
    )
    _INVALID_MB: str = (
        "mb:MB must be int >= MIN_MB and <= MAX_MB"
    )
    _INVALID_CPU: str = (
        "cpu:CPU must be int >= MIN_CPU and <= MAX_CPU"
    )
    _INVALID_CORES: str = (
        "cores:CORES must be int >= MIN_CORES and <= MAX_CORES"
    )
    _INVALID_TAG_SIZE: str = (
        "tag_size:SIZE must be int >= MIN_TAG_SIZE"
    )
    _INVALID_SALT_SIZE: str = (
        "salt_size:SIZE must be int >= MIN_SALT_SIZE and <= MAX_SALT_SIZE"
    )
    _UNTRUSTED_RESOURCE_CONSUMPTION: str = (
        "The PARAMETER parameter was blocked from being processed because "
        "it fell outside of the allowed range of resource consumption set "
        "by the verification method. To continue verifying the provided "
        "hash, explicit permission must be given in the form of a "
        "`builtins.range` object which includes the value VALUE.\n\n"
        " _____________________________________\n"
        "|                                     |\n"
        "|            Usage Example:           |\n"
        "|_____________________________________|\n\n"
        "from aiootp import Passcrypt\n\n"
        "allowed_resource_consumption = dict(\n"
        "    mb_allowed=range(16, 256),  # Less than 256 MiB allowed\n"
        "    cpu_allowed=range(2, 8),    # Less than 8 complexity allowed\n"
        "    cores_allowed=range(1, 5),  # Less than 5 processes allowed\n"
        ")\n"
        "try:\n"
        "    Passcrypt.verify(hashed_pw, pw, **allowed_resource_consumption)\n"
        "except ResourceWarning as danger:\n"
        "    admin.log(danger)\n"
        "    hard_limits_exceeded = (\n"
        "        danger.requested_resources.mb > 512\n"
        "        or danger.requested_resources.cpu > 11\n"
        "        or danger.requested_resources.cores > 8\n"
        "    )\n"
        "    below_security_guidelines = (\n"
        "        danger.requested_resources.mb < 16\n"
        "        or danger.requested_resources.cpu < 2\n"
        "    )\n"
        "    if hard_limits_exceeded:\n"
        "        raise danger\n"
        "    elif below_security_guidelines:\n"
        "        raise PermissionError('Minimum hash difficulty unmet.')\n"
        "    Passcrypt.verify(hashed_pw, pw)\n"
    )
    _VERIFICATION_FAILED: str = (
        "Passphrase verification failed! The hash of the passphrase & "
        "the passcrypt hash did not match!"
    )

    @classmethod
    def improper_passphrase(cls, metadata: Metadata, /) -> ValueError:
        from .keygens.passcrypt.config import passcrypt_spec as c

        if metadata.type is not bytes:
            return Issue.value_must_be_type("`passphrase`", bytes)
        issue = cls._IMPROPER_PASSPHRASE
        missing = c.MIN_PASSPHRASE_BYTES - metadata.size
        error = ImproperPassphrase(issue.replace("NEED", str(missing)))
        error.missing = missing
        return error

    @classmethod
    def improper_salt(cls, metadata: Metadata, /) -> ValueError:
        from .keygens.passcrypt.config import passcrypt_spec as c

        if metadata.type is not bytes:
            return Issue.value_must_be_type("`salt`", bytes)
        return ValueError(
            cls
            ._IMPROPER_SALT
            .replace("MIN_SALT_SIZE", repr(c.MIN_SALT_SIZE))
            .replace("MAX_SALT_SIZE", repr(c.MAX_SALT_SIZE))
        )

    @classmethod
    def improper_aad(cls, /) -> TypeError:
        return Issue.value_must_be_type("`aad`", bytes)

    @classmethod
    def invalid_mb(cls, mb: int, /) -> ValueError:
        from .keygens.passcrypt.config import passcrypt_spec as c

        if mb.__class__ is not int:
            return Issue.value_must_be_type("`mb`", int)
        return ValueError(
            cls
            ._INVALID_MB
            .replace("MIN_MB", repr(c.MIN_MB))
            .replace("MAX_MB", repr(c.MAX_MB))
            .replace("MB", repr(mb))
        )

    @classmethod
    def invalid_cpu(cls, cpu: int, /) -> ValueError:
        from .keygens.passcrypt.config import passcrypt_spec as c

        if cpu.__class__ is not int:
            return Issue.value_must_be_type("`cpu`", int)
        return ValueError(
            cls
            ._INVALID_CPU
            .replace("MIN_CPU", repr(c.MIN_CPU))
            .replace("MAX_CPU", repr(c.MAX_CPU))
            .replace("CPU", repr(cpu))
        )

    @classmethod
    def invalid_cores(cls, cores: int, /) -> ValueError:
        from .keygens.passcrypt.config import passcrypt_spec as c

        if cores.__class__ is not int:
            return Issue.value_must_be_type("`cores`", int)
        return ValueError(
            cls
            ._INVALID_CORES
            .replace("MIN_CORES", repr(c.MIN_CORES))
            .replace("MAX_CORES", repr(c.MAX_CORES))
            .replace("CORES", repr(cores))
        )

    @classmethod
    def invalid_tag_size(cls, tag_size: int, /) -> ValueError:
        from .keygens.passcrypt.config import passcrypt_spec as c

        if tag_size.__class__ is not int:
            return Issue.value_must_be_type("`tag_size`", int)
        return ValueError(
            cls
            ._INVALID_TAG_SIZE
            .replace("MIN_TAG_SIZE", repr(c.MIN_TAG_SIZE))
            .replace("SIZE", repr(tag_size))
        )

    @classmethod
    def invalid_salt_size(cls, salt_size: int, /) -> ValueError:
        from .keygens.passcrypt.config import passcrypt_spec as c

        if salt_size.__class__ is not int:
            return Issue.value_must_be_type("`salt_size`", int)
        return ValueError(
            cls
            ._INVALID_SALT_SIZE
            .replace("MIN_SALT_SIZE", repr(c.MIN_SALT_SIZE))
            .replace("MAX_SALT_SIZE", repr(c.MAX_SALT_SIZE))
            .replace("SIZE", repr(salt_size))
        )

    @classmethod
    def untrusted_resource_consumption(
        cls, parameter: str, header: t.Mapping[str, int], /
    ) -> ResourceWarning:
        value = header[parameter]
        issue = cls._UNTRUSTED_RESOURCE_CONSUMPTION
        issue = issue.replace("PARAMETER", repr(parameter))
        danger = ResourceWarning(issue.replace("VALUE", repr(value)))
        danger.requested_resources = header
        danger.parameter = parameter
        danger.value = value
        return danger

    @classmethod
    def verification_failed(cls, /) -> InvalidPassphrase:
        return InvalidPassphrase(cls._VERIFICATION_FAILED)


class DatabaseIssue:
    """
    A class to help with the readability of raising issues related to
    `AsyncDatabase` & `Database` values & processes with more precise
    error messages for users.
    """

    __slots__ = ()

    _FILE_NOT_FOUND: str = "The NAME filename was not located."
    _NO_EXISTING_METATAG: str = "No metatag database named TAG."
    _MISSING_PROFILE: str = "Profile doesn't exist or is corrupt."
    _TAG_FILE_DOESNT_EXIST: str = "TAG tag data isn't in the database."

    @classmethod
    def file_not_found(cls, filename: str, /) -> LookupError:
        issue = cls._FILE_NOT_FOUND
        return LookupError(issue.replace("NAME", repr(filename)))

    @classmethod
    def no_existing_metatag(cls, tag: str, /) -> LookupError:
        issue = cls._NO_EXISTING_METATAG
        return LookupError(issue.replace("TAG", repr(tag)))

    @classmethod
    def tag_file_doesnt_exist(cls, tag: str, /) -> LookupError:
        issue = cls._TAG_FILE_DOESNT_EXIST
        return LookupError(issue.replace("TAG", repr(tag)))


class PackageSignerIssue:
    """
    A class to help with the readability of raising issues related to
    `PackageSigner` values & processes with more precise error messages
    for users.
    """

    __slots__ = ()

    _INVALID_FILE_DIGEST: str = (
        "The summary & the hash digest of the given file don't match: "
        "FILENAME."
    )
    _PACKAGE_HASNT_BEEN_SIGNED: str = (
        "This version of the package must be signed before querying its "
        "signature."
    )
    _SIGNING_KEY_HASNT_BEEN_SET: str = (
        "The `PackageSigner` instance's signing key hasn't been set."
    )
    _OUT_OF_SYNC_PACKAGE_SIGNATURE: str = (
        "The calculated package signature is out of sync with the "
        "current checksum of the package summary."
    )
    _MUST_CONNECT_TO_SECURE_DATABASE: str = (
        "Must first connect to the package signing session's secure "
        "database before it can be updated or queried."
    )

    @classmethod
    def invalid_file_digest(
        cls, filename: t.Union[str, Path], /
    ) -> InvalidDigest:
        issue = cls._INVALID_FILE_DIGEST
        return InvalidDigest(issue.replace("FILENAME", repr(filename)))

    @classmethod
    def package_hasnt_been_signed(cls, /) -> RuntimeError:
        return RuntimeError(cls._PACKAGE_HASNT_BEEN_SIGNED)

    @classmethod
    def signing_key_hasnt_been_set(cls, /) -> LookupError:
        return LookupError(cls._SIGNING_KEY_HASNT_BEEN_SET)

    @classmethod
    def out_of_sync_package_signature(cls, /) -> ValueError:
        return ValueError(cls._OUT_OF_SYNC_PACKAGE_SIGNATURE)

    @classmethod
    def must_connect_to_secure_database(cls, /) -> RuntimeError:
        return RuntimeError(cls._MUST_CONNECT_TO_SECURE_DATABASE)


module_api = dict(
    AuthenticationFailed=t.add_type(AuthenticationFailed),
    CanonicalEncodingError=t.add_type(CanonicalEncodingError),
    CanonicalIssue=t.add_type(CanonicalIssue),
    CipherStreamIssue=t.add_type(CipherStreamIssue),
    DatabaseIssue=t.add_type(DatabaseIssue),
    Ignore=t.add_type(Ignore),
    ImproperPassphrase=t.add_type(ImproperPassphrase),
    InvalidBlockID=t.add_type(InvalidBlockID),
    InvalidCiphertextSize=t.add_type(InvalidCiphertextSize),
    InvalidDigest=t.add_type(InvalidDigest),
    InvalidPassphrase=t.add_type(InvalidPassphrase),
    InvalidSHMAC=t.add_type(InvalidSHMAC),
    InvalidSignature=t.add_type(InvalidSignature),
    Issue=t.add_type(Issue),
    KeyAADIssue=t.add_type(KeyAADIssue),
    Metadata=t.add_type(Metadata),
    PackageSignerIssue=t.add_type(PackageSignerIssue),
    PasscryptIssue=t.add_type(PasscryptIssue),
    ReturnValue=t.add_type(ReturnValue),
    SHMACIssue=t.add_type(SHMACIssue),
    TimestampExpired=t.add_type(TimestampExpired),
    TypeUncheckableAtRuntime=t.add_type(TypeUncheckableAtRuntime),
    UndefinedRequiredAttributes=t.add_type(UndefinedRequiredAttributes),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    raise_exception=raise_exception,
)

