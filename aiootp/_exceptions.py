# This file is part of aiootp, an asynchronous crypto and anonymity
# library. Home of the Chunky2048 psuedo one-time pad stream cipher.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "AuthenticationFailed",
    "CanonicalIssue",
    "CipherStreamIssue",
    "CiphertextIssue",
    "DatabaseIssue",
    "ImproperPassphrase",
    "InvalidBlockID",
    "InvalidHMAC",
    "InvalidPassphrase",
    "InvalidSHMAC",
    "Issue",
    "KeyAADIssue",
    "Metadata",
    "PackageSignerIssue",
    "PaddingIssue",
    "PasscryptIssue",
    "TimestampIssue",
    "ReturnValue",
    "SHMACIssue",
    "TimestampExpired",
    "aignore",
    "araise_exception",
    "ignore",
    "raise_exception",
]


__doc__ = (
    "Organizes the package's exceptions in declarative classes & expres"
    "sive methods on those classes."
)


import json
import typing as t
from pathlib import Path
from asyncio import sleep as asleep
from contextlib import contextmanager
from .__dependencies import async_contextmanager
from .__constants import *


class Metadata:
    """
    Creates efficient containers for the generic metadata of values.
    This is used so that potentially sensitive values can be analyzed
    while keeping the raw values from being passed around or displayed
    in error outputs.
    """

    __slots__ = ("size", "type")

    def __init__(self, value: t.Any) -> None:
        self.type = value.__class__
        self.size = len(value) if hasattr(value, "__len__") else None


def is_exception(obj) -> bool:
    """
    Returns a bool of whether ``obj`` is an exception object.
    """
    return hasattr(obj, "__cause__")


async def araise_exception(obj: Exception) -> None:
    """
    Simply provides a callable which raises ``obj`` turning the raise
    statement into an expression.
    """
    raise obj


def raise_exception(obj: Exception) -> None:
    """
    Simply provides a callable which raises ``obj`` turning the raise
    statement into an expression.
    """
    raise obj


def display_exception_info(error) -> None:
    """
    Prints out debug information of exceptions.
    """
    print("Error Type:", error.__class__)
    print("Error Args:", error.args)
    print("Error Cause:", error.__cause__)
    print("Error Value:", repr(getattr(error, "value", None)))
    print("Error Attributes:", [n for n in dir(error) if not n[0] == "_"])


class PlaceholderException(Exception):
    """
    Empty, unused placeholder exception.
    """


class AsyncRelayExceptions:
    """
    Creates objects which can run user-specified async code in the event
    of an exception, the absence of an exception, or at the end of a
    context.
    """

    __slots__ = (
        "aexcept_code", "aelse_code", "afinally_code", "error", "message_bus"
    )

    _read_me = f"""
    Overwrite {__slots__[:3]} methods with custom async functions.
    They will proc in ``aiootp.generics.aignore`` async context manager
    when:

    1.  {__slots__[0]} - the ignored exceptions are raised within the
    context.

    2.  {__slots__[1]} - if no exception is raised within the context.

    But always,
    3.  {__slots__[2]} - at the end of the context.
    """

    def __init__(
        self,
        if_except: t.Union[None, t.Callable[[Exception], t.Any]] = None,
        if_else: t.Union[None, t.Callable[[Exception], t.Any]] = None,
        finally_run: t.Union[None, t.Callable[[Exception], t.Any]] = None,
    ) -> None:
        from .commons import Namespace

        async def placeholder(*a, **kw):
            return self._read_me

        self.message_bus = Namespace()
        self.aexcept_code = if_except if if_except else placeholder
        self.aelse_code = if_else if if_else else placeholder
        self.afinally_code = finally_run if finally_run else placeholder


class RelayExceptions:
    """
    Creates objects which can run user-specified code in the event of an
    exception, the absence of an exception, or at the end of a context.
    """

    __slots__ = (
        "except_code", "else_code", "finally_code", "error", "message_bus"
    )

    _read_me = f"""
    Overwrite {__slots__[:3]} methods with custom functions.
    They will proc in ``aiootp.generics.ignore`` context manager when:

    1.  {__slots__[0]} - the ignored exceptions are raised within the
    context.

    2.  {__slots__[1]} - if no exception is raised within the context.

    But always,
    3.  {__slots__[2]} - at the end of the context.
    """

    def __init__(
        self,
        if_except: t.Union[None, t.Callable[[Exception], t.Any]] = None,
        if_else: t.Union[None, t.Callable[[Exception], t.Any]] = None,
        finally_run: t.Union[None, t.Callable[[Exception], t.Any]] = None,
    ) -> None:
        from .commons import Namespace

        def placeholder(*a, **kw):
            return self._read_me

        self.message_bus = Namespace()
        self.except_code = if_except if if_except else placeholder
        self.else_code = if_else if if_else else placeholder
        self.finally_code = finally_run if finally_run else placeholder


@async_contextmanager
async def aignore(
    *exceptions: t.Iterable[Exception],
    if_except: t.Union[None, t.Callable[[Exception], t.Any]] = None,
    if_else: t.Union[None, t.Callable[[Exception], t.Any]] = None,
    finally_run: t.Union[None, t.Callable[[Exception], t.Any]] = None,
) -> t.AsyncContextManager:
    """
     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    async with aignore(TypeError):
        c = a + b
        # exception is surpressed if adding a and b raises a TypeError

    Or, dynamically choose which exceptions to catch, and call custom
    cleanup code. ->

    async def cleanup(error=None):
        await database.asave()

    async with ignore(DynamicException, IOError) as error_relay:
        error_relay.aexcept_code = cleanup
        # This will close ``database`` if either DynamicException or
        # IOError are raised within the block.

        error_relay.afinally_code = cleanup
        # This will ensure close is called on ``database`` in a finally
        # block.

    async with aignore(IOError, if_except=cleanup) as relay:
        # Or more cleanly, pass the function to be run during an
        # exception into ``if_except``.

    async with aignore(IOError, finally_run=cleanup) as relay:
        # Similarly, to declare a function to run in the finally block.
    """
    try:
        exceptions = exceptions if exceptions else PlaceholderException
        relay = AsyncRelayExceptions(if_except, if_else, finally_run)
        await asleep(0)
        yield relay
    except exceptions as error:
        relay.error = error
        error.message_bus = relay.message_bus
        await relay.aexcept_code(error)
    except Exception as error:
        relay.error = error
        error.message_bus = relay.message_bus
        raise error
    finally:
        try:
            0 if hasattr(relay, "error") else await relay.aelse_code()
        finally:
            await relay.afinally_code()


@contextmanager
def ignore(
    *exceptions: t.Iterable[Exception],
    if_except: t.Union[None, t.Callable[[Exception], t.Any]] = None,
    if_else: t.Union[None, t.Callable[[Exception], t.Any]] = None,
    finally_run: t.Union[None, t.Callable[[Exception], t.Any]] = None,
) -> t.ContextManager:
    """
     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    with ignore(TypeError):
        c = a + b
        # exception is surpressed if adding a and b raises a TypeError

    Or, dynamically choose which exceptions to catch, and call custom
    cleanup code. ->

    def cleanup(error=None):
        database.save()

    with ignore(DynamicException, IOError) as error_relay:
        error_relay.except_code = cleanup
        # This will close ``database`` if either DynamicException or
        # IOError are raised within the block.

        error_relay.finally_code = cleanup
        # This will ensure close is called on ``database`` in a finally
        # block.

    with ignore(DynamicException, IOError, if_except=cleanup) as relay:
        # Or more cleanly, pass the function to be run during an
        # exception into ``if_except``.

    with ignore(DynamicException, IOError, finally_run=cleanup) as relay:
        # Similarly, to declare a function to run in the finally block.
    """
    try:
        exceptions = exceptions if exceptions else PlaceholderException
        relay = RelayExceptions(if_except, if_else, finally_run)
        yield relay
    except exceptions as error:
        relay.error = error
        error.message_bus = relay.message_bus
        relay.except_code(error)
    except Exception as error:
        relay.error = error
        error.message_bus = relay.message_bus
        raise error
    finally:
        try:
            0 if hasattr(relay, "error") else relay.else_code()
        finally:
            relay.finally_code()


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


class InvalidHMAC(AuthenticationFailed):
    """
    An exception raised when a `(a)test_hmac` method detects an
    incorrect `untrusted_hmac`.
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
    _NO_VALUE_SPECIFIED: str = "No NAME was specified."
    _VALUE_MUST_BE_VALUE: str = "The NAME value must be a VALUE."
    _STREAM_IS_EMPTY: str = "An invalid emtpy stream was provided."
    _VALUE_MUST_BE_TYPE: str = "The NAME value must be a TYPE object."
    _VALUE_ALREADY_SET: str = "The OBJECT is already set to CONTEXT."
    _EXCEEDED_BLOCKSIZE: str = (
        "Data block MUST NOT exceed BLOCKSIZE bytes."
    )
    _CANT_OVERWRITE_EXISTING_ATTRIBUTE: str = (
        "Can't overwrite the existing NAME attribute."
    )
    _CANT_DELETE_FROZEN_OBJECT_ATTRIBUTE: str = (
        "Can't delete the NAME attribute of frozen object."
    )
    _UNUSED_PARAMETERS: str = (
        "The PARAMETERS parameters are not used when CONTEXT."
    )
    _INVALID_BLOCKSIZE: str = (
        "An invalid block of SIZE bytes was produced. Blocks must be DE"
        "FAULT bytes."
    )
    _UNSAFE_DETERMINISM: str = (
        "Must enable dangerous determinism to use a custom salt. Provid"
        "ing both a key & salt risks salt reuse / misuse, which is NOT "
        "safe."
    )
    _BROKEN_POOL_RESTARTED: str = (
        "The process pool was broken & has now been restarted. Try agai"
        "n."
    )

    @classmethod
    def invalid_value(cls, name: str, problem: str = "") -> ValueError:
        issue = cls._INVALID_VALUE.replace("NAME", name)
        if problem:
            issue = f"{issue} The {name} can't be {problem}."
        return ValueError(issue)

    @classmethod
    def invalid_length(cls, name: str, size: int) -> ValueError:
        issue = cls._INVALID_LENGTH.replace("NAME", name)
        return ValueError(issue.replace("LENGTH", repr(size)))

    @classmethod
    def value_must(cls, name: str, context: t.Any) -> ValueError:
        issue = cls._VALUE_MUST.replace("NAME", repr(name))
        return ValueError(issue.replace("CONTEXT", str(context)))

    @classmethod
    def must_set_value(cls, name: str, context: str) -> ValueError:
        issue = cls._MUST_SET_VALUE.replace("NAME", repr(name))
        return ValueError(issue.replace("CONTEXT", str(context)))

    @classmethod
    def no_value_specified(cls, name: str) -> ValueError:
        issue = cls._NO_VALUE_SPECIFIED
        return ValueError(issue.replace("NAME", repr(name)))

    @classmethod
    def value_must_be_value(
        cls, name: str, value: t.Any
    ) -> ValueError:
        issue = cls._VALUE_MUST_BE_VALUE.replace("NAME", str(name))
        return ValueError(issue.replace("VALUE", repr(value)))

    @classmethod
    def stream_is_empty(cls) -> ValueError:
        return ValueError(cls._STREAM_IS_EMPTY)

    @classmethod
    def value_must_be_type(cls, name: str, clss: t.Any) -> TypeError:
        issue = cls._VALUE_MUST_BE_TYPE.replace("NAME", repr(name))
        return TypeError(issue.replace("TYPE", repr(clss)))

    @classmethod
    def value_already_set(cls, obj: str, context: str) -> PermissionError:
        issue = cls._VALUE_ALREADY_SET.replace("OBJECT", str(obj))
        return PermissionError(issue.replace("CONTEXT", str(context)))

    @classmethod
    def exceeded_blocksize(cls, blocksize: int = BLOCKSIZE) -> ValueError:
        issue = cls._EXCEEDED_BLOCKSIZE
        return ValueError(issue.replace("BLOCKSIZE", repr(blocksize)))

    @classmethod
    def cant_overwrite_existing_attribute(
        cls, name: str
    ) -> PermissionError:
        issue = cls._CANT_OVERWRITE_EXISTING_ATTRIBUTE
        return PermissionError(issue.replace("NAME", repr(name)))

    @classmethod
    def cant_delete_frozen_object_attribute(
        cls, name: str
    ) -> PermissionError:
        issue = cls._CANT_MUTATE_ATTRIBUTE_OF_FROZEN_OBJECT
        return PermissionError(issue.replace("NAME", repr(name)))

    @classmethod
    def unused_parameters(cls, params: t.Any, context: str) -> ValueError:
        issue = cls._UNUSED_PARAMETERS.replace("PARAMETERS", repr(params))
        return ValueError(issue.replace("CONTEXT", str(context)))

    @classmethod
    def invalid_blocksize(cls, size: int) -> ValueError:
        issue = cls._INVALID_BLOCKSIZE.replace("SIZE", repr(size))
        return ValueError(issue.replace("DEFAULT", str(BLOCKSIZE)))

    @classmethod
    def unsafe_determinism(cls) -> PermissionError:
        return PermissionError(cls._UNSAFE_DETERMINISM)

    @classmethod
    def broken_pool_restarted(cls) -> RuntimeError:
        return RuntimeError(cls._BROKEN_POOL_RESTARTED)


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
        "The measured length of the canonically encoded item does not m"
        "atch its declared length."
    )
    _INVALID_PADDING: str = (
        "Invalid canonical encoding padding detected!"
    )
    _DATA_LENGTH_BLOCKSIZE_MISMATCH: str = (
        "Multiple of data length != declared blocksize!"
    )
    _MISSING_METADATA_ITEMS: str = (
        "The encoding lead to an unpacked data result without its requi"
        "red blocksize / pad declarations."
    )

    @classmethod
    def item_length_mismatch(cls) -> CanonicalEncodingError:
        return CanonicalEncodingError(cls._ITEM_LENGTH_MISMATCH)

    @classmethod
    def inflated_size_declaration(cls) -> CanonicalEncodingError:
        return CanonicalEncodingError(cls._INFLATED_SIZE_DECLARATION)

    @classmethod
    def invalid_padding(cls) -> CanonicalEncodingError:
        return CanonicalEncodingError(cls._INVALID_PADDING)

    @classmethod
    def data_length_blocksize_mismatch(cls) -> CanonicalEncodingError:
        return CanonicalEncodingError(cls._DATA_LENGTH_BLOCKSIZE_MISMATCH)

    @classmethod
    def missing_metadata_items(cls) -> CanonicalEncodingError:
        return CanonicalEncodingError(cls._MISSING_METADATA_ITEMS)


class KeyAADIssue:
    """
    A class to help with the readability of raising issues related to
    `Chunky2048` `keys`, `salt` & `aad` values with more precise error
    messages for users.
    """

    __slots__ = ()

    _INVALID_KEY: str = (
        f"The ``key`` must be at least {MIN_KEY_BYTES} bytes."
    )
    _INVALID_SALT: str = (
        f"The ``salt`` must be a {SALT_BYTES}-byte value."
    )
    _MODE_ISNT_CORRECT: str = (
        "The KDF mode must be set to MODE to use MODE key derivation."
    )
    _NO_KDF_MODE_DECLARED: str = (
        "KeyAADBundle objects need to be set to either sync or async mo"
        "des prior to querying their derived keys."
    )
    _VALIDATOR_ALREADY_REGISTERED: str = (
        "This KeyAADBundle object was registered for use by another val"
        "idator object. Create a new bundle with fresh randomness inste"
        "ad."
    )
    _KEYSTREAM_ALREADY_REGISTERED: str = (
        "This KeyAADBundle object was already registered for use by ano"
        "ther keystream. Create a new bundle with fresh randomness inst"
        "ead."
    )
    _MUST_CREATE_A_NEW_OBJECT_EXPLICITLY: str = (
        "Cipher contexts are more safely changed by explicitly creating"
        " a new key bundle instance with different values than by chang"
        "ing the NAME value of an existing instance."
    )

    @classmethod
    def invalid_key(cls) -> ValueError:
        return ValueError(cls._INVALID_KEY)

    @classmethod
    def invalid_salt(cls, SALT_BYTES: int) -> ValueError:
        return ValueError(cls._INVALID_SALT)

    @classmethod
    def mode_isnt_correct(cls, mode: str) -> ValueError:
        issue = cls._MODE_ISNT_CORRECT.replace("MODE", repr(mode))
        return ValueError(issue)

    @classmethod
    def no_kdf_mode_declared(cls) -> RuntimeError:
        return RuntimeError(cls._NO_KDF_MODE_DECLARED)

    @classmethod
    def validator_already_registered(cls) -> PermissionError:
        return PermissionError(cls._VALIDATOR_ALREADY_REGISTERED)

    @classmethod
    def keystream_already_registered(cls) -> PermissionError:
        return PermissionError(cls._KEYSTREAM_ALREADY_REGISTERED)

    @classmethod
    def must_create_a_new_object_explicitly(
        cls, name: str
    ) -> PermissionError:
        issue = cls._MUST_CREATE_A_NEW_OBJECT_EXPLICITLY
        return PermissionError(issue.replace("NAME", str(name)))


class PaddingIssue:
    """
    A class to help with the readability of raising issues related to
    the `Padding` class & the padding of plaintexts.
    """

    __slots__ = ()

    _MIN_PLAINTEXT_BUFFER_NOT_ACHEIVED: str = (
        "Must buffer at least 232 bytes of plaintext into the stream so"
        " it can be padded correctly. If the end of the plaintext has a"
        "lready been reached, then call `(a)finalize` on the stream."
    )
    _MIN_CIPHERTEXT_BUFFER_NOT_ACHEIVED: str = (
        "Must buffer at least 512 bytes of ciphertext into the stream s"
        "o the underlying plaintext can be depadded correctly. If the e"
        "nd of the ciphertext has already been reached, then call `(a)f"
        "inalize` on the stream."
    )

    @classmethod
    def min_plaintext_buffer_not_acheived(cls) -> ValueError:
        return ValueError(cls._MIN_PLAINTEXT_BUFFER_NOT_ACHEIVED)

    @classmethod
    def min_ciphertext_buffer_not_acheived(cls) -> ValueError:
        return ValueError(cls._MIN_CIPHERTEXT_BUFFER_NOT_ACHEIVED)


class SHMACIssue:
    """
    A class to help with the readability of raising issues related to
    `StreamHMAC` values & processes with more precise error messages for
    users.
    """

    __slots__ = ()

    _NO_CIPHER_MODE_DECLARED: str = "No cipher mode has been declared."
    _ALREADY_FINALIZED: str = "The validator has already been finalized."
    _USE_FINAL_RESULT: str = (
        _ALREADY_FINALIZED + " Use the final result instead."
    )
    _VALIDATION_INCOMPLETE: str = (
        "Can't produce a result before finalization."
    )
    _INVALID_IV_USAGE: str = (
        "The ``siv`` must be manually passed into the validator during "
        "*decryption*, & only during decryption."
    )
    _BLOCK_ID_IS_TOO_BIG: str = (
        "A block id of SIZE bytes is too big. It can be at most MAX byt"
        "es."
    )
    _BLOCK_ID_IS_TOO_SMALL: str = (
        "A block id of SIZE bytes is too small. It must be at least "
        "MIN bytes to securely authenticate a block."
    )
    _INVALID_SHMAC: str = (
        "Invalid StreamHMAC hash for the given ciphertext."
    )
    _INVALID_BLOCK_ID: str = (
        "Invalid next block ID hash of the supplied ciphertext block."
    )

    @classmethod
    def no_cipher_mode_declared(cls) -> PermissionError:
        return PermissionError(cls._NO_CIPHER_MODE_DECLARED)

    @classmethod
    def already_finalized(cls) -> PermissionError:
        return PermissionError(cls._ALREADY_FINALIZED)

    @classmethod
    def use_final_result_instead(cls) -> PermissionError:
        return PermissionError(cls._USE_FINAL_RESULT)

    @classmethod
    def validation_incomplete(cls) -> PermissionError:
        return PermissionError(cls._VALIDATION_INCOMPLETE)

    @classmethod
    def invalid_siv_usage(cls) -> PermissionError:
        return PermissionError(cls._INVALID_IV_USAGE)

    @classmethod
    def block_id_is_too_big(size: int) -> PermissionError:
        issue = cls._BLOCK_ID_IS_TOO_BIG.replace("SIZE", repr(size))
        issue = issue.replace("MAX", str(MAX_BLOCK_ID_BYTES))
        return PermissionError(issue)

    @classmethod
    def block_id_is_too_small(cls, size: int) -> PermissionError:
        issue = cls._BLOCK_ID_IS_TOO_SMALL.replace("SIZE", repr(size))
        issue = issue.replace("MIN", str(MIN_BLOCK_ID_BYTES))
        return PermissionError(issue)

    @classmethod
    def invalid_shmac(cls) -> InvalidSHMAC:
        return InvalidSHMAC(cls._INVALID_SHMAC)

    @classmethod
    def invalid_block_id(cls) -> InvalidBlockID:
        return InvalidBlockID(cls._INVALID_BLOCK_ID)


class CiphertextIssue:
    """
    A class to help with the readability of raising issues related to
    processing & validating ciphertexts.
    """

    __slots__ = ()

    _INVALID_CIPHERTEXT_SIZE: str = (
        "The given ciphertext of length SIZE is not a multiple of the b"
        "locksize minus the header bytes."
    )

    @classmethod
    def invalid_ciphertext_size(cls, size: int) -> ValueError:
        issue = cls._INVALID_CIPHERTEXT_SIZE
        return ValueError(issue.replace("SIZE", repr(size)))


class TimestampIssue:
    """
    A class to help with the readability of raising issues related to
    processing & validating timestamps.
    """

    __slots__ = ()

    _TIMESTAMP_EXPIRED: str = "Timestamp expired by <TIME> UNITS."
    _INVALID_TIMESTAMP_FORMAT: str = (
        f"Invalid timestamp format! It must be BYTES bytes long."
    )

    @classmethod
    def timestamp_expired(
        cls, unit: str, expired_by: int
    ) -> TimestampExpired:
        issue = cls._TIMESTAMP_EXPIRED.replace("UNITS", repr(unit))
        error = TimestampExpired(issue.replace("TIME", repr(expired_by)))
        error.unit = unit
        error.expired_by = expired_by
        return error

    @classmethod
    def invalid_timestamp_format(
        cls, timestamp_bytes: int = TIMESTAMP_BYTES
    ) -> ValueError:
        issue = cls._INVALID_TIMESTAMP_FORMAT
        return ValueError(issue.replace("BYTES", str(timestamp_bytes)))


class CipherStreamIssue:
    """
    A class to help with the readability of raising issues related to
    `(Async)CipherStream` & `(Async)DecipherStream` values & processes
    with more precise error messages for users.
    """

    __slots__ = ()

    _STREAM_HAS_BEEN_CLOSED: str = (
        "The stream has been closed. Cannot add more ``data`` to the bu"
        "ffer of an already closed stream."
    )
    _INVALID_BUFFER_SIZE: str = (
        "The buffer must only be updated with a # of bytes that is a mu"
        "ltiple of MULTIPLE, the given buffer of BUFFER_SIZE bytes is i"
        "nvalid."
    )

    @classmethod
    def stream_has_been_closed(cls) -> InterruptedError:
        return InterruptedError(cls._STREAM_HAS_BEEN_CLOSED)

    @classmethod
    def invalid_buffer_size(cls, buffer_size: int) -> ValueError:
        issue = cls._INVALID_BUFFER_SIZE
        issue = issue.replace("MULTIPLE", str(PACKETSIZE))
        issue = issue.replace("BUFFER_SIZE", str(buffer_size))
        return ValueError(issue)


class PasscryptIssue:
    """
    A class to help with the readability of raising issues related to
    `Passcrypt` values & processes with more precise error messages for
    users.
    """

    __slots__ = ()

    _IMPROPER_PASSPHRASE: str = (
        "The given passphrase is too short, at least NEED more characte"
        "rs need to be added. \nTry using aiootp.mnemonic, it can help "
        "in generating a strong passphrase.\n"
        " _____________________________________\n"
        "|                                     |\n"
        "|            Usage Example:           |\n"
        "|_____________________________________|\n\n"
        "my_new_passphrase = b'-'.join(aiootp.mnemonic())\n\n"
        "print(my_new_passphrase)\n"
        "b'review-letter-blast-giant-connect-ring-balcony-frown'"
    )
    _IMPROPER_SALT: str = "len(salt) must be >= 8 and <= 256"
    _INVALID_MB: str = "mb:MB must be int >= 1 and <= 256**3"
    _INVALID_CPU: str = "cpu:CPU must be int >= 2 and <= 256"
    _INVALID_CORES: str = "cores:CORES must be int >= 1 and <= 256"
    _INVALID_TAG_SIZE: str = "tag_size:SIZE must be int >= 16"
    _INVALID_SALT_SIZE: str = "salt_size:SIZE must be int >= 4 and <= 256"
    _DECODING_FAILED: str = "Hash decoder returned failure: FAILURE."
    _UNTRUSTED_RESOURCE_CONSUMPTION: str = (
        "The PARAMETER parameter was blocked from being processed becau"
        "se it fell outside of the allowed range of resource consumptio"
        "n set by the verification method. To continue verifying the pr"
        "ovided hash, explicit permission must be given in the form of "
        "a `builtins.range` object which includes the value VALUE.\n\n"
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
        "Passphrase verification failed! The hash of the passphrase & t"
        "he passcrypt hash did not match!"
    )

    @classmethod
    def improper_passphrase(cls, metadata: Metadata) -> ValueError:
        if metadata.type is not bytes:
            return Issue.value_must_be_type("``passphrase``", bytes)
        else:
            issue = cls._IMPROPER_PASSPHRASE
            missing = MIN_PASSPHRASE_BYTES - metadata.size
            error = ImproperPassphrase(issue.replace("NEED", str(missing)))
            error.missing = missing
            return error

    @classmethod
    def improper_salt(cls, metadata: Metadata) -> ValueError:
        if metadata.type is not bytes:
            return Issue.value_must_be_type("``salt``", bytes)
        return ValueError(cls._IMPROPER_SALT)

    @classmethod
    def improper_aad(cls) -> TypeError:
        return Issue.value_must_be_type("``aad``", bytes)

    @classmethod
    def invalid_mb(cls, mb: int) -> ValueError:
        if mb.__class__ is not int:
            return Issue.value_must_be_type("``mb``", int)
        return ValueError(cls._INVALID_MB.replace("MB", repr(mb)))

    @classmethod
    def invalid_cpu(cls, cpu: int) -> ValueError:
        if cpu.__class__ is not int:
            return Issue.value_must_be_type("``cpu``", int)
        return ValueError(cls._INVALID_CPU.replace("CPU", repr(cpu)))

    @classmethod
    def invalid_cores(cls, cores: int) -> ValueError:
        if cores.__class__ is not int:
            return Issue.value_must_be_type("``cores``", int)
        issue = cls._INVALID_CORES
        return ValueError(issue.replace("CORES", repr(cores)))

    @classmethod
    def invalid_tag_size(cls, tag_size: int) -> ValueError:
        if tag_size.__class__ is not int:
            return Issue.value_must_be_type("``tag_size``", int)
        issue = cls._INVALID_TAG_SIZE
        return ValueError(issue.replace("SIZE", repr(tag_size)))

    @classmethod
    def invalid_salt_size(cls, salt_size: int) -> ValueError:
        if salt_size.__class__ is not int:
            return Issue.value_must_be_type("``salt_size``", int)
        issue = cls._INVALID_SALT_SIZE
        return ValueError(issue.replace("SIZE", repr(salt_size)))

    @classmethod
    def decoding_failed(cls, failure: str) -> ValueError:
        issue = cls._DECODING_FAILED
        return ValueError(issue.replace("FAILURE", repr(failure)))

    @classmethod
    def untrusted_resource_consumption(
        cls, parameter: str, header: t.Mapping[str, int]
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
    def verification_failed(cls) -> InvalidPassphrase:
        return InvalidPassphrase(cls._VERIFICATION_FAILED)


class DatabaseIssue:
    """
    A class to help with the readability of raising issues related to
    `AsyncDatabase` & `Database` values & processes with more precise
    error messages for users.
    """

    __slots__ = ()

    _INVALID_HMAC: str = "Invalid HMAC hash for the given data."
    _INVALID_WRITE_ATTEMPT: str = "Invalid write attempted."
    _FILE_NOT_FOUND: str = "The NAME filename was not located."
    _NO_EXISTING_METATAG: str = "No metatag database named TAG."
    _MISSING_PROFILE: str = "Profile doesn't exist or is corrupt."
    _TAG_FILE_DOESNT_EXIST: str = "TAG tag data isn't in the cache."
    _KEY_HAS_BEEN_DELETED: str = "The database keys have been deleted."
    _CANT_DELETE_MAINTENANCE_RECORDS: str = (
        "Can't delete database maintenance records."
    )
    _INVALID_ENTRY_TYPE: str = (
        "Database entries must be JSON serializable or bytes types."
    )

    @classmethod
    def invalid_hmac(cls) -> InvalidHMAC:
        return InvalidHMAC(cls._INVALID_HMAC)

    @classmethod
    def invalid_write_attempt(cls) -> PermissionError:
        return PermissionError(cls._INVALID_WRITE_ATTEMPT)

    @classmethod
    def file_not_found(cls, filename: str) -> LookupError:
        issue = cls._FILE_NOT_FOUND
        return LookupError(issue.replace("NAME", repr(filename)))

    @classmethod
    def no_existing_metatag(cls, tag: str) -> LookupError:
        issue = cls._NO_EXISTING_METATAG
        return LookupError(issue.replace("TAG", repr(tag)))

    @classmethod
    def tag_file_doesnt_exist(cls, tag: str) -> LookupError:
        issue = cls._TAG_FILE_DOESNT_EXIST
        return LookupError(issue.replace("TAG", repr(tag)))

    @classmethod
    def key_has_been_deleted(cls) -> PermissionError:
        return PermissionError(cls._KEY_HAS_BEEN_DELETED)

    @classmethod
    def cant_delete_maintenance_records(cls) -> PermissionError:
        return PermissionError(cls._CANT_DELETE_MAINTENANCE_RECORDS)

    @classmethod
    def invalid_entry_type(cls) -> TypeError:
        return TypeError(cls._INVALID_ENTRY_TYPE)


class PackageSignerIssue:
    """
    A class to help with the readability of raising issues related to
    `PackageSigner` values & processes with more precise error messages
    for users.
    """

    __slots__ = ()

    _INVALID_FILE_DIGEST: str = (
        "The summary & the hash digest of the given file don't match: F"
        "ILENAME."
    )
    _PACKAGE_HASNT_BEEN_SIGNED: str = (
        "This version of the package must be signed before querying its"
        " signature."
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
    def invalid_file_digest(
        cls, filename: t.Union[str, Path]
    ) -> InvalidDigest:
        issue = cls._INVALID_FILE_DIGEST
        return InvalidDigest(issue.replace("FILENAME", repr(filename)))

    @classmethod
    def package_hasnt_been_signed(cls) -> RuntimeError:
        return RuntimeError(cls._PACKAGE_HASNT_BEEN_SIGNED)

    @classmethod
    def signing_key_hasnt_been_set(cls) -> LookupError:
        return LookupError(cls._SIGNING_KEY_HASNT_BEEN_SET)

    @classmethod
    def out_of_sync_package_signature(cls) -> ValueError:
        return ValueError(cls._OUT_OF_SYNC_PACKAGE_SIGNATURE)

    @classmethod
    def must_connect_to_secure_database(cls) -> RuntimeError:
        return RuntimeError(cls._MUST_CONNECT_TO_SECURE_DATABASE)

