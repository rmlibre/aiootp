# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "ciphers",
    "akeys",
    "keys",
    "abytes_keys",
    "bytes_keys",
    "aplaintext_stream",
    "plaintext_stream",
    "apasscrypt",
    "passcrypt",
    "ajson_decrypt",
    "json_decrypt",
    "ajson_encrypt",
    "json_encrypt",
    "abytes_decrypt",
    "bytes_decrypt",
    "abytes_encrypt",
    "bytes_encrypt",
    "Chunky2048",
    "Passcrypt",
    "AsyncDatabase",
    "Database",
    "StreamHMAC",
    "DomainKDF",
]


__doc__ = (
    "A collection of low-level tools & higher level abstractions which "
    "can be used to create custom security tools, or as pre-assembled "
    "recipes, including the package's main MRAE / AEAD pseudo-one-time-"
    "pad cipher called Chunky2048."
)


import hmac
import json
import base64
from functools import wraps
from functools import partial
from contextlib import contextmanager
from hashlib import sha3_256, sha3_512
from .__aiocontext import async_contextmanager
from .paths import *
from .paths import Path
from .asynchs import *
from .commons import *
from commons import *  # import the module's constants
from .randoms import csprbg, acsprbg
from .randoms import csprng, acsprng
from .randoms import csprng as _csprng
from .randoms import make_uuids, amake_uuids
from .randoms import generate_salt, agenerate_salt
from .generics import arange
from .generics import Hasher
from .generics import BytesIO
from .generics import Domains
from .generics import Padding
from .generics import AsyncInit
from .generics import hash_bytes
from .generics import _zip, azip
from .generics import data, adata
from .generics import cycle, acycle
from .generics import unpack, aunpack
from .generics import ignore, aignore
from .generics import sha_256, asha_256
from .generics import sha_512, asha_512
from .generics import wait_on, await_on
from .generics import is_async_function
from .generics import time_safe_equality
from .generics import atime_safe_equality
from .generics import lru_cache, alru_cache
from .generics import Comprende, comprehension
from .generics import int_to_base, aint_to_base
from .generics import sha_256_hmac, asha_256_hmac
from .generics import sha_512_hmac, asha_512_hmac
from .generics import convert_class_method_to_member


async def atest_key_and_salt(key, salt):
    """
    Validates the main symmetric user ``key`` & ephemeral ``salt`` for
    use in the pseudo-one-time-pad cipher.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    elif not salt:
        raise ValueError("No ``salt`` was specified.")
    elif len(salt) != SALT_NIBBLES or not int(salt, 16):
        raise ValueError("``salt`` must be a 256-bit hex string.")


def test_key_and_salt(key, salt):
    """
    Validates the main symmetric user ``key`` & ephemeral ``salt`` for
    use in the pseudo-one-time-pad cipher.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    elif not salt:
        raise ValueError("No ``salt`` was specified.")
    elif len(salt) != SALT_NIBBLES or not int(salt, 16):
        raise ValueError("``salt`` must be a 256-bit hex string.")


class StreamHMAC:
    """
    This class is used as an inline validator for ciphertext streams as
    they are being created & decrypted. Its design was inspired by AES-GCM,
    but by default it uses a sha3_256 hash function instead of Galois
    multiplication.
    """
    _ENCRYPTION = ENCRYPTION
    _DECRYPTION = DECRYPTION
    _INVALID_HMAC = INVALID_HMAC
    _INVALID_DIGEST = INVALID_DIGEST
    _INVALID_BLOCK_ID = INVALID_BLOCK_ID
    _EXCEEDED_BLOCKSIZE = EXCEEDED_BLOCKSIZE
    _VALIDATION_INCOMPLETE = "Can't produce a result before finalization."
    _ALREADY_FINALIZED = "The validator has already been finalized."
    _USE_FINAL_RESULT = (
        _ALREADY_FINALIZED + " Use the final result instead."
    )
    _UNTRUSTED_HMAC_ISNT_BYTES = "``untrusted_hmac`` must be bytes."
    _UNTRUSTED_DIGEST_ISNT_BYTES = "``untrusted_digest`` must be bytes."
    _UNTRUSTED_BLOCK_ID_ISNT_BYTES = "``untrusted_block_id`` must be bytes."
    _NO_CIPHER_MODE_DECLARED = "No cipher mode has been declared."
    _INVALID_SIV_USAGE = (
        "The ``siv`` must be manually passed into the validator during "
        "*decryption*."
    )
    _SIV_ALREADY_SET = "The ``siv`` may only be set once per instance."
    _siv = ""
    _type = sha3_256
    _key_type = sha3_512

    @staticmethod
    async def _aencode_key(*keys, domain=Domains.KDF.hex()):
        """
        Receives any arbitrary amount of keys, salts or pids of any type,
        & hashes them together to returm a uniform 512-bit bytes encoded
        key.
        """
        return bytes.fromhex(await asha_512(domain, *keys))

    @staticmethod
    def _encode_key(*keys, domain=Domains.KDF.hex()):
        """
        Receives any arbitrary amount of keys, salts or pids of any type,
        & hashes them together to returm a uniform 512-bit bytes encoded
        key.
        """
        return bytes.fromhex(sha_512(domain, *keys))

    def __init__(self, key, *, salt, pid=0, siv=""):
        """
        Begins a stateful hash object that's used to calculate a keyed-
        message authentication code referred to as an hmac. The instance
        derives an encoded key from the hash of the user-defined
        ``key``, ``salt`` & ``pid`` values described below.

        ``key``: An arbitrary, non-zero amount & type of entropic key
                material whose __repr__ returns the user's desired
                entropy & cryptographic strength. Designed to be used as
                a longer-term user encryption / decryption key & should
                be a 512-bit value.
        ``salt``: An ephemeral 256-bit random hexidecimal string that
                MUST BE USED ONLY ONCE for each encryption. This value
                is sent in the clear along with the ciphertext.
        ``pid``: An arbitrary value whose __repr__ function returns any
                value that a user decides to categorize keystreams. It
                safely differentiates those keystreams & initially was
                designed to permute parallelized keystreams derived from
                the same ``key`` & ``salt``. Since this value is now
                verified during message authentication, it can be used
                to verify arbitrary additional data.
        """
        self._set_counter()
        self._mode = None
        self._finalized = False
        self._result_is_ready = False
        self._set_encoded_key(key, salt, pid)
        self._set_mac_object()
        self.siv = siv

    @property
    def siv(self):
        """
        Returns the instance's synthetic IV, which is used as a seed to
        the encryption key stream algorithm. It's derived from the first
        block of plaintext during the padding phase. The ``siv`` is
        attached to the ciphertext so it's available to this method
        during decryption.
        """
        return self._siv

    @siv.setter
    def siv(self, value):
        """
        An interface for setting the instance's SIV & assist users by
        warning against invalid usage.
        """
        if self.siv:
            raise PermissionError(self._SIV_ALREADY_SET)
        elif value:
            self._siv = value
            self.update_key(siv=value)
        else:
            self._siv = ""

    def _set_counter(self):
        """
        Initializes the block counter value. Leaves the option open to
        use custom counter objects that implement `__iadd__` & `to_bytes`
        methods.
        """
        self._block_counter = 0

    def _set_encoded_key(self, key, salt, pid):
        """
        Ensure the ``key`` & ``salt`` conform to the specification used
        in this package's AEAD cipher & set the validator's HMAC key.
        """
        test_key_and_salt(key, salt)
        self._encoded_key = self._encode_key(key, pid, salt, key)

    def _set_mac_object(self):
        """
        The keyed-hashing object is created for the duration of the
        instance's HMAC validation algorithm.
        """
        domain = Domains.SHMAC
        key = 2 * self._encoded_key
        self.__mac = self._type(domain + key)
        self._last_mac = self.__mac.digest()

    @property
    def _mac(self):
        """
        After the validator has been finalized, the final HMAC result is
        available from the `result` & `aresult` methods. The hashing
        object used to calculate the HMAC is then made unavailable to
        warn the user on how to use the validator correctly.
        """
        if self._result_is_ready:
            raise PermissionError(self._ALREADY_FINALIZED)
        return self.__mac

    @property
    def mode(self):
        """
        Returns the mode which the instance was instructed to be in by
        the user.
        """
        return self._mode

    async def aupdate_key(self, key="", *, salt="", pid=0, siv=""):
        """
        This method provides a public interface for updating the HMAC
        key during validation of the stream of ciphertext. This allows
        users to ratchet their encryption ``key`` & have the validator
        track when the key changes & validate the change. The ``salt``
        & ``pid`` for this method are optional since their original
        values are already incorporated in the validator during instance
        initialization. Although, new ``salt``, ``pid`` & ``siv`` values
        may be passed in to be authenticated.
        """
        if self._finalized:
            raise PermissionError(self._ALREADY_FINALIZED)
        old_key = self._encoded_key.hex()
        self._encoded_key = await self._aencode_key(
            old_key, siv, pid, salt, key
        )
        return self

    def update_key(self, key="", *, salt="", pid=0, siv=""):
        """
        This method provides a public interface for updating the HMAC
        key during validation of the stream of ciphertext. This allows
        users to ratchet their encryption ``key`` & have the validator
        track when the key changes & validate the change. The ``salt``
        & ``pid`` for this method are optional since their original
        values are already incorporated in the validator during instance
        initialization. Although, new ``salt``, ``pid`` & ``siv`` values
        may be passed in to be authenticated.
        """
        if self._finalized:
            raise PermissionError(self._ALREADY_FINALIZED)
        old_key = self._encoded_key.hex()
        self._encoded_key = self._encode_key(old_key, siv, pid, salt, key)
        return self

    def for_encryption(self):
        """
        Instructs the HMAC validator instance to prepare itself for
        validating ciphertext within the `xor` generator as plaintext
        is being encrypted.

        Usage Example:

        from aiootp import StreamHMAC, data, generate_salt, sha_256

        salt = generate_salt()
        pid = sha_256("known additional data")
        hmac = StreamHMAC(key, salt=salt, pid=pid).for_encryption()
        cipher = data(b"some bytes of plaintext").bytes_encipher

        with cipher(key, salt=salt, pid=pid, validator=hmac) as ciphering:
            return {
                "ciphertext": ciphering.list(),
                "hmac": hmac.finalize().hex(),
                "salt": salt,
                "synthetic_iv": hmac.siv,
            }
        """
        if self.mode:
            raise PermissionError(f"Validator already set for {self.mode}.")
        elif self._finalized:
            raise PermissionError(self._ALREADY_FINALIZED)
        elif self.siv:
            raise PermissionError(self._INVALID_SIV_USAGE)
        self._mode = self._ENCRYPTION
        self.update = self._update
        self.aupdate = self._aupdate
        self.validated_xor = self._xor_then_hash
        self.avalidated_xor = self._axor_then_hash
        return self

    def for_decryption(self):
        """
        Instructs the HMAC validator instance to prepare itself for
        validating ciphertext within the `xor` generator as it's being
        decrypted.

        Usage Example:

        from aiootp import StreamHMAC, unpack, sha_256

        salt = message["salt"]
        siv = message["sythetic_iv"]
        pid = sha_256("known additional data")
        hmac = StreamHMAC(key, salt=salt, pid=pid, siv=siv).for_decryption()
        decipher = unpack(message["ciphertext"]).bytes_decipher

        with decipher(key, salt=salt, pid=pid, validator=hmac) as deciphering:
            plaintext = deciphering.join(b"")
            hmac.finalize()
            hmac.test_hmac(bytes.fromhex(message["hmac"]))
        """
        if self.mode:
            raise PermissionError(f"Validator already set for {self.mode}.")
        elif self._finalized:
            raise PermissionError(self._ALREADY_FINALIZED)
        elif not self.siv:
            raise PermissionError(self._INVALID_SIV_USAGE)
        self._mode = self._DECRYPTION
        self.update = self._update
        self.aupdate = self._aupdate
        self.validated_xor = self._hash_then_xor
        self.avalidated_xor = self._ahash_then_xor
        return self

    async def _ablock_count(self):
        """
        Returns a 32-byte representation of the number which counts how
        many ciphertext blocks have been processed already by the
        `StreamHMAC` algorithm. This size for the counter leaves open
        the usage for the counter as a custom counting object that
        doesn't merely increment by one for each ciphertext block
        processed.
        """
        await asleep(0)
        return self._block_counter.to_bytes(32, "big")

    def _block_count(self):
        """
        Returns a 32-byte representation of the number which counts how
        many ciphertext blocks have been processed already by the
        `StreamHMAC` algorithm. This size for the counter leaves open
        the usage for the counter as a custom counting object that
        doesn't merely increment by one for each ciphertext block
        processed.
        """
        return self._block_counter.to_bytes(32, "big")

    async def _aupdate(self, ciphertext_chunk):
        """
        This method is called automatically when an instance is passed
        into an encipher or decipher generator as a `validator`. It
        increments the ciphertext block counter & updates the hashing
        object with the bytes type ``cipehrtext_chunk``.
        """
        await asleep(0)
        self._block_counter += 1
        self._last_mac = self._mac.digest()
        self._mac.update(ciphertext_chunk)
        return self

    def _update(self, ciphertext_chunk):
        """
        This method is called automatically when an instance is passed
        into an encipher or decipher generator as a `validator`. It
        increments the ciphertext block counter & updates the hashing
        object with the bytes type ``cipehrtext_chunk``.
        """
        self._block_counter += 1
        self._last_mac = self._mac.digest()
        self._mac.update(ciphertext_chunk)
        return self

    async def aupdate(self, payload):
        """
        This method is overwritten with the propper functionality when a
        cipher mode is declared with either the `for_encryption` or
        `for_decryption` methods. This interface helps use the object
        correctly.
        """
        raise PermissionError(self._NO_CIPHER_MODE_DECLARED)

    def update(self, payload):
        """
        This method is overwritten with the propper functionality when a
        cipher mode is declared with either the `for_encryption` or
        `for_decryption` methods. This interface helps use the object
        correctly.
        """
        raise PermissionError(self._NO_CIPHER_MODE_DECLARED)

    async def _aget_block_id_mac(self):
        """
        Returns a correct mac digest considering that during encryption
        the instance is updated before the block id is generated, & it
        must be checked by an instance during decryption before being
        updated.
        """
        if self.mode == self._ENCRYPTION:
            return self._last_mac
        elif self.mode == self._DECRYPTION:
            return self._mac.digest()
        else:
            raise PermissionError(self._NO_CIPHER_MODE_DECLARED)

    def _get_block_id_mac(self):
        """
        Returns a correct mac digest considering that during encryption
        the instance is updated before the block id is generated, & it
        must be checked by an instance during decryption before being
        updated.
        """
        if self.mode == self._ENCRYPTION:
            return self._last_mac
        elif self.mode == self._DECRYPTION:
            return self._mac.digest()
        else:
            raise PermissionError(self._NO_CIPHER_MODE_DECLARED)

    async def anext_block_id(self, next_block, *, size=16):
        """
        Returns a ``size``-byte block id the instance derives from its
        current state & the supplied ``next_block`` chunk of ciphertext.
        These block ids can be used to detect out-of-order messages, as
        well as ciphertext forgeries, without altering the instance's
        internal state. This allows for robust decryption of ciphertext
        streams & mitigates adversarial attempts to crash communication
        channels.

        Usage Example (Encryption): # when the `key` & `pid` are already
                                    # shared
        import aiootp

        pad = aiootp.Chunky2048(key)
        salt = await aiootp.agenerate_salt()
        pid = await aiootp.asha_256("known additional data")
        hmac = pad.StreamHMAC(salt=salt, pid=pid).for_encryption()

        plaintext = b"some data to be encrypted..."
        datastream = pad.aplaintext_stream(plaintext, salt=salt, pid=pid)
        cipherstream = datastream.abytes_encipher(
            key=pad.key, salt=salt, pid=pid, validator=hmac
        )

        first_block = await cipherstream()
        yield salt, hmac.siv
        yield first_block, await hmac.anext_block_id(first_block)
        async for block in cipherstream:
            yield block, hmac.next_block_id(block)


        Usage Example (Decryption): # when the `key` & `pid` are already
                                    # shared
        import aiootp

        pad = aiootp.Chunky2048(key)
        pid = await aiootp.asha_256("known additional data")
        stream = aiootp.Enumerate(internet.receiving_stream())
        salt, siv = await stream.asend(None)
        hmac = pad.StreamHMAC(salt=salt, pid=pid, siv=siv).for_decryption()

        ciphertext = []
        deciphering = aiootp.aunpack(ciphertext).abytes_decipher(
            key, salt=salt, pid=pid, validator=hmac
        )

        padded_plaintext = b""
        async for index, (ciphertext_block, block_id) in stream:
            while True:
                try:
                    # Throws if the block_id doesn't validate the ciphertext
                    await hmac.atest_next_block_id(block_id, ciphertext_block)
                    break
                except ValueError:
                    internet.ask_peer_to_resend(index)
            ciphertext.append(ciphertext_block)
            plaintext_block = await deciphering()
            padded_plaintext += plaintext_block

        plaintext = await pad.io.adepad_plaintext(
            padded_plaintext,
            padding_key=await pad.apadding_key(salt=salt, pid=pid),
        )
        """
        await asleep(0)
        domain = Domains.BLOCK_ID
        id_size = size.to_bytes(4, "big")
        blocksize = len(next_block).to_bytes(4, "big")
        key = id_size + blocksize + self._encoded_key
        mac = id_size + blocksize + 2 * self._get_block_id_mac()
        block_id = self._type(domain + key + mac + next_block)
        return block_id.digest()[:size]

    def next_block_id(self, next_block, *, size=16):
        """
        Returns a ``size``-byte block id the instance derives from its
        current state & the supplied ``next_block`` chunk of ciphertext.
        These block ids can be used to detect out-of-order messages, as
        well as ciphertext forgeries, without altering the instance's
        internal state. This allows for robust decryption of ciphertext
        streams & mitigates adversarial attempts to crash communication
        channels.

        Usage Example (Encryption): # when the `key` & `pid` are already
                                    # shared
        import aiootp

        pad = aiootp.Chunky2048(key)
        salt = aiootp.generate_salt()
        pid = aiootp.sha_256("known additional data")
        hmac = pad.StreamHMAC(salt=salt, pid=pid).for_encryption()

        plaintext = b"some data to be encrypted..."
        datastream = pad.plaintext_stream(plaintext, salt=salt, pid=pid)
        cipherstream = datastream.bytes_encipher(
            key=pad.key, salt=salt, pid=pid, validator=hmac
        )

        first_block = cipherstream()
        yield salt, hmac.siv
        yield first_block, hmac.next_block_id(first_block)
        for block in cipherstream:
            yield block, hmac.next_block_id(block)


        Usage Example (Decryption): # when the `key` & `pid` are already
                                    # shared
        import aiootp

        pad = aiootp.Chunky2048(key)
        stream = internet.receiving_stream()
        salt, siv = stream.send(None)
        pid = aiootp.sha_256("known additional data")
        hmac = pad.StreamHMAC(salt=salt, pid=pid, siv=siv).for_decryption()

        ciphertext = []
        deciphering = aiootp.unpack(ciphertext).bytes_decipher(
            key, salt=salt, pid=pid, validator=hmac
        )

        padded_plaintext = b""
        for index, (ciphertext_block, block_id) in enumerate(stream):
            try:
                # Throws if the block_id doesn't validate the ciphertext
                hmac.test_next_block_id(block_id, ciphertext_block)
                ciphertext.append(ciphertext_block)
                plaintext_block = deciphering()
                padded_plaintext += plaintext_block
            except ValueError:
                internet.ask_peer_to_resend(index)

        plaintext = pad.io.depad_plaintext(
            padded_plaintext,
            padding_key=pad.padding_key(salt=salt, pid=pid),
        )
        """
        domain = Domains.BLOCK_ID
        id_size = size.to_bytes(4, "big")
        blocksize = len(next_block).to_bytes(4, "big")
        key = id_size + blocksize + self._encoded_key
        mac = id_size + blocksize + 2 * self._get_block_id_mac()
        block_id = self._type(domain + key + mac + next_block)
        return block_id.digest()[:size]

    async def _acurrent_digest(self, *, obj=_type):
        """
        Returns a secure, 32-byte, domain-specific digest by default,
        which authenticates the ciphertext up to the current point of
        execution of the StreamHMAC algorithm.
        """
        await asleep(0)
        domain = Domains.DIGEST
        key = self._encoded_key
        payload = await self._ablock_count() + self._mac.digest()
        return obj(domain + key + payload + domain).digest()

    def _current_digest(self, *, obj=_type):
        """
        Returns a secure, 32-byte domain-specific digest by default,
        which authenticates the ciphertext up to the current point of
        execution of the StreamHMAC algorithm.
        """
        domain = Domains.DIGEST
        key = self._encoded_key
        payload = self._block_count() + self._mac.digest()
        return obj(domain + key + payload + domain).digest()

    async def acurrent_digest(self, *, obj=_type):
        """
        Returns a secure digest that authenticates the ciphertext up to
        the current point of execution of the StreamHMAC algorithm. It
        incorporates the number of blocks of ciphertext blocks processed,
        the encoded key derived from the user's key, salt, & pid, as
        well as the hashing object's current digest.

        Usage Example (Encryption): # when the `key` & `pid` are already
                                    # shared
        import aiootp

        key = await aiootp.acsprng()
        salt = await aiootp.agenerate_salt()
        pid = aiootp.sha_256("known additional data")
        hmac = aiootp.StreamHMAC(key, salt=salt, pid=pid).for_encryption()

        plaintext = b"some data to be encrypted"
        datastream = aiootp.aplaintext_stream(
            plaintext, key, salt=salt, pid=pid
        )
        cipherstream = datastream.abytes_encipher(
            key, salt=salt, pid=pid, validator=hmac
        )

        first_block = await cipherstream()
        yield salt, hmac.siv
        yield first_block, await hmac.acurrent_digest()
        while True:
            yield await cipherstream(), await hmac.acurrent_digest()


        Usage Example (Decryption): # when the `key` & `pid` are already
                                    # shared
        import aiootp

        pad = aiootp.Chunky2048(key)
        pid = aiootp.sha_256("known additional data")
        stream = internet.receiving_stream()
        salt, siv = await stream.asend(None)
        hmac = pad.StreamHMAC(salt=salt, pid=pid, siv=siv).for_decryption()

        ciphertext = []
        deciphering = aiootp.aunpack(ciphertext).abytes_decipher(
            key, salt=salt, pid=pid, validator=hmac
        )

        padded_plaintext = b""
        async for chunk, mac in stream:
            ciphertext.append(chunk)
            plaintext_chunk = await deciphering()
            await hmac.atest_current_digest(mac)
            padded_plaintext += plaintext_chunk

        plaintext = await pad.io.adepad_plaintext(
            padded_plaintext,
            padding_key=await pad.apadding_key(salt=salt, pid=pid),
        )
        """
        await asleep(0)
        if self._result_is_ready:
            raise PermissionError(self._USE_FINAL_RESULT)
        return await self._acurrent_digest(obj=obj)

    def current_digest(self, *, obj=_type):
        """
        Returns a secure digest that authenticates the ciphertext up to
        the current point of execution of the StreamHMAC algorithm. It
        incorporates the number of blocks of ciphertext blocks processed,
        the encoded key derived from the user's key, salt, & pid, as
        well as the hashing object's current digest.

        Usage Example (Encryption): # when the `key` & `pid` are already
                                    # shared
        import aiootp

        key = aiootp.csprng()
        salt = aiootp.generate_salt()
        pid = aiootp.sha_256("known additional data")
        hmac = aiootp.StreamHMAC(key, salt=salt, pid=pid).for_encryption()

        plaintext = b"some data to be encrypted"
        datastream = aiootp.plaintext_stream(
            plaintext, key, salt=salt, pid=pid
        )
        cipherstream = datastream.bytes_encipher(
            key, salt=salt, pid=pid, validator=hmac
        )

        first_block = cipherstream()
        yield salt, hmac.siv
        yield first_block, hmac.current_digest()
        while True:
            yield cipherstream(), hmac.current_digest()


        Usage Example (Decryption): # when the `key` & `pid` are already
                                    # shared
        import aiootp

        pad = aiootp.Chunky2048(key)
        pid = aiootp.sha_256("known additional data")
        stream = internet.receiving_stream()
        salt, siv = stream.send(None)
        hmac = pad.StreamHMAC(salt=salt, pid=pid, siv=siv).for_decryption()

        ciphertext = []
        deciphering = aiootp.unpack(ciphertext).bytes_decipher(
            key, salt=salt, pid=pid, validator=hmac
        )

        padded_plaintext = b""
        for chunk, mac in stream:
            ciphertext.append(chunk)
            plaintext_chunk = deciphering()
            hmac.test_current_digest(mac)
            padded_plaintext += plaintext_chunk

        plaintext = pad.io.depad_plaintext(
            padded_plaintext,
            padding_key=pad.padding_key(salt=salt, pid=pid),
        )
        """
        if self._result_is_ready:
            raise PermissionError(self._USE_FINAL_RESULT)
        return self._current_digest(obj=obj)

    async def _axor_then_hash(self, data_chunk, key_chunk):
        """
        This method is inserted as the instance's `validated_xor` method
        after the user chooses the encryption mode. The mode is chosen
        by calling the `for_encryption` method. It receives a plaintext
        & key chunk, xors them into a 256 byte ciphertext block, then
        is used to update the instance's validation hash object.
        """
        try:
            ciphertext_chunk = data_chunk ^ key_chunk
            self.update(ciphertext_chunk.to_bytes(256, "big"))
            return ciphertext_chunk
        except OverflowError:
            raise ValueError(self._EXCEEDED_BLOCKSIZE)

    def _xor_then_hash(self, data_chunk, key_chunk):
        """
        This method is inserted as the instance's `validated_xor` method
        after the user chooses the encryption mode. The mode is chosen
        by calling the `for_encryption` method. It receives a plaintext
        & key chunk, xors them into a 256 byte ciphertext block, then
        is used to update the instance's validation hash object.
        """
        try:
            ciphertext_chunk = data_chunk ^ key_chunk
            self.update(ciphertext_chunk.to_bytes(256, "big"))
            return ciphertext_chunk
        except OverflowError:
            raise ValueError(self._EXCEEDED_BLOCKSIZE)

    async def _ahash_then_xor(self, ciphertext_chunk, key_chunk):
        """
        This method is inserted as the instance's `validated_xor` method
        after the user chooses the decryption mode. The mode is chosen
        by calling the `for_decryption` method. It receives a ciphertext
        & key chunk, uses the ciphertext to update the instance's
        validation hash object, then returns the 256 byte xor of the
        chunks.
        """
        try:
            self.update(ciphertext_chunk.to_bytes(256, "big"))
            return ciphertext_chunk ^ key_chunk
        except OverflowError:
            raise ValueError(self._EXCEEDED_BLOCKSIZE)

    def _hash_then_xor(self, ciphertext_chunk, key_chunk):
        """
        This method is inserted as the instance's `validated_xor` method
        after the user chooses the decryption mode. The mode is chosen
        by calling the `for_decryption` method. It receives a ciphertext
        & key chunk, uses the ciphertext to update the instance's
        validation hash object, then returns the 256 byte xor of the
        chunks.
        """
        try:
            self.update(ciphertext_chunk.to_bytes(256, "big"))
            return ciphertext_chunk ^ key_chunk
        except OverflowError:
            raise ValueError(self._EXCEEDED_BLOCKSIZE)

    async def avalidated_xor(self, *a, **kw):
        """
        A method which is defined when the mode for the validator is
        specified by the user by using either of the following methods:

        `for_encryption`:   Instructs this method to first xor the key
            chunks with the plaintext chunks prior to hashing the result
            with the mac object.
        `for_decryption`:   Instructs this method to first hash the
            ciphertext chunks prior to revealing the plaintext by xoring
            them with the key chunks.
        """
        raise PermissionError(self._NO_CIPHER_MODE_DECLARED)

    def validated_xor(self, *a, **kw):
        """
        A method which is defined when the mode for the validator is
        specified by the user by using either of the following methods:

        `for_encryption`:   Instructs this method to first xor the key
            chunks with the plaintext chunks prior to hashing the result
            with the mac object.
        `for_decryption`:   Instructs this method to first hash the
            ciphertext chunks prior to revealing the plaintext by xoring
            them with the key chunks.
        """
        raise PermissionError(self._NO_CIPHER_MODE_DECLARED)

    async def _aset_final_result(self):
        """
        Caps off the instance's validation hash object with a secure &
        keyed current digest, & populates the instance's final result
        with the keyed hash of the resulting digest. This signals the
        end of a stream of data that can be validated with the current
        instance.
        """
        await asleep(0)
        self._mac.update(self._encoded_key)
        domain = Domains.SHMAC
        key = self._encoded_key
        count = await self._ablock_count()
        mac = 2 * self._mac.digest()
        self._result = self._type(domain + key + count + mac).digest()

    def _set_final_result(self):
        """
        Caps off the instance's validation hash object with a secure &
        keyed current digest, & populates the instance's final result
        with the keyed hash of the resulting digest. This signals the
        end of a stream of data that can be validated with the current
        instance.
        """
        self._mac.update(self._encoded_key)
        domain = Domains.SHMAC
        key = self._encoded_key
        count = self._block_count()
        mac = 2 * self._mac.digest()
        self._result = self._type(domain + key + count + mac).digest()

    async def afinalize(self):
        """
        Caps off the instance's validation hash object with a secure &
        keyed current digest, then populates & returns the instance's
        final result which is the keyed hash of the resulting digest.
        This signals the end of a stream of data that can be validated
        with the current instance.
        """
        if self._finalized:
            raise PermissionError(self._ALREADY_FINALIZED)
        self._finalized = True
        await self._aset_final_result()
        self._result_is_ready = True
        del self.__mac
        return self._result

    def finalize(self):
        """
        Caps off the instance's validation hash object with a secure &
        keyed current digest, then populates & returns the instance's
        final result which is the keyed hash of the resulting digest.
        This signals the end of a stream of data that can be validated
        with the current instance.
        """
        if self._finalized:
            raise PermissionError(self._ALREADY_FINALIZED)
        self._finalized = True
        self._set_final_result()
        self._result_is_ready = True
        del self.__mac
        return self._result

    async def aresult(self):
        """
        Returns the instance's final result which is the secure HMAC of
        the ciphertext that was processed through the instance.
        """
        if not self._finalized or not self._result_is_ready:
            raise PermissionError(self._VALIDATION_INCOMPLETE)
        return self._result

    def result(self):
        """
        Returns the instance's final result which is the secure HMAC of
        the ciphertext that was processed through the instance.
        """
        if not self._finalized or not self._result_is_ready:
            raise PermissionError(self._VALIDATION_INCOMPLETE)
        return self._result

    async def atest_next_block_id(self, untrusted_block_id, next_block):
        """
        Does a non-constant-time, but instead, a safe randomized-time
        comparison of a supplied ``untrusted_block_id`` with a block id
        that the instance derives from it's current state & the supplied
        ``next_block`` chunk of ciphertext. Raises `ValueError` if the
        untrusted block id is invalid. These block id checks can detect
        out of order messages or ciphertext forgeries without altering
        the instance's internal state. This allows for robust decryption
        of ciphertext streams & mitigates adversarial attempts to crash
        a communication channel.
        """
        if not issubclass(untrusted_block_id.__class__, bytes):
            raise TypeError(self._UNTRUSTED_BLOCK_ID_ISNT_BYTES)
        key = self._encoded_key.hex()
        size = len(untrusted_block_id)
        block_id = await self.anext_block_id(next_block, size=size)
        ids = (untrusted_block_id, block_id)
        if await atime_safe_equality(*ids, key=key):
            return True
        else:
            raise ValueError(self._INVALID_BLOCK_ID)

    def test_next_block_id(self, untrusted_block_id, next_block):
        """
        Does a non-constant-time, but instead, a safe randomized-time
        comparison of a supplied ``untrusted_block_id`` with a block id
        that the instance derives from it's current state & the supplied
        ``next_block`` chunk of ciphertext. Raises `ValueError` if the
        untrusted block id is invalid. These block id checks can detect
        out of order messages or ciphertext forgeries without altering
        the instance's internal state. This allows for robust decryption
        of ciphertext streams & mitigates adversarial attempts to crash
        a communication channel.
        """
        if not issubclass(untrusted_block_id.__class__, bytes):
            raise TypeError(self._UNTRUSTED_BLOCK_ID_ISNT_BYTES)
        key = self._encoded_key.hex()
        size = len(untrusted_block_id)
        block_id = self.next_block_id(next_block, size=size)
        ids = (untrusted_block_id, block_id)
        if time_safe_equality(*ids, key=key):
            return True
        else:
            raise ValueError(self._INVALID_BLOCK_ID)

    async def atest_current_digest(self, untrusted_digest):
        """
        Does a non-constant-time, but instead a safe randomized-time
        comparison of a supplied ``untrusted_digest`` with the output
        of the instance's current digest of an unfinished stream of
        ciphertext. Raises `ValueError` if the instance's current digest
        doesn't match.
        """
        if not issubclass(untrusted_digest.__class__, bytes):
            raise TypeError(self._UNTRUSTED_DIGEST_ISNT_BYTES)
        key = self._encoded_key.hex()
        digests = (untrusted_digest, await self.acurrent_digest())
        if await atime_safe_equality(*digests, key=key):
            return True
        else:
            raise ValueError(self._INVALID_DIGEST)

    def test_current_digest(self, untrusted_digest):
        """
        Does a non-constant-time, but instead a safe randomized-time
        comparison of a supplied ``untrusted_digest`` with the output
        of the instance's current digest of an unfinished stream of
        ciphertext. Raises `ValueError` if the instance's current digest
        doesn't match.
        """
        if not issubclass(untrusted_digest.__class__, bytes):
            raise TypeError(self._UNTRUSTED_DIGEST_ISNT_BYTES)
        key = self._encoded_key.hex()
        digests = (untrusted_digest, self.current_digest())
        if time_safe_equality(*digests, key=key):
            return True
        else:
            raise ValueError(self._INVALID_DIGEST)

    async def atest_hmac(self, untrusted_hmac):
        """
        Does a non-constant-time, but instead a safe randomized-time
        comparison of a supplied ``untrusted_hmac`` with the instance's
        final result hmac. Raises `ValueError` if the hmac doesn't match.
        """
        if not issubclass(untrusted_hmac.__class__, bytes):
            raise TypeError(self._UNTRUSTED_HMAC_ISNT_BYTES)
        key = self._encoded_key.hex()
        hmacs = (untrusted_hmac, await self.aresult())
        if await atime_safe_equality(*hmacs, key=key):
            return True
        else:
            raise ValueError(self._INVALID_HMAC)

    def test_hmac(self, untrusted_hmac):
        """
        Does a non-constant-time, but instead a safe randomized-time
        comparison of a supplied ``untrusted_hmac`` with the instance's
        final result hmac. Raises `ValueError` if the hmac doesn't match.
        """
        if not issubclass(untrusted_hmac.__class__, bytes):
            raise TypeError(self._UNTRUSTED_HMAC_ISNT_BYTES)
        key = self._encoded_key.hex()
        hmacs = (untrusted_hmac, self.result())
        if time_safe_equality(*hmacs, key=key):
            return True
        else:
            raise ValueError(self._INVALID_HMAC)


class SyntheticIV:
    """
    Manages the derivation & application of synthetic IVs which improve
    the salt reuse / misuse resistance of the package's online-offline
    AEAD cipher. This class is handled automatically within the xor
    generators & the `StreamHMAC` class.
    """
    _DECRYPTION = DECRYPTION
    _ENCRYPTION = ENCRYPTION
    _BLOCKSIZE = BLOCKSIZE
    _SIV_BYTES = SIV_BYTES
    _SIV_NIBBLES = SIV_NIBBLES
    _SIV_KEY_BYTES = SIV_KEY_BYTES
    _SIV_KEY_NIBBLES = SIV_KEY_NIBBLES

    @staticmethod
    def _int(key):
        """
        Converts a bytes or hex sequence into an integer.
        """
        if key.__class__ == bytes:
            return int.from_bytes(key, "big")
        else:
            return int(key, 16)

    @classmethod
    async def amake_siv(cls, plaintext_block, validator):
        """
        Returns a 16-byte, truncated hexidecimal keyed-hash of a
        plaintext block to be used as a synthetic IV to improve the salt
        reuse / misuse resistance of a stream of key material.
        """
        try:
            await asleep(0)
            return sha3_256(
                Domains.SIV
                + Domains.SIV_KEY
                + validator._encoded_key
                + validator._mac.digest()
                + plaintext_block.to_bytes(cls._BLOCKSIZE, "big")
            ).hexdigest()[:cls._SIV_NIBBLES]
        except OverflowError:
            raise ValueError(EXCEEDED_BLOCKSIZE)

    @classmethod
    def make_siv(cls, plaintext_block, validator):
        """
        Returns a 16-byte, truncated hexidecimal keyed-hash of a
        plaintext block to be used as a synthetic IV to improve the salt
        reuse / misuse resistance of a stream of key material.
        """
        try:
            return sha3_256(
                Domains.SIV
                + Domains.SIV_KEY
                + validator._encoded_key
                + validator._mac.digest()
                + plaintext_block.to_bytes(cls._BLOCKSIZE, "big")
            ).hexdigest()[:cls._SIV_NIBBLES]
        except OverflowError:
            raise ValueError(EXCEEDED_BLOCKSIZE)

    @classmethod
    async def avalidated_xor(cls, datastream, keystream, validator):
        """
        Derives the synthetic IV from the beginning of the plaintext &
        seeds it into both the keystream & the validator.

        This method ciphers/deciphers the first block of plaintext/
        ciphertext depending on whether the validator has been set to
        encryption or decryption modes. It feeds a syncthetic IV value,
        which is derived from the keyed-hash of the first block of
        plaintext & is attached to the ciphertext, into the keystream
        coroutine prior to xoring the first block. This improves the
        cipher's salt reuse/misuse resistance since if either the first
        232 bytes of plaintext are unique, or the 24-byte inner header
        is unique, then the entire stream of key material will be unique.
        The inner header is prepended to the first plaintext block, &
        consists of an 8-byte timestamp & an 16-byte random & ephemeral
        SIV-key.
        """
        try:
            await keystream(None)  # prime the keystream
            first_block = await datastream.asend(None)
        except StopAsyncIteration:
            raise ValueError(STREAM_IS_EMPTY)
        if validator.mode == cls._ENCRYPTION:
            siv = await cls.amake_siv(first_block, validator)
            validator.siv = siv
        else:
            siv = validator.siv
        key_chunk = cls._int(await keystream(siv) + await keystream(siv))
        return await validator.avalidated_xor(first_block, key_chunk)

    @classmethod
    def validated_xor(cls, datastream, keystream, validator):
        """
        Derives the synthetic IV from the beginning of the plaintext &
        seeds it into both the keystream & the validator.

        This method ciphers/deciphers the first block of plaintext/
        ciphertext depending on whether the validator has been set to
        encryption or decryption modes. It feeds a syncthetic IV value,
        which is derived from the keyed-hash of the first block of
        plaintext & is attached to the ciphertext, into the keystream
        coroutine prior to xoring the first block. This improves the
        cipher's salt reuse/misuse resistance since if either the first
        232 bytes of plaintext are unique, or the 24-byte inner header
        is unique, then the entire stream of key material will be unique.
        The inner header is prepended to the first plaintext block, &
        consists of an 8-byte timestamp & an 16-byte random & ephemeral
        SIV-key.
        """
        try:
            keystream(None)  # prime the keystream
            first_block = datastream.send(None)
        except StopIteration:
            raise ValueError(STREAM_IS_EMPTY)
        if validator.mode == cls._ENCRYPTION:
            siv = cls.make_siv(first_block, validator)
            validator.siv = siv
        else:
            siv = validator.siv
        key_chunk = cls._int(keystream(siv) + keystream(siv))
        return validator.validated_xor(first_block, key_chunk)


async def axor_shortcuts(data, key, validator):
    """
    Returns a series of function pointers & a datastream generator that
    are used within the pseudo-one-time-pad xor coroutines. This is done
    to improve readability & the efficiency of the ciphers execution
    time.
    """
    return (
        aunpack.root(data),
        key.asend,
        validator.avalidated_xor,
        validator._mac.hexdigest,
    )


def xor_shortcuts(data, key, validator):
    """
    Returns a series of function pointers & a datastream generator that
    are used within the pseudo-one-time-pad xor coroutines. This is done
    to improve readability & the efficiency of the ciphers execution
    time.
    """
    return (
        unpack.root(data),
        key.send,
        validator.validated_xor,
        validator._mac.hexdigest,
    )


@comprehension()
async def axor(data, *, key, validator):
    """
    'Chunky2048' - an online MRAE / AEAD pseudo-one-time-pad cipher
    implementation.

    Gathers both an iterable of 256-byte integers of ``data``, & a
    non-repeating generator of deterministic hex string ``key`` material,
    then bitwise xors the streams together producing pseudo-one-time-pad
    ciphertext chunks 256 bytes long. The keystream MUST produce 128-
    bytes of hexidecimal string key material each iteration, as each
    output is paired with another to reach exactly 256 pseudo-random
    bytes for each cipher block.

    Restricting the ciphertext to a distinct size is a measure to
    protect the metadata of plaintext from adversaries that could make
    informed guesses of the plaintext given accurate sizes of its
    chunks. Also, this allows for the deterministic & reversible
    construction of bytestreams of ciphertext.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes or
    less per iteration or security WILL BE BROKEN by directly leaking
    plaintext. The plaintext MUST be padded using the `Padding` class in
    order to add salt reuse / misuse resistance (MRAE) to the cipher.

    WARNING: ``key`` MUST produce key chunks of exactly 256 hexidecimal
    characters per iteration or security WILL BE BROKEN by directly
    leaking plaintext.
    """
    datastream, keystream, validated_xor, hmac_hexdigest = (
        await axor_shortcuts(data, key, validator)
    )
    yield await SyntheticIV.avalidated_xor(datastream, keystream, validator)
    async for chunk in datastream:
        seed = hmac_hexdigest()
        key_chunk = int(await keystream(seed) + await keystream(seed), 16)
        result = await validated_xor(chunk, key_chunk)
        if result >> 2048:
            raise ValueError(EXCEEDED_BLOCKSIZE)
        yield result


@comprehension()
def xor(data, *, key, validator):
    """
    'Chunky2048' - an online MRAE / AEAD pseudo-one-time-pad cipher
    implementation.

    Gathers both an iterable of 256-byte integers of ``data``, & a
    non-repeating generator of deterministic hex string ``key`` material,
    then bitwise xors the streams together producing pseudo-one-time-pad
    ciphertext chunks 256 bytes long. The keystream MUST produce 128-
    bytes of hexidecimal string key material each iteration, as each
    output is paired with another to reach exactly 256 pseudo-random
    bytes for each cipher block.

    Restricting the ciphertext to a distinct size is a measure to
    protect the metadata of plaintext from adversaries that could make
    informed guesses of the plaintext given accurate sizes of its
    chunks. Also, this allows for the deterministic & reversible
    construction of bytestreams of ciphertext.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes or
    less per iteration or security WILL BE BROKEN by directly leaking
    plaintext. The plaintext MUST be padded using the `Padding` class in
    order to add salt reuse / misuse resistance (MRAE) to the cipher.

    WARNING: ``key`` MUST produce key chunks of exactly 256 hexidecimal
    characters per iteration or security WILL BE BROKEN by directly
    leaking plaintext.
    """
    datastream, keystream, validated_xor, hmac_hexdigest = xor_shortcuts(
        data, key, validator
    )
    yield SyntheticIV.validated_xor(datastream, keystream, validator)
    for chunk in datastream:
        seed = hmac_hexdigest()
        key_chunk = int(keystream(seed) + keystream(seed), 16)
        result = validated_xor(chunk, key_chunk)
        if result >> 2048:
            raise ValueError(EXCEEDED_BLOCKSIZE)
        yield result


@comprehension()
async def abytes_xor(data, *, key, validator):
    """
    'Chunky2048' - an online MRAE / AEAD pseudo-one-time-pad cipher
    implementation.

    Gathers both an iterable of 256-byte integers of ``data``, & a
    non-repeating generator of deterministic bytes ``key`` material,
    then bitwise xors the streams together producing pseudo-one-time-pad
    ciphertext chunks 256 bytes long. The keystream MUST produce 128-
    bytes of bytes type key material each iteration, as each output is
    paired with another to reach exactly 256 pseudo-random bytes for
    each cipher block.

    Restricting the ciphertext to a distinct size is a measure to
    protect the metadata of plaintext from adversaries that could make
    informed guesses of the plaintext given accurate sizes of its
    chunks. Also, this allows for the deterministic & reversible
    construction of bytestreams of ciphertext.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes or
    less per iteration or security WILL BE BROKEN by directly leaking
    plaintext. The plaintext MUST be padded using the `Padding` class in
    order to add salt reuse / misuse resistance (MRAE) to the cipher.

    WARNING: ``key`` MUST produce key chunks of exactly 128 bytes per
    iteration or security WILL BE BROKEN by directly leaking plaintext.
    """
    as_int = int.from_bytes
    datastream, keystream, validated_xor, hmac_hexdigest = (
        await axor_shortcuts(data, key, validator)
    )
    yield await SyntheticIV.avalidated_xor(datastream, keystream, validator)
    async for chunk in datastream:
        seed = hmac_hexdigest()
        key_chunk = as_int(
            await keystream(seed) + await keystream(seed), "big"
        )
        result = await validated_xor(chunk, key_chunk)
        if result >> 2048:
            raise ValueError(EXCEEDED_BLOCKSIZE)
        yield result


@comprehension()
def bytes_xor(data, *, key, validator):
    """
    'Chunky2048' - an online MRAE / AEAD pseudo-one-time-pad cipher
    implementation.

    Gathers both an iterable of 256-byte integers of ``data``, & a
    non-repeating generator of deterministic bytes ``key`` material,
    then bitwise xors the streams together producing pseudo-one-time-pad
    ciphertext chunks 256 bytes long. The keystream MUST produce 128-
    bytes of bytes type key material each iteration, as each output is
    paired with another to reach exactly 256 pseudo-random bytes for
    each cipher block.

    Restricting the ciphertext to a distinct size is a measure to
    protect the metadata of plaintext from adversaries that could make
    informed guesses of the plaintext given accurate sizes of its
    chunks. Also, this allows for the deterministic & reversible
    construction of bytestreams of ciphertext.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes or
    less per iteration or security WILL BE BROKEN by directly leaking
    plaintext. The plaintext MUST be padded using the `Padding` class in
    order to add salt reuse / misuse resistance (MRAE) to the cipher.

    WARNING: ``key`` MUST produce key chunks of exactly 128 bytes per
    iteration or security WILL BE BROKEN by directly leaking plaintext.
    """
    as_int = int.from_bytes
    datastream, keystream, validated_xor, hmac_hexdigest = xor_shortcuts(
        data, key, validator
    )
    yield SyntheticIV.validated_xor(datastream, keystream, validator)
    for chunk in datastream:
        seed = hmac_hexdigest()
        key_chunk = as_int(keystream(seed) + keystream(seed), "big")
        result = validated_xor(chunk, key_chunk)
        if result >> 2048:
            raise ValueError(EXCEEDED_BLOCKSIZE)
        yield result


async def akeypair_ratchets(key, salt, pid=0):
    """
    Returns a 512-bit seed value & three ``hashlib.sha3_512`` objects
    that have been primed in different ways with the hash of the values
    passed in as arguments to the function. The returned values can be
    used to construct a keypair ratchet algorithm of the user's choosing.
    """
    domain = Domains.CHUNKY_2048
    _bytes = bytes.fromhex
    seed_0 = _bytes(await asha_512(domain.hex(), key, salt, pid))
    seed_1 = _bytes(await asha_512(domain.hex(), seed_0, key, salt, pid))
    seed_kdf = sha3_512(domain + seed_1 + seed_0)
    left_kdf = sha3_512(domain + seed_kdf.digest() + seed_0)
    right_kdf = sha3_512(domain + left_kdf.digest() + seed_0)
    return seed_1, seed_kdf, left_kdf, right_kdf


def keypair_ratchets(key, salt, pid=0):
    """
    Returns a 512-bit seed value & three ``hashlib.sha3_512`` objects
    that have been primed in different ways with the hash of the values
    passed in as arguments to the function. The returned values can be
    used to construct a keypair ratchet algorithm of the user's choosing.
    """
    domain = Domains.CHUNKY_2048
    seed_0 = bytes.fromhex(sha_512(domain.hex(), key, salt, pid))
    seed_1 = bytes.fromhex(sha_512(domain.hex(), seed_0, key, salt, pid))
    seed_kdf = sha3_512(domain + seed_1 + seed_0)
    left_kdf = sha3_512(domain + seed_kdf.digest() + seed_0)
    right_kdf = sha3_512(domain + left_kdf.digest() + seed_0)
    return seed_1, seed_kdf, left_kdf, right_kdf


@comprehension()
async def akeys(key=csprng(), *, salt=None, pid=0):
    """
    An efficient async generator which produces an unending, non-
    repeating, deterministic stream of string key material.

    Each iteration yields 256 hex characters, iteratively derived by the
    mixing & hashing of the permutation of the kwargs, previous hashed
    results, & the ``entropy`` users may send into this generator as a
    coroutine.

    The ``key`` kwarg is meant to be a longer-term user key credential
    (should be a random 512-bit hex value), the ``salt`` kwarg is meant
    to be ephemeral to each stream (by default a random 256-bit hex
    value), & the user-defined ``pid`` can be used to safely parallelize
    keystreams with the same ``key`` & ``salt`` by specifying a unique
    ``pid`` to each process, thread or the like, which will result in a
    unique keystream for each. Since this value is now verified during
    ciphertext authentication, it can also be used to verify arbitrary
    additional data.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    salt = salt if salt else await agenerate_salt()
    seed, seed_kdf, left_kdf, right_kdf = await akeypair_ratchets(
        key, salt, pid
    )
    async with Comprende.aclass_relay(salt):
        while True:
            await asleep(0)
            ratchet = seed_kdf.digest()
            left_kdf.update(LEFT_PAD + ratchet)  # update with 72-bytes
            right_kdf.update(RIGHT_PAD + ratchet)  # update with 72-bytes
            entropy = yield left_kdf.hexdigest() + right_kdf.hexdigest()
            seed_kdf.update(str(entropy).encode() + ratchet + seed)


@comprehension()
def keys(key=csprng(), *, salt=None, pid=0):
    """
    An efficient sync generator which produces an unending, non-
    repeating, deterministic stream of string key material.

    Each iteration yields 256 hex characters, iteratively derived by the
    mixing & hashing of the permutation of the kwargs, previous hashed
    results, & the ``entropy`` users may send into this generator as a
    coroutine.

    The ``key`` kwarg is meant to be a longer-term user key credential
    (should be a random 512-bit hex value), the ``salt`` kwarg is meant
    to be ephemeral to each stream (by default a random 256-bit hex
    value), & the user-defined ``pid`` can be used to safely parallelize
    keystreams with the same ``key`` & ``salt`` by specifying a unique
    ``pid`` to each process, thread or the like, which will result in a
    unique keystream for each. Since this value is now verified during
    ciphertext authentication, it can also be used to verify arbitrary
    additional data.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    salt = salt if salt else generate_salt()
    seed, seed_kdf, left_kdf, right_kdf = keypair_ratchets(key, salt, pid)
    with Comprende.class_relay(salt):
        while True:
            ratchet = seed_kdf.digest()
            left_kdf.update(LEFT_PAD + ratchet)  # update with 72-bytes
            right_kdf.update(RIGHT_PAD + ratchet)  # update with 72-bytes
            entropy = yield left_kdf.hexdigest() + right_kdf.hexdigest()
            seed_kdf.update(str(entropy).encode() + ratchet + seed)


@comprehension()
async def abytes_keys(key=csprng(), *, salt=None, pid=0):
    """
    An efficient async generator which produces an unending, non-
    repeating, deterministic stream of bytes key material.

    Each iteration yields 128 bytes, iteratively derived by the mixing &
    hashing of the permutation of the kwargs, previous hashed results, &
    the ``entropy`` users may send into this generator as a coroutine.

    The ``key`` kwarg is meant to be a longer-term user key credential
    (should be a random 512-bit hex value), the ``salt`` kwarg is meant
    to be ephemeral to each stream (by default a random 256-bit hex
    value), & the user-defined ``pid`` can be used to safely parallelize
    keystreams with the same ``key`` & ``salt`` by specifying a unique
    ``pid`` to each process, thread or the like, which will result in a
    unique keystream for each. Since this value is now verified during
    ciphertext authentication, it can also be used to verify arbitrary
    additional data.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    salt = salt if salt else await agenerate_salt()
    seed, seed_kdf, left_kdf, right_kdf = await akeypair_ratchets(
        key, salt, pid
    )
    async with Comprende.aclass_relay(salt):
        while True:
            await asleep(0)
            ratchet = seed_kdf.digest()
            left_kdf.update(LEFT_PAD + ratchet)  # update with 72-bytes
            right_kdf.update(RIGHT_PAD + ratchet)  # update with 72-bytes
            entropy = yield left_kdf.digest() + right_kdf.digest()
            seed_kdf.update(str(entropy).encode() + ratchet + seed)


@comprehension()
def bytes_keys(key=csprng(), *, salt=None, pid=0):
    """
    An efficient sync generator which produces an unending, non-
    repeating, deterministic stream of bytes key material.

    Each iteration yields 128 bytes, iteratively derived by the mixing &
    hashing of the permutation of the kwargs, previous hashed results, &
    the ``entropy`` users may send into this generator as a coroutine.

    The ``key`` kwarg is meant to be a longer-term user key credential
    (should be a random 512-bit hex value), the ``salt`` kwarg is meant
    to be ephemeral to each stream (by default a random 256-bit hex
    value), & the user-defined ``pid`` can be used to safely parallelize
    keystreams with the same ``key`` & ``salt`` by specifying a unique
    ``pid`` to each process, thread or the like, which will result in a
    unique keystream for each. Since this value is now verified during
    ciphertext authentication, it can also be used to verify arbitrary
    additional data.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    salt = salt if salt else generate_salt()
    seed, seed_kdf, left_kdf, right_kdf = keypair_ratchets(key, salt, pid)
    with Comprende.class_relay(salt):
        while True:
            ratchet = seed_kdf.digest()
            left_kdf.update(LEFT_PAD + ratchet)  # update with 72-bytes
            right_kdf.update(RIGHT_PAD + ratchet)  # update with 72-bytes
            entropy = yield left_kdf.digest() + right_kdf.digest()
            seed_kdf.update(str(entropy).encode() + ratchet + seed)


async def apadding_key(key, *, salt, pid=0):
    """
    Returns the salted & hashed key used for building the pseudo-random
    bytes that pad plaintext messages.
    """
    await atest_key_and_salt(key, salt)
    domain = Domains.PADDING_KEY.hex()
    return bytes.fromhex(await asha_512(domain, pid, salt, key))


def padding_key(key, *, salt, pid=0):
    """
    Returns the salted & hashed key used for building the pseudo-random
    bytes that pad plaintext messages.
    """
    test_key_and_salt(key, salt)
    domain = Domains.PADDING_KEY.hex()
    return bytes.fromhex(sha_512(domain, pid, salt, key))


@comprehension()
async def aplaintext_stream(data, key, *, salt, pid=0):
    """
    Takes in plaintext bytes ``data``, then pads & yields it in 256-byte
    chunks per iteration. The plaintext padding is done in two separate
    ways:
        First, an 8-byte timestamp & a 16-byte ephemeral SIV-key are
    prepended to the plaintext. This makes the first block, & the SIV
    which is derived from it, globally unique. This allows the cipher to
    be both online & be strongly salt-reuse/misuse resistant, counter to
    the findings in https://eprint.iacr.org/2015/189.pdf.
        Second, the ``key``, ``salt`` & ``pid`` are used to derive some
    pseudo-random padding bytes which are appended to the plaintext.
    This padding bytes make the resulting plaintext a multiple of the
    256-byte blocksize.
    """
    padding_key = await Padding.aderive_key(key, salt=salt, pid=pid)
    plaintext = await Padding.apad_plaintext(data, padding_key=padding_key)
    async for chunk in adata.root(plaintext):
        yield chunk


@comprehension()
def plaintext_stream(data, key, *, salt, pid=0):
    """
    Takes in plaintext bytes ``data``, then pads & yields it in 256-byte
    chunks per iteration. The plaintext padding is done in two separate
    ways:
        First, an 8-byte timestamp & a 16-byte ephemeral SIV-key are
    prepended to the plaintext. This makes the first block, & the SIV
    which is derived from it, globally unique. This allows the cipher to
    be both online & be strongly salt-reuse/misuse resistant, counter to
    the findings in https://eprint.iacr.org/2015/189.pdf.
        Second, the ``key``, ``salt`` & ``pid`` are used to derive some
    pseudo-random padding bytes which are appended to the plaintext.
    This padding bytes make the resulting plaintext a multiple of the
    256-byte blocksize.
    """
    padding_key = Padding.derive_key(key, salt=salt, pid=pid)
    plaintext = Padding.pad_plaintext(data, padding_key=padding_key)
    for chunk in Chunky2048.data.root(plaintext):
        yield chunk


async def ajson_encrypt(
    data,
    key=csprng(),
    *,
    salt=None,
    pid=0,
    allow_dangerous_determinism=False,
):
    """
    A high-level public interface to the package's MRAE / AEAD pseudo-
    one-time-pad cipher implementation called 'Chunky2048'.

    Returns a dictionary containing pseudo-one-time-pad ciphertext of
    any json serializable ``data``. The dictionary also contains the
    ephemeral 256-bit salt, a 128-bit SIV, & a 256-bit HMAC used to
    verify the integrity & authenticity of the ciphertext & the values
    used to create it. The key stream is derived from permutations of
    these values:

    ``key``: An arbitrary, non-zero amount & type of entropic key
            material whose __repr__ returns the user's desired
            entropy & cryptographic strength. Designed to be used as
            a longer-term user encryption / decryption key & should be a
            512-bit value.
    ``salt``: An ephemeral 256-bit random hexidecimal string that MUST
            BE USED ONLY ONCE for each encryption. This value is sent in
            the clear along with the ciphertext.
    ``pid``: An arbitrary value that can be used to categorize key
            material streams & safely distinguishes the values they
            produce. Designed to safely destinguish parallelized key
            material streams with the same ``key`` & ``salt``. But
            can be used for any arbitrary categorization of streams
            as long as the encryption & decryption processes for a
            given stream use the same ``pid`` value.
    """
    return await abytes_encrypt(
        json.dumps(data).encode(),
        key=key,
        salt=salt,
        pid=pid,
        allow_dangerous_determinism=allow_dangerous_determinism,
    )


def json_encrypt(
    data,
    key=csprng(),
    *,
    salt=None,
    pid=0,
    allow_dangerous_determinism=False,
):
    """
    A high-level public interface to the package's MRAE / AEAD pseudo-
    one-time-pad cipher implementation called 'Chunky2048'.

    Returns a dictionary containing pseudo-one-time-pad ciphertext of
    any json serializable ``data``. The dictionary also contains the
    ephemeral 256-bit salt, a 128-bit SIV, & a 256-bit HMAC used to
    verify the integrity & authenticity of the ciphertext & the values
    used to create it. The key stream is derived from permutations of
    these values:

    ``key``: An arbitrary, non-zero amount & type of entropic key
            material whose __repr__ returns the user's desired entropy
            & cryptographic strength. Designed to be used as a longer-
            term user encryption / decryption key & should be a 512-bit
            value.
    ``salt``: An ephemeral 256-bit random hexidecimal string that MUST
            BE USED ONLY ONCE for each encryption. This value is sent in
            the clear along with the ciphertext.
    ``pid``: An arbitrary value whose __repr__ function returns any
            value that a user decides to categorize keystreams. It
            safely differentiates those keystreams & initially was
            designed to permute parallelized keystreams derived from
            the same ``key`` & ``salt``. Since this value is now
            verified during message authentication, it can be used
            to verify arbitrary additional data.
    """
    return bytes_encrypt(
        json.dumps(data).encode(),
        key=key,
        salt=salt,
        pid=pid,
        allow_dangerous_determinism=allow_dangerous_determinism,
    )


async def ajson_decrypt(data, key, *, pid=0, ttl=0):
    """
    A high-level public interface to the package's MRAE / AEAD pseudo-
    one-time-pad cipher implementation called 'Chunky2048'.

    Returns the plaintext bytes of the pseudo-one-time pad ciphertext
    ``data``. ``data`` is a dictionary or json object containing an
    iterable of ciphertext, a 256-bit hex string ephemeral salt, a 128-
    bit SIV & a 256-bit HMAC used to verify the integrity & authenticity
    of the ciphertext & the values used to create it. The keystream is
    derived from permutations of these values:

    ``key``: An arbitrary, non-zero amount & type of entropic key
            material whose __repr__ returns the user's desired
            entropy & cryptographic strength. Designed to be used as
            a longer-term user encryption / decryption key & should
            be a 512-bit value.
    ``pid``: An arbitrary value whose __repr__ function returns any
            value that a user decides to categorize keystreams. It
            safely differentiates those keystreams & initially was
            designed to permute parallelized keystreams derived from
            the same ``key`` & ``salt``. Since this value is now
            verified during message authentication, it can be used
            to verify arbitrary additional data.
    ``ttl``: An amount of seconds that dictate the allowable age of
            the decrypted message.
    """
    if not issubclass(data.__class__, dict):
        data = json.loads(data)
    plaintext_bytes = await abytes_decrypt(data, key=key, pid=pid, ttl=ttl)
    return json.loads(plaintext_bytes.decode())


def json_decrypt(data, key, *, pid=0, ttl=0):
    """
    A high-level public interface to the package's MRAE / AEAD pseudo-
    one-time-pad cipher implementation called 'Chunky2048'.

    Returns the plaintext bytes of the pseudo-one-time pad ciphertext
    ``data``. ``data`` is a dictionary or json object containing an
    iterable of ciphertext, a 256-bit hex string ephemeral salt, a 128-
    bit SIV & a 256-bit HMAC used to verify the integrity & authenticity
    of the ciphertext & the values used to create it. The keystream is
    derived from permutations of these values:

    ``key``: An arbitrary, non-zero amount & type of entropic key
            material whose __repr__ returns the user's desired
            entropy & cryptographic strength. Designed to be used as
            a longer-term user encryption / decryption key & should
            be a 512-bit value.
    ``pid``: An arbitrary value whose __repr__ function returns any
            value that a user decides to categorize keystreams. It
            safely differentiates those keystreams & initially was
            designed to permute parallelized keystreams derived from
            the same ``key`` & ``salt``. Since this value is now
            verified during message authentication, it can be used
            to verify arbitrary additional data.
    ``ttl``: An amount of seconds that dictate the allowable age of
            the decrypted message.
    """
    if not issubclass(data.__class__, dict):
        data = json.loads(data)
    plaintext_bytes = bytes_decrypt(data, key, pid=pid, ttl=ttl)
    return json.loads(plaintext_bytes.decode())


async def amake_salt_non_deterministic(salt=None, disable=False):
    """
    Prevents a deterministic salt from being used for an encryption
    procedure without explicitly passing the appropriate flag to do so.
    Returns a random 256-bit salt otherwise.
    """
    if disable:
        return salt if salt else await agenerate_salt()
    elif salt and not disable:
        raise PermissionError(UNSAFE_DETERMINISM)
    else:
        return await agenerate_salt()


def make_salt_non_deterministic(salt=None, disable=False):
    """
    Prevents a deterministic salt from being used for an encryption
    procedure without explicitly passing the appropriate flag to do so.
    Returns a random 256-bit salt otherwise.
    """
    if disable:
        return salt if salt else generate_salt()
    elif salt and not disable:
        raise PermissionError(UNSAFE_DETERMINISM)
    else:
        return generate_salt()


async def abytes_encrypt(
    data,
    key=csprng(),
    *,
    salt=None,
    pid=0,
    allow_dangerous_determinism=False,
):
    """
    A high-level public interface to the package's MRAE / AEAD pseudo-
    one-time-pad cipher implementation called 'Chunky2048'.

    Returns a dictionary containing pseudo-one-time-pad ciphertext of
    any bytes type ``data``. The dictionary also contains the ephemeral
    256-bit salt, the 128-bit SIV, & a 256-bit HMAC used to verify the
    integrity & authenticity of the ciphertext & values used to create
    it. The key stream is derived from permutations of these values:

    ``key``: An arbitrary, non-zero amount & type of entropic key
            material whose __repr__ returns the user's desired
            entropy & cryptographic strength. Designed to be used as
            a longer-term user encryption / decryption key & should
            be a 512-bit value.
    ``salt``: An ephemeral 256-bit random hexidecimal string that MUST
            BE USED ONLY ONCE for each encryption. This value is sent in
            the clear along with the ciphertext.
    ``pid``: An arbitrary value whose __repr__ function returns any
            value that a user decides to categorize keystreams. It
            safely differentiates those keystreams & initially was
            designed to permute parallelized keystreams derived from
            the same ``key`` & ``salt``. Since this value is now
            verified during message authentication, it can be used
            to verify arbitrary additional data.
    """
    salt = await amake_salt_non_deterministic(
        salt, disable=allow_dangerous_determinism
    )
    await atest_key_and_salt(key, salt)
    plaintext = aplaintext_stream(data, key, salt=salt, pid=pid)
    hmac = StreamHMAC(key, salt=salt, pid=pid).for_encryption()
    cipher = plaintext.abytes_encipher
    async with cipher(key, salt=salt, pid=pid, validator=hmac) as ciphering:
        return {
            CIPHERTEXT: await ciphering.alist(mutable=True),
            HMAC: (await hmac.afinalize()).hex(),
            SALT: salt,
            SIV: hmac.siv,
        }


def bytes_encrypt(
    data,
    key=csprng(),
    *,
    salt=None,
    pid=0,
    allow_dangerous_determinism=False,
):
    """
    A high-level public interface to the package's MRAE / AEAD pseudo-
    one-time-pad cipher implementation called 'Chunky2048'.

    Returns a dictionary containing pseudo-one-time-pad ciphertext of
    any bytes type ``data``. The dictionary also contains the ephemeral
    256-bit salt, the 128-bit SIV, & a 256-bit HMAC used to verify the
    integrity & authenticity of the ciphertext & values used to create
    it. The key stream is derived from permutations of these values:

    ``key``: An arbitrary, non-zero amount & type of entropic key
            material whose __repr__ returns the user's desired
            entropy & cryptographic strength. Designed to be used as
            a longer-term user encryption / decryption key & should
            be a 512-bit value.
    ``salt``: An ephemeral 256-bit random hexidecimal string that MUST
            BE USED ONLY ONCE for each encryption. This value is sent in
            the clear along with the ciphertext.
    ``pid``: An arbitrary value whose __repr__ function returns any
            value that a user decides to categorize keystreams. It
            safely differentiates those keystreams & initially was
            designed to permute parallelized keystreams derived from
            the same ``key`` & ``salt``. Since this value is now
            verified during message authentication, it can be used
            to verify arbitrary additional data.
    """
    salt = make_salt_non_deterministic(
        salt, disable=allow_dangerous_determinism
    )
    test_key_and_salt(key, salt)
    plaintext = plaintext_stream(data, key, salt=salt, pid=pid)
    hmac = StreamHMAC(key, salt=salt, pid=pid).for_encryption()
    cipher = plaintext.bytes_encipher
    with cipher(key, salt=salt, pid=pid, validator=hmac) as ciphering:
        return {
            CIPHERTEXT: ciphering.list(mutable=True),
            HMAC: hmac.finalize().hex(),
            SALT: salt,
            SIV: hmac.siv,
        }


async def abytes_decrypt(data, key, *, pid=0, ttl=0):
    """
    A high-level public interface to the package's MRAE / AEAD pseudo-
    one-time-pad cipher implementation called 'Chunky2048'.

    Returns the plaintext bytes of the pseudo-one-time pad ciphertext
    ``data``. ``data`` is a dictionary containing an iterable of
    ciphertext, a 256-bit hex string ephemeral salt, a 128-bit SIV, & a
    256-bit HMAC used to verify the integrity & authenticity of the
    ciphertext & values used to create it. The keystream is derived from
    permutations of these values:

    ``key``: An arbitrary, non-zero amount & type of entropic key
            material whose __repr__ returns the user's desired
            entropy & cryptographic strength. Designed to be used as
            a longer-term user encryption / decryption key & should
            be a 512-bit value.
    ``pid``: An arbitrary value whose __repr__ function returns any
            value that a user decides to categorize keystreams. It
            safely differentiates those keystreams & initially was
            designed to permute parallelized keystreams derived from
            the same ``key`` & ``salt``. Since this value is now
            verified during message authentication, it can be used
            to verify arbitrary additional data.
    ``ttl``: An amount of seconds that dictate the allowable age of
            the decrypted message.
    """
    data = Namespace(data)
    key_aad = Namespace(key=key, salt=data.salt, pid=pid)
    hmac = StreamHMAC(**key_aad, siv=data.synthetic_iv).for_decryption()
    decipher = aunpack(data.ciphertext).abytes_decipher
    async with decipher(**key_aad, validator=hmac) as deciphering:
        plaintext = await deciphering.ajoin(b"")
        await hmac.afinalize()
        await hmac.atest_hmac(bytes.fromhex(data.hmac))
        return await Padding.adepad_plaintext(
            plaintext, padding_key=await apadding_key(**key_aad), ttl=ttl
        )


def bytes_decrypt(data, key, *, pid=0, ttl=0):
    """
    A high-level public interface to the package's MRAE / AEAD pseudo-
    one-time-pad cipher implementation called 'Chunky2048'.

    Returns the plaintext bytes of the pseudo-one-time pad ciphertext
    ``data``. ``data`` is a dictionary containing an iterable of
    ciphertext, a 256-bit hex string ephemeral salt, a 128-bit SIV, & a
    256-bit HMAC used to verify the integrity & authenticity of the
    ciphertext & values used to create it. The keystream is derived from
    permutations of these values:

    ``key``: An arbitrary, non-zero amount & type of entropic key
            material whose __repr__ returns the user's desired
            entropy & cryptographic strength. Designed to be used as
            a longer-term user encryption / decryption key & should
            be a 512-bit value.
    ``pid``: An arbitrary value whose __repr__ function returns any
            value that a user decides to categorize keystreams. It
            safely differentiates those keystreams & initially was
            designed to permute parallelized keystreams derived from
            the same ``key`` & ``salt``. Since this value is now
            verified during message authentication, it can be used
            to verify arbitrary additional data.
    ``ttl``: An amount of seconds that dictate the allowable age of
            the decrypted message.
    """
    data = Namespace(data)
    key_aad = Namespace(key=key, salt=data.salt, pid=pid)
    hmac = StreamHMAC(**key_aad, siv=data.synthetic_iv).for_decryption()
    decipher = unpack(data.ciphertext).bytes_decipher
    with decipher(**key_aad, validator=hmac) as deciphering:
        plaintext = deciphering.join(b"")
        hmac.finalize()
        hmac.test_hmac(bytes.fromhex(data.hmac))
        return Padding.depad_plaintext(
            plaintext, padding_key=padding_key(**key_aad), ttl=ttl
        )


class Passcrypt:
    """
    This class is used to implement an Argon2id-like password-based key
    derivation function that's designed to be resistant to cache-timing
    side-channel attacks & time-memory trade-offs.

    It's hybrid data dependant / independant. The algorithm requires a
    tunable amount of memory (in kilobytes) & cpu time to compute. If
    the memory cost is too high, it can eat up all the ram on a machine
    very quickly. The ``cpu`` time cost is linearly proportional to the
    number of sha3_512 hashes of cache columns that are calculated per
    column. The ``hardness`` parameter measures the minimum number of
    columns in the memory cache.

    The algorithm initializes all the columns for the cache using the
    `bytes_keys` generator after being fed the password, salt & the hash
    of all the parameters. The number of columns is computed dynamically
    to reach the specified memory cost considering the ``cpu`` cost also
    sequentially adds 128 bytes of sha3_512 digests to the cache ``cpu``
    * columns number of times. The effect is that, hashing the bytes in
    a column, is same as a proving knowledge of the state of that column
    for all past passes over the cache.

    The sequential passes involve a current column index, the index of
    the current index's reflection across the cache, & an index chosen
    pseudo-randomly using the current digest of the sha3_512 object that
    does all of the hashing.

    This algorithm is also decribed by this diagram:

           _____width of the cache is the # of columns______
          |                                                 |
          v              initial memory cache               v
    row-> |-------------------------------------------------| each
    row-> |-------------------------------------------------| element in
                                                              a row is
                                                              64-bytes.
                                pseudo-random selection
                                          |
    ram = |--------'----------------------'--------'--------| columns
        = |--------'----------------------'--------'--------| are hashed
        = |ooooooooO                               Xxxxxxxxx| sequentially
                   |   ->                     <-   |          & new row
                 index                        reflection      elements
                                                              are added.
                           reflection
                          <-   |
    ram = |-'------------------'-------'--------------------| A pseudo-
        = |-'------------------'-------'--------------------| random index
        = |o'oooooooooooooooooo'ooooxxx'xxxxxxxxxxxxxxxxxxxx| is also
        = | |                  XxxxxoooO                    | chosen &
            |                          |   ->                 the column
    pseudo-random selection          index                    at the index
                                                              is also
       pseudo-random selection                                hashed.
                 |
    ram = |--'---'---------------------------------------'--| Each index,
        = |--'---'---------------------------------------'--| reflection,
        = |oo'ooo'ooooooooooooooooooxxxxxxxxxxxxxxxxxxxxx'xx| & pseudo-
        = |xx'xxx'xxxxxxxxxxxxxxxxxxooooooooooooooooooooo'oo| random index
        = |ooO                                           Xxx| tuple represents
             |   ->                                 <-   |    one round.
           index                                    reflection
                                   |
                                   |
                                   v Continue until there are
                                     2 * (cpu + 1) total rows,
                                     completing (0.5 * rows - 1) * columns
                                     total rounds.
    `kb` == rows * columns * 64
    rows == 2 * (`cpu` + 1)
    columns == `kb` / (128 * (`cpu` + 1))
    """

    generate_salt = staticmethod(generate_salt)
    agenerate_salt = staticmethod(agenerate_salt)
    _DEFAULT_KB = 1024
    _DEFAULT_CPU = 3
    _DEFAULT_HARDNESS = 1024

    def __init__(
        self,
        kb=_DEFAULT_KB,
        cpu=_DEFAULT_CPU,
        hardness=_DEFAULT_HARDNESS,
    ):
        """
        Stores a dict of user-defined settings which are automatically
        passed into instance methods when they are called.
        """
        self._validate_args(kb=kb, cpu=cpu, hardness=hardness)
        self._settings = dict(kb=kb, cpu=cpu, hardness=hardness)
        for method in self.instance_methods:
            convert_class_method_to_member(
                self,
                method.__func__.__name__,
                method,
                **self._settings,
            )

    @staticmethod
    def _check_inputs(password: any, salt: any):
        """
        Makes sure ``password`` & ``salt`` are truthy. Throws ValueError
        if not.
        """
        if not password:
            raise ValueError("No ``password`` was specified.")
        elif not salt:
            raise ValueError("No ``salt`` was specified.")

    @staticmethod
    def _validate_args(kb: int, cpu: int, hardness: int):
        """
        Ensures the values ``kb``, ``cpu`` and ``hardness`` passed into
        this module's Argon2id-like, password-based key derivation
        function are within acceptable bounds & types. Then performs a
        calculation to determine how many iterations of the ``bytes_keys``
        generator will sum to the desired number of kilobytes, taking
        into account that for every element in that cache, 2 * ``cpu``
        number of extra sha3_512 hashes will be added to the cache as
        proofs of memory & work.
        """
        if hardness < 256 or not isinstance(hardness, int):
            raise ValueError(f"hardness:{hardness} must be int >= 256")
        elif cpu < 2 or cpu >= 65536 or not isinstance(cpu, int):
            raise ValueError(f"cpu:{cpu} must be int >= 2 and < 65536")
        elif kb < hardness or not isinstance(kb, int):
            raise ValueError(f"kb:{kb} must be int >= hardness:{hardness}")

    @classmethod
    def cache_width(cls, kb: int, cpu: int, hardness: int):
        """
        Returns the width of the cache that will be built given the
        desired amount of kilobytes ``kb`` & the depth of hash updates &
        proofs ``cpu`` that will be computed & added to the cache
        sequentially. This should help users determine optimal ratios
        for their applications.

        Explanation:
        user_input = kb
        desired_bytes = user_input * 1024
        build_size = 128 * build_iterations
        proof_size = (64 + 64) * build_iterations * cpu
        desired_bytes == build_size + proof_size
        # solve for build_iterations given cpu & kb
        width = build_iterations
        """
        cls._validate_args(kb, cpu, hardness)
        width = int((kb * 1024) / (128 * (cpu + 1)))
        return width if width >= hardness else hardness

    @staticmethod
    def _work_memory_prover(proof: sha3_512, ram: list, cpu: int):
        """
        Returns the key scanning function which combines sequential
        passes over the memory cache with a pseudo-random selection
        algorithm which makes the scheme hybrid data-dependent /
        independent. It ensures an attacker attempting to crack a
        password hash must have the entirety of the cache in memory &
        compute the algorithm sequentially.
        """

        def keyed_scanner():
            """
            Combines sequential passes over the memory cache with a
            pseudo-random selection algorithm which makes this scheme
            hybrid data-dependent/independent.

            The ``proof`` argument is a ``sha3_512`` object that has
            been primed with the last element in the cache of keys & the
            hash of the arguments passed into the algorithm. For each
            element in the cache, it passes over the cache ``cpu`` times,
            updating itself with a pseudo-random selection from the
            cache & the current indexed item, then the item of the
            reflected index, & sequentially adds ``proof``'s digests
            to the cache at every index & reflected index.

            More updating of the proof per element is done if more cpu
            usage is specified with the ``cpu`` argument. This algorithm
            further ensures the whole cache is processed sequentially &
            is held in memory in its entirety for the duration of the
            computation of proofs. Even if a side-channel attack on the
            pseudo-random selection is performed, the memory savings at
            the mid-way point of the last pass are upper bounded by the
            the size of the last layer which is = total/(2*(cpu+1)).
            """
            nonlocal digest

            for _ in range(cpu):
                index = next_index()
                reflection = -index - 1

                update(ram[index] + choose())
                ram[index] += summary()

                update(ram[reflection])
                digest = summary()
                ram[reflection] += digest
            return digest

        update = proof.update
        summary = proof.digest
        digest = summary()
        cache_width = len(ram)
        to_int = int.from_bytes
        next_index = cycle.root(range(cache_width)).__next__
        choose = lambda: ram[to_int(digest, "big") % cache_width]
        return keyed_scanner

    @classmethod
    async def _apasscrypt(
        cls,
        password,
        salt,
        *,
        kb=_DEFAULT_KB,
        cpu=_DEFAULT_CPU,
        hardness=_DEFAULT_HARDNESS,
    ):
        """
        An implementation of an Argon2id-like password-based key
        derivation function that's designed to be resistant to cache-
        timing side- channel attacks & time-memory trade-offs.

        It's hybrid data dependant / independant. The algorithm requires
        a tunable amount of memory (in kilobytes) & cpu time to compute.
        If the memory cost is too high, it can eat up all the ram on a
        machine very quickly. The ``cpu`` time cost is linearly
        proportional to the number of sha3_512 hashes of cache columns
        that are calculated per column. The ``hardness`` parameter
        measures the minimum number of columns in the memory cache.

        The algorithm initializes all the columns for the cache using
        the `abytes_keys` generator after being fed the password, salt
        & the hash of all the parameters. The number of columns is
        computed dynamically to reach the specified memory cost
        considering the ``cpu`` cost also sequentially adds 128 bytes of
        sha3_512 digests to the cache ``cpu`` * columns number of times.
        The effect is that, hashing the bytes in a column, is same as a
        proving knowledge of the state of that column for all past
        passes over the cache.

        The sequential passes involve a current column index, the index
        of the current index's reflection across the cache, & an index
        chosen pseudo-randomly using the current digest of the sha3_512
        object that does all of the hashing.

        `kb` == rows * columns * 64
        rows == 2 * (`cpu` + 1)
        columns == `kb` / (128 * (`cpu` + 1))
        """
        cls._check_inputs(password, salt)
        cache_width = cls.cache_width(kb, cpu, hardness)
        args = bytes.fromhex(sha_512(password, salt, kb, cpu, hardness))
        cache_builder = abytes_keys(password, salt=salt, pid=args)
        async with cache_builder[:cache_width] as cache:
            ram = await cache.alist(mutable=True)
            proof = sha3_512(ram[-1] + args)
            prove = cls._work_memory_prover(proof, ram, cpu)
            for element in ram:
                prove()
                await asleep(0)
            return proof.hexdigest()

    @classmethod
    def _passcrypt(
        cls,
        password,
        salt,
        *,
        kb=_DEFAULT_KB,
        cpu=_DEFAULT_CPU,
        hardness=_DEFAULT_HARDNESS,
    ):
        """
        An implementation of an Argon2id-like password-based key
        derivation function that's designed to be resistant to cache-
        timing side- channel attacks & time-memory trade-offs.

        It's hybrid data dependant / independant. The algorithm requires
        a tunable amount of memory (in kilobytes) & cpu time to compute.
        If the memory cost is too high, it can eat up all the ram on a
        machine very quickly. The ``cpu`` time cost is linearly
        proportional to the number of sha3_512 hashes of cache columns
        that are calculated per column. The ``hardness`` parameter
        measures the minimum number of columns in the memory cache.

        The algorithm initializes all the columns for the cache using
        the `bytes_keys` generator after being fed the password, salt
        & the hash of all the parameters. The number of columns is
        computed dynamically to reach the specified memory cost
        considering the ``cpu`` cost also sequentially adds 128 bytes of
        sha3_512 digests to the cache ``cpu`` * columns number of times.
        The effect is that, hashing the bytes in a column, is same as a
        proving knowledge of the state of that column for all past
        passes over the cache.

        The sequential passes involve a current column index, the index
        of the current index's reflection across the cache, & an index
        chosen pseudo-randomly using the current digest of the sha3_512
        object that does all of the hashing.

        `kb` == rows * columns * 64
        rows == 2 * (`cpu` + 1)
        columns == `kb` / (128 * (`cpu` + 1))
        """
        cls._check_inputs(password, salt)
        cache_width = cls.cache_width(kb, cpu, hardness)
        args = bytes.fromhex(sha_512(password, salt, kb, cpu, hardness))
        cache_builder = bytes_keys(password, salt=salt, pid=args)
        with cache_builder[:cache_width] as cache:
            ram = cache.list(mutable=True)
            proof = sha3_512(ram[-1] + args)
            prove = cls._work_memory_prover(proof, ram, cpu)
            for element in ram:
                prove()
            return proof.hexdigest()

    @classmethod
    async def anew(
        cls,
        password,
        salt,
        *,
        kb=_DEFAULT_KB,
        cpu=_DEFAULT_CPU,
        hardness=_DEFAULT_HARDNESS,
    ):
        """
        Returns just the 64-byte hexidecimal passcrypt hash of the
        ``password`` when mixed with the given ``salt`` & difficulty
        settings.

        The passcrypt algorithm can be highly memory intensive. These
        resources may not be freed up, & often are not, because of
        python quirks around memory management. This is a huge problem.
        So to force the release of those resources, we run the function
        in another process which is guaranteed to release them.
        """
        cls._check_inputs(password, salt)
        cls._validate_args(kb, cpu, hardness)
        return await Processes.anew(
            cls._passcrypt,
            password,
            salt,
            kb=kb,
            cpu=cpu,
            hardness=hardness,
            probe_frequency=0.01,
        )

    @classmethod
    def new(
        cls,
        password,
        salt,
        *,
        kb=_DEFAULT_KB,
        cpu=_DEFAULT_CPU,
        hardness=_DEFAULT_HARDNESS,
    ):
        """
        Returns just the 64-byte hexidecimal passcrypt hash of the
        ``password`` when mixed with the given ``salt`` & difficulty
        settings.

        The passcrypt algorithm can be highly memory intensive. These
        resources may not be freed up, & often are not, because of
        python quirks around memory management. This is a huge problem.
        So to force the release of those resources, we run the function
        in another process which is guaranteed to release them.
        """
        cls._check_inputs(password, salt)
        cls._validate_args(kb, cpu, hardness)
        return Processes.new(
            cls._passcrypt,
            password,
            salt,
            kb=kb,
            cpu=cpu,
            hardness=hardness,
            probe_frequency=0.01,
        )


    @classmethod
    async def _acompose_password_hash(
        cls, password_hash, salt, kb, cpu, hardness
    ):
        """
        Attaches the difficulty settings & salt to the passcrypt hash
        of the password.
        """
        await asleep(0)
        return (
            kb.to_bytes(4, "big")
            + cpu.to_bytes(2, "big")
            + hardness.to_bytes(4, "big")
            + bytes.fromhex(salt)
            + bytes.fromhex(password_hash)
        )

    @classmethod
    def _compose_password_hash(cls, password_hash, salt, kb, cpu, hardness):
        """
        Attaches the difficulty settings & salt to the passcrypt hash
        of the password.
        """
        return (
            kb.to_bytes(4, "big")
            + cpu.to_bytes(2, "big")
            + hardness.to_bytes(4, "big")
            + bytes.fromhex(salt)
            + bytes.fromhex(password_hash)
        )

    @classmethod
    async def _adecompose_password_hash(cls, raw_password_hash):
        """
        Separates the passcrypt hash, salt & difficulty settings &
        returns them in a namespace object available by dotted lookup.
        """
        await asleep(0)
        return Namespace(
            kb=int.from_bytes(raw_password_hash[:4], "big"),
            cpu=int.from_bytes(raw_password_hash[4:6], "big"),
            hardness=int.from_bytes(raw_password_hash[6:10], "big"),
            salt=raw_password_hash[10:42].hex(),
            password_hash=raw_password_hash[42:].hex(),
        )

    @classmethod
    def _decompose_password_hash(cls, raw_password_hash):
        """
        Separates the passcrypt hash, salt & difficulty settings &
        returns them in a namespace object available by dotted lookup.
        """
        return Namespace(
            kb=int.from_bytes(raw_password_hash[:4], "big"),
            cpu=int.from_bytes(raw_password_hash[4:6], "big"),
            hardness=int.from_bytes(raw_password_hash[6:10], "big"),
            salt=raw_password_hash[10:42].hex(),
            password_hash=raw_password_hash[42:].hex(),
        )

    @classmethod
    async def ahash_password_raw(
        cls,
        password,
        *,
        kb=_DEFAULT_KB,
        cpu=_DEFAULT_CPU,
        hardness=_DEFAULT_HARDNESS,
    ):
        """
        Returns the passcrypt difficulty settings, salt & hash of the
        ``password`` in a single raw bytes sequence for convenient
        storage. The salt here is automatically generated.

        Metadata hash layout:
        4-bytes - 2-bytes - 4-bytes - 32-bytes - 64-bytes
          kb        cpu     hardness    salt       hash
        """
        salt = await agenerate_salt()
        password_hash = await cls.anew(
            password, salt, kb=kb, cpu=cpu, hardness=hardness
        )
        return await cls._acompose_password_hash(
            password_hash, salt, kb, cpu, hardness
        )

    @classmethod
    def hash_password_raw(
        cls,
        password,
        *,
        kb=_DEFAULT_KB,
        cpu=_DEFAULT_CPU,
        hardness=_DEFAULT_HARDNESS,
    ):
        """
        Returns the passcrypt difficulty settings, salt & hash of the
        ``password`` in a single raw bytes sequence for convenient
        storage. The salt here is automatically generated.

        Metadata hash layout:
        4-bytes - 2-bytes - 4-bytes - 32-bytes - 64-bytes
          kb        cpu     hardness    salt       hash
        """
        salt = generate_salt()
        password_hash = cls.new(
            password, salt, kb=kb, cpu=cpu, hardness=hardness
        )
        return cls._compose_password_hash(
            password_hash, salt, kb, cpu, hardness
        )

    @classmethod
    async def ahash_password(
        cls,
        password,
        *,
        kb=_DEFAULT_KB,
        cpu=_DEFAULT_CPU,
        hardness=_DEFAULT_HARDNESS,
    ):
        """
        Returns the passcrypt difficulty settings, salt & hash of the
        ``password`` in a single urlsafe base64 encoded string for
        convenient storage. The salt here is automatically generated.

        Metadata hash layout:
        4-bytes - 2-bytes - 4-bytes - 32-bytes - 64-bytes
          kb        cpu     hardness    salt       hash
        """
        raw_password_hash = await cls.ahash_password_raw(
            password, kb=kb, cpu=cpu, hardness=hardness
        )
        return (await BytesIO.abytes_to_urlsafe(raw_password_hash)).decode()

    @classmethod
    def hash_password(
        cls,
        password,
        *,
        kb=_DEFAULT_KB,
        cpu=_DEFAULT_CPU,
        hardness=_DEFAULT_HARDNESS,
    ):
        """
        Returns the passcrypt difficulty settings, salt & hash of the
        ``password`` in a single urlsafe base64 encoded string for
        convenient storage. The salt here is automatically generated.

        Metadata hash layout:
        4-bytes - 2-bytes - 4-bytes - 32-bytes - 64-bytes
          kb        cpu     hardness    salt       hash
        """
        raw_password_hash = cls.hash_password_raw(
            password, kb=kb, cpu=cpu, hardness=hardness
        )
        return BytesIO.bytes_to_urlsafe(raw_password_hash).decode()

    @classmethod
    async def averify_raw(cls, composed_password_hash, password):
        """
        Verifies that a supplied ``password`` was indeed used to build
        the ``composed_password_hash``.

        Runs the passcrypt algorithm on the ``password`` with the
        parameters specified in the ``composed_password_hash`` value's
        attached metadata. If the result doesn't match the hash in
        ``composed_password_hash`` then `ValueError` is raised. The
        ``composed_password_hash`` passed into this method must be
        raw bytes.
        """
        parts = await cls._adecompose_password_hash(composed_password_hash)
        untrusted_hash = await cls.anew(
            password,
            parts.salt,
            kb=parts.kb,
            cpu=parts.cpu,
            hardness=parts.hardness,
        )
        if not await atime_safe_equality(
            untrusted_hash, parts.password_hash
        ):
            raise ValueError("Invalid password!")
        return True

    @classmethod
    def verify_raw(cls, composed_password_hash, password):
        """
        Verifies that a supplied ``password`` was indeed used to build
        the ``composed_password_hash``.

        Runs the passcrypt algorithm on the ``password`` with the
        parameters specified in the ``composed_password_hash`` value's
        attached metadata. If the result doesn't match the hash in
        ``composed_password_hash`` then `ValueError` is raised. The
        ``composed_password_hash`` passed into this method must be
        raw bytes.
        """
        parts = cls._decompose_password_hash(composed_password_hash)
        untrusted_hash = cls.new(
            password,
            parts.salt,
            kb=parts.kb,
            cpu=parts.cpu,
            hardness=parts.hardness,
        )
        if not time_safe_equality(untrusted_hash, parts.password_hash):
            raise ValueError("Invalid password!")
        return True

    @classmethod
    async def averify(cls, composed_password_hash, password):
        """
        Verifies that a supplied ``password`` was indeed used to build
        the ``composed_password_hash``.

        Runs the passcrypt algorithm on the ``password`` with the
        parameters specified in the ``composed_password_hash`` value's
        attached metadata. If the result doesn't match the hash in
        ``composed_password_hash`` then `ValueError` is raised. The
        ``composed_password_hash`` passed into this method must be
        urlsafe base64 encoded.
        """
        if composed_password_hash.__class__ == str:
            composed_password_hash = composed_password_hash.encode()
        return await cls.averify_raw(
            await BytesIO.aurlsafe_to_bytes(composed_password_hash),
            password,
        )

    @classmethod
    def verify(cls, composed_password_hash, password):
        """
        Verifies that a supplied ``password`` was indeed used to build
        the ``composed_password_hash``.

        Runs the passcrypt algorithm on the ``password`` with the
        parameters specified in the ``composed_password_hash`` value's
        attached metadata. If the result doesn't match the hash in
        ``composed_password_hash`` then `ValueError` is raised. The
        ``composed_password_hash`` passed into this method must be
        urlsafe base64 encoded.
        """
        if composed_password_hash.__class__ == str:
            composed_password_hash = composed_password_hash.encode()
        return cls.verify_raw(
            BytesIO.urlsafe_to_bytes(composed_password_hash), password
        )

    instance_methods = {
        # The kb, cpu & hardness settings automatically get passed into
        # these methods when called from an instance of the class.
        new,
        anew,
        hash_password,
        ahash_password,
        hash_password_raw,
        ahash_password_raw,
    }


@wraps(Passcrypt._apasscrypt)
async def apasscrypt(
    password,
    salt,
    *,
    kb=Passcrypt._DEFAULT_KB,
    cpu=Passcrypt._DEFAULT_CPU,
    hardness=Passcrypt._DEFAULT_HARDNESS,
):
    """
    Creates an async function which simplifies the ui/ux for access to
    the module's implementation of an Argon2id-like password-based key
    derivation function. It requires a tunable amount of memory & cpu
    time to compute. The function takes a ``password`` & a random
    ``salt`` of any arbitrary, non-zero size & type. The memory cost is
    measured in ``kb`` kilobytes. If the memory cost is too high, it
    will eat up all the ram on a machine very quickly. The cpu time cost
    is measured in the ``cpu`` number of passes over the cache &
    iterations of ``sha3_512`` updates desired per element in the memory
    cache.
    """
    return await Passcrypt.anew(
        password, salt, kb=kb, cpu=cpu, hardness=hardness
    )


@wraps(Passcrypt._passcrypt)
def passcrypt(
    password,
    salt,
    *,
    kb=Passcrypt._DEFAULT_KB,
    cpu=Passcrypt._DEFAULT_CPU,
    hardness=Passcrypt._DEFAULT_HARDNESS,
):
    """
    Creates a function which simplifies the ui/ux for users to access
    the module's implementation of an Argon2id-like password-based key
    derivation function. It requires a tunable amount of memory & cpu
    time to compute. The function takes a ``password`` & a random
    ``salt`` of any arbitrary, non-zero size & type. The memory cost is
    measured in ``kb`` kilobytes. If the memory cost is too high, it
    will eat up all the ram on a machine very quickly. The cpu time cost
    is measured in the ``cpu`` number of passes over the cache &
    iterations of ``sha3_512`` updates desired per element in the memory
    cache.
    """
    return Passcrypt.new(password, salt, kb=kb, cpu=cpu, hardness=hardness)


class Chunky2048:
    """
    A high-level public interface to the package's  pseudo-one-time-pad
    cipher implementation.

    A class composed of the low-level procedures used to implement this
    package's online-offline MRAE / AEAD pseudo-one-time pad cipher, &
    higher level interfaces to utilize the cipher. This implementation
    is built entirely out of generators & the data processing pipelines
    that are made simple by this package's ``Comprende`` generators.

    # The Chunky2048 class carries the key so users don't have to pass
    # it around everywhere ->
    pad = aiootp.Chunky2048(key)
    encrypted = pad.bytes_encrypt(b"binary data")
    decrypted = pad.bytes_decrypt(encrypted)

    # The class also has access to an encoder for transforming
    # ciphertext to & from its default dictionary format ->
    bytes_ciphertext = pad.io.json_to_bytes(encrypted)
    dict_ciphertext = pad.io.bytes_to_json(bytes_ciphertext)

    # As well as tools for saving ciphertext to files on disk as bytes ->
    path = aiootp.DatabasePath() / "testing_ciphertext"
    pad.io.write(path, encrypted)
    assert encrypted == pad.io.read(path)

    # Or ciphertext can be encoded to & from a urlsafe string ->
    urlsafe_ciphertext = pad.io.bytes_to_urlsafe(bytes_ciphertext)
    bytes_ciphertext = pad.io.urlsafe_to_bytes(urlsafe_ciphertext)

    # These urlsafe tokens have their own convenience functions ->
    token = pad.make_token(b"binary data")
    assert b"binary data" == pad.read_token(token)
    """
    _LEFT_PAD = LEFT_PAD
    _RIGHT_PAD = RIGHT_PAD

    io = BytesIO()

    instance_methods = {
        akeys,
        keys,
        abytes_keys,
        bytes_keys,
        ajson_encrypt,
        json_encrypt,
        ajson_decrypt,
        json_decrypt,
        abytes_encrypt,
        bytes_encrypt,
        abytes_decrypt,
        bytes_decrypt,
        apadding_key,
        padding_key,
        aplaintext_stream,
        plaintext_stream,
        StreamHMAC,
        ## Do Not Uncomment:
        ## apasscrypt,  Instance passcrypt methods use the instance key
        ## passcrypt,   to further protect processed passwords.
        ## ahmac,       Instances can also validate data with hmac
        ## hmac,        methods that are automatically passed the
        ## atest_hmac,  instance key to do the hashing & validation.
        ## test_hmac,
    }

    Padding = Padding
    StreamHMAC = StreamHMAC
    axor = staticmethod(axor)
    xor = staticmethod(xor)
    abytes_xor = staticmethod(abytes_xor)
    bytes_xor = staticmethod(bytes_xor)
    adata = staticmethod(adata)
    data = staticmethod(data)
    aunpack = staticmethod(aunpack)
    unpack = staticmethod(unpack)
    aplaintext_stream = staticmethod(aplaintext_stream)
    plaintext_stream = staticmethod(plaintext_stream)
    apadding_key = staticmethod(apadding_key)
    padding_key = staticmethod(padding_key)
    agenerate_salt = staticmethod(agenerate_salt)
    generate_salt = staticmethod(generate_salt)
    acsprbg = staticmethod(acsprbg)
    csprbg = staticmethod(csprbg)
    acsprng = staticmethod(acsprng)
    csprng = staticmethod(csprng)
    akeys = staticmethod(akeys)
    keys = staticmethod(keys)
    abytes_keys = staticmethod(abytes_keys)
    bytes_keys = staticmethod(bytes_keys)
    apasscrypt = staticmethod(apasscrypt)
    passcrypt = staticmethod(passcrypt)
    ajson_encrypt = staticmethod(ajson_encrypt)
    json_encrypt = staticmethod(json_encrypt)
    ajson_decrypt = staticmethod(ajson_decrypt)
    json_decrypt = staticmethod(json_decrypt)
    abytes_encrypt = staticmethod(abytes_encrypt)
    bytes_encrypt = staticmethod(bytes_encrypt)
    abytes_decrypt = staticmethod(abytes_decrypt)
    bytes_decrypt = staticmethod(bytes_decrypt)

    @property
    def key(self):
        """
        Returns the instance's main symmetric key.
        """
        return self._key

    async def amake_token(self, data, *, key=None, pid=0):
        """
        A high-level public interface to the package's online-offline
        MRAE / AEAD pseudo-one-time-pad cipher implementation, called
        'Chunky2048'.

        Encrypts ``data`` with the instance key, or with ``key`` if a
        keyword value is sent by the user, & returns a urlsafe encoded
        ciphertext token.
        """
        if not issubclass(data.__class__, bytes):
            raise TypeError(PLAINTEXT_ISNT_BYTES)
        key = key if key else self.key
        ciphertext = await self.abytes_encrypt(data=data, key=key, pid=pid)
        bytes_token = await self.io.ajson_to_bytes(ciphertext)
        return await self.io.abytes_to_urlsafe(bytes_token)

    def make_token(self, data, *, key=None, pid=0):
        """
        A high-level public interface to the package's online-offline
        MRAE / AEAD pseudo-one-time-pad cipher implementation, called
        'Chunky2048'.

        Encrypts ``data`` with the instance key, or with ``key`` if a
        keyword value is sent by the user, & returns a urlsafe encoded
        ciphertext token.
        """
        if not issubclass(data.__class__, bytes):
            raise TypeError(PLAINTEXT_ISNT_BYTES)
        key = key if key else self.key
        ciphertext = self.bytes_encrypt(data=data, key=key, pid=pid)
        bytes_token = self.io.json_to_bytes(ciphertext)
        return self.io.bytes_to_urlsafe(bytes_token)

    async def aread_token(self, token, *, key=None, pid=0, ttl=0):
        """
        A high-level public interface to the package's online-offline
        MRAE / AEAD pseudo-one-time-pad cipher implementation, called
        'Chunky2048'.

        Decodes a ciphertext token & returns the decrypted token data.
        ``ttl`` is the maximum age of a token, in seconds, that will
        be allowed during the token's validation. The age in measured
        from a timestamp that is removed from the plaintext token data.
        """
        if not issubclass(token.__class__, bytes):
            token = token.encode()
        key = key if key else self.key
        bytes_ciphertext = await self.io.aurlsafe_to_bytes(token)
        ciphertext = await self.io.abytes_to_json(bytes_ciphertext)
        return await self.abytes_decrypt(
            ciphertext, key=key, pid=pid, ttl=ttl
        )

    def read_token(self, token, *, key=None, pid=0, ttl=0):
        """
        A high-level public interface to the package's online-offline
        MRAE / AEAD pseudo-one-time-pad cipher implementation, called
        'Chunky2048'.

        Decodes a ciphertext token & returns the decrypted token data.
        ``ttl`` is the maximum age of a token, in seconds, that will
        be allowed during the token's validation. The age in measured
        from a timestamp that is removed from the plaintext token data.
        """
        if not issubclass(token.__class__, bytes):
            token = token.encode()
        key = key if key else self.key
        bytes_ciphertext = self.io.urlsafe_to_bytes(token)
        ciphertext = self.io.bytes_to_json(bytes_ciphertext)
        return self.bytes_decrypt(ciphertext, key=key, pid=pid, ttl=ttl)

    @comprehension(chained=True)
    async def _abytes_encipher(
        self, key=_csprng(), *, salt, pid=0, validator
    ):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        this package's online-offline MRAE / AEAD pseudo-one-time-pad
        cipher algorithm called Chunky2048.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all async generators
        that are decorated with ``comprehension`` can encrypt the
        plaintext bytes type strings it yields.

        ``key``: An arbitrary, non-zero amount & type of entropic key
                material whose __repr__ returns the user's desired
                entropy & cryptographic strength. Designed to be used as
                a longer-term user encryption / decryption key & should
                be a 512-bit value.

        ``salt``: An ephemeral 256-bit random hexidecimal string that
                MUST BE USED ONLY ONCE for each encryption. This value
                is sent in the clear along with the ciphertext.

        ``pid``: An arbitrary value whose __repr__ function returns any
                value that a user decides to categorize keystreams. It
                safely differentiates those keystreams & initially was
                designed to permute parallelized keystreams derived from
                the same ``key`` & ``salt``. Since this value is now
                verified during message authentication, it can be used
                to verify arbitrary additional data.

        WARNING: ``self`` MUST produce plaintext in chunks of 256 bytes
        or less per iteration or security WILL BE BROKEN by directly
        leaking plaintext. The plaintext MUST also be padded using the
        `Padding` class in order to add salt reuse / misuse resistance
        (MRAE) to the cipher.

        WARNING: This generator does not provide authentication of the
        ciphertexts or associated data it handles. Nor does it do any
        message padding or checking of inputs for adequacy. Those are
        functionalities which must be obtained through other means. Just
        passing in a ``validator`` will not authenticate ciphertext
        itself. The `finalize` or `afinalize` methods must be called on
        the ``validator`` once all of the cipehrtext has been created /
        decrypted. Then the final HMAC is available from the `aresult`
        & `result` methods, & can be tested against untrusted HMACs
        with the `atest_hmac` & `test_hmac` methods. The validator also
        has `current_digest` & `acurrent_digest` methods that can be
        used to authenticate unfinished streams of cipehrtext.
        """
        if validator.mode != ENCRYPTION:
            raise ValueError(INVALID_ENCRYPTION_VALIDATOR)
        keystream = abytes_keys.root(key=key, salt=salt, pid=pid)
        encrypting = abytes_xor.root(
            data=self.abytes_to_int(), key=keystream, validator=validator
        )
        async for result in encrypting:
            yield result
        await keystream.athrow(UserWarning)

    @comprehension(chained=True)
    def _bytes_encipher(self, key=_csprng(), *, salt, pid=0, validator):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        this package's online-offline MRAE / AEAD pseudo-one-time-pad
        cipher algorithm called Chunky2048.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all generators that
        are decorated with ``comprehension`` can encrypt the plaintext
        bytes type strings it yields.

        ``key``: An arbitrary, non-zero amount & type of entropic key
                material whose __repr__ returns the user's desired
                entropy & cryptographic strength. Designed to be used as
                a longer-term user encryption / decryption key & should
                be a 512-bit value.

        ``salt``: An ephemeral 256-bit random hexidecimal string that
                MUST BE USED ONLY ONCE for each encryption. This value
                is sent in the clear along with the ciphertext.

        ``pid``: An arbitrary value whose __repr__ function returns any
                value that a user decides to categorize keystreams. It
                safely differentiates those keystreams & initially was
                designed to permute parallelized keystreams derived from
                the same ``key`` & ``salt``. Since this value is now
                verified during message authentication, it can be used
                to verify arbitrary additional data.

        WARNING: ``self`` MUST produce plaintext in chunks of 256 bytes
        or less per iteration or security WILL BE BROKEN by directly
        leaking plaintext. The plaintext MUST also be padded using the
        `Padding` class in order to add salt reuse / misuse resistance
        (MRAE) to the cipher.

        WARNING: This generator does not provide authentication of the
        ciphertexts or associated data it handles. Nor does it do any
        message padding or checking of inputs for adequacy. Those are
        functionalities which must be obtained through other means. Just
        passing in a ``validator`` will not authenticate ciphertext
        itself. The `finalize` or `afinalize` methods must be called on
        the ``validator`` once all of the cipehrtext has been created /
        decrypted. Then the final HMAC is available from the `aresult`
        & `result` methods, & can be tested against untrusted HMACs
        with the `atest_hmac` & `test_hmac` methods. The validator
        also has `current_digest` & `acurrent_digest` methods that can
        be used to authenticate unfinished streams of cipehrtext.
        """
        if validator.mode != ENCRYPTION:
            raise ValueError(INVALID_ENCRYPTION_VALIDATOR)
        keystream = bytes_keys.root(key=key, salt=salt, pid=pid)
        encrypting = bytes_xor.root(
            data=self.bytes_to_int(), key=keystream, validator=validator
        )
        for result in encrypting:
            yield result
        keystream.throw(UserWarning)

    @comprehension(chained=True)
    async def _abytes_decipher(self, key, *, salt, pid=0, validator):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        this package's online-offline MRAE / AEAD pseudo-one-time-pad
        cipher algorithm called Chunky2048.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all async generators
        that are decorated with ``comprehension`` can decrypt valid
        streams of pseudo-one-time-pad encrypted ciphertext of bytes
        type data.

        ``key``: An arbitrary, non-zero amount & type of entropic key
                material whose __repr__ returns the user's desired
                entropy & cryptographic strength. Designed to be used as
                a longer-term user encryption / decryption key & should
                be a 512-bit value.

        ``salt``: An ephemeral 256-bit random hexidecimal string that
                MUST BE USED ONLY ONCE for each encryption. This value
                is sent in the clear along with the ciphertext.

        ``pid``: An arbitrary value whose __repr__ function returns any
                value that a user decides to categorize keystreams. It
                safely differentiates those keystreams & initially was
                designed to permute parallelized keystreams derived from
                the same ``key`` & ``salt``. Since this value is now
                verified during message authentication, it can be used
                to verify arbitrary additional data.

        WARNING: This generator does not provide authentication of the
        ciphertexts or associated data it handles. Nor does it do any
        message padding or checking of inputs for adequacy. Those are
        functionalities which must be obtained through other means. Just
        passing in a ``validator`` will not authenticate ciphertext
        itself. The `finalize` or `afinalize` methods must be called on
        the ``validator`` once all of the cipehrtext has been created /
        decrypted. Then the final HMAC is available from the `aresult`
        & `result` methods, & can be tested against untrusted HMACs
        with the `atest_hmac` & `test_hmac` methods. The validator
        also has `current_digest` & `acurrent_digest` methods that can
        be used to authenticate unfinished streams of cipehrtext.
        """
        if validator.mode != DECRYPTION:
            raise ValueError(INVALID_DECRYPTION_VALIDATOR)
        keystream = abytes_keys.root(key=key, salt=salt, pid=pid)
        decrypting = abytes_xor.root(
            data=self, key=keystream, validator=validator
        )
        async for plaintext in decrypting:
            yield plaintext.to_bytes(BLOCKSIZE, "big")

    @comprehension(chained=True)
    def _bytes_decipher(self, key, *, salt, pid=0, validator):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        this package's online-offline MRAE / AEAD pseudo-one-time-pad
        cipher algorithm called Chunky2048.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all generators that
        are decorated with ``comprehension`` can decrypt valid streams
        of pseudo-one-time-pad encrypted ciphertext of bytes type data.

        ``key``: An arbitrary, non-zero amount & type of entropic key
                material whose __repr__ returns the user's desired
                entropy & cryptographic strength. Designed to be used as
                a longer-term user encryption / decryption key & should
                be a 512-bit value.

        ``salt``: An ephemeral 256-bit random hexidecimal string that
                MUST BE USED ONLY ONCE for each encryption. This value
                is sent in the clear along with the ciphertext.

        ``pid``: An arbitrary value whose __repr__ function returns any
                value that a user decides to categorize keystreams. It
                safely differentiates those keystreams & initially was
                designed to permute parallelized keystreams derived from
                the same ``key`` & ``salt``. Since this value is now
                verified during message authentication, it can be used
                to verify arbitrary additional data.

        WARNING: This generator does not provide authentication of the
        ciphertexts or associated data it handles. Nor does it do any
        message padding or checking of inputs for adequacy. Those are
        functionalities which must be obtained through other means. Just
        passing in a ``validator`` will not authenticate ciphertext
        itself. The `finalize` or `afinalize` methods must be called on
        the ``validator`` once all of the cipehrtext has been created /
        decrypted. Then the final HMAC is available from the `aresult`
        & `result` methods, & can be tested against untrusted HMACs
        with the `atest_hmac` & `test_hmac` methods. The validator
        also has `current_digest` & `acurrent_digest` methods that can
        be used to authenticate unfinished streams of cipehrtext.
        """
        if validator.mode != DECRYPTION:
            raise ValueError(INVALID_DECRYPTION_VALIDATOR)
        keystream = bytes_keys.root(key=key, salt=salt, pid=pid)
        decrypting = bytes_xor.root(
            data=self, key=keystream, validator=validator
        )
        for plaintext in decrypting:
            yield plaintext.to_bytes(BLOCKSIZE, "big")


class DomainKDF:
    """
    Creates objects able to derive domain & payload-specific HMAC hashes.
    """
    _hmac = hmac.new
    _sha3_256 = sha3_256
    _sha3_512 = sha3_512

    @staticmethod
    def _type_check(domain=b"", payload=b"", key=b""):
        """
        Assure that all arguments to the initializer are bytes objects.
        """
        if type(domain) != bytes:
            raise TypeError("``domain`` must be bytes type.")
        elif type(payload) != bytes:
            raise TypeError("``payload`` must be bytes type.")
        elif type(key) != bytes:
            raise TypeError("``key`` must be bytes type.")

    def __init__(self, domain, payload=b"", *, key):
        """
        Validate the input values before initializing the object.
        """
        self._type_check(domain, payload, key)
        self._domain = domain
        self._key = domain + key
        self._payload = sha3_256(self._key + payload)

    async def aupdate(self, payload):
        """
        Updates the payload object with additional payload. This allows
        large amounts of data to be used for key derivation without a
        large in-memory cost.
        """
        await asleep(0)
        self._payload.update(payload)
        return self

    def update(self, payload):
        """
        Updates the payload object with additional payload. This allows
        large amounts of data to be used for key derivation without a
        large in-memory cost.
        """
        self._payload.update(payload)
        return self

    async def aupdate_key(self, key):
        """
        Derive's a new instance key from the its domain, new ``key``
        material & the previous key.
        """
        await asleep(0)
        self._key = self._domain + sha3_512(self._key + key).digest()
        return self

    def update_key(self, key):
        """
        Derive's a new instance key from the its domain, new ``key``
        material & the previous key.
        """
        self._key = self._domain + sha3_512(self._key + key).digest()
        return self

    async def asha3_256(self, *, _hmac=_hmac):
        """
        Return the sha3_256_hmac of the instance's state.
        """
        await asleep(0)
        obj = _hmac(self._key, self._payload.digest(), self._sha3_256)
        return obj.digest()

    def sha3_256(self, *, _hmac=_hmac):
        """
        Return the sha3_256_hmac of the instance's state.
        """
        obj = _hmac(self._key, self._payload.digest(), self._sha3_256)
        return obj.digest()

    async def asha3_512(self, *, _hmac=_hmac):
        """
        Return the sha3_512_hmac of the instance's state.
        """
        await asleep(0)
        obj = _hmac(self._key, self._payload.digest(), self._sha3_512)
        return obj.digest()

    def sha3_512(self, *, _hmac=_hmac):
        """
        Return the sha3_512_hmac of the instance's state.
        """
        obj = _hmac(self._key, self._payload.digest(), self._sha3_512)
        return obj.digest()


class AsyncDatabase(metaclass=AsyncInit):
    """
    This class creates databases which enable the disk persistence of
    any json serializable, native python data-types, with fully
    transparent, asynchronous encryption / decryption using the
    library's pseudo-one-time-pad cipher implementation called
    Chunky2048.


    Usage Examples:

    key = await aiootp.acsprng()
    db = await AsyncDatabase(key)

    # Elements in a database are organized by user-defined tags ->
    db["income"] = 32000

    # Databases can store any json serializable data ->
    db["dict"] = {0: 1, 2: 3, 4: 5}
    db["lists"] = ["juice", ["nested juice"]]

    # Retrieve items by their tags ->
    db["dict"]
    >>> {0: 1, 2: 3, 4: 5}

    # Save changes to disk ->
    await db.asave()

    # Create child databases using what are called metatags ->
    taxes = await db.ametatag("taxes")
    taxes[2020] = {"jan": 130.25, "feb": 163.23, "mar": 149.68}
    assert taxes == db.taxes
    assert taxes[2020] == db.taxes[2020]

    # Delete a child database ->
    await db.adelete_metatag("taxes")

    # Purge the filesystem of the database files ->
    await db.adelete_database()
    """

    io = BytesIO()
    directory = DatabasePath()
    agenerate_salt = staticmethod(agenerate_salt)
    _ENCODING = LIST_ENCODING
    _BASE_38_TABLE = BASE_38_TABLE
    _NO_PROFILE_OR_CORRUPT = NO_PROFILE_OR_CORRUPT
    _KDF = Domains.KDF
    _HMAC = Domains.HMAC
    _SALT = Domains.SALT
    _SEED = Domains.SEED
    _UUID = Domains.UUID
    _MANIFEST = Domains.MANIFEST
    _FILENAME = Domains.FILENAME
    _FILE_KEY = Domains.FILE_KEY
    _METATAG_KEY = Domains.METATAG_KEY
    _METATAGS = sha3_256(Domains.METATAG + Domains.FILENAME).digest()

    @classmethod
    async def abase64_encode(cls, byte_sequence):
        """
        Encodes a raw ``bytes_sequence`` into a urlsafe base64 string
        that can be stored in a database, since they only accept json
        serializable data.
        """
        await asleep(0)
        return base64.urlsafe_b64encode(byte_sequence).decode()

    @classmethod
    async def abase64_decode(cls, base64_sequence):
        """
        Decodes a urlsafe base64 string or bytes sequence into raw bytes.
        """
        await asleep(0)
        if base64_sequence.__class__ != bytes:
            base64_sequence = base64_sequence.encode()
        return base64.urlsafe_b64decode(base64_sequence)

    @classmethod
    def _hash_to_base38(cls, hex_string):
        """
        Returns the received ``hex_hash`` in base38 encoding.
        """
        return int_to_base(
            int(hex_string, 16), base=38, table=cls._BASE_38_TABLE
        )

    @classmethod
    async def _ahash_to_base38(cls, hex_string):
        """
        Returns the received ``hex_hash`` in base38 encoding.
        """
        return await aint_to_base(
            int(hex_string, 16), base=38, table=cls._BASE_38_TABLE
        )

    @classmethod
    async def aprofile_exists(cls, tokens):
        """
        Tests if a profile that ``tokens`` would open has saved a salt
        file on the user filesystem. Retruens false if not.
        """
        filename = await paths.adeniable_filename(tokens._bytes_key)
        path = (DatabasePath() / "secure") / filename
        return path.exists()

    @classmethod
    async def agenerate_profile_tokens(
        cls,
        *credentials,
        username,
        password,
        salt=None,
        kb=32768,
        cpu=3,
        hardness=1024,
    ):
        """
        Runs a very expensive key derivation function to build keys
        for users to open a database with only access to potentially
        weakly entropic credentials & the filesystem.

        Usage Example:

        tokens = await aiootp.AsyncDatabase.agenerate_profile_tokens(
            "server_url",     # Any number of arguments can be passed
            "email_address",  # here as additional, optional credentials.
            username="username",
            password="password",
            salt="optional salt keyword argument",
        )

        db = await aiootp.AsyncDatabase.agenerate_profile(tokens)
        """
        await asleep(0)
        UUID = cls._UUID
        summary = str((salt, password, *credentials, username)).encode()
        uuid = await asha_512_hmac(UUID + summary, key=summary)
        key = await apasscrypt(
            password, uuid, kb=kb, cpu=cpu, hardness=hardness
        )
        tokens = Namespace(_uuid=uuid, _bytes_key=bytes.fromhex(key))
        return tokens

    @classmethod
    async def _agenerate_profile_salt(cls, tokens):
        """
        Creates or loads a salt value saved on the user filesystem to
        help add more entropy to their key derivation functions when
        preparing to open a profile database.
        """
        tokens._salt_path = await paths.AsyncSecurePath(
            key=tokens._bytes_key
        )
        tokens._salt = await paths._aread_salt_file(tokens._salt_path)
        return tokens._salt

    @classmethod
    async def _agenerate_profile_login_key(cls, tokens):
        """
        Combines the output of the expensive key derivation functions &
        the salt stored on the filesystem gathered in preparation to
        safely open a profile database.
        """
        tokens._login_key = await apasscrypt(
            tokens._bytes_key.hex(), tokens._salt
        )
        return tokens._login_key

    @classmethod
    async def agenerate_profile(cls, tokens, **kw):
        """
        Creates & loads a profile database for a user from the ``tokens``
        passed in.

        Usage Example:

        tokens = await aiootp.AsyncDatabase.agenerate_profile_tokens(
            "server_url",     # Any number of arguments can be passed
            "email_address",  # here as additional, optional credentials.
            username="username",
            password="password",
            salt="optional salt keyword argument",
        )

        db = await aiootp.AsyncDatabase.agenerate_profile(tokens)
        """
        await cls._agenerate_profile_salt(tokens)
        await cls._agenerate_profile_login_key(tokens)
        tokens.profile = await cls(
            key=tokens._login_key, password_depth=10000, **kw
        )
        await tokens.profile.asave()
        return tokens.profile

    @classmethod
    async def aload_profile(cls, tokens, **kw):
        """
        Loads a profile database for a user from the ``tokens`` passed
        in. Throws ``LookupError`` if the profile has not yet been
        generated.
        """
        if not await cls.aprofile_exists(tokens):
            raise LookupError(cls._NO_PROFILE_OR_CORRUPT)
        return await cls.agenerate_profile(tokens, **kw)

    @classmethod
    async def adelete_profile(cls, tokens):
        """
        Deletes the profile's salt saved on the filesystem & all of its
        database files.
        """
        try:
            await tokens.profile.adelete_database()
        except AttributeError:
            await cls.aload_profile(tokens, preload=False)
            await tokens.profile.adelete_database()
        await asynchs.aos.remove(tokens._salt_path)

    async def __init__(
        self,
        key,
        *,
        password_depth=0,  # >= 5000 if ``key`` is weak
        preload=True,
        directory=directory,
        metatag=False,
        silent=True,
    ):
        """
        Sets a database object's basic key generators & cryptographic
        values based on the unique permutations of the ``key`` &
        ``password_depth`` values. If ``key`` is a password, or has very
        low entropy, then ``password_depth`` should be a larger number
        since it will cause the object to compute for that many more
        interations when deterministically deriving its cryptopraghic
        root keys. But, opening a database with a low entropy password
        is safer done by using the `agenerate_profile_tokens` & then the
        `agenerate_profile` methods.

        ``preload``:    This boolean value tells the object to -- True --
            load all of the stored database values from the filesystem
            into the cache during initialization, or -- False -- skip
            the loading stage. This can save time up front so users can
            pay the cost of loading data only when that value is needed.
            Tags in async databases that are not preloaded cannot be
            accessed using bracketed lookups until they are loaded into
            the cache using the ``aquery`` method. Metatags also cannot
            be accessed by dotted lookup before awaiting ``ametatag``
            & passing in the label for that metatag.

        ``directory``:  This value is the string or ``Pathlib.Path``
            object that points to the filesystem location where the
            database files reside / will be saved. By default, stores
            values in the directory "databases" relative to the package
            source code.

        ``metatag``:    This boolean value tells the class whether to
            prepare itself as a sub-database or not, which generally
            means less storage overhead used to secure its cryptographic
            material. Parent databases that are not metatags store a
            random salt value in their ``self._root_path`` file which is
            encrypted twice. Where metatags only encrypt their salts
            with the outter layer of file encryption. This makes metatag
            child databases more light-weight organizational additions
            to existing databases.

        ``silent``:     This boolean value tells the class to surpress
            exceptions when loading files so that errors in the database
            don't prevent a user from logging in.
        """
        self._silent = silent
        self._corrupted_files = {}
        self._cache = Namespace()
        self._manifest = Namespace()
        self.directory = Path(directory)
        self._is_metatag = True if metatag else False
        self._root_key, self._root_hash, self._root_filename = (
            await self._ainitialize_keys(key, password_depth)
        )
        await self._aload_manifest()
        await self._ainitialize_metatags()
        if preload:
            await self.aload(silent=silent)

    @classmethod
    async def _aderive_root_key(cls, key, password_depth):
        """
        Returns a root key derived from the user supplied key & context
        data.
        """
        key_aad = dict(
            key=key, salt=key, pid=(cls._KDF, password_depth)
        )
        return await abytes_keys(**key_aad)[password_depth]()

    @classmethod
    async def _aderive_root_hash(cls, root_key):
        """
        Returns a hash derived from the instance's root key.
        """
        root_hash = await asha_512_hmac(cls._KDF + root_key, key=root_key)
        return bytes.fromhex(root_hash)

    @classmethod
    async def _aderive_root_filename(cls, root_hash):
        """
        Returns a 256-bit hash encoded in base38 used as the instance's
        manifest filename.
        """
        root_filename_hash = await asha_256_hmac(
            cls._FILENAME + root_hash, key=root_hash
        )
        return await cls._ahash_to_base38(root_filename_hash)

    @classmethod
    async def _ainitialize_keys(cls, key, password_depth=0):
        """
        Derives the database's cryptographic root key material and the
        filename of the manifest ledger.
        """
        root_key = await cls._aderive_root_key(key, password_depth)
        root_hash = await cls._aderive_root_hash(root_key)
        root_filename = await cls._aderive_root_filename(root_hash)
        return root_key, root_hash, root_filename

    @property
    def _root_path(self):
        """
        Returns a ``pathlib.Path`` object that points to the file that
        contains the manifest ledger.
        """
        return self.directory / self._root_filename

    @property
    def _maintenance_files(self):
        """
        Returns the filenames of entries in the database that refer to
        administrative values used by objects to track and coordinate
        themselves internally.
        """
        return {self._root_filename, self._metatags_filename}

    @property
    def tags(self):
        """
        Returns a list of all user-defined names for values stored in
        the database object.
        """
        database = dict(self._manifest.namespace)
        for filename in self._maintenance_files:
            database.pop(filename) if filename in database else 0
        return list(database.values())

    @property
    def metatags(self):
        """
        Returns the list of metatags that a database contains.
        """
        return self._manifest.namespace.get(self._metatags_filename)

    @property
    def _root_salt_filename(self):
        """
        Returns the filename of the database's root salt.
        """
        key = self._root_key
        payload = self._root_hash
        domain = self._SALT + self._FILENAME
        filename = DomainKDF(domain, payload, key=key).sha3_256().hex()
        return self._hash_to_base38(filename)

    @property
    def _root_salt_path(self):
        """
        Returns the path of the database's root salt file if the
        instance is not a metatag.
        """
        if not self._is_metatag:
            return self.directory / self._root_salt_filename

    async def _aroot_encryption_key(self, filename, salt):
        """
        Takes a ``filename`` & ``salt`` to construct a unique symmetric
        cryptographic key with preliminary database key material.
        """
        await asleep(0)
        domain = self._KDF + self._FILE_KEY
        key = self._root_hash
        payload = self._root_key + repr((salt, filename)).encode()
        return (await DomainKDF(domain, payload, key=key).asha3_512()).hex()

    async def _aopen_manifest(self):
        """
        Loads an existing manifest file ledger from the filesystem.
        """
        ciphertext = await self.io.aread(
            path=self._root_path, encoding=self._ENCODING
        )
        salt = self._root_session_salt = ciphertext["salt"]
        key = await self._aroot_encryption_key(self._MANIFEST, salt)
        return await ajson_decrypt(ciphertext, key=key)

    async def _aload_root_salt(self):
        """
        Pulls the root salt from the filesystem for a database instance,
        or retrieves it from the manifest file if the database is a
        metatag. Returns the result.
        """
        if self._is_metatag:
            await asleep(0)
            return self._manifest[self._root_filename]
        else:
            encrypted_root_salt = await self.io.aread(
                path=self._root_salt_path, encoding=self._ENCODING
            )
            key = await self._aroot_encryption_key(self._SALT, salt=None)
            return await ajson_decrypt(encrypted_root_salt, key=key)

    async def _agenerate_root_salt(self):
        """
        Returns a 32 byte hex salt for a metatag database, or a 64 byte
        hex salt otherwise.
        """
        if self._is_metatag:
            return await agenerate_salt(self._root_hash)
        else:
            return await acsprng(self._root_hash)

    async def _ainstall_root_salt(self, salt=None):
        """
        Gives the manifest knowledge of the database's root ``salt``.
        This salt is the source of entropy for the database that is not
        derived from the user's key that opens the database. This salt
        is saved in the manifest if the database is a metatag, or the
        salt is saved in its own file if the database is a main parent
        database.
        """
        if self._is_metatag:
            self._manifest[self._root_filename] = salt
        else:
            self._manifest[self._root_filename] = 0

    async def _agenerate_root_seed(self):
        """
        Returns a key that is derived from the database's main key &
        the root salt's entropy.
        """
        domain = self._SEED
        key = self.__root_salt
        payload = self._root_hash + self._root_key
        return await DomainKDF(domain, payload, key=key).asha3_512()

    async def _aload_manifest(self):
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """
        if self._root_path.exists():
            self._manifest = Namespace(await self._aopen_manifest())
            root_salt = await self._aload_root_salt()
        else:
            self._manifest = Namespace()
            self._root_session_salt = await agenerate_salt()
            root_salt = await self._agenerate_root_salt()
            await self._ainstall_root_salt(root_salt)

        self.__root_salt = bytes.fromhex(root_salt)
        self._root_seed = await self._agenerate_root_seed()

    async def _ainitialize_metatags(self):
        """
        Initializes the values that organize database metatags, which
        are children databases contained within their parent.
        """
        self._metatags_filename = await self.afilename(self._METATAGS)
        if self.metatags == None:
            self._manifest[self._metatags_filename] = []

    async def aload_tags(self, silent=False):
        """
        Specifically loads all of the database's tag values into the
        cache.
        """
        if not self.tags:
            await asleep(0)
            return self

        maintenance_files = set(self._maintenance_files)
        tags = (
            self.aquery(tag, silent=silent)
            for filename, tag in self._manifest.namespace.items()
            if filename not in maintenance_files
        )
        await gather(*tags, return_exceptions=True)
        return self

    async def aload_metatags(self, *, preload=True, silent=False):
        """
        Specifically loads all of the database's metatag values into the
        cache. If the ``preload`` keyword argument is falsey then the
        metatag references are populated in the database's instance
        dictionary, but their internal values are not loaded.
        """
        metatags_set = set(self.metatags)
        if not metatags_set:
            await asleep(0)
            return self

        metatags = (
            self.ametatag(metatag, preload=preload, silent=silent)
            for metatag in metatags_set
        )
        await gather(*metatags, return_exceptions=True)
        return self

    async def aload(self, *, metatags=True, manifest=False, silent=False):
        """
        Loads all the database object's values from the filesystem into
        the database cache. This brings the database values into the
        cache, enables up-to-date bracket lookup of tag values & dotted
        lookup of metatags. Otherwise, values would have to be queried
        using the awaitable ``aquery`` & ``ametatag`` methods.
        """
        if manifest:
            await self._aload_manifest()
        await gather(
            self.aload_metatags(preload=metatags, silent=silent),
            self.aload_tags(silent=silent),
            return_exceptions=True,
        )
        return self

    @lru_cache(maxsize=256)
    def _filename(self, tag=None):
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        domain = self._FILENAME
        payload = repr(tag).encode()
        key = self._root_hash + self._root_seed
        filename = DomainKDF(domain, payload, key=key).sha3_256().hex()
        return self._hash_to_base38(filename)

    @alru_cache(maxsize=256)
    async def afilename(self, tag=None):
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        await asleep(0)
        domain = self._FILENAME
        payload = repr(tag).encode()
        key = self._root_hash + self._root_seed
        filename = await DomainKDF(domain, payload, key=key).asha3_256()
        return await self._ahash_to_base38(filename.hex())

    async def ahmac(self, *data):
        """
        Derives an HMAC hash of the arguments passed into ``*data`` with
        a unique permutation of the database's keys & a domain-specific
        kdf.
        """
        await asleep(0)
        domain = self._HMAC
        payload = repr(data).encode()
        key = self._root_seed + self._root_hash
        return (await DomainKDF(domain, payload, key=key).asha3_256()).hex()

    async def atest_hmac(self, *data, hmac=None):
        """
        Tests if ``hmac`` of ``*data`` is valid using database keys.
        Instead of using a constant time character by character check on
        the hmac, the hmac itself is hashed with a random salt & is
        checked against the salted hash of the correct hmac. This
        non-constant-time check on the hash of the supplied hmac doesn't
        reveal meaningful information about either hmac since the
        attacker doesn't have access to the secret key or the salt. This
        scheme is easier to implement correctly & is easier to prove
        guarantees of the infeasibility of timing attacks.
        """
        if not hmac:
            raise ValueError("`hmac` keyword argument was not given.")
        key = self._root_seed
        true_hmac = await self.ahmac(*data)
        if await atime_safe_equality(hmac, true_hmac, key=key):
            return True
        else:
            raise ValueError("HMAC of `data` isn't valid.")

    async def apasscrypt(
        self,
        password,
        salt,
        *,
        kb=Passcrypt._DEFAULT_KB,
        cpu=Passcrypt._DEFAULT_CPU,
        hardness=Passcrypt._DEFAULT_HARDNESS,
    ):
        """
        An implementation of an Argon2id-like password-based derivation
        function which requires a tunable amount of memory & cpu time to
        compute. The function takes a ``password`` & a random ``salt``
        of any arbitrary size & type. The memory cost is measured in
        ``kb`` kilobytes. If the memory cost is too high, it will eat up
        all the ram on a machine very quickly. The ``cpu`` time cost is
        measured in the number of iterations of the sha3_512 hashing
        algorithm done per element in the memory cache. This method also
        protects the passwords it processes with a pair of the
        instance's keys, which forces attackers to also find a way to
        retrieve them in order to crack the passwords.
        """
        Passcrypt._check_inputs(password, salt)
        salted_password = await self.ahmac(password, salt)
        return await Passcrypt.anew(
            salted_password, salt, kb=kb, cpu=cpu, hardness=hardness
        )

    async def auuids(self, category=None, *, size=16, salt=None):
        """
        Returns an async coroutine that can safely create unique user
        IDs based on the category set by the user. The keyword arguments
        refer to:

        ``category``: Any object sent by the user which identifies the
            category or context that the uuids are being made for, such
            as 'emails', 'unregistered_user', 'address'. It is up to the
            user, these categories distinguish the uuids created
            uniquely from other categories.
        ``size``: The length of the hex strings returned by this uuid
            generator.
        ``salt``: An optional random salt value of arbitrary type & size
            that, if passed, needs to be managed manually by the user.
            It provides entropy for the uuids created, which further
            distinguishes them, & provides resistance against certain
            kinds of hash cracking attacks. The salt can be retrieved by
            awaiting the ``aresult(exit=True)`` method of the returned
            async ``Comprende`` generator.

        Usage Examples:

        import aiootp

        key = await aiootp.acsprng()
        db = await aiootp.AsyncDatabase(key)

        responses = await db.ametatag("responses")
        uuids = await responses.auuids("emails", salt=None)

        # Backup json data to the encrypted database ->
        for email_address in server.emails:
            uuid = await uuids(email_address)
            responses[uuid] = server.responses[email_address]

        # Retrieve the random salt used to create the uuids ->
        responses["salt"] = await uuids.aresult(exit=True)
        await db.asave()
        """

        @comprehension()
        async def _auuids(salt=salt):
            """
            A programmable async coroutine which creates unique user IDs
            that are specific to a particular category.
            """
            name = await self.afilename(category)
            uuids = await amake_uuids(size, salt=name).aprime()
            salt = salt if salt else generate_salt()
            async with uuids.arelay(salt) as ids:
                stamp = None
                while True:
                    stamp = yield await ids(
                        await asha_256(name, salt, stamp)
                    )

        return await _auuids().aprime()

    async def _aencryption_key(self, filename, salt):
        """
        Takes a ``filename`` & ``salt`` to contruct a unique symmetric
        cryptographic key.
        """
        await asleep(0)
        domain = self._FILE_KEY
        key = self._root_seed
        payload = self.__root_salt + repr((salt, filename)).encode()
        return (await DomainKDF(domain, payload, key=key).asha3_512()).hex()

    async def abytes_encrypt(self, plaintext, *, filename=None):
        """
        Encrypts ``plaintext`` with keys specific to the ``filename``
        value.

        ``filename``:   This is the hashed tag that labels a piece of
            data in the database.
        ``plaintext``:  This is any bytes type object that's to be
            encrypted.
        """
        salt = await agenerate_salt()
        key = await self._aencryption_key(filename, salt)
        return await Chunky2048.abytes_encrypt(
            data=plaintext,
            key=key,
            salt=salt,
            allow_dangerous_determinism=True,
        )

    async def ajson_encrypt(self, plaintext, *, filename=None):
        """
        Encrypts ``plaintext`` with keys specific to the ``filename``
        value.

        ``filename``:   This is the hashed tag that labels a piece of
            data in the database.
        ``plaintext``:  This is any json serializable object that's to
            be encrypted.
        """
        salt = await agenerate_salt()
        key = await self._aencryption_key(filename, salt)
        return await Chunky2048.ajson_encrypt(
            data=plaintext,
            key=key,
            salt=salt,
            allow_dangerous_determinism=True,
        )

    async def abytes_decrypt(self, ciphertext, *, filename=None, ttl=0):
        """
        Decrypts ``ciphertext`` with keys specific to the ``filename``
        value.

        ``filename``:   This is the hashed tag that labels a piece of
            data in the database.
        ``ciphertext``: This is a dictionary of ciphertext.
        ``ttl``:        An amount of seconds that dictate the allowable
            age of the decrypted message.
        """
        salt = ciphertext["salt"]
        key = await self._aencryption_key(filename, salt)
        return await Chunky2048.abytes_decrypt(
            data=ciphertext, key=key, ttl=ttl
        )

    async def ajson_decrypt(self, ciphertext, *, filename=None, ttl=0):
        """
        Decrypts ``ciphertext`` with keys specific to the ``filename``
        value.

        ``filename``:   This is the hashed tag that labels a piece of
            data in the database.
        ``ciphertext``: This is a dictionary of ciphertext.
        ``ttl``:        An amount of seconds that dictate the allowable
            age of the decrypted message.
        """
        salt = ciphertext["salt"]
        key = await self._aencryption_key(filename, salt)
        return await Chunky2048.ajson_decrypt(
            data=ciphertext, key=key, ttl=ttl
        )

    async def _asave_ciphertext(self, filename=None, ciphertext=None):
        """
        Saves the encrypted value ``ciphertext`` in the database file
        called ``filename``.
        """
        path = self.directory / filename
        await self.io.awrite(path=path, ciphertext=ciphertext)

    async def aset(self, tag=None, data=None):
        """
        Allows users to add the value ``data`` under the name ``tag``
        into the database.
        """
        filename = await self.afilename(tag)
        self._cache[filename] = data
        self._manifest[filename] = tag

    async def _aquery_ciphertext(self, filename=None, *, silent=False):
        """
        Retrieves the value stored in the database file that's called
        ``filename``.
        """
        try:
            path = self.directory / filename
            return await self.io.aread(path=path, encoding=self._ENCODING)
        except FileNotFoundError as corrupt_database:
            self._corrupted_files[filename] = True
            if not silent:
                raise corrupt_database

    async def aquery(self, tag=None, *, silent=False):
        """
        Allows users to retrieve the value stored under the name ``tag``
        from the database.
        """
        filename = await self.afilename(tag)
        if filename in self._cache:
            return self._cache[filename]
        elif filename in self._manifest:
            ciphertext = await self._aquery_ciphertext(
                filename, silent=silent
            )
            if not ciphertext and silent:
                return
            result = await self.ajson_decrypt(ciphertext, filename=filename)
            self._cache[filename] = result
            return result

    async def _adelete_file(self, filename=None):
        """
        Deletes a file in the database directory by ``filename``.
        """
        try:
            await asynchs.aos.remove(self.directory / filename)
        except FileNotFoundError:
            pass

    async def apop(self, tag=None, *, admin=False):
        """
        Returns a value from the database by it's ``tag`` & deletes the
        associated file in the database directory.
        """
        filename = await self.afilename(tag)
        if filename in self._maintenance_files and not admin:
            raise PermissionError("Cannot delete maintenance files.")
        try:
            value = await self.aquery(tag)
        except FileNotFoundError:
            value = None
        try:
            del self._manifest[filename]
        except KeyError:
            pass
        try:
            del self._cache[filename]
        except KeyError:
            pass
        await self._adelete_file(filename)
        return value

    async def _ametatag_key(self, tag=None):
        """
        Derives the metatag's database key given a user-defined ``tag``.
        """
        await asleep(0)
        key = self.__root_salt
        domain = self._METATAG_KEY
        payload = self._root_seed + repr(tag).encode()
        return (await DomainKDF(domain, payload, key=key).asha3_512()).hex()

    async def ametatag(self, tag=None, *, preload=True, silent=False):
        """
        Allows a user to create a child database with the name ``tag``
        accessible by dotted lookup from the parent database. Child
        databases are synchronized by their parents automatically.

        Usage Example:

        # Create a parent database ->
        key = aiootp.csprng()
        parent = await AsyncDatabase(key)

        # Name the child database ->
        tag = "sub_database"
        child = await parent.ametatag(tag)

        # The child is now accessible from the parent by the tag ->
        assert child == parent.sub_database
        """
        if tag in self.__class__.__dict__:
            raise PermissionError("Can't overwrite class attributes.")
        elif tag in self.__dict__:
            if issubclass(self.__dict__[tag].__class__, self.__class__):
                return self.__dict__[tag]
            else:
                raise PermissionError("Can't overwrite object attributes.")
        self.__dict__[tag] = await self.__class__(
            key=await self._ametatag_key(tag),
            password_depth=0,
            preload=preload,
            directory=self.directory,
            metatag=True,
            silent=silent,
        )
        if not tag in self.metatags:
            self.metatags.append(tag)
        return self.__dict__[tag]

    async def adelete_metatag(self, tag=None):
        """
        Removes the child database named ``tag``.
        """
        if metatag not in self.metatags:
            raise FileNotFoundError(f"No child database named {tag}.")
        sub_db = await self.ametatag(tag)
        await sub_db.adelete_database()
        self.__dict__.pop(tag)
        self.metatags.remove(tag)

    async def _anullify(self):
        """
        Clears the database's memory caches & instance variables of all
        values so a deleted database no longer makes changes to the
        filesystem.
        """
        self._manifest.namespace.clear()
        self._cache.namespace.clear()
        self.__dict__.clear()
        await asleep(0)

    async def adelete_database(self):
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        for metatag in self.metatags:
            sub_db = await self.ametatag(metatag, preload=False)
            await sub_db.adelete_database()
        for filename in self._manifest.namespace:
            await self._adelete_file(filename)
        await self._adelete_file(self._root_salt_filename)
        await self._anullify()

    async def _aencrypt_manifest(self, salt):
        """
        Takes a ``salt`` & returns the database's manifest encrypted.
        """
        manifest = self._manifest.namespace
        key = await self._aroot_encryption_key(self._MANIFEST, salt)
        return await ajson_encrypt(
            manifest, key=key, salt=salt, allow_dangerous_determinism=True
        )

    async def _asave_manifest(self, ciphertext=None):
        """
        Writes the manifest ledger to disk. It contains all database
        filenames & special cryptographic values for initializing the
        database's key derivation functions.
        """
        if not ciphertext:
            raise PermissionError("Invalid write attempted.")
        await self.io.awrite(path=self._root_path, ciphertext=ciphertext)

    async def _asave_root_salt(self, salt):
        """
        Writes a non-metatag database instance's root salt to disk as a
        separate file.
        """
        key = await self._aroot_encryption_key(self._SALT, salt=None)
        await self.io.awrite(
            path=self._root_salt_path,
            ciphertext=await ajson_encrypt(salt.hex(), key=key),
        )

    async def _aclose_manifest(self):
        """
        Prepares for & writes the manifest ledger to disk. The manifest
        contains all database filenames & other metadata used to
        organize databases.
        """
        if not self._is_metatag:
            await self._asave_root_salt(self.__root_salt)
        manifest = await self._aencrypt_manifest(await agenerate_salt())
        self._root_session_salt = manifest["salt"]
        await self._asave_manifest(manifest)

    async def _asave_file(self, filename=None, *, admin=False):
        """
        Writes the cached value for a user-specified ``filename`` to the
        user filesystem.
        """
        if not admin and filename in self._maintenance_files:
            raise PermissionError("Cannot edit maintenance files.")
        ciphertext = await self.ajson_encrypt(
            self._cache[filename], filename=filename
        )
        await self._asave_ciphertext(filename, ciphertext)

    async def _asave_tags(self):
        """
        Writes the database's user-defined tags to disk.
        """
        maintenance_files = self._maintenance_files
        tags = (
            self._asave_file(filename)
            for filename in set(self._cache.namespace)
            if filename not in maintenance_files
        )
        await gather(*tags, return_exceptions=True)

    async def _asave_metatags(self):
        """
        Writes the database's child databases to disk.
        """
        metatags = (
            self.__dict__[metatag].asave()
            for metatag in set(self.metatags)
            if isinstance(self.__dict__.get(metatag), self.__class__)
        )
        await gather(*metatags, return_exceptions=True)

    async def asave_tag(self, tag=None, *, admin=False):
        """
        Writes the cached value for a user-specified ``tag`` to the user
        filesystem.
        """
        filename = await self.afilename(tag)
        try:
            await self._asave_file(filename, admin=admin)
        except AttributeError:
            raise FileNotFoundError("That tag file doesn't exist.")

    async def asave(self):
        """
        Writes the database's values to disk with transparent encryption.
        """
        if self._root_filename not in self._manifest:
            raise PermissionError("The database keys have been deleted.")
        await self._aclose_manifest()
        await gather(
            self._asave_metatags(),
            self._asave_tags(),
            return_exceptions=True,
        )

    async def ainto_namespace(self):
        """
        Returns a ``Namespace`` object of databases' tags & decrypted
        values. The tags are then accessible by dotted look-up on that
        namespace. This allows for orders of magnitude faster look-up
        times than square-bracket lookup on the database object.

        Usage example:

        key = aiootp.csprng()
        db = await aiootp.AsyncDatabase(key)

        db["tag"] = ["value"]
        namespace = await db.ainto_namespace()

        assert namespace.tag == ["value"]
        assert namespace.tag == db["tag"]
        assert namespace.tag is db["tag"]
        """
        return Namespace({tag: value async for tag, value in self})

    async def amirror_database(self, database=None):
        """
        Copies over all of the stored & loaded values, tags & metatags
        from the ``database`` object passed into this function.
        """
        async for tag, value in aunpack(database):
            await self.aset(tag, value)
        async for metatag in aunpack(set(database.metatags)):
            my_metatag = await self.ametatag(metatag)
            await my_metatag.amirror_database(database.__dict__[metatag])

    def __contains__(self, tag=None):
        """
        Checks the cache & manifest for the filename associated with the
        user-defined ``tag``.
        """
        filename = self._filename(tag)
        return filename in self._manifest or filename in self._cache

    def __bool__(self):
        """
        Returns true if the instance dictionary is populated or the
        manifast is saved to the filesystem.
        """
        return bool(self.__dict__)

    async def __aenter__(self):
        """
        The context manager automatically writes database changes made
        by a user to disk.
        """
        return self

    async def __aexit__(
        self, exc_type=None, exc_value=None, traceback=None
    ):
        """
        The context manager automatically writes database changes made
        by a user to disk.
        """
        await self.asave()

    async def __aiter__(self):
        """
        Provides an interface to the names & values stored in databases.
        """
        maintenance_files = self._maintenance_files
        for filename, tag in dict(self._manifest.namespace).items():
            if filename in maintenance_files:
                continue
            yield tag, await self.aquery(tag, silent=self._silent)

    def __setitem__(self, tag=None, data=None):
        """
        Allows users to add the value ``data`` under the name ``tag``
        into the database.
        """
        filename = self._filename(tag)
        self._cache[filename] = data
        self._manifest[filename] = tag

    def __getitem__(self, tag=None):
        """
        Allows users to retrieve the value stored under the name ``tag``
        from the database.
        """
        filename = self._filename(tag)
        if filename in self._cache:
            return self._cache[filename]

    def __delitem__(self, tag=None):
        """
        Allows users to delete the value stored under the name ``tag``
        from the database.
        """
        filename = self._filename(tag)
        try:
            del self._manifest[filename]
        except KeyError:
            pass
        try:
            del self._cache[filename]
        except KeyError:
            pass
        try:
            (self.directory / filename).unlink()
        except FileNotFoundError:
            pass

    __len__ = lambda self: (
        len(self._manifest) - len(self._maintenance_files)
    )


class Database:
    """
    This class creates databases which enable the disk persistence of
    any json serializable, native python data-types, with fully
    transparent encryption / decryption using the library's pseudo-one-
    time-pad cipher implementation called Chunky2048.


    Usage Examples:

    key = aiootp.csprng()
    db = Database(key)

    # Elements in a database are organized by user-defined tags ->
    db["income"] = 32000

    # Databases can store any json serializable data ->
    db["dict"] = {0: 1, 2: 3, 4: 5}
    db["lists"] = ["juice", ["nested juice"]]

    # Retrieve items by their tags ->
    db["dict"]
    >>> {0: 1, 2: 3, 4: 5}

    # Save changes to disk ->
    db.save()

    # Create child databases using what are called metatags ->
    taxes = db.metatag("taxes")
    taxes[2020] = {"jan": 130.25, "feb": 163.23, "mar": 149.68}
    assert taxes == db.taxes
    assert taxes[2020] == db.taxes[2020]

    # Delete a child database ->
    db.delete_metatag("taxes")

    # Purge the filesystem of the database files ->
    db.delete_database()
    """

    io = BytesIO()
    directory = DatabasePath()
    generate_salt = staticmethod(generate_salt)
    _ENCODING = LIST_ENCODING
    _BASE_38_TABLE = BASE_38_TABLE
    _NO_PROFILE_OR_CORRUPT = NO_PROFILE_OR_CORRUPT
    _KDF = Domains.KDF
    _HMAC = Domains.HMAC
    _SALT = Domains.SALT
    _SEED = Domains.SEED
    _UUID = Domains.UUID
    _MANIFEST = Domains.MANIFEST
    _FILENAME = Domains.FILENAME
    _FILE_KEY = Domains.FILE_KEY
    _METATAG_KEY = Domains.METATAG_KEY
    _METATAGS = sha3_256(Domains.METATAG + Domains.FILENAME).digest()

    @classmethod
    def base64_encode(cls, byte_sequence):
        """
        Encodes a raw ``bytes_sequence`` into a urlsafe base64 string
        that can be stored in a database, since they only accept json
        serializable data.
        """
        return base64.urlsafe_b64encode(byte_sequence).decode()

    @classmethod
    def base64_decode(cls, base64_sequence):
        """
        Decodes a urlsafe base64 string or bytes sequence into raw bytes.
        """
        if base64_sequence.__class__ != bytes:
            base64_sequence = base64_sequence.encode()
        return base64.urlsafe_b64decode(base64_sequence)

    @classmethod
    def _hash_to_base38(cls, hex_string):
        """
        Returns the received ``hex_hash`` in base38 encoding.
        """
        return int_to_base(
            int(hex_string, 16), base=38, table=cls._BASE_38_TABLE
        )

    @classmethod
    def profile_exists(cls, tokens):
        """
        Tests if a profile that ``tokens`` would open has saved a salt
        file on the user filesystem. Retruens false if not.
        """
        filename = paths.deniable_filename(tokens._bytes_key)
        path = (DatabasePath() / "secure") / filename
        return path.exists()

    @classmethod
    def generate_profile_tokens(
        cls,
        *credentials,
        username,
        password,
        salt=None,
        kb=32768,
        cpu=3,
        hardness=1024,
    ):
        """
        Runs a very expensive key derivation function to build keys
        for users to open a database with only access to potentially
        weakly entropic credentials & the filesystem.

        Usage Example:

        tokens = aiootp.Database.generate_profile_tokens(
            "server_url",     # Any number of arguments can be passed
            "email_address",  # here as additional, optional credentials.
            username="username",
            password="password",
            salt="optional salt keyword argument",
        )

        db = aiootp.Database.generate_profile(tokens)
        """
        UUID = cls._UUID
        summary = str((salt, password, *credentials, username)).encode()
        uuid = sha_512_hmac(UUID + summary, key=summary)
        key = passcrypt(password, uuid, kb=kb, cpu=cpu, hardness=hardness)
        tokens = Namespace(_uuid=uuid, _bytes_key=bytes.fromhex(key))
        return tokens

    @classmethod
    def _generate_profile_salt(cls, tokens):
        """
        Creates or loads a salt value saved on the user filesystem to
        help add more entropy to their key derivation functions when
        preparing to open a profile database.
        """
        tokens._salt_path = paths.SecurePath(key=tokens._bytes_key)
        tokens._salt = paths._read_salt_file(tokens._salt_path)
        return tokens._salt

    @classmethod
    def _generate_profile_login_key(cls, tokens):
        """
        Combines the output of the expensive key derivation functions &
        the salt stored on the filesystem gathered in preparation to
        safely open a profile database.
        """
        tokens._login_key = passcrypt(tokens._bytes_key.hex(), tokens._salt)
        return tokens._login_key

    @classmethod
    def generate_profile(cls, tokens, **kw):
        """
        Creates & loads a profile database for a user from the ``tokens``
        passed in.

        Usage Example:

        tokens = aiootp.Database.generate_profile_tokens(
            "server_url",     # Any number of arguments can be passed
            "email_address",  # here as additional, optional credentials.
            username="username",
            password="password",
            salt="optional salt keyword argument",
        )

        db = aiootp.Database.generate_profile(tokens)
        """
        cls._generate_profile_salt(tokens)
        cls._generate_profile_login_key(tokens)
        tokens.profile = cls(
            key=tokens._login_key, password_depth=10000, **kw
        )
        tokens.profile.save()
        return tokens.profile

    @classmethod
    def load_profile(cls, tokens, **kw):
        """
        Loads a profile database for a user from the ``tokens`` passed
        in. Throws ``LookupError`` if the profile has not yet been
        generated.
        """
        if not cls.profile_exists(tokens):
            raise LookupError(cls._NO_PROFILE_OR_CORRUPT)
        return cls.generate_profile(tokens, **kw)

    @classmethod
    def delete_profile(cls, tokens):
        """
        Deletes the profile's salt saved on the filesystem & all of its
        database files.
        """
        try:
            tokens.profile.delete_database()
        except AttributeError:
            cls.load_profile(tokens, preload=False)
            tokens.profile.delete_database()
        tokens._salt_path.unlink()

    def __init__(
        self,
        key,
        *,
        password_depth=0,  # >= 5000 if ``key`` is weak
        preload=True,
        directory=directory,
        metatag=False,
        silent=True,
    ):
        """
        Sets a database object's basic key generators & cryptographic
        values based on the unique permutations of the ``key`` &
        ``password_depth`` values. If ``key`` is a password, or has very
        low entropy, then ``password_depth`` should be a larger number
        since it will cause the object to compute for that many more
        interations when deterministically deriving its cryptopraghic
        root keys. But, opening a database with a low entropy password
        is safer done by using the `generate_profile_tokens` & then the
        `generate_profile` methods.

        ``preload``:    This boolean value tells the object to -- True --
            load all of the stored database values from the filesystem
            into the cache during initialization, or -- False -- skip
            the loading stage. This can save time up front so users can
            pay the cost of loading data only when that value is needed.
            Tags in synchronous databases that aren't preloaded can
            still be accessed using bracketed lookups. Metatags cannot
            be accessed by dotted lookup before calling ``metatag`` &
            passing in the label for that metatag.

        ``directory``:  This value is the string or ``Pathlib.Path``
            object that points to the filesystem location where the
            database files reside / will be saved. By default, stores
            values in the directory "databases" relative to the package
            source code.

        ``metatag``:    This boolean value tells the class whether to
            prepare itself as a sub-database or not, which generally
            means less storage overhead used to secure its cryptographic
            material. Parent databases that are not metatags store a
            random salt value in their ``self._root_path`` file which is
            encrypted twice. Where metatags only encrypt their salts
            with the outter layer of file encryption. This makes metatag
            child databases more light-weight organizational additions
            to existing databases.

        ``silent``:     This boolean value tells the class to surpress
            exceptions when loading files so that errors in the database
            don't prevent a user from logging in.
        """
        self._silent = silent
        self._corrupted_files = {}
        self._cache = Namespace()
        self._manifest = Namespace()
        self.directory = Path(directory)
        self._is_metatag = True if metatag else False
        self._root_key, self._root_hash, self._root_filename = (
            self._initialize_keys(key, password_depth)
        )
        self._load_manifest()
        self._initialize_metatags()
        if preload:
            self.load(silent=silent)

    @classmethod
    def _derive_root_key(cls, key, password_depth):
        """
        Returns a root key derived from the user supplied key & context
        data.
        """
        key_aad = dict(
            key=key, salt=key, pid=(cls._KDF, password_depth)
        )
        return bytes_keys(**key_aad)[password_depth]()

    @classmethod
    def _derive_root_hash(cls, root_key):
        """
        Returns a hash derived from the instance's root key.
        """
        root_hash = sha_512_hmac(cls._KDF + root_key, key=root_key)
        return bytes.fromhex(root_hash)

    @classmethod
    def _derive_root_filename(cls, root_hash):
        """
        Returns a 256-bit hash encoded in base38 used as the instance's
        manifest filename.
        """
        root_filename_hash = sha_256_hmac(
            cls._FILENAME + root_hash, key=root_hash
        )
        return cls._hash_to_base38(root_filename_hash)

    @classmethod
    def _initialize_keys(cls, key, password_depth=0):
        """
        Derives the database's cryptographic root key material and the
        filename of the manifest ledger.
        """
        root_key = cls._derive_root_key(key, password_depth)
        root_hash = cls._derive_root_hash(root_key)
        root_filename = cls._derive_root_filename(root_hash)
        return root_key, root_hash, root_filename

    @property
    def _root_path(self):
        """
        Returns a ``pathlib.Path`` object that points to the file that
        contains the manifest ledger.
        """
        return self.directory / self._root_filename

    @property
    def _maintenance_files(self):
        """
        Returns the filenames of entries in the database that refer to
        administrative values used by objects to track and coordinate
        themselves internally.
        """
        return {self._root_filename, self._metatags_filename}

    @property
    def tags(self):
        """
        Returns a list of all user-defined names for values stored in
        the database object.
        """
        database = dict(self._manifest.namespace)
        for filename in self._maintenance_files:
            database.pop(filename) if filename in database else 0
        return list(database.values())

    @property
    def metatags(self):
        """
        Returns the list of metatags that a database contains.
        """
        return self._manifest.namespace.get(self._metatags_filename)

    @property
    def _root_salt_filename(self):
        """
        Returns the filename of the database's root salt.
        """
        key = self._root_key
        payload = self._root_hash
        domain = self._SALT + self._FILENAME
        filename = DomainKDF(domain, payload, key=key).sha3_256().hex()
        return self._hash_to_base38(filename)

    @property
    def _root_salt_path(self):
        """
        Returns the path of the database's root salt file if the
        instance is not a metatag.
        """
        if not self._is_metatag:
            return self.directory / self._root_salt_filename

    def _root_encryption_key(self, filename, salt):
        """
        Takes a ``filename`` & ``salt`` to construct a unique symmetric
        cryptographic key with preliminary database key material.
        """
        domain = self._KDF + self._FILE_KEY
        key = self._root_hash
        payload = self._root_key + repr((salt, filename)).encode()
        return DomainKDF(domain, payload, key=key).sha3_512().hex()

    def _open_manifest(self):
        """
        Loads an existing manifest file ledger from the filesystem.
        """
        ciphertext = self.io.read(
            path=self._root_path, encoding=self._ENCODING
        )
        salt = self._root_session_salt = ciphertext["salt"]
        key = self._root_encryption_key(self._MANIFEST, salt)
        return json_decrypt(ciphertext, key=key)

    def _load_root_salt(self):
        """
        Pulls the root salt from the filesystem for a database instance,
        or retrieves it from the manifest file if the database is a
        metatag. Returns the result.
        """
        if self._is_metatag:
            return self._manifest[self._root_filename]
        else:
            encrypted_root_salt = self.io.read(
                path=self._root_salt_path, encoding=self._ENCODING
            )
            key = self._root_encryption_key(self._SALT, salt=None)
            return json_decrypt(encrypted_root_salt, key=key)

    def _generate_root_salt(self):
        """
        Returns a 32 byte hex salt for a metatag database, or a 64 byte
        hex salt otherwise.
        """
        if self._is_metatag:
            return generate_salt(self._root_hash)
        else:
            return csprng(self._root_hash)

    def _install_root_salt(self, salt=None):
        """
        Gives the manifest knowledge of the database's root ``salt``.
        This salt is the source of entropy for the database that is not
        derived from the user's key that opens the database. This salt
        is saved in the manifest if the database is a metatag, or the
        salt is saved in its own file if the database is a main parent
        database.
        """
        if self._is_metatag:
            self._manifest[self._root_filename] = salt
        else:
            self._manifest[self._root_filename] = 0

    def _generate_root_seed(self):
        """
        Returns a key that is derived from the database's main key &
        the root salt's entropy.
        """
        domain = self._SEED
        key = self.__root_salt
        payload = self._root_hash + self._root_key
        return DomainKDF(domain, payload, key=key).sha3_512()

    def _load_manifest(self):
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """
        if self._root_path.exists():
            self._manifest = Namespace(self._open_manifest())
            root_salt = self._load_root_salt()
        else:
            self._manifest = Namespace()
            self._root_session_salt = generate_salt()
            root_salt = self._generate_root_salt()
            self._install_root_salt(root_salt)

        self.__root_salt = bytes.fromhex(root_salt)
        self._root_seed = self._generate_root_seed()

    def _initialize_metatags(self):
        """
        Initializes the values that organize database metatags, which
        are children databases contained within their parent.
        """
        self._metatags_filename = self.filename(self._METATAGS)
        if self.metatags == None:
            self._manifest[self._metatags_filename] = []

    def load_tags(self, silent=False):
        """
        Specifically loads all of the database's tag values into the
        cache.
        """
        maintenance_files = set(self._maintenance_files)
        for filename, tag in self._manifest.namespace.items():
            if filename not in maintenance_files:
                self.query(tag, silent=silent)
        return self

    def load_metatags(self, *, preload=True, silent=False):
        """
        Specifically loads all of the database's metatag values into the
        cache. If the ``preload`` keyword argument is falsey then the
        metatag references are populated in the database's instance
        dictionary, but their internal values are not loaded.
        """
        for metatag in set(self.metatags):
            self.metatag(metatag, preload=preload, silent=silent)
        return self

    def load(self, *, metatags=True, silent=False, manifest=False):
        """
        Loads all the database object's values from the filesystem into
        the database cache. This brings the database values into the
        cache, enables up-to-date bracket lookup of tag values & dotted
        lookup of metatags.
        """
        if manifest:
            self._load_manifest()
        self.load_metatags(preload=metatags, silent=silent)
        self.load_tags(silent=silent)
        return self

    @lru_cache(maxsize=256)
    def filename(self, tag=None):
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        domain = self._FILENAME
        payload = repr(tag).encode()
        key = self._root_hash + self._root_seed
        filename = DomainKDF(domain, payload, key=key).sha3_256().hex()
        return self._hash_to_base38(filename)

    def hmac(self, *data):
        """
        Derives an HMAC hash of the arguments passed into ``*data`` with
        a unique permutation of the database's keys & a domain-specific
        kdf.
        """
        domain = self._HMAC
        payload = repr(data).encode()
        key = self._root_seed + self._root_hash
        return DomainKDF(domain, payload, key=key).sha3_256().hex()

    def test_hmac(self, *data, hmac=None):
        """
        Tests if ``hmac`` of ``*data`` is valid using database keys.
        Instead of using a constant time character by character check on
        the hmac, the hmac itself is hashed with a random salt & is
        checked against the salted hash of the correct hmac. This
        non-constant-time check on the hash of the supplied hmac doesn't
        reveal meaningful information about either hmac since the
        attacker doesn't have access to the secret key or the salt. This
        scheme is easier to implement correctly & is easier to prove
        guarantees of the infeasibility of timing attacks.
        """
        if not hmac:
            raise ValueError("`hmac` keyword argument was not given.")
        key = self._root_seed
        true_hmac = self.hmac(*data)
        if time_safe_equality(hmac, true_hmac, key=key):
            return True
        else:
            raise ValueError("HMAC of `data` isn't valid.")

    def passcrypt(
        self,
        password,
        salt,
        *,
        kb=Passcrypt._DEFAULT_KB,
        cpu=Passcrypt._DEFAULT_CPU,
        hardness=Passcrypt._DEFAULT_HARDNESS,
    ):
        """
        An implementation of an Argon2id-like password-based derivation
        function which requires a tunable amount of memory & cpu time to
        compute.

        The function takes a ``password`` & a random ``salt`` of any
        arbitrary size & type. The memory cost is measured in ``kb``
        kilobytes. If the memory cost is too high, it will eat up all
        the ram on a machine very quickly. The ``cpu`` time cost is
        measured in the number of iterations of the sha3_512 hashing
        algorithm done per element in the memory cache. This method also
        protects the passwords it processes with a pair of the
        instance's keys, which forces attackers to also find a way to
        retrieve them in order to crack the passwords.
        """
        Passcrypt._check_inputs(password, salt)
        salted_password = self.hmac(password, salt)
        return Passcrypt.new(
            salted_password, salt, kb=kb, cpu=cpu, hardness=hardness
        )

    def uuids(self, category=None, *, size=16, salt=None):
        """
        Returns a coroutine that can safely create unique user IDs based
        on the category set by the user. The keyword arguments refer to:

        ``category``: Any object sent by the user which identifies the
            category or context that the uuids are being made for, such
            as 'emails', 'unregistered_user', 'address'. It is up to the
            user, these categories distinguish the uuids created
            uniquely from other categories.
        ``size``: The length of the hex strings returned by this
            uuid generator.
        ``salt``: An optional random salt value of arbitrary type & size
            that, if passed, needs to be managed manually by the user.
            It provides entropy for the uuids created, which further
            distinguishes them, & provides resistance against certain
            kinds of hash cracking attacks. The salt can be retrieved by
            calling the ``result(exit=True)`` method of the returned
            ``Comprende`` generator.

        Usage Examples:

        import aiootp

        key = aiootp.csprng()
        db = aiootp.Database(key)

        responses = db.metatag("responses")
        uuids = responses.uuids("emails", salt=None)

        # Backup json data to the encrypted database ->
        for email_address in server.emails:
            uuid = uuids(email_address)
            responses[uuid] = server.responses[email_address]

        # Retrieve the random salt used to create the uuids ->
        responses["salt"] = uuids.result(exit=True)
        db.save()
        """

        @comprehension()
        def _uuids(salt=salt):
            """
            A programmable coroutine which creates unique user IDs
            that are specific to a particular category.
            """
            name = self.filename(category)
            uuids = make_uuids(size, salt=name).prime()
            salt = salt if salt else generate_salt()
            with uuids.relay(salt) as ids:
                stamp = None
                while True:
                    stamp = yield ids(sha_256(name, salt, stamp))

        return _uuids().prime()

    def _encryption_key(self, filename, salt):
        """
        Takes a ``filename`` & ``salt`` to contruct a unique symmetric
        cryptographic key.
        """
        domain = self._FILE_KEY
        key = self._root_seed
        payload = self.__root_salt + repr((salt, filename)).encode()
        return DomainKDF(domain, payload, key=key).sha3_512().hex()

    def bytes_encrypt(self, plaintext, *, filename=None):
        """
        Encrypts ``plaintext`` with keys specific to the ``filename``
        value.

        ``filename``:   This is the hashed tag that labels a piece of
            data in the database.
        ``plaintext``:  This is any bytes type object that's to be
            encrypted.
        """
        salt = generate_salt()
        key = self._encryption_key(filename, salt)
        return Chunky2048.bytes_encrypt(
            data=plaintext,
            key=key,
            salt=salt,
            allow_dangerous_determinism=True,
        )

    def json_encrypt(self, plaintext, *, filename=None):
        """
        Encrypts ``plaintext`` with keys specific to the ``filename``
        value.

        ``filename``:   This is the hashed tag that labels a piece of
            data in the database.
        ``plaintext``:  This is any json serializable object that is to
            be encrypted.
        """
        salt = generate_salt()
        key = self._encryption_key(filename, salt)
        return Chunky2048.json_encrypt(
            data=plaintext,
            key=key,
            salt=salt,
            allow_dangerous_determinism=True,
        )

    def bytes_decrypt(self, ciphertext, *, filename=None, ttl=0):
        """
        Decrypts ``ciphertext`` with keys specific to the ``filename``
        value.

        ``filename``:   This is the hashed tag that labels a piece of
            data in the database.
        ``ciphertext``: This is a dictionary of ciphertext.
        """
        salt = ciphertext["salt"]
        key = self._encryption_key(filename, salt)
        return Chunky2048.bytes_decrypt(data=ciphertext, key=key, ttl=ttl)

    def json_decrypt(self, ciphertext, *, filename=None, ttl=0):
        """
        Decrypts ``ciphertext`` with keys specific to the ``filename``
        value.

        ``filename``:   This is the hashed tag that labels a piece of
            data in the database.
        ``ciphertext``: This is a dictionary of ciphertext.
        """
        salt = ciphertext["salt"]
        key = self._encryption_key(filename, salt)
        return Chunky2048.json_decrypt(data=ciphertext, key=key, ttl=ttl)

    def _save_ciphertext(self, filename=None, ciphertext=None):
        """
        Saves the encrypted value ``ciphertext`` in the database file
        called ``filename``.
        """
        path = self.directory / filename
        self.io.write(path=path, ciphertext=ciphertext)

    def set(self, tag=None, data=None):
        """
        Allows users to add the value ``data`` under the name ``tag``
        into the database.
        """
        filename = self.filename(tag)
        self._cache[filename] = data
        self._manifest[filename] = tag

    def _query_ciphertext(self, filename=None, *, silent=False):
        """
        Retrieves the value stored in the database file that's called
        ``filename``.
        """
        try:
            path = self.directory / filename
            return self.io.read(path=path, encoding=self._ENCODING)
        except FileNotFoundError as corrupt_database:
            self._corrupted_files[filename] = True
            if not silent:
                raise corrupt_database

    def query(self, tag=None, *, silent=False):
        """
        Allows users to retrieve the value stored under the name ``tag``
        from the database.
        """
        filename = self.filename(tag)
        if filename in self._cache:
            return self._cache[filename]
        elif filename in self._manifest:
            ciphertext = self._query_ciphertext(filename, silent=silent)
            if not ciphertext and silent:
                return
            result = self.json_decrypt(ciphertext, filename=filename)
            self._cache[filename] = result
            return result

    def _delete_file(self, filename=None):
        """
        Deletes a file in the database directory by ``filename``.
        """
        try:
            (self.directory / filename).unlink()
        except FileNotFoundError:
            pass

    def pop(self, tag=None, *, admin=False):
        """
        Returns a value from the database by it's ``tag`` & deletes the
        associated file in the database directory.
        """
        filename = self.filename(tag)
        if filename in self._maintenance_files and not admin:
            raise PermissionError("Cannot delete maintenance files.")
        try:
            value = self.query(tag)
        except FileNotFoundError:
            value = None
        try:
            del self._manifest[filename]
        except KeyError:
            pass
        try:
            del self._cache[filename]
        except KeyError:
            pass
        self._delete_file(filename)
        return value

    def _metatag_key(self, tag=None):
        """
        Derives the metatag's database key given a user-defined ``tag``.
        """
        key = self.__root_salt
        domain = self._METATAG_KEY
        payload = self._root_seed + repr(tag).encode()
        return DomainKDF(domain, payload, key=key).sha3_512().hex()

    def metatag(self, tag=None, *, preload=True, silent=False):
        """
        Allows a user to create a child database with the name ``tag``
        accessible by dotted lookup from the parent database. Child
        databases are synchronized by their parents automatically.

        Usage Example:

        # Create a parent database ->
        key = aiootp.csprng()
        parent = Database(key)

        # Name the child database ->
        tag = "sub_database"
        child = await parent.ametatag(tag)

        # The child is now accessible from the parent by the tag ->
        assert child == parent.sub_database
        """
        if tag in self.__class__.__dict__:
            raise PermissionError("Can't overwrite class attributes.")
        elif tag in self.__dict__:
            if issubclass(self.__dict__[tag].__class__, self.__class__):
                return self.__dict__[tag]
            else:
                raise PermissionError("Can't overwrite object attributes.")
        self.__dict__[tag] = self.__class__(
            key=self._metatag_key(tag),
            password_depth=0,
            preload=preload,
            directory=self.directory,
            metatag=True,
            silent=silent,
        )
        if not tag in self.metatags:
            self.metatags.append(tag)
        return self.__dict__[tag]

    def delete_metatag(self, tag=None):
        """
        Removes the child database named ``tag``.
        """
        if tag not in self.metatags:
            raise FileNotFoundError(f"No child database named {tag}.")
        self.metatag(tag).delete_database()
        self.__dict__.pop(tag)
        self.metatags.remove(tag)

    def _nullify(self):
        """
        Clears the database's memory caches & instance variables of all
        values so a deleted database no longer makes changes to the
        filesystem.
        """
        self._manifest.namespace.clear()
        self._cache.namespace.clear()
        self.__dict__.clear()

    def delete_database(self):
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        for metatag in self.metatags:
            self.metatag(metatag, preload=False).delete_database()
        for filename in self._manifest.namespace:
            self._delete_file(filename)
        self._delete_file(self._root_salt_filename)
        self._nullify()

    def _encrypt_manifest(self, salt):
        """
        Takes a ``salt`` & returns the database's manifest encrypted.
        """
        manifest = self._manifest.namespace
        key = self._root_encryption_key(self._MANIFEST, salt)
        return json_encrypt(
            manifest, key=key, salt=salt, allow_dangerous_determinism=True
        )

    def _save_manifest(self, ciphertext=None):
        """
        Writes the manifest ledger to disk. It contains all database
        filenames & special cryptographic values for initializing the
        database's key derivation functions.
        """
        if not ciphertext:
            raise PermissionError("Invalid write attempted.")
        self.io.write(path=self._root_path, ciphertext=ciphertext)

    def _save_root_salt(self, salt):
        """
        Writes a non-metatag database instance's root salt to disk as a
        separate file.
        """
        key = self._root_encryption_key(self._SALT, salt=None)
        self.io.write(
            path=self._root_salt_path,
            ciphertext=json_encrypt(salt.hex(), key=key),
        )

    def _close_manifest(self):
        """
        Prepares for & writes the manifest ledger to disk. The manifest
        contains all database filenames & other metadata used to
        organize databases.
        """
        if not self._is_metatag:
            self._save_root_salt(self.__root_salt)
        manifest = self._encrypt_manifest(generate_salt())
        self._root_session_salt = manifest["salt"]
        self._save_manifest(manifest)

    def _save_file(self, filename=None, *, admin=False):
        """
        Writes the cached value for a user-specified ``filename`` to the
        user filesystem.
        """
        if not admin and filename in self._maintenance_files:
            raise PermissionError("Cannot edit maintenance files.")
        ciphertext = self.json_encrypt(
            self._cache[filename], filename=filename
        )
        self._save_ciphertext(filename, ciphertext)

    def _save_tags(self):
        """
        Writes the database's user-defined tags to disk.
        """
        maintenance_files = self._maintenance_files
        for filename in self._cache.namespace:
            if filename not in maintenance_files:
                self._save_file(filename)

    def _save_metatags(self):
        """
        Writes the database's child databases to disk.
        """
        for metatag in self.metatags:
            if self.__dict__.get(metatag):
                self.__dict__[metatag].save()

    def save_tag(self, tag=None, *, admin=False):
        """
        Writes the cached value for a user-specified ``tag`` to the user
        filesystem.
        """
        filename = self.filename(tag)
        try:
            self._save_file(filename, admin=admin)
        except AttributeError:
            raise FileNotFoundError("That tag file doesn't exist.")

    def save(self):
        """
        Writes the database's values to disk with transparent encryption.
        """
        if self._root_filename not in self._manifest:
            raise PermissionError("The database keys have been deleted.")
        self._close_manifest()
        self._save_metatags()
        self._save_tags()

    def into_namespace(self):
        """
        Returns a ``Namespace`` object of databases' tags & decrypted
        values. The tags are then accessible by dotted look-up on that
        namespace. This allows for orders of magnitude faster look-up
        times than square-bracket lookup on the database object.

        Usage example:

        key = aiootp.csprng()
        db = aiootp.Database(key)

        db["tag"] = ["value"]
        namespace = db.into_namespace()

        assert namespace.tag == ["value"]
        assert namespace.tag == db["tag"]
        assert namespace.tag is db["tag"]
        """
        return Namespace({tag: value for tag, value in self})

    def mirror_database(self, database=None):
        """
        Copies over all of the stored & loaded values, tags & metatags
        from the ``database`` object passed into this function.
        """
        if issubclass(database.__class__, self.__class__):
            for tag, value in database:
                self[tag] = value
        else:
            # Works with async databases, but doesn't load unloaded values
            for tag in database.tags:
                self[tag] = database[tag]
        for metatag in set(database.metatags):
            my_metatag = self.metatag(metatag)
            my_metatag.mirror_database(database.__dict__[metatag])

    def __contains__(self, tag=None):
        """
        Checks the cache & manifest for the filename associated with the
        user-defined ``tag``.
        """
        filename = self.filename(tag)
        return filename in self._manifest or filename in self._cache

    def __bool__(self):
        """
        Returns true if the instance dictionary is populated or the
        manifast is saved to the filesystem.
        """
        return bool(self.__dict__)

    def __enter__(self):
        """
        The context manager automatically writes database changes made
        by a user to disk.
        """
        return self

    def __exit__(self, exc_type=None, exc_value=None, traceback=None):
        """
        The context manager automatically writes database changes made
        by a user to disk.
        """
        self.save()

    def __iter__(self):
        """
        Provides an interface to the names & values stored in databases.
        """
        maintenance_files = self._maintenance_files
        for filename, tag in dict(self._manifest.namespace).items():
            if filename in maintenance_files:
                continue
            yield tag, self.query(tag, silent=self._silent)

    __delitem__ = pop
    __getitem__ = query
    __setitem__ = vars()["set"]
    __len__ = lambda self: (
        len(self._manifest) - len(self._maintenance_files)
    )


__extras = {
    "AsyncDatabase": AsyncDatabase,
    "Database": Database,
    "DomainKDF": DomainKDF,
    "Passcrypt": Passcrypt,
    "Chunky2048": Chunky2048,
    "StreamHMAC": StreamHMAC,
    "SyntheticIV": SyntheticIV,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "_axor_shortcuts": axor_shortcuts,
    "_xor_shortcuts": xor_shortcuts,
    "abytes_decrypt": abytes_decrypt,
    "abytes_encrypt": abytes_encrypt,
    "abytes_keys": abytes_keys,
    "abytes_xor": abytes_xor,
    "atest_key_and_salt": atest_key_and_salt,
    "ajson_decrypt": ajson_decrypt,
    "ajson_encrypt": ajson_encrypt,
    "akeypair_ratchets": akeypair_ratchets,
    "akeys": akeys,
    "amake_salt_non_deterministic": amake_salt_non_deterministic,
    "apadding_key": apadding_key,
    "apasscrypt": apasscrypt,
    "aplaintext_stream": aplaintext_stream,
    "axor": axor,
    "bytes_decrypt": bytes_decrypt,
    "bytes_encrypt": bytes_encrypt,
    "bytes_keys": bytes_keys,
    "bytes_xor": bytes_xor,
    "test_key_and_salt": test_key_and_salt,
    "json_decrypt": json_decrypt,
    "json_encrypt": json_encrypt,
    "keypair_ratchets": keypair_ratchets,
    "keys": keys,
    "make_salt_non_deterministic": make_salt_non_deterministic,
    "padding_key": padding_key,
    "passcrypt": passcrypt,
    "plaintext_stream": plaintext_stream,
    "xor": xor,
}


ciphers = Namespace.make_module("ciphers", mapping=__extras)

