# This file is part of aiootp, an asynchronous one-time-pad based crypto
# and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
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
    "OneTimePad",
    "Passcrypt",
    "Ropake",
    "AsyncDatabase",
    "Database",
]


__doc__ = """
A collection of low-level tools & higher level abstractions which can be
used to create custom security tools & provides a OneTimePad cipher.
"""


import math
import json
import asyncio
import builtins
from functools import wraps
from hashlib import sha3_512
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .__aiocontext import async_contextmanager
from .paths import *
from .paths import Path
from .asynchs import *
from .asynchs import Processes
from .commons import *
from .commons import NONE
from .randoms import is_prime
from .randoms import prev_prime
from .randoms import next_prime
from .randoms import salt, asalt
from .randoms import csprbg, acsprbg
from .randoms import csprng, acsprng
from .randoms import make_uuid, amake_uuid
from .generics import astr
from .generics import aiter
from .generics import anext
from .generics import arange
from .generics import BytesIO
from .generics import generics
from .generics import AsyncInit
from .generics import hash_bytes
from .generics import _zip, azip
from .generics import data, adata
from .generics import pick, apick
from .generics import cycle, acycle
from .generics import order, aorder
from .generics import birth, abirth
from .generics import unpack, aunpack
from .generics import ignore, aignore
from .generics import nc_512, anc_512
from .generics import nc_2048, anc_2048
from .generics import sha_256, asha_256
from .generics import sha_512, asha_512
from .generics import wait_on, await_on
from .generics import is_async_function
from .generics import lru_cache, alru_cache
from .generics import Comprende, comprehension
from .generics import json_encode, ajson_encode
from .generics import nc_512_hmac, anc_512_hmac
from .generics import sha_256_hmac, asha_256_hmac
from .generics import sha_512_hmac, asha_512_hmac
from .generics import json_to_bytes_encode
from .generics import ajson_to_bytes_encode
from .generics import pad_bytes, apad_bytes
from .generics import depad_bytes, adepad_bytes
from .generics import ascii_to_bytes_data as a2b_data
from .generics import aascii_to_bytes_data as aa2b_data


@comprehension()
async def axor(data=None, *, key=None):
    """
    'The one-time-stream algorithm'

    Gathers both an iterable of 256-byte integers of ``data``, & a
    non-repeating generator of deterministic string ``key`` material,
    then bitwise xors the streams together producing a one-time pad
    ciphertext 256 bytes long. The elements produced by the keystream
    will be concatenated with each other to reach exactly 256
    pseudo-random bytes.

    Restricting the ciphertext to a distinct size is a measure to
    protect the metadata of plaintext from adversaries that could make
    informed guesses of the plaintext given accurate sizes of its
    chunks. Also, this allows for the deterministic & reversible
    construction of bytestreams of ciphertext.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes or
    less per iteration or security WILL BE BROKEN by directly leaking
    plaintext.
    """
    keystream = key.asend
    seed = await asha_256(await keystream(None))
    async for chunk in data:
        key_chunk = int(await keystream(seed) + await keystream(seed), 16)
        result = chunk ^ key_chunk
        if result.bit_length() > 2048:
            raise ValueError("Data MUST NOT exceed 256 bytes.")
        yield result


@comprehension()
def xor(data=None, *, key=None):
    """
    'The one-time-stream algorithm'

    Gathers both an iterable of 256-byte integers of ``data``, & a
    non-repeating generator of deterministic string ``key`` material,
    then bitwise xors the streams together producing a one-time pad
    ciphertext 256 bytes long. The elements produced by the keystream
    will be concatenated with each other to reach exactly 256
    pseudo-random bytes.

    Restricting the ciphertext to a distinct size is a measure to
    protect the metadata of plaintext from adversaries that could make
    informed guesses of the plaintext given accurate sizes of its
    chunks. Also, this allows for the deterministic & reversible
    construction of bytestreams of ciphertext.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes or
    less per iteration or security WILL BE BROKEN by directly leaking
    plaintext.
    """

    keystream = key.send
    seed = sha_256(keystream(None))
    for chunk in data:
        key_chunk = int(keystream(seed) + keystream(seed), 16)
        result = chunk ^ key_chunk
        if result.bit_length() > 2048:
            raise ValueError("Data MUST NOT exceed 256 bytes.")
        yield result


@comprehension()
async def abytes_xor(data=None, *, key=None):
    """
    'The one-time-stream algorithm'

    Gathers both an iterable of 256-byte integers of ``data``, & a
    non-repeating generator of deterministic bytes ``key`` material,
    then bitwise xors the streams together producing a one-time pad
    ciphertext 256 bytes long. The elements produced by the keystream
    will be concatenated with each other to reach exactly 256
    pseudo-random bytes.

    Restricting the ciphertext to a distinct size is a measure to
    protect the metadata of plaintext from adversaries that could make
    informed guesses of the plaintext given accurate sizes of its
    chunks. Also, this allows for the deterministic & reversible
    construction of bytestreams of ciphertext.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes or
    less per iteration or security WILL BE BROKEN by directly leaking
    plaintext.
    """
    keystream = key.asend
    as_int = int.from_bytes
    seed = await asha_256((await keystream(None)).hex())
    async for chunk in data:
        key_chunk = as_int(
            await keystream(seed) + await keystream(seed), "big"
        )
        result = chunk ^ key_chunk
        if result.bit_length() > 2048:
            raise ValueError("Data MUST NOT exceed 256 bytes.")
        yield result


@comprehension()
def bytes_xor(data=None, *, key=None):
    """
    'The one-time-stream algorithm'

    Gathers both an iterable of 256-byte integers of ``data``, & a
    non-repeating generator of deterministic bytes ``key`` material,
    then bitwise xors the streams together producing a one-time pad
    ciphertext 256 bytes long. The elements produced by the keystream
    will be concatenated with each other to reach exactly 256
    pseudo-random bytes.

    Restricting the ciphertext to a distinct size is a measure to
    protect the metadata of plaintext from adversaries that could make
    informed guesses of the plaintext given accurate sizes of its
    chunks. Also, this allows for the deterministic & reversible
    construction of bytestreams of ciphertext.

    WARNING: ``data`` MUST produce plaintext in chunks of 256 bytes or
    less per iteration or security WILL BE BROKEN by directly leaking
    plaintext.
    """
    keystream = key.send
    as_int = int.from_bytes
    seed = sha_256(keystream(None).hex())
    for chunk in data:
        key_chunk = as_int(keystream(seed) + keystream(seed), "big")
        result = chunk ^ key_chunk
        if result.bit_length() > 2048:
            raise ValueError("Data MUST NOT exceed 256 bytes.")
        yield result


async def akeypair_ratchets(key=None, salt=None, pid=0):
    """
    Returns a 512-bit seed value & three ``hashlib.sha3_512`` objects
    that have been primed in different ways with the hash of the values
    passed in as arguments to the function. The returned values can be
    used to construct a keypair ratchet algorithm of the user's choosing.
    """
    seed_0 = sha3_512((await astr((key, salt, pid))).encode()).digest()
    seed_1 = sha3_512(str((key, salt, pid, seed_0)).encode()).digest()
    kdf_0 = sha3_512(seed_1 + seed_0)
    kdf_1 = sha3_512(kdf_0.digest() + seed_0)
    kdf_2 = sha3_512(kdf_1.digest() + seed_0)
    return seed_1, kdf_0, kdf_1, kdf_2


def keypair_ratchets(key=None, salt=None, pid=0):
    """
    Returns a 512-bit seed value & three ``hashlib.sha3_512`` objects
    that have been primed in different ways with the hash of the values
    passed in as arguments to the function. The returned values can be
    used to construct a keypair ratchet algorithm of the user's choosing.
    """
    seed_0 = sha3_512(str((key, salt, pid)).encode()).digest()
    seed_1 = sha3_512(str((key, salt, pid, seed_0)).encode()).digest()
    kdf_0 = sha3_512(seed_1 + seed_0)
    kdf_1 = sha3_512(kdf_0.digest() + seed_0)
    kdf_2 = sha3_512(kdf_1.digest() + seed_0)
    return seed_1, kdf_0, kdf_1, kdf_2


@comprehension()
async def akeys(key=csprng(), *, salt=None, pid=0):
    """
    An efficient async generator which produces an unending, non
    repeating, deterministc stream of string key material. Each
    iteration yields 256 hexidecimal characters, iteratively derived
    by the mixing & hashing the permutation of the kwargs, previous
    hashed results, & the ``entropy`` users may send into this generator
    as a coroutine. The ``key`` kwarg is meant to be a longer-term user
    key credential (should be a random 512-bit hex value), the ``salt``
    kwarg is meant to be ephemeral to each stream (also by default a
    random 256-bit hex value), and the user-defined ``pid`` can be used
    to safely parallelize key streams with the same ``key`` & ``salt``
    by specifying a unique ``pid`` to each process, thread or the like,
    which will result in a unique key stream for each.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    salt = salt if salt else (await acsprng())[:64]
    seed, kdf_0, kdf_1, kdf_2 = await akeypair_ratchets(key, salt, pid)
    async with Comprende.aclass_relay(salt):
        while True:
            ratchet = kdf_0.digest()
            kdf_1.update(ratchet)
            kdf_2.update(ratchet)
            entropy = yield kdf_1.hexdigest() + kdf_2.hexdigest()
            kdf_0.update(str(entropy).encode() + ratchet + seed)


@comprehension()
def keys(key=csprng(), *, salt=None, pid=0):
    """
    An efficient sync generator which produces an unending, non
    repeating, deterministc stream of string key material. Each
    iteration yields 256 hexidecimal characters, iteratively derived
    by the mixing & hashing the permutation of the kwargs, previous
    hashed results, & the ``entropy`` users may send into this generator
    as a coroutine. The ``key`` kwarg is meant to be a longer-term user
    key credential (should be a random 512-bit hex value), the ``salt``
    kwarg is meant to be ephemeral to each stream (also by default a
    random 256-bit hex value), and the user-defined ``pid`` can be used
    to safely parallelize key streams with the same ``key`` & ``salt``
    by specifying a unique ``pid`` to each process, thread or the like,
    which will result in a unique key stream for each.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    salt = salt if salt else csprng()[:64]
    seed, kdf_0, kdf_1, kdf_2 = keypair_ratchets(key, salt, pid)
    with Comprende.class_relay(salt):
        while True:
            ratchet = kdf_0.digest()
            kdf_1.update(ratchet)
            kdf_2.update(ratchet)
            entropy = yield kdf_1.hexdigest() + kdf_2.hexdigest()
            kdf_0.update(str(entropy).encode() + ratchet + seed)


@comprehension()
async def abytes_keys(key=csprng(), *, salt=None, pid=0):
    """
    An efficient async generator which produces an unending, non
    repeating, deterministc stream of bytes key material. Each
    iteration yields 256 bytes hexidecimal characters, iteratively
    derived by the mixing & hashing the permutation of the kwargs,
    previous hashed results, & the ``entropy`` users may send into this
    generator as a coroutine. The ``key`` kwarg is meant to be a
    longer-term user key credential (should be a random 512-bit hex
    value), the ``salt`` kwarg is meant to be ephemeral to each stream
    (also by default a random 256-bit hex value), and the user-defined
    ``pid`` can be used to safely parallelize key streams with the same
    ``key`` & ``salt`` by specifying a unique ``pid`` to each process,
    thread or the like, which will result in a unique key stream for
    each.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    salt = salt if salt else (await acsprng())[:64]
    seed, kdf_0, kdf_1, kdf_2 = await akeypair_ratchets(key, salt, pid)
    async with Comprende.aclass_relay(salt):
        while True:
            ratchet = kdf_0.digest()
            kdf_1.update(ratchet)
            kdf_2.update(ratchet)
            entropy = yield kdf_1.digest() + kdf_2.digest()
            kdf_0.update(str(entropy).encode() + ratchet + seed)


@comprehension()
def bytes_keys(key=csprng(), *, salt=None, pid=0):
    """
    An efficient sync generator which produces an unending, non
    repeating, deterministc stream of bytes key material. Each
    iteration yields 256 bytes hexidecimal characters, iteratively
    derived by the mixing & hashing the permutation of the kwargs,
    previous hashed results, & the ``entropy`` users may send into this
    generator as a coroutine. The ``key`` kwarg is meant to be a
    longer-term user key credential (should be a random 512-bit hex
    value), the ``salt`` kwarg is meant to be ephemeral to each stream
    (also by default a random 256-bit hex value), and the user-defined
    ``pid`` can be used to safely parallelize key streams with the same
    ``key`` & ``salt`` by specifying a unique ``pid`` to each process,
    thread or the like, which will result in a unique key stream for
    each.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    salt = salt if salt else csprng()[:64]
    seed, kdf_0, kdf_1, kdf_2 = keypair_ratchets(key, salt, pid)
    with Comprende.class_relay(salt):
        while True:
            ratchet = kdf_0.digest()
            kdf_1.update(ratchet)
            kdf_2.update(ratchet)
            entropy = yield kdf_1.digest() + kdf_2.digest()
            kdf_0.update(str(entropy).encode() + ratchet + seed)


async def acheck_key_and_salt(key, salt):
    """
    Validates the main symmetric user ``key`` & ephemeral ``salt`` for
    use in the one-time-pad cipher.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    elif not salt:
        raise ValueError("No ``salt`` was specified.")
    elif len(salt) != 64 or not int(salt, 16):
        raise ValueError("``salt`` must be a 256-bit hex string.")


def check_key_and_salt(key, salt):
    """
    Validates the main symmetric user ``key`` & ephemeral ``salt`` for
    use in the one-time-pad cipher.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    elif not salt:
        raise ValueError("No ``salt`` was specified.")
    elif len(salt) != 64 or not int(salt, 16):
        raise ValueError("``salt`` must be a 256-bit hex string.")


async def apadding_key(key=None, *, salt=None, pid=0):
    """
    Returns the salted & hashed key used for building the pseudo-random
    bytes that pad plaintext messages.
    """
    await acheck_key_and_salt(key, salt)
    return bytes.fromhex(await asha_512(pid, salt, key))


def padding_key(key=None, *, salt=None, pid=0):
    """
    Returns the salted & hashed key used for building the pseudo-random
    bytes that pad plaintext messages.
    """
    check_key_and_salt(key, salt)
    return bytes.fromhex(sha_512(pid, salt, key))


@comprehension()
async def aplaintext_stream(data=None, key=None, *, salt=None, pid=0):
    """
    Takes in plaintext bytes ``data``, pads the data to a multiple of
    256 bytes using the ``key``, ``salt`` & ``pid`` material to build
    the pseudo-random bytes. Yields 256 bytes of plaintext per iteration
    of this generator.
    """
    padded_data = await apad_bytes(
        data, salted_key=await apadding_key(key, salt=salt, pid=pid)
    )
    async for chunk in OneTimePad.adata.root(padded_data):
        yield chunk


@comprehension()
def plaintext_stream(data=None, key=None, *, salt=None, pid=0):
    """
    Takes in plaintext bytes ``data``, pads the data to a multiple of
    256 bytes using the ``key``, ``salt`` & ``pid`` material to build
    the pseudo-random bytes. Yields 256 bytes of plaintext per iteration
    of this generator.
    """
    padded_data = pad_bytes(
        data, salted_key=padding_key(key, salt=salt, pid=pid)
    )
    for chunk in OneTimePad.data.root(padded_data):
        yield chunk


async def ajson_encrypt(data=None, key=csprng(), *, salt=None, pid=0):
    """
    Returns a json ready dictionary containing one-time pad ciphertext
    of any json serializable ``data`` that's created from a key stream
    derived from permutations of these values:

    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   A 256-bit hexidecimal string of ephemeral entropic
                material whose str() representation contains the user's
                desired entropy & cryptographic strength.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes the values they
                produce. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    """
    return await abytes_encrypt(
        json.dumps(data).encode(), key=key, salt=salt, pid=pid,
    )


def json_encrypt(data=None, key=csprng(), *, salt=None, pid=0):
    """
    Returns a json ready dictionary containing one-time pad ciphertext
    of any json serializable ``data`` that's created from a key stream
    derived from permutations of these values:

    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   A 256-bit hexidecimal string of ephemeral entropic
                material whose str() representation contains the user's
                desired entropy & cryptographic strength.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes the values they
                produce. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    """
    return bytes_encrypt(
        json.dumps(data).encode(), key=key, salt=salt, pid=pid,
    )


async def ajson_decrypt(data=None, key=None, *, pid=0, ttl=0):
    """
    Returns the original plaintext from a json / dictionary containing
    ciphertext ``data`` that's created by xoring it with a key stream
    derived from a permutation of these values:

    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes the values they
                produce. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    """
    if type(data) != dict:
        data = json.loads(data)
    plaintext_bytes = await abytes_decrypt(data, key=key, pid=pid, ttl=ttl)
    return json.loads(plaintext_bytes.decode())


def json_decrypt(data=None, key=None, *, pid=0, ttl=0):
    """
    Returns the original plaintext from a json / dictionary containing
    ciphertext ``data`` that's created by xoring it with a key stream
    derived from a permutation of these values:

    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes the values they
                produce. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    """
    if type(data) != dict:
        data = json.loads(data)
    plaintext_bytes = bytes_decrypt(data, key, pid=pid, ttl=ttl)
    return json.loads(plaintext_bytes.decode())


async def abytes_encrypt(data=None, key=csprng(), *, salt=None, pid=0):
    """
    Returns a list of the encrypted one-time pad ciphertext of the
    binary ``data`` with a key stream derived from permutations of these
    values:

    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   A 256-bit hexidecimal string of ephemeral entropic
                material whose str() representation contains the user's
                desired entropy & cryptographic strength.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes the values they
                produce. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    """
    salt = salt if salt else csprng()[:64]
    await acheck_key_and_salt(key, salt)
    plaintext = aplaintext_stream(data, key, salt=salt, pid=pid)
    encrypting = plaintext.abytes_encrypt(key, salt=salt, pid=pid)
    async with encrypting as ciphertext:
        result = await ciphertext.alist(True)
        hmac = await validator.ahmac(result, key=key)
        return {"ciphertext": result, "hmac": hmac, "salt": salt}


def bytes_encrypt(data=None, key=csprng(), *, salt=None, pid=0):
    """
    Returns a list of the encrypted one-time pad ciphertext of the
    binary ``data`` with a key stream derived from permutations of these
    values:

    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   A 256-bit hexidecimal string of ephemeral entropic
                material whose str() representation contains the user's
                desired entropy & cryptographic strength.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes the values they
                produce. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    """
    salt = salt if salt else csprng()[:64]
    check_key_and_salt(key, salt)
    plaintext = plaintext_stream(data, key, salt=salt, pid=pid)
    encrypting = plaintext.bytes_encrypt(key, salt=salt, pid=pid)
    with encrypting as ciphertext:
        result = ciphertext.list(True)
        hmac = validator.hmac(result, key=key)
        return {"ciphertext": result, "hmac": hmac, "salt": salt}


async def abytes_decrypt(data=None, key=None, *, pid=0, ttl=0):
    """
    Returns the plaintext bytes of the one-time pad ciphertext ``data``
    with a key stream derived from permutations of these values:

    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes the values they
                produce. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    """
    hmac = data["hmac"]
    salt = data["salt"]
    data = data["ciphertext"]
    await validator.atest_hmac(data, key=key, hmac=hmac)
    decryptor = aunpack(data).abytes_decrypt(key, salt=salt, pid=pid)
    async with decryptor as decrypting:
        return await adepad_bytes(
            data=await decrypting.ajoin(b""),
            salted_key=await apadding_key(key, salt=salt, pid=pid),
            ttl=ttl,
        )


def bytes_decrypt(data=None, key=None, *, pid=0, ttl=0):
    """
    Returns the plaintext bytes of the one-time pad ciphertext ``data``
    with a key stream derived from permutations of these values:

    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes the values they
                produce. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    """
    hmac = data["hmac"]
    salt = data["salt"]
    data = data["ciphertext"]
    validator.test_hmac(data, key=key, hmac=hmac)
    decryptor = unpack(data).bytes_decrypt(key, salt=salt, pid=pid)
    with decryptor as decrypting:
        return depad_bytes(
            data=decrypting.join(b""),
            salted_key=padding_key(key, salt=salt, pid=pid),
            ttl=ttl,
        )


class Passcrypt:
    """
    This class is used to implement of an scrypt-like password-based key
    derivation function that is resistant to cache-timing side-channel
    attacks, & which requires a tunable amount of memory & cpu time to
    compute. The ``anew`` & ``new`` methods take a ``password`` & a
    random ``salt`` of any arbitrary size & type. The memory cost is
    measured in ``kb`` kilobytes. If the memory cost is too high, it
    will eat up all the ram on a machine very quickly. The ``cpu`` time
    cost is measured in the number of sha3_512 hashes & cache proofs
    calculated per element in the memory cache. By default, the
    algorithm costs 1MB to compute, & the number of hashes done is
    computed dynamically to reach the memory cost considering that 2
    extra hashes are added to the memory cache ``cpu`` times for each
    element in the cache.
    """

    salt = staticmethod(salt)
    asalt = staticmethod(asalt)

    def __call__(
        self, password, salt, *, kb=1024, cpu=3, hardness=1024, aio=False
    ):
        """
        Allows instances to use the call functionality to process a new
        job for the user & returns the hash.
        """
        settings = dict(kb=kb, cpu=cpu, hardness=hardness)
        if aio:
            return self.anew(password, salt, **settings)
        else:
            return self.new(password, salt, **settings)

    @staticmethod
    def _check_inputs(password: any, salt: any):
        if not password:
            raise ValueError("No ``password`` was specified.")
        elif not salt:
            raise ValueError("No ``salt`` was specified.")

    @staticmethod
    def _validate_args(kb: int, cpu: int, hardness: int):
        """
        Ensures the values ``kb``, ``cpu`` and ``hardness`` passed into
        this module's scrypt-like, password-based key derivation
        functions are within acceptable bounds & types. Then performs a
        calculation to determine how many iterations of the ``bytes_keys``
        generator will sum to the desired number of kilobytes, taking
        into account that for every element in that cache, 2 * ``cpu``
        number of extra sha3_512 hashes will be added to the cache as
        proofs of memory & work.
        """
        if hardness < 256 or not isinstance(hardness, int):
            raise ValueError(f"hardness:{hardness} must be int >= 256")
        elif cpu <= 1 or not isinstance(cpu, int):
            raise ValueError(f"cpu:{cpu} must be int >= 2")
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
        width = solve for build_iterations given cpu & kb
        """
        cls._validate_args(kb, cpu, hardness)
        width = int((kb * 1024) / (128 * (1 + cpu)))
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

                                        pseudo-random selection
                                                  |
            ram = |--------'----------------------'--------'--------|
                = |--------'----------------------'--------'--------|
                  |oooooooo'                               'xxxxxxxx|
                           |   ->                     <-   |
                         index                        reflection

                                   reflection
                                  <-   |
            ram = |-'------------------'-------'--------------------|
                = |-'------------------'-------'--------------------|
                  |o'oooooooooooooooooo'ooooxxx'xxxxxxxxxxxxxxxxxxxx|
                    |                  'xxxxooo'
            pseudo-random selection            |   ->
                                             index

               pseudo-random selection
                         |
            ram = |--'---'---------------------------------------'--|
                = |--'---'---------------------------------------'--|
                  |oo'ooo'ooooooooooooooooooxxxxxxxxxxxxxxxxxxxxx'xx|
                  |xx'xxx'xxxxxxxxxxxxxxxxxxooooooooooooooooooooo'oo|
                  |oo'                                           'xx|
                     |   ->                                 <-   |
                   index                                    reflection
                                           |
                                           |
                                           v Continue until there are
                                             2 * (cpu + 1) total layers
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
        next_index = cycle(range(cache_width)).__next__
        choose = lambda: ram[to_int(digest, "big") % cache_width]
        return keyed_scanner

    @classmethod
    async def _apasscrypt(
        cls, password, salt, *, kb=1024, cpu=3, hardness=1024
    ):
        """
        An async implementation of an scrypt-like password-based key
        derivation function which requires a tunable amount of memory &
        cpu time to compute. This method takes a ``password`` & a random
        ``salt`` of any arbitrary size & type. The memory cost is
        measured in ``kb`` kilobytes. If the memory cost is too high, it
        will eat up all the ram on a machine very quickly. The ``cpu``
        time cost is measured in the number of sha3_512 hashes done per
        element in the cache. By default, the algorithm costs 1MB to
        compute, & the number of hashes done is computed dynamically to
        reach the memory overhead considering that two extra hashes are
        added to the memory cache ``cpu`` times for each element in the
        cache. To fully prove use of memory, a simple rule for users is:
        if ``kb`` == ``hardness`` then ``cpu`` only needs to be set to 3,
        since that will cause the final proof to scan over the entire
        cache when producing the summary.
        """
        cls._check_inputs(password, salt)
        cache_width = cls.cache_width(kb, cpu, hardness)
        args = sha_512(password, salt, kb, cpu, hardness).encode()
        cache_builder = abytes_keys(password, salt=salt, pid=args)
        async with cache_builder[:cache_width] as cache:
            ram = await cache.alist(mutable=True)
            proof = sha3_512(ram[-1] + args)
            prove = cls._work_memory_prover(proof, ram, cpu)
            for element in ram:
                prove()
                await switch()
            final_proof = azip(ram[:hardness], reversed(ram))
            async with final_proof.asum_sha_256(proof.digest()) as summary:
                return await asha_512(await summary.alist(mutable=True))

    @classmethod
    def _passcrypt(cls, password, salt, *, kb=1024, cpu=3, hardness=1024):
        """
        A sync implementation of an scrypt-like password-based key
        derivation function which requires a tunable amount of memory &
        cpu time to compute. This method takes a ``password`` & a random
        ``salt`` of any arbitrary size & type. The memory cost is
        measured in ``kb`` kilobytes. If the memory cost is too high, it
        will eat up all the ram on a machine very quickly. The ``cpu``
        time cost is measured in the number of sha3_512 hashes done per
        element in the cache. By default, the algorithm costs 1MB to
        compute, & the number of hashes done is computed dynamically to
        reach the memory overhead considering that two extra hashes are
        added to the memory cache ``cpu`` times for each element in the
        cache. To fully prove use of memory, a simple rule for users is:
        if ``kb`` == ``hardness`` then ``cpu`` only needs to be set to 3,
        since that will cause the final proof to scan over the entire
        cache when producing the summary.
        """
        cls._check_inputs(password, salt)
        cache_width = cls.cache_width(kb, cpu, hardness)
        args = sha_512(password, salt, kb, cpu, hardness).encode()
        cache_builder = bytes_keys(password, salt=salt, pid=args)
        with cache_builder[:cache_width] as cache:
            ram = cache.list(mutable=True)
            proof = sha3_512(ram[-1] + args)
            prove = cls._work_memory_prover(proof, ram, cpu)
            for element in ram:
                prove()
            final_proof = _zip(ram[:hardness], reversed(ram))
            with final_proof.sum_sha_256(proof.digest()) as summary:
                return sha_512(summary.list(mutable=True))

    @classmethod
    async def anew(cls, password, salt, *, kb=1024, cpu=3, hardness=1024):
        """
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
        )

    @classmethod
    def new(cls, password, salt, *, kb=1024, cpu=3, hardness=1024):
        """
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
        )


@wraps(Passcrypt._apasscrypt)
async def apasscrypt(password, salt, *, kb=1024, cpu=3, hardness=1024):
    """
    Creates an async function which simplifies the ui/ux for users to
    access the module's implementation of an scrypt-like password-based
    key derivation function. It requires a tunable amount of memory &
    cpu time to compute. The function takes a ``password`` & a random
    ``salt`` of any arbitrary size & type. The memory cost is measured
    in ``kb`` kilobytes. If the memory cost is too high, it will eat up
    all the ram on a machine very quickly. The cpu time cost is measured
    in the ``cpu`` number of passes over the cache & iterations of
    ``sha3_512`` updates desired per element in the memory cache.
    """
    return await Passcrypt.anew(
        password, salt, kb=kb, cpu=cpu, hardness=hardness
    )


@wraps(Passcrypt._passcrypt)
def passcrypt(password, salt, *, kb=1024, cpu=3, hardness=1024):
    """
    Creates a function which simplifies the ui/ux for users to access
    the module's implementation of an scrypt-like password-based key
    derivation function. It requires a tunable amount of memory & cpu
    time to compute. The function takes a ``password`` & a random
    ``salt`` of any arbitrary size & type. The memory cost is measured
    in ``kb`` kilobytes. If the memory cost is too high, it will eat up
    all the ram on a machine very quickly. The cpu time cost is measured
    in the ``cpu`` number of passes over the cache & iterations of
    ``sha3_512`` updates desired per element in the memory cache.
    """
    return Passcrypt.new(
        password, salt, kb=kb, cpu=cpu, hardness=hardness
    )


class OneTimePad:
    """
    A class composed of the low-level procedures used to implement this
    package's one-time pad cipher, & the higher level interfaces for
    utilizing the one-time pad cipher. This cipher implementation is
    built entirely out of generators & the data processing pipelines
    that are made simple by this package's ``Comprende`` generators.
    """

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
        ## Do Not Uncomment:
        ## apasscrypt,  Instance passcrypt methods use the instance key
        ## passcrypt,   to further protect processed passwords.

        ## ahmac,       Instances can also validate data with hmac
        ## hmac,        methods that are automatically passed the
        ## atest_hmac,  instance key to do the hashing & validation.
        ## test_hmac,
    }

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
    asalt = staticmethod(asalt)
    salt = staticmethod(salt)
    acsprbg = staticmethod(acsprbg)
    csprbg = staticmethod(csprbg)
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

    @comprehension()
    async def _amap_encrypt(self, names=None, keystream=None):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, async one-time-pad encryption algorithm, while also
        keeping some encapsulation of code and functionality.

        When ``names`` is a stream of deterministic key material, this
        algorithm produces a hashmap of ciphertext, such that without
        the key material used to derive the stream, ordering the chunks
        of ciphertext correctly is a guessing game.

        ``keystream`` should be an async ``Comprende`` generator which,
        like ``aiootp.akeys``, yields a stream key material from some
        source key material and a random salt >= 256-bits.

        ``self`` is an instance of a ``Comprende`` generator that yields
        256 or less plaintext bytes per iteration.

        WARNING: ``self`` MUST produce plaintext in chunks of 256 bytes
        or less per iteration or security WILL BE BROKEN by directly
        leaking plaintext.
        """
        data = self.abytes_to_int()
        async for name, ciphertext in axor(data, key=keystream).atag(names):
            yield name, ciphertext

    @comprehension()
    def _map_encrypt(self, names=None, keystream=None):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, sync one-time-pad encryption algorithm, while also
        keeping some encapsulation of code and functionality.

        When ``names`` is a stream of deterministic key material, this
        algorithm produces a hashmap of ciphertext, such that without
        the key material used to derive the stream, ordering the chunks
        of ciphertext correctly is a guessing game.

        ``keystream`` should be an sync ``Comprende`` generator which,
        like ``aiootp.keys``, yields a stream key material from some
        source key material and a random salt >= 256-bits.

        ``self`` is an instance of a ``Comprende`` generator that yields
        256 or less plaintext bytes per iteration.

        WARNING: ``self`` MUST produce plaintext in chunks of 256 bytes
        or less per iteration or security WILL BE BROKEN by directly
        leaking plaintext.
        """
        data = self.bytes_to_int()
        for name, ciphertext in xor(data, key=keystream).tag(names):
            yield name, ciphertext

    @comprehension()
    async def _amap_decrypt(self, keystream=None):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, async one-time-pad decryption algorithm, while also
        keeping some encapsulation of code and functionality.

        ``keystream`` should be an async ``Comprende`` generator which,
        like ``aiootp.akeys``, yields a stream key material from some
        source key material and a random salt >= 256-bits. The salt must
        be the same as the one used for encryption.

        ``self`` is an instance of an async ``Comprende`` generator that
        yields a chunk of ciphertext in the correct order each iteration.
        ``keystream`` is the async ``Comprende`` generator that produces
        the same key material stream used during encryption.
        """
        async for plaintext in axor.root(data=self, key=keystream):
            yield plaintext.to_bytes(256, "big")

    @comprehension()
    def _map_decrypt(self, keystream=None):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, sync one-time-pad decryption algorithm, while also
        keeping some encapsulation of code and functionality.

        ``keystream`` should be an sync ``Comprende`` generator which,
        like ``aiootp.keys``, yields a stream key material from some
        source key material and a random salt >= 256-bits. The salt must
        be the same as the one used for encryption.

        ``self`` is an instance of an sync ``Comprende`` generator that
        yields a chunk of ciphertext in the correct order each iteration.
        ``keystream`` is the sync ``Comprende`` generator that produces
        the same key material stream used during encryption.
        """
        for plaintext in xor.root(data=self, key=keystream):
            yield plaintext.to_bytes(256, "big")

    @comprehension()
    async def _aotp_encrypt(self, key=csprng(), *, salt=None, pid=0):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, async one-time-pad encryption algorithm, while also
        keeping some encapsulation of code and functionality.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all async generators
        that are decorated with ``comprehension`` can encrypt the
        plaintext str type strings it yields.

        The ``key`` keyword is the user's main encryption / decryption
        key for any particular context.

        The ``salt`` keyword should be a random 256-bit hash. It's used
        as an ephemeral key to initialize a deterministc & unique stream
        of key material.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.

        WARNING: ``self`` MUST produce plaintext in chunks of 256 bytes
        or less per iteration or security WILL BE BROKEN by directly
        leaking plaintext.
        """
        data = self.aencode()
        encrypting = data.abytes_encrypt(key=key, salt=salt, pid=pid)
        async for ciphertext in encrypting:
            yield ciphertext
        raise UserWarning(await encrypting.aresult())

    @comprehension()
    def _otp_encrypt(self, key=csprng(), *, salt=None, pid=0):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, one-time-pad encryption algorithm, while also
        keeping some encapsulation of code and functionality.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all generators that
        are decorated with ``comprehension`` can encrypt the plaintext
        str type strings it yields.

        The ``key`` keyword is the user's main encryption / decryption
        key for any particular context.

        The ``salt`` keyword should be a random 256-bit hash. It's used
        as an ephemeral key to initialize a deterministc & unique stream
        of key material.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.

        WARNING: ``self`` MUST produce plaintext in chunks of 256 bytes
        or less per iteration or security WILL BE BROKEN by directly
        leaking plaintext.
        """
        data = self.encode()
        encrypting = data.bytes_encrypt(key=key, salt=salt, pid=pid)
        for ciphertext in encrypting:
            yield ciphertext
        return encrypting.result()

    @comprehension()
    async def _aotp_decrypt(self, key=csprng(), *, salt=None, pid=0):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, async one-time-pad decryption algorithm, while also
        keeping some encapsulation of code and functionality.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all async generators
        that are decorated with ``comprehension`` can decrypt valid
        streams of one-time-pad encrypted ciphertext.

        The ``key`` keyword is the user's main encryption / decryption
        key. The salt is a random 256-bit hash which is used as an
        ephemeral key to initialize a deterministc & unique stream of
        key material.

        The ``salt`` keyword should be a random 256-bit hash. It's used
        as an ephemeral key to initialize a deterministc & unique stream
        of key material.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.
        """
        decrypting = self.abytes_decrypt(key=key, salt=salt, pid=pid)
        async for plaintext in decrypting:
            yield plaintext.decode()

    @comprehension()
    def _otp_decrypt(self, key=csprng(), *, salt=None, pid=0):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, one-time-pad decryption algorithm, while also
        keeping some encapsulation of code and functionality.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all generators that
        are decorated with ``comprehension`` can decrypt valid streams
        of one-time-pad encrypted ciphertext.

        The ``key`` keyword is the user's main encryption / decryption
        key. The salt is a random 256-bit hash which is used as an
        ephemeral key to initialize a deterministc & unique stream of
        key material.

        The ``salt`` keyword should be a random 256-bit hash. It's used
        as an ephemeral key to initialize a deterministc & unique stream
        of key material.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.
        """
        decrypting = self.bytes_decrypt(key=key, salt=salt, pid=pid)
        for plaintext in decrypting:
            yield plaintext.decode()

    @comprehension()
    async def _abytes_encrypt(self, key=csprng(), *, salt=None, pid=0):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, one-time-pad encryption algorithm for binary data,
        while also keeping some encapsulation of code and functionality.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all async generators
        that are decorated with ``comprehension`` can encrypt the
        plaintext bytes type strings it yields.

        The ``key`` keyword is the user's main encryption / decryption
        key for any particular context.

        The ``salt`` keyword should be a random 256-bit hash. It's used
        as an ephemeral key to initialize a deterministc & unique stream
        of key material.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.

        WARNING: ``self`` MUST produce plaintext in chunks of 256 bytes
        or less per iteration or security WILL BE BROKEN by directly
        leaking plaintext.
        """
        keystream = abytes_keys.root(key=key, salt=salt, pid=pid)
        encrypting = abytes_xor.root(self.abytes_to_int(), key=keystream)
        async for result in encrypting:
            yield result
        await keystream.athrow(UserWarning)

    @comprehension()
    def _bytes_encrypt(self, key=csprng(), *, salt=None, pid=0):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, one-time-pad encryption algorithm for binary data,
        while also keeping some encapsulation of code and functionality.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all generators that
        are decorated with ``comprehension`` can encrypt the plaintext
        bytes type strings it yields.

        The ``key`` keyword is the user's main encryption / decryption
        key for any particular context.

        The ``salt`` keyword should be a random 256-bit hash. It's used
        as an ephemeral key to initialize a deterministc & unique stream
        of key material.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.

        WARNING: ``self`` MUST produce plaintext in chunks of 256 bytes
        or less per iteration or security WILL BE BROKEN by directly
        leaking plaintext.
        """
        keystream = bytes_keys.root(key=key, salt=salt, pid=pid)
        encrypting = bytes_xor.root(self.bytes_to_int(), key=keystream)
        for result in encrypting:
            yield result
        keystream.throw(UserWarning)

    @comprehension()
    async def _abytes_decrypt(self, key=None, *, salt=None, pid=0):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, one-time-pad decryption algorithm for binary data,
        while also keeping some encapsulation of code and functionality.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all async generators
        that are decorated with ``comprehension`` can decrypt valid
        streams of one-time-pad encrypted ciphertext of bytes type data.

        The ``key`` keyword is the user's main encryption / decryption
        key for any particular context.

        The ``salt`` keyword should be a random 256-bit hash. It's used
        as an ephemeral key to initialize a deterministc & unique stream
        of key material.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.
        """
        keystream = abytes_keys.root(key=key, salt=salt, pid=pid)
        decrypting = abytes_xor.root(self, key=keystream)
        async for plaintext in decrypting:
            yield plaintext.to_bytes(256, "big")

    @comprehension()
    def _bytes_decrypt(self, key=None, *, salt=None, pid=0):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, one-time-pad decryption algorithm for binary data,
        while also keeping some encapsulation of code and functionality.

        Once copied, the ``self`` argument becomes a reference to an
        instance of ``Comprende``. With that, now all generators that
        are decorated with ``comprehension`` can decrypt valid streams
        of one-time-pad encrypted ciphertext of bytes type data.

        The ``key`` keyword is the user's main encryption / decryption
        key for any particular context.

        The ``salt`` keyword should be a random 256-bit hash. It's used
        as an ephemeral key to initialize a deterministc & unique stream
        of key material.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.
        """
        keystream = bytes_keys.root(key=key, salt=salt, pid=pid)
        decrypting = bytes_xor.root(self, key=keystream)
        for plaintext in decrypting:
            yield plaintext.to_bytes(256, "big")


class AsyncDatabase(metaclass=AsyncInit):
    """
    This class creates databases which enable the disk persistence of
    any json serializable, native python data-types, with fully
    transparent & asynchronous encryption / decryption using the
    one-time-pad cipher.


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
    asalt = staticmethod(asalt)
    _METATAG = commons.METATAG
    _MANIFEST = commons.MANIFEST
    _ENCODING = io.LIST_ENCODING
    _NO_PROFILE_OR_CORRUPT = commons.NO_PROFILE_OR_CORRUPT

    @classmethod
    async def aprofile_exists(cls, tokens):
        """
        Tests if a profile that ``tokens`` would open has saved a salt
        file on the user filesystem. Retruens false if not.
        """
        filename = await paths._adeniable_filename(tokens._bytes_key)
        path = (DatabasePath() / "secure") / filename
        return path.exists()

    @classmethod
    async def agenerate_profile_tokens(
        cls,
        username,
        password,
        *credentials,
        salt=None,
        kb=32768,
        cpu=3,
        hardness=1024,
    ):
        """
        Runs a very expensive key derivation function to build keys
        for users to open a database with only access to potentially
        weakly entropic credentials & the filesystem.
        """
        uuid = await asha_512(username, password, *credentials, salt)
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
    async def agenerate_profile(cls, tokens):
        """
        Creates & loads a profile database for a user from the ``tokens``
        passed in.
        """
        await cls._agenerate_profile_salt(tokens)
        await cls._agenerate_profile_login_key(tokens)
        tokens.profile = await cls(
            key=tokens._login_key, password_depth=10000
        )
        await tokens.profile.asave()
        return tokens.profile

    @classmethod
    async def aload_profile(cls, tokens):
        """
        Loads a profile database for a user from the ``tokens`` passed
        in. Throws ``LookupError`` if the profile has not yet been
        generated.
        """
        if not await cls.aprofile_exists(tokens):
            raise LookupError(cls._NO_PROFILE_OR_CORRUPT)
        return await cls.agenerate_profile(tokens)

    @classmethod
    async def adelete_profile(cls, tokens):
        """
        Deletes the profile's salt saved on the filesystem & all of its
        database files.
        """
        try:
            await tokens.profile.adelete_database()
        except AttributeError:
            await cls.aload_profile(tokens)
            await tokens.profile.adelete_database()
        tokens._salt_path.unlink()

    async def __init__(
        self,
        key=None,
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
        root keys.

        ``preload``:    This boolean value tells the object to -- True --
            load all of the stored database values from the filesystem
            into the cache during initialization, or -- False -- skip
            the loading stage.

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
        """
        self._silent = silent
        self._cache = Namespace()
        self._manifest = Namespace()
        self.directory = Path(directory)
        self._root_key, self._root_hash, self._root_filename = (
            await self._ainitialize_keys(key, password_depth)
        )
        if metatag:
            self._is_metatag = True
        else:
            self._is_metatag = False
        await self._aload_manifest()
        await self._ainitialize_metatags()
        if preload:
            await self.aload(silent=silent)

    @staticmethod
    async def _ainitialize_keys(key=None, password_depth=0):
        """
        Derives the database's cryptographic root key material and the
        filename of the manifest ledger.
        """
        root_key = await akeys(key, salt=key, pid=key)[password_depth]()
        root_hash = await asha_512_hmac(root_key, key=root_key)
        root_filename = await asha_256_hmac(root_hash, key=root_hash)
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
            del database[filename]
        return list(database.values())

    async def _aroot_encryption_key(self, filename, salt):
        """
        Takes a ``filename`` & ``salt`` to construct a unique symmetric
        cryptographic key with preliminary database key material.
        """
        return await asha_512_hmac(
            (filename, self._root_key, salt), key=self._root_hash
        )

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

    async def _acreate_salting_function(self, salt=None):
        """
        Creates and returns an async function for the instance to
        retrieve a cryptographic ``salt`` key. If the instance is a
        metatag child database, then the returned key is assumed to not
        have been stored encrypted. Otherwise, the ``salt`` is assumed
        to be encrypted, and is decrypted within the created function.
        """
        instance_hash = sha_256_hmac(
            (hash(self), salt), key=self._root_hash
        )

        @alru_cache()
        async def __aroot_salt(database=instance_hash):
            """
            Keeps the ``root_salt`` tucked away until queried, where
            then it's cached for efficiency.
            """
            if self._is_metatag:
                return salt
            else:
                return await ajson_decrypt(salt, self._root_key)

        return __aroot_salt

    async def _ainstall_root_salt(
        self, root_salt=None, *, auto_encrypt=True
    ):
        """
        Resets & inserts the database's root entropy source in the
        manifest ledger & the instance's caches of keys. Tags & metatags
        not loaded into the cache will be unretrievable without the
        root_salt that is replaced in this function.
        """
        salt = (
            root_salt
            if self._is_metatag or not auto_encrypt
            else await ajson_encrypt(root_salt, self._root_key)
        )
        self._manifest[self._root_filename] = salt
        self.__aroot_salt = await self._acreate_salting_function(salt)
        self._root_seed = await asha_512_hmac(
            await self.__aroot_salt(), self._root_key
        )

    async def _aload_manifest(self):
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """
        if self._root_path.exists():
            self._manifest = Namespace(await self._aopen_manifest())
            root_salt = self._manifest[self._root_filename]
        else:
            self._manifest = Namespace()
            self._root_session_salt = await asalt()
            if self._is_metatag:
                root_salt = await asalt()
            else:
                root_salt = await ajson_encrypt(csprng(), self._root_key)

        await self._ainstall_root_salt(root_salt, auto_encrypt=False)

    async def _asave_manifest(self, ciphertext=None):
        """
        Writes the manifest ledger to disk. It contains all database
        filenames & special cryptographic values for initializing the
        database's key derivation functions.
        """
        if not ciphertext:
            raise PermissionError("Invalid write attempted.")
        await self.io.awrite(path=self._root_path, ciphertext=ciphertext)

    async def _aencrypt_manifest(self, salt):
        """
        Takes a ``salt`` & returns the database's manifest encrypted.
        """
        manifest = self._manifest.namespace
        key = await self._aroot_encryption_key(self._MANIFEST, salt)
        return await ajson_encrypt(manifest, key=key, salt=salt)

    async def _aclose_manifest(self):
        """
        Prepares for & writes the manifest ledger to disk. The manifest
        contains all database filenames & special cryptographic values
        for initializing the database's key derivation functions.
        """
        salt = self._root_session_salt = await asalt()
        manifest = await self._aencrypt_manifest(salt)
        await self._asave_manifest(manifest)

    async def aload_metatags(self, *, preload=True, silent=False):
        """
        Specifically loads all of the database's metatag values into the
        cache. If the ``preload`` keyword argument is falsey then the
        metatag references are populated in the database's instance
        dictionary, but their internal values are not loaded.
        """
        await gather(
            *[
                self.ametatag(metatag, preload=preload, silent=silent)
                for metatag in set(self.metatags)
            ],
            return_exceptions=True,
        )

    async def aload_tags(self, silent=False):
        """
        Specifically loads all of the database's tag values into the
        cache.
        """
        database = dict(self._manifest.namespace)
        for maintenance_file in self._maintenance_files:
            del database[maintenance_file]
        await gather(
            *[
                self.aquery(tag, silent=silent)
                for filename, tag in database.items()
            ],
            return_exceptions=True,
        )

    async def aload(self, *, metatags=True, silent=False):
        """
        Loads all the database object's values from the filesystem into
        the database cache. This brings the database values into the
        cache, enables up-to-date bracket lookup of tag values & dotted
        lookup of metatags. Otherwise, values would have to be queried
        using the awaitable ``aquery`` & ``ametatag`` methods.
        """
        await gather(
            self.aload_metatags(preload=metatags, silent=silent),
            self.aload_tags(silent=silent),
            return_exceptions=True,
        )
        return self

    async def afilename(self, tag=None):
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        return await asha_256_hmac(
            (tag, self._root_seed), key=self._root_hash
        )

    async def ahmac(self, *data):
        """
        Creates an HMAC hash of the arguments passed into ``*data`` with
        keys derived from the key used to open the database instance.
        """
        return await asha_256_hmac(
            (data, self._root_hash), key=self._root_seed
        )

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
        true_hmac = await self.ahmac(*data)
        if await validator.atime_safe_equality(hmac, true_hmac):
            return True
        else:
            raise ValueError("HMAC of ``data`` isn't valid.")

    async def apasscrypt(
        self, password, salt, *, kb=1024, cpu=3, hardness=1024
    ):
        """
        An implementation of an scrypt-like password derivation function
        which requires a tunable amount of memory & cpu time to compute.
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
        salted_password = await self.ahmac(password, salt)
        return await OneTimePad.apasscrypt(
            salted_password, salt, kb=kb, cpu=cpu, hardness=hardness
        )

    async def auuids(self, category=None, size=16, salt=None):
        """
        Returns an async coroutine that can safely create unique user
        IDs based on the category set by the user. The keyword arguments
        refer to:

        ``category``    Any object sent by the user which identifies the
            category or context that the uuids are being made for, such
            as 'emails', 'unregistered_user', 'address'. It is up to the
            user, these categories distinguish the uuids created
            uniquely from other categories.
        ``size``        The length of the hex strings returned by this
            uuid generator.
        ``salt``        An optional random salt value of arbitrary type &
            size that, if passed needs to be managed manually by the
            user. It provides entropy into the uuids created, further
            distinguishing them, and provides resistance against certain
            kinds of hash cracking attacks. The salt can be by calling
            the ``result(exit=True)`` method of the returned ``Comprende``
            generator.

        Usage Examples:

        import aiootp

        db = await aiootp.AsyncDatabase(
            key="regular shared solo minutes", password_depth=6000
        )
        responses = await db.ametatag("responses")
        uuids = await responses.auuids("emails", salt=server.salt)

        # Backup json data to the encrypted database ->
        for email_address in server.emails:
            uuid = await uuids(email_address)
            responses[uuid] = server.responses[email_address]

        await db.asave()
        """

        @comprehension()
        async def _auuids(salt=salt):
            """
            A programmable async coroutine which creates unique user IDs
            that are specific to a particular category.
            """
            name = await self.afilename(category)
            uuids = await amake_uuid(size, salt=name).aprime()
            salt = salt if salt else csprng()[:64]
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
        return await asha_512_hmac(
            (filename, salt), key=await self.ahmac(filename, salt),
        )

    async def abytes_decrypt(self, filename, ciphertext, ttl=0):
        """
        Decrypts ``ciphertext`` with keys specific to a the ``filename``
        value.

        ``filename``    This is the hashed tag that labels a piece of
            data in the database.
        ``ciphertext``  This is a dictionary of ciphertext.
        """
        salt = ciphertext["salt"]
        key = await self._aencryption_key(filename, salt)
        return await abytes_decrypt(ciphertext, key=key, ttl=ttl)

    async def adecrypt(self, filename, ciphertext, ttl=0):
        """
        Decrypts ``ciphertext`` with keys specific to a the ``filename``
        value.

        ``filename``    This is the hashed tag that labels a piece of
            data in the database.
        ``ciphertext``  This is a dictionary of ciphertext.
        """
        salt = ciphertext["salt"]
        key = await self._aencryption_key(filename, salt)
        return await ajson_decrypt(ciphertext, key=key, ttl=ttl)

    async def abytes_encrypt(self, filename, plaintext):
        """
        Encrypts ``plaintext`` with keys specific to a the ``filename``
        value.

        ``filename``    This is the hashed tag that labels a piece of
            data in the database.
        ``plaintext``   This is any json serializable object that is to
            be encrypted.
        """
        salt = (await acsprng())[:64]
        key = await self._aencryption_key(filename, salt)
        return await abytes_encrypt(plaintext, key=key, salt=salt)

    async def aencrypt(self, filename, plaintext):
        """
        Encrypts ``plaintext`` with keys specific to a the ``filename``
        value.

        ``filename``    This is the hashed tag that labels a piece of
            data in the database.
        ``plaintext``   This is any json serializable object that is to
            be encrypted.
        """
        salt = (await acsprng())[:64]
        key = await self._aencryption_key(filename, salt)
        return await ajson_encrypt(plaintext, key=key, salt=salt)

    async def aset(self, tag=None, data=None):
        """
        Allows users to add the value ``data`` under the name ``tag``
        into the database.
        """
        filename = await self.afilename(tag)
        self._cache[filename] = data
        self._manifest[filename] = tag

    async def aquery(self, tag=None, silent=False):
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
            result = await self.adecrypt(filename, ciphertext)
            self._cache[filename] = result
            return result

    async def apop(self, tag=None):
        """
        Returns a value from the database by it's ``tag`` & deletes the
        associated file in the database directory.
        """
        filename = await self.afilename(tag)
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

    async def _ainitialize_metatags(self):
        """
        Initializes the values that organize database metatags, which
        are children databases contained within their parent.
        """
        self._metatags_filename = await self.afilename(self._METATAG)
        if self.metatags == None:
            self._manifest[self._metatags_filename] = []

    @property
    def metatags(self):
        """
        Returns the list of metatags that a database contains.
        """
        return self._manifest.namespace.get(self._metatags_filename)

    async def _ametatag_key(self, tag=None):
        """
        Derives the metatag's database key given a user-defined ``tag``.
        """
        return await asha_512_hmac((tag, self._root_seed), self._root_hash)

    async def ametatag(self, tag=None, preload=True, silent=False):
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
        await (await self.ametatag(tag)).adelete_database()
        self.__dict__.pop(tag)
        self.metatags.remove(tag)

    async def _asave_metatags(self):
        """
        Writes the database's child databases to disk.
        """
        for metatag in set(self.metatags):
            if self.__dict__.get(metatag):
                await self.__dict__[metatag].asave()

    async def asave_tag(self, tag=None, *, admin=False):
        """
        Writes the cached value for a user-specified ``tag`` to the user
        filesystem.
        """
        filename = await self.afilename(tag)
        await self._asave_file(filename, admin=admin)

    async def _asave_tags(self):
        """
        Writes the database's user-defined tags to disk.
        """
        maintenance_files = self._maintenance_files
        for filename in self._cache.namespace:
            if filename in maintenance_files:
                continue
            await self._asave_file(filename, admin=True)

    async def _adelete_file(self, filename=None):
        """
        Deletes a file in the database directory by ``filename``.
        """
        try:
            await asynchs.aos.remove(self.directory / filename)
        except FileNotFoundError:
            pass

    async def _asave_file(self, filename=None, *, admin=False):
        """
        Writes the cached value for a user-specified ``filename`` to the
        user filesystem.
        """
        if not admin and filename in self._maintenance_files:
            raise PermissionError("Cannot edit maintenance files.")
        ciphertext = await self.aencrypt(filename, self._cache[filename])
        await self._asave_ciphertext(filename, ciphertext)

    async def _aquery_ciphertext(self, filename=None, silent=False):
        """
        Retrieves the value stored in the database file that's called
        ``filename``.
        """
        try:
            path = self.directory / filename
            return await self.io.aread(path=path, encoding=self._ENCODING)
        except FileNotFoundError as corrupt_database:
            if not silent:
                raise corrupt_database

    async def _asave_ciphertext(self, filename=None, ciphertext=None):
        """
        Saves the encrypted value ``ciphertext`` in the database file
        called ``filename``.
        """
        path = self.directory / filename
        await self.io.awrite(path=path, ciphertext=ciphertext)

    async def adelete_database(self):
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        for metatag in self.metatags:
            await (await self.ametatag(metatag)).adelete_database()
        for filename in self._manifest.namespace:
            await self._adelete_file(filename)
        self._cache.namespace.clear()
        self._manifest.namespace.clear()

    async def asave(self):
        """
        Writes the database's values to disk.
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
        async with aunpack(self) as namespace:
            return Namespace(await namespace.adict())

    async def amirror_database(self, database=None):
        """
        Takes a ``Database`` object & copies over all if its loaded &
        stored values, tags & metatags.
        """
        my_metatags = self.metatags
        its_metatags = aunpack(set(database.metatags))
        my_metatags += [
            tag async for tag in its_metatags if tag not in my_metatags
        ]
        async for tag, value in aunpack(database):
            filename = await self.afilename(tag)
            self._cache[filename] = value
            self._manifest[filename] = tag
        async for metatag in its_metatags:
            my_metatag = await self.ametatag(metatag)
            await my_metatag.amirror_database(database.__dict__[metatag])

    def __contains__(self, tag=None):
        """
        Checks the cache & manifest for the filename associated with the
        user-defined ``tag``.
        """
        filename = sha_256_hmac((tag, self._root_seed), self._root_hash)
        return filename in self._manifest or filename in self._cache

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
        filename = sha_256_hmac((tag, self._root_seed), self._root_hash)
        self._cache[filename] = data
        self._manifest[filename] = tag

    def __getitem__(self, tag=None):
        """
        Allows users to retrieve the value stored under the name ``tag``
        from the database.
        """
        filename = sha_256_hmac((tag, self._root_seed), self._root_hash)
        if filename in self._cache:
            return self._cache[filename]

    def __delitem__(self, tag=None):
        """
        Allows users to delete the value stored under the name ``tag``
        from the database.
        """
        filename = sha_256_hmac((tag, self._root_seed), self._root_hash)
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

    __len__ = lambda self: len(self._manifest.namespace)


class Database:
    """
    This class creates databases which enable the disk persistence of
    any json serializable, native python data-types, with fully
    transparent & asynchronous encryption / decryption using the
    one-time-pad cipher.


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
    salt = staticmethod(salt)
    _METATAG = commons.METATAG
    _MANIFEST = commons.MANIFEST
    _ENCODING = io.LIST_ENCODING
    _NO_PROFILE_OR_CORRUPT = commons.NO_PROFILE_OR_CORRUPT

    @classmethod
    def profile_exists(cls, tokens):
        """
        Tests if a profile that ``tokens`` would open has saved a salt
        file on the user filesystem. Retruens false if not.
        """
        filename = paths._deniable_filename(tokens._bytes_key)
        path = (DatabasePath() / "secure") / filename
        return path.exists()

    @classmethod
    def generate_profile_tokens(
        cls,
        username,
        password,
        *credentials,
        salt=None,
        kb=32768,
        cpu=3,
        hardness=1024,
    ):
        """
        Runs a very expensive key derivation function to build keys
        for users to open a database with only access to potentially
        weakly entropic credentials & the filesystem.
        """
        uuid = sha_512(username, password, *credentials, salt)
        key = passcrypt(
            password, uuid, kb=kb, cpu=cpu, hardness=hardness
        )
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
    def generate_profile(cls, tokens):
        """
        Creates & loads a profile database for a user from the ``tokens``
        passed in.
        """
        cls._generate_profile_salt(tokens)
        cls._generate_profile_login_key(tokens)
        tokens.profile = cls(key=tokens._login_key, password_depth=10000)
        tokens.profile.save()
        return tokens.profile

    @classmethod
    def load_profile(cls, tokens):
        """
        Loads a profile database for a user from the ``tokens`` passed
        in. Throws ``LookupError`` if the profile has not yet been
        generated.
        """
        if not cls.profile_exists(tokens):
            raise LookupError(cls._NO_PROFILE_OR_CORRUPT)
        return cls.generate_profile(tokens)

    @classmethod
    def delete_profile(cls, tokens):
        """
        Deletes the profile's salt saved on the filesystem & all of its
        database files.
        """
        try:
            tokens.profile.delete_database()
        except AttributeError:
            cls.load_profile(tokens)
            tokens.profile.delete_database()
        tokens._salt_path.unlink()

    def __init__(
        self,
        key=None,
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
        root keys.

        ``preload``:    This boolean value tells the object to -- True --
            load all of the stored database values from the filesystem
            into the cache during initialization, or -- False -- skip
            the loading stage.

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
        """
        self._silent = silent
        self._cache = Namespace()
        self._manifest = Namespace()
        self.directory = Path(directory)
        self._root_key, self._root_hash, self._root_filename = (
            self._initialize_keys(key, password_depth)
        )
        if metatag:
            self._is_metatag = True
        else:
            self._is_metatag = False
        self._load_manifest()
        self._initialize_metatags()
        if preload:
            self.load(silent=silent)

    @staticmethod
    def _initialize_keys(key=None, password_depth=0):
        """
        Derives the database's cryptographic root key material and the
        filename of the manifest ledger.
        """
        root_key = keys(key, salt=key, pid=key)[password_depth]()
        root_hash = sha_512_hmac(root_key, key=root_key)
        root_filename = sha_256_hmac(root_hash, key=root_hash)
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
            del database[filename]
        return list(database.values())

    def _root_encryption_key(self, filename, salt):
        """
        Takes a ``filename`` & ``salt`` to construct a unique symmetric
        cryptographic key with preliminary database key material.
        """
        return sha_512_hmac(
            (filename, self._root_key, salt), key=self._root_hash
        )

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

    def _create_salting_function(self, salt=None):
        """
        Creates and returns a function for the instance to retrieve a
        cryptographic ``salt`` key. If the instance is a metatag child
        database, then the returned key is assumed to not have been
        stored encrypted. Otherwise, the ``salt`` is assumed to be
        encrypted, and is decrypted within the created function.
        """
        instance_hash = sha_256_hmac(
            (hash(self), salt), key=self._root_hash
        )

        @lru_cache()
        def __root_salt(database=instance_hash):
            """
            Keeps the ``root_salt`` tucked away until queried, where
            then it's cached for efficiency.
            """
            if self._is_metatag:
                return salt
            else:
                return json_decrypt(salt, self._root_key)

        return __root_salt

    def _install_root_salt(self, root_salt=None, *, auto_encrypt=True):
        """
        Inserts the database's root entropy source in the manifest
        ledger & the instance's caches of keys. Tags & metatags not
        loaded into the cache will be unretrievable without the
        root_salt that is replaced in this function.
        """
        salt = (
            root_salt
            if self._is_metatag or not auto_encrypt
            else json_encrypt(root_salt, self._root_key)
        )
        self._manifest[self._root_filename] = salt
        self.__root_salt = self._create_salting_function(salt)
        self._root_seed = sha_512_hmac(self.__root_salt(), self._root_key)

    def _load_manifest(self):
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """
        if self._root_path.exists():
            self._manifest = Namespace(self._open_manifest())
            root_salt = self._manifest[self._root_filename]
        else:
            self._manifest = Namespace()
            self._root_session_salt = salt()
            if self._is_metatag:
                root_salt = salt()
            else:
                root_salt = json_encrypt(csprng(), self._root_key)

        self._install_root_salt(root_salt, auto_encrypt=False)

    def _save_manifest(self, ciphertext=None):
        """
        Writes the manifest ledger to disk. It contains all database
        filenames & special cryptographic values for initializing the
        database's key derivation functions.
        """
        if not ciphertext:
            raise PermissionError("Invalid write attempted.")
        self.io.write(path=self._root_path, ciphertext=ciphertext)

    def _encrypt_manifest(self, salt):
        """
        Takes a ``salt`` & returns the database's manifest encrypted.
        """
        manifest = self._manifest.namespace
        key = self._root_encryption_key(self._MANIFEST, salt)
        return json_encrypt(manifest, key=key, salt=salt)

    def _close_manifest(self):
        """
        Prepares for & writes the manifest ledger to disk. The manifest
        contains all database filenames & special cryptographic values
        for initializing the database's key derivation functions.
        """
        salt = self._root_session_salt = csprng()[:64]
        manifest = self._encrypt_manifest(salt)
        self._save_manifest(manifest)

    def load_metatags(self, *, preload=True, silent=False):
        """
        Specifically loads all of the database's metatag values into the
        cache. If the ``preload`` keyword argument is falsey then the
        metatag references are populated in the database's instance
        dictionary, but their internal values are not loaded.
        """
        for metatag in set(self.metatags):
            self.metatag(metatag, preload=preload, silent=silent)

    def load_tags(self, silent=False):
        """
        Specifically loads all of the database's tag values into the
        cache.
        """
        database = dict(self._manifest.namespace)
        for maintenance_file in self._maintenance_files:
            del database[maintenance_file]
        for filename, tag in database.items():
            self.query(tag, silent=silent)

    def load(self, *, metatags=True, silent=False):
        """
        Loads all the database object's values from the filesystem into
        the database cache. This brings the database values into the
        cache, enables up-to-date bracket lookup of tag values & dotted
        lookup of metatags.
        """
        self.load_metatags(preload=metatags, silent=silent)
        self.load_tags(silent=silent)
        return self

    def filename(self, tag=None):
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        return sha_256_hmac((tag, self._root_seed), key=self._root_hash)

    def hmac(self, *data):
        """
        Creates an HMAC hash of the arguments passed into ``*data`` with
        keys derived from the key used to open the database instance.
        """
        return sha_256_hmac((data, self._root_hash), key=self._root_seed)

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
        true_hmac = self.hmac(*data)
        if validator.time_safe_equality(hmac, true_hmac):
            return True
        else:
            raise ValueError("HMAC of ``data`` isn't valid.")

    def passcrypt(self, password, salt, *, kb=1024, cpu=3, hardness=1024):
        """
        An implementation of an scrypt-like password derivation function
        which requires a tunable amount of memory & cpu time to compute.
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
        return OneTimePad.passcrypt(
            salted_password, salt, kb=kb, cpu=cpu, hardness=hardness
        )

    def uuids(self, category=None, size=16, salt=None):
        """
        Returns a coroutine that can safely create unique user IDs based
        on the category set by the user. The keyword arguments refer to:

        ``category``    Any object sent by the user which identifies the
            category or context that the uuids are being made for, such
            as 'emails', 'unregistered_user', 'address'. It is up to the
            user, these categories distinguish the uuids created
            uniquely from other categories.
        ``size``        The length of the hex strings returned by this
            uuid generator.
        ``salt``        An optional random salt value of arbitrary type &
            size that, if passed needs to be managed manually by the
            user. It provides entropy into the uuids created, further
            distinguishing them, and provides resistance against certain
            kinds of hash cracking attacks. The salt can be by calling
            the ``result(exit=True)`` method of the returned ``Comprende``
            generator.

        Usage Examples:

        import aiootp

        db = aiootp.Database(
            key="regular shared solo minutes", password_depth=6000
        )
        responses = db.metatag("responses")
        uuids = responses.uuids("emails", salt=server.salt)

        # Backup json data to the encrypted database ->
        for email_address in server.emails:
            uuid = uuids(email_address)
            responses[uuid] = server.responses[email_address]

        db.save()
        """

        @comprehension()
        def _uuids(salt=salt):
            """
            A programmable coroutine which creates unique user IDs
            that are specific to a particular category.
            """
            name = self.filename(category)
            uuids = make_uuid(size, salt=name).prime()
            salt = salt if salt else csprng()[:64]
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
        return sha_512_hmac(
            (filename, salt), key=self.hmac(filename, salt),
        )

    def bytes_decrypt(self, filename, ciphertext, ttl=0):
        """
        Decrypts ``ciphertext`` with keys specific to a the ``filename``
        value.

        ``filename``    This is the hashed tag that labels a piece of
            data in the database.
        ``ciphertext``  This is a dictionary of ciphertext.
        """
        salt = ciphertext["salt"]
        key = self._encryption_key(filename, salt)
        return bytes_decrypt(ciphertext, key=key, ttl=ttl)

    def decrypt(self, filename, ciphertext, ttl=0):
        """
        Decrypts ``ciphertext`` with keys specific to a the ``filename``
        value.

        ``filename``    This is the hashed tag that labels a piece of
            data in the database.
        ``ciphertext``  This is a dictionary of ciphertext.
        """
        salt = ciphertext["salt"]
        key = self._encryption_key(filename, salt)
        return json_decrypt(ciphertext, key=key, ttl=ttl)

    def bytes_encrypt(self, filename, plaintext):
        """
        Encrypts ``plaintext`` with keys specific to a the ``filename``
        value.

        ``filename``    This is the hashed tag that labels a piece of
            data in the database.
        ``plaintext``   This is any json serializable object that is to
            be encrypted.
        """
        salt = csprng()[:64]
        key = self._encryption_key(filename, salt)
        return bytes_encrypt(plaintext, key=key, salt=salt)

    def encrypt(self, filename, plaintext):
        """
        Encrypts ``plaintext`` with keys specific to a the ``filename``
        value.

        ``filename``    This is the hashed tag that labels a piece of
            data in the database.
        ``plaintext``   This is any json serializable object that is to
            be encrypted.
        """
        salt = csprng()[:64]
        key = self._encryption_key(filename, salt)
        return json_encrypt(plaintext, key=key, salt=salt)

    def set(self, tag=None, data=None):
        """
        Allows users to add the value ``data`` under the name ``tag``
        into the database.
        """
        filename = self.filename(tag)
        self._cache[filename] = data
        self._manifest[filename] = tag

    def query(self, tag=None, silent=False):
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
            result = self.decrypt(filename, ciphertext)
            self._cache[filename] = result
            return result

    def pop(self, tag=None):
        """
        Returns a value from the database by it's ``tag`` & deletes the
        associated file in the database directory.
        """
        filename = self.filename(tag)
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

    def _initialize_metatags(self):
        """
        Initializes the values that organize database metatags, which
        are children databases contained within their parent.
        """
        self._metatags_filename = self.filename(self._METATAG)
        if self.metatags == None:
            self._manifest[self._metatags_filename] = []

    @property
    def metatags(self):
        """
        Returns the list of metatags that a database contains.
        """
        return self._manifest.namespace.get(self._metatags_filename)

    def _metatag_key(self, tag=None):
        """
        Derives the metatag's database key given a user-defined ``tag``.
        """
        return sha_512_hmac((tag, self._root_seed), self._root_hash)

    def metatag(self, tag=None, preload=True, silent=False):
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

    def _save_metatags(self):
        """
        Writes the database's child databases to disk.
        """
        for metatag in set(self.metatags):
            if self.__dict__.get(metatag):
                self.__dict__[metatag].save()

    def save_tag(self, tag=None, *, admin=False):
        """
        Writes the cached value for a user-specified ``tag`` to the user
        filesystem.
        """
        filename = self.filename(tag)
        self._save_file(filename, admin=admin)

    def _save_tags(self):
        """
        Writes the database's user-defined tags to disk.
        """
        maintenance_files = self._maintenance_files
        for filename in self._cache.namespace:
            if filename in maintenance_files:
                continue
            self._save_file(filename, admin=True)

    def _delete_file(self, filename=None):
        """
        Deletes a file in the database directory by ``filename``.
        """
        try:
            (self.directory / filename).unlink()
        except FileNotFoundError:
            pass

    def _save_file(self, filename=None, *, admin=False):
        """
        Writes the cached value for a user-specified ``filename`` to the
        user filesystem.
        """
        if not admin and filename in self._maintenance_files:
            raise PermissionError("Cannot edit maintenance files.")
        ciphertext = self.encrypt(filename, self._cache[filename])
        self._save_ciphertext(filename, ciphertext)

    def _query_ciphertext(self, filename=None, silent=False):
        """
        Retrieves the value stored in the database file that's called
        ``filename``.
        """
        try:
            path = self.directory / filename
            return self.io.read(path=path, encoding=self._ENCODING)
        except FileNotFoundError as corrupt_database:
            if not silent:
                raise corrupt_database

    def _save_ciphertext(self, filename=None, ciphertext=None):
        """
        Saves the encrypted value ``ciphertext`` in the database file
        called ``filename``.
        """
        path = self.directory / filename
        self.io.write(path=path, ciphertext=ciphertext)

    def delete_database(self):
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        for metatag in self.metatags:
            self.metatag(metatag).delete_database()
        for filename in self._manifest.namespace:
            self._delete_file(filename)
        self._cache.namespace.clear()
        self._manifest.namespace.clear()

    def save(self):
        """
        Writes the database's values to disk.
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
        with unpack(self) as namespace:
            return Namespace(namespace.dict())

    def mirror_database(self, database=None):
        """
        Takes a ``Database`` object & copies over all if its loaded &
        stored values, tags & metatags.
        """
        my_metatags = self.metatags
        its_metatags = set(database.metatags)
        my_metatags += [
            tag for tag in its_metatags if tag not in my_metatags
        ]
        if issubclass(database.__class__, self.__class__):
            for tag, value in database:
                filename = self.filename(tag)
                self._cache[filename] = value
                self._manifest[filename] = tag
        else:
            # Works with async databases, but doesn't load unloaded values
            for tag in database.tags:
                filename = self.filename(tag)
                self._cache[filename] = database[tag]
                self._manifest[filename] = tag
        for metatag in its_metatags:
            my_metatag = self.metatag(metatag)
            my_metatag.mirror_database(database.__dict__[metatag])

    def __contains__(self, tag=None):
        """
        Checks the cache & manifest for the filename associated with the
        user-defined ``tag``.
        """
        filename = self.filename(tag)
        return filename in self._manifest or filename in self._cache

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
    __len__ = lambda self: len(self._manifest.namespace)


class Ropake():
    """
    Ratcheting Opaque Password Authenticated Key Exchange

    An implementation of a password-authenticated key exchange protocol
    for servers to securely authenticate users & users to authenticate
    servers. User passwords aren't disclosed to the servers. They are
    used to build persistently secure connection keys which are made
    future & forward secure with a new elliptic curve diffie-hellman
    shared key being used for every authentication & mixed with keys
    established from past authentications. The protocol requires that
    the client & server are able to securely store cryptographic
    material, & by default this module's ``AsyncDatabase`` & ``Database``
    classes are intended to be used for this purpose.

    Usage Examples:

    import aiootp
    from aiootp import Ropake

    new_account = True
    # The arguments must contain at least one unique element for each
    # service the client wants to authenticate with, such as ->
    uuid = aiootp.sha_256("server_url", "username")
    db = Ropake.client_database(uuid, "password")
    if new_account:
        client = Ropake.client_registration(db)
    else:
        client = Ropake.client(db)
    client_hello = client()
    internet.send(client_hello)

    server_db = aiootp.Database("some_cryptographic_key")
    client_hello = internet.receive()
    if Ropake.is_registering(client_hello):
        server = Ropake.server_registration(client_hello, server_db)
    else:
        server = Ropake.server(client_hello, server_db)
    server_hello = server()
    internet.send(server_hello)
    try:
        server()
    except StopIteration:
        shared_keys = server.result()
        # The user's KEY_ID for storing account data in the server
        # database does not need to be remain secret to ensure the
        # security of the encryption keys.
        key_id = shared_keys[Ropake.KEY_ID]
        # The key used during the user's next login authentication
        server_db[key_id][Ropake.KEY] == shared_keys[Ropake.KEY]
        # The key used to encrypt communication for the current session
        server_db[key_id][Ropake.SESSION_KEY] == shared_keys[Ropake.SESSION_KEY]
        # A user is authenticated if they can decrypt messages encrypted
        # with the session key & again proves themselves on the next
        # authentication attempt by encrypting the hello message with
        # the Ropake.KEY & successfully reproducing the keyed password
        # from a stored secret 512-bit salt.

    server_hello = internet.receive()
    try:
        client(server_hello)
    except StopIteration:
        shared_keys = client.result()
        # These shared keys will be the same as the one's the server
        # derived if the registration / authentication was successful.
    """

    PUB = commons.PUB
    KEY = commons.KEY
    SALT = commons.SALT
    KEY_ID = commons.KEY_ID
    SECRET = commons.SECRET
    NEXT_SALT = commons.NEXT_SALT
    CIPHERTEXT = commons.CIPHERTEXT
    SHARED_KEY = commons.SHARED_KEY
    SESSION_KEY = commons.SESSION_KEY
    SESSION_SALT = commons.SESSION_SALT
    REGISTRATION = commons.REGISTRATION
    VERIFICATION = commons.VERIFICATION
    SHARED_SECRET = commons.SHARED_SECRET
    PASSWORD_SALT = commons.PASSWORD_SALT
    KEYED_PASSWORD = commons.KEYED_PASSWORD
    NEXT_KEYED_PASSWORD = commons.NEXT_KEYED_PASSWORD
    X25519PublicKey = X25519PublicKey
    X25519PrivateKey = X25519PrivateKey
    Ed25519PublicKey = Ed25519PublicKey
    Ed25519PrivateKey = Ed25519PrivateKey
    PrimeGroups = commons.PrimeGroups
    salt = staticmethod(csprng)
    asalt = staticmethod(acsprng)
    directory = DatabasePath()
    default_directory = DatabasePath()

    _KEYED_PASSWORD_TUTORIAL = f"""\
    ``database`` needs a {commons.KEYED_PASSWORD} entry.
    H = lambda x: int(Ropake.id(x), 16)
    db = Ropake.client_database(username, password, salt=secret_salt)
    db["salt"] = salt = Ropake.salt()
    db["keyed_password"] = H((db._root_key, salt)) ^ H(salt)
    db["next_salt"] = next_salt = Ropake.salt()
    db["next_keyed_password"] = H((db._root_key, next_salt)) ^ H(next_salt)
    # client sends keyed_password to server during registration & sends
    # H(salt) to the server during authentication, as well as the next
    # keyed_password to be used during the next authentication.
    """
    _PUBLIC_BYTES_ENUM = {
        "encoding": serialization.Encoding.Raw,
        "format": serialization.PublicFormat.Raw,
    }
    _PRIVATE_BYTES_ENUM = {
        "encoding": serialization.Encoding.Raw,
        "format": serialization.PrivateFormat.Raw,
        "encryption_algorithm": serialization.NoEncryption(),
    }

    def __init__(self, key: any, directory=default_directory):
        """
        An optional initializer which instructs the class to use either
        a default key to open a default database for clients to store
        cryptographic material. Or, it can receive a key from a user to
        instruct the class to create / open a custom database for
        better security of cryptographic material stored on the user's
        filesystem. The default key is not secure if an adversary can
        read arbitrary directory names on the user's filesystem. It is
        highly recommended to create a user-defined key for the class
        instead, potentially with a password & using the class's
        ``database_login_key`` method like such ->
        Ropake(
            key=Ropake.database_login_key(
                "username", "password", salt="salt"
            )
        )

        This should be thought of as a class method as it will impact
        the entire class and all instances of the class.
        """
        cls = self.__class__
        cls.directory = Path(directory).absolute()
        cls._key = key if key else cls._default_class_key()
        db = cls._db = Database(cls._key)
        default_db = db["default"]
        if not default_db or not isinstance(default_db, dict):
            db["default"] = {cls.SALT: csprng()}
            db.save()
        elif not cls.SALT in default_db or not default_db[cls.SALT]:
            db["default"][cls.SALT] = csprng()
            db.save()

    @staticmethod
    async def _adefault_class_key():
        """
        Returns the default key for the class' database, which is
        insecurely derived from the name of a directory & a salt stored
        as a file in that directory. The filename & salt are pseudo-
        random 256-bit values saved on the user's filesystem after the
        first usage of the ``SecurePath()`` function.
        """
        path = SecurePath()
        secret = await paths._aread_salt_file(path)
        return await asha_512_hmac(path, key=secret)

    @staticmethod
    def _default_class_key():
        """
        Returns the default key for the class' database, which is
        insecurely derived from the name of a directory & a salt stored
        as a file in that directory. The filename & salt are pseudo-
        random 256-bit values saved on the user's filesystem after the
        first usage of the ``SecurePath()`` function.
        """
        path = SecurePath()
        secret = paths._read_salt_file(path)
        return sha_512_hmac(path, key=secret)

    @classmethod
    async def _adefault_class_salt(cls):
        """
        Returns the default class salt which is stored on a user file-
        system. It's mixed with user credentials in a tunably memory &
        cpu hard hash function to create a cryptographic key that opens
        encrypted databases. The databases themselves store service
        specific authentication keys for use in the ROPAKE protocol.
        """
        return cls._db["default"][cls.SALT]

    @classmethod
    def _default_class_salt(cls):
        """
        Returns the default class salt which is stored on a user file-
        system. It's mixed with user credentials in a tunably memory &
        cpu hard hash function to create a cryptographic key that opens
        encrypted databases. The databases themselves store service
        specific authentication keys for use in the ROPAKE protocol.
        """
        return cls._db["default"][cls.SALT]

    @classmethod
    def is_registering(cls, client_hello=None):
        """
        Takes a ``client_hello`` protocol packet & returns ``"Maybe""``
        if it contains neither a KEY_ID or CIPHERTEXT element signifying
        it may be a registration packet instead of an authentication
        packet. Returns ``False`` if either a KEY_ID or CIPHERTEXT
        element is present, meaning it's definitely not a compatible
        registration packet.
        """
        if not isinstance(client_hello, dict) or not client_hello:
            return False
        elif (
            cls.KEY_ID not in client_hello
            and cls.CIPHERTEXT not in client_hello
        ):
            return "Maybe"
        else:
            return False

    @classmethod
    def is_authenticating(cls, client_hello=None):
        """
        Takes a ``client_hello`` protocol packet & returns ``"Maybe"``
        if it does contain a KEY_ID & CIPHERTEXT element, signifying
        that it may be an authentication packet instead of registration
        packet. Returns ``False`` if the KEY_ID or CIPHERTEXT element
        isn't present, meaning that it's definitely not a compatible
        authentication packet.
        """
        if not isinstance(client_hello, dict) or not client_hello:
            return False
        elif (
            cls.KEY_ID in client_hello and cls.CIPHERTEXT in client_hello
        ):
            return "Maybe"
        else:
            return False

    @staticmethod
    async def aed25519_key():
        """
        Returns an ``Ed25519PrivateKey`` from the cryptography package
        used to make elliptic curve signatures of data.
        """
        return Ed25519PrivateKey.generate()

    @staticmethod
    def ed25519_key():
        """
        Returns an ``Ed25519PrivateKey`` from the cryptography package
        used to make elliptic curve signatures of data.
        """
        return Ed25519PrivateKey.generate()

    @staticmethod
    async def ax25519_key():
        """
        Returns a ``X25519PrivateKey`` from the cryptography package for
        use in an elliptic curve diffie-hellman exchange.
        """
        return X25519PrivateKey.generate()

    @staticmethod
    def x25519_key():
        """
        Returns a ``X25519PrivateKey`` from the cryptography package for
        use in an elliptic curve diffie-hellman exchange.
        """
        return X25519PrivateKey.generate()

    @classmethod
    async def aec25519_public_bytes(cls, secret, *, hex=False):
        """
        Returns the public key bytes of either an ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` from the cryptography package for an
        elliptic curve diffie-hellman exchange or signature verification
        key. If ``hex`` is truthy, then a hex string of the public key
        is returned instead of bytes.
        """
        if hasattr(secret, "public_key"):
            public_key = secret.public_key()
        else:
            public_key = secret

        public_bytes = public_key.public_bytes(**cls._PUBLIC_BYTES_ENUM)
        if hex:
            return public_bytes.hex()
        else:
            return public_bytes

    @classmethod
    def ec25519_public_bytes(cls, secret, *, hex=False):
        """
        Returns the public key bytes of either an ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` from the cryptography package for an
        elliptic curve diffie-hellman exchange or signature verification
        key. If ``hex`` is truthy, then a hex string of the public key
        is returned instead of bytes.
        """
        if hasattr(secret, "public_key"):
            public_key = secret.public_key()
        else:
            public_key = secret

        public_bytes = public_key.public_bytes(**cls._PUBLIC_BYTES_ENUM)
        if hex:
            return public_bytes.hex()
        else:
            return public_bytes

    @classmethod
    async def aec25519_private_bytes(cls, secret, *, hex=False):
        """
        Returns the private key bytes of either an ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` from the cryptography package for an
        elliptic curve diffie-hellman exchange or signature creation
        key. If ``hex`` is truthy, then a hex string of the private key
        is returned instead of bytes.
        """
        private_bytes = secret.private_bytes(**cls._PRIVATE_BYTES_ENUM)
        if hex:
            return private_bytes.hex()
        else:
            return private_bytes

    @classmethod
    def ec25519_private_bytes(cls, secret, *, hex=False):
        """
        Returns the private key bytes of either an ``X25519PrivateKey``
        or ``Ed25519PrivateKey`` from the cryptography package for an
        elliptic curve diffie-hellman exchange or signature creation
        key. If ``hex`` is truthy, then a hex string of the private key
        is returned instead of bytes.
        """
        private_bytes = secret.private_bytes(**cls._PRIVATE_BYTES_ENUM)
        if hex:
            return private_bytes.hex()
        else:
            return private_bytes

    @staticmethod
    async def ax25519_exchange(secret: X25519PrivateKey, pub: bytes):
        """
        Returns the shared key bytes derived from an elliptic curve key
        exchange with the user's ``secret`` key, & their communicating
        peer's ``pub`` public key's bytes or hex value.
        """
        pub = pub if isinstance(pub, bytes) else bytes.fromhex(pub)
        return secret.exchange(X25519PublicKey.from_public_bytes(pub))

    @staticmethod
    def x25519_exchange(secret: X25519PrivateKey, pub: bytes):
        """
        Returns the shared key bytes derived from an elliptic curve key
        exchange with the user's ``secret`` key, & their communicating
        peer's ``pub`` public key's bytes or hex value.
        """
        pub = pub if isinstance(pub, bytes) else bytes.fromhex(pub)
        return secret.exchange(X25519PublicKey.from_public_bytes(pub))

    @staticmethod
    async def aid(key=None):
        """
        Returns a deterministic hmac of any arbitrary key material. This
        is typically used to identify a particular connection between a
        server & client which avoids personal or device identfiable
        information being needed for authenticating parties to identify
        each other.
        """
        return await asha_512_hmac(key, key=key)

    @staticmethod
    def id(key=None):
        """
        Returns a deterministic hmac of any arbitrary key material. This
        is typically used to identify a particular connection between a
        server & client which avoids personal or device identfiable
        information being needed for authenticating parties to identify
        each other.
        """
        return sha_512_hmac(key, key=key)

    @staticmethod
    async def aclient_message_key(key, *, label="client_hello"):
        """
        Hashes a ROPAKE protocol authentication ``key`` with a ``label``
        converting it into a one-time client_hello message key. This
        prevents replay attacks on the messages between the client &
        server if a unique label is used per distinct key. Since the key
        already ratchets in a future & foward secure way after each
        authentication, the label doesn't need to change during default
        usage of this method.
        """
        if key:
            prekey = ("client", label, key)
            return await asha_512_hmac(prekey, key=prekey)
        else:
            raise ValueError(
                "Must provide ``key`` material to mix with ``label``."
            )

    @staticmethod
    def client_message_key(key, *, label="client_hello"):
        """
        Hashes a ROPAKE protocol authentication ``key`` with a ``label``
        converting it into a one-time client_hello message key. This
        prevents replay attacks on the messages between the client &
        server if a unique label is used per distinct key. Since the key
        already ratchets in a future & foward secure way after each
        authentication, the label doesn't need to change during default
        usage of this method.
        """
        if key:
            prekey = ("client", label, key)
            return sha_512_hmac(prekey, key=prekey)
        else:
            raise ValueError(
                "Must provide ``key`` material to mix with ``label``."
            )

    @staticmethod
    async def aserver_message_key(key, *, label="server_hello"):
        """
        Hashes a ROPAKE protocol authentication ``key`` with a ``label``
        converting it into a one-time server_hello message key. This
        prevents replay attacks on the messages between the client &
        server if a unique label is used per distinct key. Since the key
        already ratchets in a future & foward secure way after each
        authentication, the label doesn't need to change during default
        usage of this method.
        """
        if key:
            prekey = ("server", label, key)
            return await asha_512_hmac(prekey, key=prekey)
        else:
            raise ValueError(
                "Must provide ``key`` material to mix with ``label``."
            )

    @staticmethod
    def server_message_key(key, *, label="server_hello"):
        """
        Hashes a ROPAKE protocol authentication ``key`` with a ``label``
        converting it into a one-time server_hello message key. This
        prevents replay attacks on the messages between the client &
        server if a unique label is used per distinct key. Since the key
        already ratchets in a future & foward secure way after each
        authentication, the label doesn't need to change during default
        usage of this method.
        """
        if key:
            prekey = ("server", label, key)
            return sha_512_hmac(prekey, key=prekey)
        else:
            raise ValueError(
                "Must provide ``key`` material to mix with ``label``."
            )

    @classmethod
    async def aencrypt(cls, *, key_id=None, message_key=None, **plaintext):
        """
        A flexible one-time pad encryption method which turns the
        keyword arguments passed as ``**plaintext`` into a dictionary
        which is encrypted as a json object with the ``message_key``
        value. If a ``key_id`` is specified, then a registration has
        already established a shared key between the client & server,
        so the key_id is attached to the outside of the ciphertext so
        the other party knows which user/server is attempting to
        communicate with them.
        """
        message = await ajson_encrypt(plaintext, key=message_key)
        if key_id:
            return {cls.KEY_ID: key_id, **message}
        else:
            return message

    @classmethod
    def encrypt(cls, *, key_id=None, message_key=None, **plaintext):
        """
        A flexible one-time pad encryption method which turns the
        keyword arguments passed as ``**plaintext`` into a dictionary
        which is encrypted as a json object with the ``message_key``
        value. If a ``key_id`` is specified, then a registration has
        already established a shared key between the client & server,
        so the key_id is attached to the outside of the ciphertext so
        the other party knows which user/server is attempting to
        communicate with them.
        """
        message = json_encrypt(plaintext, key=message_key)
        if key_id:
            return {cls.KEY_ID: key_id, **message}
        else:
            return message

    @classmethod
    async def adecrypt(cls, *, message_key=None, ciphertext=None):
        """
        Decrypts a one-time pad ``ciphertext`` of json data with the
        ``message_key`` & returns the plaintext as well as the key_id
        in a dictionary if it was attached to the ciphertext.
        """
        if ciphertext.get(cls.KEY_ID):
            key_id = ciphertext.pop(cls.KEY_ID)
            message = await ajson_decrypt(ciphertext, key=message_key)
            return {cls.KEY_ID: key_id, **message}
        else:
            return await ajson_decrypt(ciphertext, key=message_key)

    @classmethod
    def decrypt(cls, *, message_key=None, ciphertext=None):
        """
        Decrypts a one-time pad ``ciphertext`` of json data with the
        ``message_key`` & returns the plaintext as well as the key_id
        in a dictionary if it was attached to the ciphertext.
        """
        if ciphertext.get(cls.KEY_ID):
            key_id = ciphertext.pop(cls.KEY_ID)
            message = json_decrypt(ciphertext, key=message_key)
            return {cls.KEY_ID: key_id, **message}
        else:
            return json_decrypt(ciphertext, key=message_key)

    @classmethod
    async def adatabase_login_key(
        cls,
        uuid: any,
        password: any,
        *credentials,
        salt=None,
        kb=1024,
        cpu=3,
        hardness=1024,
    ):
        """
        Processes user defined credentials with a tunably memory & cpu
        hard hash function & returns a cryptohraphic key used to open a
        database. If no salt is specified then the default class salt,
        which is stored encrypted on the user filesystem, is used
        instead.
        """
        if not all([uuid, password]):
            raise ValueError("Must supply a uuid & password.")
        salt = salt if salt else await cls._adefault_class_salt()
        login = await anc_512(uuid, password, salt, *credentials)
        return await apasscrypt(
            login, salt, kb=kb, cpu=cpu, hardness=hardness
        )

    @classmethod
    def database_login_key(
        cls,
        uuid: any,
        password: any,
        *credentials,
        salt=None,
        kb=1024,
        cpu=3,
        hardness=1024,
    ):
        """
        Processes user defined credentials with a tunably memory & cpu
        hard hash function & returns a cryptohraphic key used to open a
        database. If no salt is specified then the default class salt,
        which is stored encrypted on the user filesystem, is used
        instead.
        """
        if not all([uuid, password]):
            raise ValueError("Must supply a uuid & password.")
        salt = salt if salt else cls._default_class_salt()
        login = nc_512(uuid, password, salt, *credentials)
        return passcrypt(login, salt, kb=kb, cpu=cpu, hardness=hardness)

    @classmethod
    async def aclient_database(
        cls,
        uuid: any,
        password: any,
        *credentials,
        salt=None,
        kb=1024,
        cpu=3,
        hardness=1024,
        directory=None,
    ):
        """
        A unique database is opened for each permutation of arguments &
        keyword arguments to this method. If no salt is specified then
        the default class salt, which is stored encrypted on the user
        filesystem, is used instead. An asynchronous ``AsyncDatabase``
        object is returned which only works with asynchronous ``aclient``
        & ``aclient_registration`` methods.
        """
        db_key = await cls.adatabase_login_key(
            uuid,
            password,
            *credentials,
            salt=salt,
            kb=kb,
            cpu=cpu,
            hardness=hardness,
        )
        directory = directory if directory else cls.directory
        return await AsyncDatabase(
            key=db_key, password_depth=8192, directory=directory
        )

    @classmethod
    def client_database(
        cls,
        uuid: any,
        password: any,
        *credentials,
        salt=None,
        kb=1024,
        cpu=3,
        hardness=1024,
        directory=None,
    ):
        """
        A unique database is opened for each permutation of arguments &
        keyword arguments to this method. If no salt is specified then
        the default class salt, which is stored encrypted on the user
        filesystem, is used instead. A synchronous ``Database`` object
        is returned which only works with synchronous ``client`` &
        ``client_registration`` methods.
        """
        db_key = cls.database_login_key(
            uuid,
            password,
            *credentials,
            salt=salt,
            kb=kb,
            cpu=cpu,
            hardness=hardness,
        )
        directory = directory if directory else cls.directory
        return Database(
            key=db_key, password_depth=8192, directory=directory
        )

    @classmethod
    async def amake_commit(cls, password_hash, salt):
        """
        Takes in a hashed password string & a secret salt then returns
        a number which functions as a commit message between the client
        & server during the ROPAKE protocol. This commit message is
        shared with the server, then on the subsequent authentication
        with the server, the client will send the hash of the secret
        salt. This allows both parties to arrive at a common value
        without the server ever learning brute-forceable information
        about the password hash (if the secret salt is >= 256 bits).
        """
        return (
            int(await cls.aid((password_hash, salt)), 16)
            ^ int(await cls.aid(salt), 16)
        )

    @classmethod
    def make_commit(cls, password_hash, salt):
        """
        Takes in a hashed password string & a secret salt then returns
        a number which functions as a commit message between the client
        & server during the ROPAKE protocol. This commit message is
        shared with the server, then on the subsequent authentication
        with the server, the client will send the hash of the secret
        salt. This allows both parties to arrive at a common value
        without the server ever learning brute-forceable information
        about the password hash (if the secret salt is >= 256 bits).
        """
        return (
            int(cls.id((password_hash, salt)), 16) ^ int(cls.id(salt), 16)
        )

    @classmethod
    async def apopulate_database(cls, database: AsyncDatabase):
        """
        Inserts session values into a client database for their use in
        the registration & authentication processes.
        """
        db = database
        if not db[cls.KEY]:
            password_salt = db[cls.SALT] = await cls.asalt()
            db[cls.KEYED_PASSWORD] = (
                await cls.amake_commit(db._root_key, password_salt)
            )
        else:
            password_salt = db[cls.SALT]
            db[cls.KEYED_PASSWORD] = (
                await cls.amake_commit(db._root_key, password_salt)
            )
            password_salt = db[cls.NEXT_SALT] = await cls.asalt()
            db[cls.NEXT_KEYED_PASSWORD] = (
                await cls.amake_commit(db._root_key, password_salt)
            )

    @classmethod
    def populate_database(cls, database: Database):
        """
        Inserts session values into a client database for their use in
        the registration & authentication processes.
        """
        db = database
        if not db[cls.KEY]:
            password_salt = db[cls.SALT] = cls.salt()
            db[cls.KEYED_PASSWORD] = (
                cls.make_commit(db._root_key, password_salt)
            )
        else:
            password_salt = db[cls.SALT]
            db[cls.KEYED_PASSWORD] = (
                cls.make_commit(db._root_key, password_salt)
            )
            password_salt = db[cls.NEXT_SALT] = cls.salt()
            db[cls.NEXT_KEYED_PASSWORD] = (
                cls.make_commit(db._root_key, password_salt)
            )

    @classmethod
    async def ainit_protocol(cls):
        """
        Instatiates a ``Namespace`` object with the generic values used
        to execute the ``Ropake`` registration & authentication protocols
        for both the server & client, then returns it.
        """
        values = Namespace()
        values.salt = await cls.asalt()
        values.session_salt = await cls.asalt()
        values.ecdhe_key = await cls.ax25519_key()
        values.pub = await cls.aec25519_public_bytes(values.ecdhe_key)
        return values

    @classmethod
    def init_protocol(cls):
        """
        Instatiates a ``Namespace`` object with the generic values used
        to execute the ``Ropake`` registration & authentication protocols
        for both the server & client, then returns it.
        """
        values = Namespace()
        values.salt = cls.salt()
        values.session_salt = cls.salt()
        values.ecdhe_key = cls.x25519_key()
        values.pub = cls.ec25519_public_bytes(values.ecdhe_key)
        return values

    @classmethod
    async def aunpack_client_hello(cls, client_hello: dict, key=None):
        """
        Allows a server to quickly decrypt or unpack the client's hello
        data into a ``Namespace`` object for efficient & more readable
        processing of the data for authentication & registration.
        """
        if key:
            client_hello = await cls.adecrypt(
                ciphertext=client_hello,
                message_key=await cls.aclient_message_key(key),
            )
        return Namespace(client_hello)

    @classmethod
    def unpack_client_hello(cls, client_hello: dict, key=None):
        """
        Allows a server to quickly decrypt or unpack the client's hello
        data into a ``Namespace`` object for efficient & more readable
        processing of the data for authentication & registration.
        """
        if key:
            client_hello = cls.decrypt(
                ciphertext=client_hello,
                message_key=cls.client_message_key(key),
            )
        return Namespace(client_hello)

    @classmethod
    async def afinalize(cls, key: any, shared_key: any, shared_secret: any):
        """
        Combines the current sessions' derived keys, with the keys
        derived during the last session & the current session encryption
        key into brand new key for the next authentication, & a new
        session key which updates the current session's encryption key.
        Returns a ``Namespace`` object containing these new keys.
        """
        key = await asha_512_hmac((key, shared_key), key=shared_secret)
        session_key = await asha_512(key, shared_key, shared_secret)
        return Namespace(
            mapping={
                cls.KEY: key,
                cls.SESSION_KEY: session_key,
            }
        )

    @classmethod
    def finalize(cls, key: any, shared_key: any, shared_secret: any):
        """
        Combines the current sessions' derived keys, with the keys
        derived during the last session & the current session encryption
        key into brand new key for the next authentication, & a new
        session key which updates the current session's encryption key.
        Returns a ``Namespace`` object containing these new keys.
        """
        key = sha_512_hmac((key, shared_key), key=shared_secret)
        session_key = sha_512(key, shared_key, shared_secret)
        return Namespace(
            mapping={
                cls.KEY: key,
                cls.SESSION_KEY: session_key,
            }
        )

    @classmethod
    async def aintegrate_salts(
        cls, results: Namespace, client_session_salt, server_session_salt
    ):
        """
        Mixes in random session salts to the shared key generation
        results of the Ropake protocol & returns the mutated results.
        """
        salt = results.session_salt = await asha_512(
            results.session_key, client_session_salt, server_session_salt
        )
        results.key = await asha_512(salt, results.key)
        results.session_key = await asha_512(salt, results.session_key)
        results.key_id = await cls.aid(results.key)
        return results

    @classmethod
    def integrate_salts(
        cls, results: Namespace, client_session_salt, server_session_salt
    ):
        """
        Mixes in random session salts to the shared key generation
        results of the Ropake protocol & returns the mutated results.
        """
        salt = results.session_salt = sha_512(
            results.session_key, client_session_salt, server_session_salt
        )
        results.key = sha_512(salt, results.key)
        results.session_key = sha_512(salt, results.session_key)
        results.key_id = cls.id(results.key)
        return results

    @classmethod
    @comprehension()
    async def aclient_registration(cls, database: AsyncDatabase = None):
        """
        This is an oblivious, one-message async password authenticated
        key exchange registration protocol. Takes in a user database
        opened using unique credentials for a particular service. The
        database persists cryptographic material on the client's
        filesystem for establishing a ratcheting verification system.
        The user password is never transmitted to the server, instead
        it's processed through the ``passcrypt`` function & the
        database key initializer, then hashed with a random secret salt
        stored on the filesystem & xor'd with the hash of the secret.
        The hash of the secret is shared with the server during the next
        authentication so a common value based on the password can be
        revealed without revealing any brute-forceable data to the
        server. Every subsequent authentication is encrypted with &
        modified by the key produced by the prior exchange in a
        ratcheting protocol which is resistent to man-in-the-middle
        attacks if any prior exchange was not man-in-the-middled.

        Usage Example:

        # The arguments must contain at least one unique element for
        # each service the client wants to authenticate with, such as ->

        uuid = await aiootp.asha_256("server_url", "username")
        db = await Ropake.aclient_database(uuid, "password")

        async with Ropake.aclient_registration(db) as client:
            client_hello = await client()
            internet.send(client_hello)
            server_hello = internet.receive()
            await client(server_hello)

        shared_keys = await client.aresult()
        """
        db = database
        await cls.apopulate_database(db)
        values = await cls.ainit_protocol()
        response = yield {
            cls.PUB: values.pub.hex(),
            cls.SALT: values.salt,
            cls.SESSION_SALT: values.session_salt,
            cls.KEYED_PASSWORD: await db.apop(cls.KEYED_PASSWORD),
        }
        shared_key = await cls.ax25519_exchange(
            secret=values.ecdhe_key, pub=response[cls.PUB]
        )
        results = await cls.afinalize(
            values.salt, response[cls.SALT], shared_key
        )
        await cls.aintegrate_salts(
            results, values.session_salt, response[cls.SESSION_SALT]
        )
        db[cls.KEY] = results.key
        await db.asave()
        raise UserWarning(
            Namespace(
                key=results.key,
                key_id=results.key_id,
                session_key=results.session_key,
            )
        )

    @classmethod
    @comprehension()
    def client_registration(cls, database: Database = None):
        """
        This is an oblivious, one-message sync password authenticated
        key exchange registration protocol. Takes in a user database
        opened using unique credentials for a particular service. The
        database persists cryptographic material on the client's
        filesystem for establishing a ratcheting verification system.
        The user password is never transmitted to the server, instead
        it's processed through the ``passcrypt`` function & the
        database key initializer, then hashed with a random secret salt
        stored on the filesystem & xor'd with the hash of the secret.
        The hash of the secret is shared with the server during the next
        authentication so a common value based on the password can be
        revealed without revealing any brute-forceable data to the
        server. Every subsequent authentication is encrypted with &
        modified by the key produced by the prior exchange in a
        ratcheting protocol which is resistent to man-in-the-middle
        attacks if any prior exchange was not man-in-the-middled.

        Usage Example:

        # The arguments must contain at least one unique element for
        # each service the client wants to authenticate with, such as ->

        uuid = aiootp.sha_256("server_url", "username")
        db = Ropake.client_database(uuid, "password")

        with Ropake.client_registration(db) as client:
            client_hello = client()
            internet.send(client_hello)
            server_hello = internet.receive()
            client(server_hello)

        shared_keys = client.result()
        """
        db = database
        cls.populate_database(db)
        values = cls.init_protocol()
        response = yield {
            cls.PUB: values.pub.hex(),
            cls.SALT: values.salt,
            cls.SESSION_SALT: values.session_salt,
            cls.KEYED_PASSWORD: db.pop(cls.KEYED_PASSWORD),
        }
        shared_key = cls.x25519_exchange(
            secret=values.ecdhe_key, pub=response[cls.PUB]
        )
        results = cls.finalize(
            values.salt, response[cls.SALT], shared_key
        )
        cls.integrate_salts(
            results, values.session_salt, response[cls.SESSION_SALT]
        )
        db[cls.KEY] = results.key
        db.save()
        return Namespace(
            key=results.key,
            key_id=results.key_id,
            session_key=results.session_key,
        )

    @classmethod
    @comprehension()
    async def aserver_registration(cls, client_hello=None, database=None):
        """
        This is an oblivious, one-message async password authenticated
        key exchange registration protocol. It takes in a client's
        hello protocol message, & an encrypted server database, to
        retrieve & store the cryptographic values used in the exchange.
        The user's password is never transmitted to the server, but is
        used to make a new verifier which is stored on the server during
        each registration & authentication step, & used for secure
        authentication on each subsequent authentication. The point is
        to build a shared key with the client based on a shared elliptic
        curve diffie-hellman exchange, key material from past sessions
        & verifiers that are commited then revealed, which protects the
        protocol from man-in-the-middle attacks by updating the shared
        keys with the combination of past & current sessions' keys.

        Usage Example:

        db = await AsyncDatabase("server_database_key")
        client_hello = internet.receive()

        async with Ropake.aserver_registration(client_hello, db) as server:
            server_hello = await server()
            internet.send(server_hello)
            await server()

        shared_keys = await server.aresult()
        """
        values = await cls.ainit_protocol()
        client = await cls.aunpack_client_hello(client_hello)
        shared_key = await cls.ax25519_exchange(
            secret=values.ecdhe_key, pub=client.pub
        )
        results = await cls.afinalize(
            client.salt, values.salt, shared_key
        )
        await cls.aintegrate_salts(
            results, client.session_salt, values.session_salt
        )
        database[results.key_id] = {
            cls.KEY: results.key, cls.KEYED_PASSWORD: client.keyed_password
        }
        yield {
            cls.PUB: values.pub,
            cls.SALT: values.salt,
            cls.SESSION_SALT: values.session_salt,
        }
        raise UserWarning(
            Namespace(
                key=results.key,
                key_id=results.key_id,
                session_key=results.session_key,
            )
        )

    @classmethod
    @comprehension()
    def server_registration(cls, client_hello=None, database=None):
        """
        This is a one-message, ratcheting, oblivious, password
        authenticated key exchange registration protocol. It takes in
        a client's hello protocol message, & an encrypted server
        database, to retrieve & store the cryptographic values used in
        the exchange. The user's password is never transmitted to the
        server, but is used to make a new verifier which is stored on
        the server during each registration & authentication step, &
        used for secure authentication on each subsequent authentication.
        The point is to build a shared key with the client based on a
        shared elliptic curve diffie-hellman exchange, key material from
        past sessions & verifiers that are commited then revealed, which
        protects the protocol from man-in-the-middle attacks by updating
        the shared keys with the combination of past & current sessions'
        keys.

        Usage Example:

        server_db = Database("server_database_key")
        client_hello = internet.receive()

        with Ropake.server_registration(client_hello, server_db) as server:
            server_hello = server()
            internet.send(server_hello)
            server()

        shared_keys = server.result()
        """
        values = cls.init_protocol()
        client = cls.unpack_client_hello(client_hello)
        shared_key = cls.x25519_exchange(
            secret=values.ecdhe_key, pub=client.pub
        )
        results = cls.finalize(
            client.salt, values.salt, shared_key
        )
        cls.integrate_salts(
            results, client.session_salt, values.session_salt
        )
        database[results.key_id] = {
            cls.KEY: results.key, cls.KEYED_PASSWORD: client.keyed_password
        }
        yield {
            cls.PUB: values.pub,
            cls.SALT: values.salt,
            cls.SESSION_SALT: values.session_salt,
        }
        return Namespace(
            key=results.key,
            key_id=results.key_id,
            session_key=results.session_key,
        )

    @classmethod
    @comprehension()
    async def aclient(cls, database: AsyncDatabase = None):
        """
        This is an oblivious, one-message async password authenticated
        key exchange authentication protocol. Takes in a user database
        opened using unique credentials for a particular service. The
        database persists cryptographic material on the client's
        filesystem for establishing a ratcheting verification system.
        The user password is never transmitted to the server, instead
        it's processed through the ``passcrypt`` function & the
        database key initializer, then hashed with a random secret salt
        stored on the filesystem & xor'd with the hash of the secret.
        The hash of the secret is shared with the server during the next
        authentication so a common value based on the password can be
        revealed without revealing any brute-forceable data to the
        server. Every subsequent authentication is encrypted with &
        modified by the key produced by the prior exchange in a
        ratcheting protocol which is resistent to man-in-the-middle
        attacks if any prior exchange was not man-in-the-middled.

        Usage Example:

        # The arguments must contain at least one unique element for
        # each service the client wants to authenticate with, such as ->

        uuid = await aiootp.asha_256("server_url", "username")
        db = await Ropake.aclient_database(uuid, "password")

        async with Ropake.aclient(db) as client:
            client_hello = await client()
            internet.send(client_hello)
            server_hello = internet.receive()
            await client(server_hello)

        shared_keys = await client.aresult()
        """
        db = database
        await cls.apopulate_database(db)
        key = db[cls.KEY]
        key_id = await cls.aid(key)
        values = await cls.ainit_protocol()
        password_salt = await cls.aid(db[cls.SALT])
        encrypted_response = yield await cls.aencrypt(
            key_id=key_id,
            message_key=await cls.aclient_message_key(key),
            salt=values.salt,
            pub=values.pub.hex(),
            password_salt=password_salt,
            session_salt=values.session_salt,
            keyed_password=await db.apop(cls.NEXT_KEYED_PASSWORD),
        )
        response = await ajson_decrypt(
            encrypted_response, key=await cls.aserver_message_key(key),
        )
        shared_key = await cls.ax25519_exchange(
            secret=values.ecdhe_key, pub=response[cls.PUB]
        )
        shared_secret = await asha_512(
            key,
            shared_key,
            values.salt,
            response[cls.SALT],
            await db.apop(cls.KEYED_PASSWORD) ^ int(password_salt, 16),
        )
        db[cls.SALT] = await db.apop(cls.NEXT_SALT)
        results = await cls.afinalize(key, shared_key, shared_secret)
        await cls.aintegrate_salts(
            results, values.session_salt, response[cls.SESSION_SALT]
        )
        db[cls.KEY] = results.key
        await db.asave()
        raise UserWarning(
            Namespace(
                key=results.key,
                key_id=results.key_id,
                session_key=results.session_key,
            )
        )

    @classmethod
    @comprehension()
    def client(cls, database: Database = None):
        """
        This is an oblivious, one-message sync password authenticated
        key exchange authentication protocol. Takes in a user database
        opened using unique credentials for a particular service. The
        database persists cryptographic material on the client's
        filesystem for establishing a ratcheting verification system.
        The user password is never transmitted to the server, instead
        it's processed through the ``passcrypt`` function & the
        database key initializer, then hashed with a random secret salt
        stored on the filesystem & xor'd with the hash of the secret.
        The hash of the secret is shared with the server during the next
        authentication so a common value based on the password can be
        revealed without revealing any brute-forceable data to the
        server. Every subsequent authentication is encrypted with &
        modified by the key produced by the prior exchange in a
        ratcheting protocol which is resistent to man-in-the-middle
        attacks if any prior exchange was not man-in-the-middled.

        Usage Example:

        # The arguments must contain at least one unique element for
        # each service the client wants to authenticate with, such as ->

        uuid = aiootp.sha_256("server_url", "username")
        db = Ropake.client_database(uuid, "password")

        with Ropake.client(db) as client:
            client_hello = client()
            internet.send(client_hello)
            server_hello = internet.receive()
            client(server_hello)

        shared_keys = client.result()
        """
        db = database
        cls.populate_database(db)
        key = db[cls.KEY]
        key_id = cls.id(key)
        values = cls.init_protocol()
        password_salt = cls.id(db[cls.SALT])
        encrypted_response = yield cls.encrypt(
            key_id=key_id,
            message_key=cls.client_message_key(key),
            salt=values.salt,
            pub=values.pub.hex(),
            password_salt=password_salt,
            session_salt=values.session_salt,
            keyed_password=db.pop(cls.NEXT_KEYED_PASSWORD),
        )
        response = json_decrypt(
            encrypted_response, key=cls.server_message_key(key),
        )
        shared_key = cls.x25519_exchange(
            secret=values.ecdhe_key, pub=response[cls.PUB]
        )
        shared_secret = sha_512(
            key,
            shared_key,
            values.salt,
            response[cls.SALT],
            db.pop(cls.KEYED_PASSWORD) ^ int(password_salt, 16),
        )
        db[cls.SALT] = db.pop(cls.NEXT_SALT)
        results = cls.finalize(key, shared_key, shared_secret)
        cls.integrate_salts(
            results, values.session_salt, response[cls.SESSION_SALT]
        )
        db[cls.KEY] = results.key
        db.save()
        return Namespace(
            key=results.key,
            key_id=results.key_id,
            session_key=results.session_key,
        )

    @classmethod
    @comprehension()
    async def aserver(cls, client_hello=None, database=None):
        """
        This is a one-message, ratcheting, oblivious, password
        authenticated key exchange authentication protocol. It takes in
        a client's hello protocol message, & an encrypted server
        database, to retrieve & store the cryptographic values used in
        the exchange. The user's password is never transmitted to the
        server, but is used to make a new verifier which is stored on
        the server during each registration & authentication step, &
        used for secure authentication on each subsequent authentication.
        The point is to build a shared key with the client based on a
        shared elliptic curve diffie-hellman exchange, key material from
        past sessions & verifiers that are commited then revealed, which
        protects the protocol from man-in-the-middle attacks by updating
        the shared keys with the combination of past & current sessions'
        keys.

        Usage Example:

        server_db = await AsyncDatabase("server_database_key")
        client_hello = internet.receive()

        async with Ropake.aserver(client_hello, server_db) as server:
            server_hello = await server()
            internet.send(server_hello)
            await server()

        shared_keys = await server.aresult()
        """
        key = database[client_hello[cls.KEY_ID]][cls.KEY]
        values = await cls.ainit_protocol()
        client = await cls.aunpack_client_hello(client_hello, key=key)
        shared_key = await cls.ax25519_exchange(
            secret=values.ecdhe_key, pub=client.pub
        )
        keyed_password = database[client.key_id][cls.KEYED_PASSWORD]
        shared_secret = await asha_512(
            key,
            shared_key,
            client.salt,
            values.salt,
            keyed_password ^ int(client.password_salt, 16),
        )
        results = await cls.afinalize(key, shared_key, shared_secret)
        await cls.aintegrate_salts(
            results, client.session_salt, values.session_salt
        )
        database[results.key_id] = {
            cls.KEY: results.key, cls.KEYED_PASSWORD: client.keyed_password
        }
        del database[client.key_id]
        yield await cls.aencrypt(
            message_key=await cls.aserver_message_key(key),
            salt=values.salt,
            pub=values.pub.hex(),
            session_salt=values.session_salt,
        )
        raise UserWarning(
            Namespace(
                key=results.key,
                key_id=results.key_id,
                session_key=results.session_key,
            )
        )

    @classmethod
    @comprehension()
    def server(cls, client_hello=None, database=None):
        """
        This is a one-message, ratcheting, oblivious, password
        authenticated key exchange authentication protocol. It takes in
        a client's hello protocol message, & an encrypted server
        database, to retrieve & store the cryptographic values used in
        the exchange. The user's password is never transmitted to the
        server, but is used to make a new verifier which is stored on
        the server during each registration & authentication step, &
        used for secure authentication on each subsequent authentication.
        The point is to build a shared key with the client based on a
        shared elliptic curve diffie-hellman exchange, key material from
        past sessions & verifiers that are commited then revealed, which
        protects the protocol from man-in-the-middle attacks by updating
        the shared keys with the combination of past & current sessions'
        keys.

        Usage Example:

        server_db = Database("server_database_key")
        client_hello = internet.receive()

        with Ropake.server(client_hello, server_db) as server:
            server_hello = server()
            internet.send(server_hello)
            server()

        shared_keys = server.result()
        """
        key = database[client_hello[cls.KEY_ID]][cls.KEY]
        values = cls.init_protocol()
        client = cls.unpack_client_hello(client_hello, key=key)
        shared_key = cls.x25519_exchange(
            secret=values.ecdhe_key, pub=client.pub
        )
        keyed_password = database[client.key_id][cls.KEYED_PASSWORD]
        shared_secret = sha_512(
            key,
            shared_key,
            client.salt,
            values.salt,
            keyed_password ^ int(client.password_salt, 16),
        )
        results = cls.finalize(key, shared_key, shared_secret)
        cls.integrate_salts(
            results, client.session_salt, values.session_salt
        )
        database[results.key_id] = {
            cls.KEY: results.key, cls.KEYED_PASSWORD: client.keyed_password
        }
        del database[client.key_id]
        yield cls.encrypt(
            message_key=cls.server_message_key(key),
            salt=values.salt,
            pub=values.pub.hex(),
            session_salt=values.session_salt,
        )
        return Namespace(
            key=results.key,
            key_id=results.key_id,
            session_key=results.session_key,
        )

    @classmethod
    @comprehension()
    async def ax25519_2dh_client(cls):
        """
        Takes in an ``X25519PrivateKey`` if passed, or generates one, to
        start a 2DH deniable client key exchange. This key is yielded as
        public key bytes. Then the server's two public keys should to be
        sent into this coroutine when they're received. Finally, causing
        this coroutine to reach the raise will let the primed, ``sha3_512``,
        kdf object be accessed by the ``aresult`` method.

        Usage Example:

        async with Ropake.ax25519_2dh_client() as client:
            client_hello = await client()
            internet.send(client_hello)
            response = internet.receive()
            await client(response)

        shared_key_kdf = await client.aresult()
        """
        private_key_d = await cls.ax25519_key()
        public_key_d = await cls.aec25519_public_bytes(private_key_d)
        public_key_a, public_key_c = yield public_key_d
        shared_key_ad = await cls.ax25519_exchange(
            private_key_d, public_key_a
        )
        shared_key_cd = await cls.ax25519_exchange(
            private_key_d, public_key_c
        )
        raise UserWarning(sha3_512(shared_key_ad + shared_key_cd))

    @classmethod
    @comprehension()
    def x25519_2dh_client(cls):
        """
        Takes in an ``X25519PrivateKey`` if passed, or generates one, to
        start a 2DH deniable client key exchange. This key is yielded as
        public key bytes. Then the server's two public keys should to be
        sent into this coroutine when they're received. Finally, causing
        this coroutine to reach the raise will let the primed, ``sha3_512``,
        kdf object be accessed by the ``aresult`` method.

        Usage Example:

        with Ropake.x25519_2dh_client() as client:
            client_hello = client()
            internet.send(client_hello)
            response = internet.receive()
            client(response)

        shared_key_kdf = client.result()
        """
        private_key_d = cls.x25519_key()
        public_key_d = cls.ec25519_public_bytes(private_key_d)
        public_key_a, public_key_c = yield public_key_d
        shared_key_ad = cls.x25519_exchange(private_key_d, public_key_a)
        shared_key_cd = cls.x25519_exchange(private_key_d, public_key_c)
        return sha3_512(shared_key_ad + shared_key_cd)

    @classmethod
    @comprehension()
    async def ax25519_2dh_server(
        cls,
        private_key_a: X25519PrivateKey,
        public_key_d: bytes,
    ):
        """
        Takes in the user's ``X25519PrivateKey`` & a peer's public key
        bytes to enact a 2DH deniable key exchange.  This yields the
        user's two public keys as bytes, one from the private key which
        was passed in as an argument, one which is ephemeral. Causing
        this coroutine to reach the raise will let the primed,
        ``sha3_512``, kdf object be accessed by the ``aresult`` method.

        Usage Example:

        skA = server_private_key = await Ropake.ax25519_key()
        pkD = client_public_key = internet.receive()

        async with Ropake.ax25519_3dh_server(skA, pkD) as server:
            internet.send(await server())
            await server()

        shared_key_kdf = await server.aresult()
        """
        private_key_c = await cls.ax25519_key()
        public_key_a = await cls.aec25519_public_bytes(private_key_a)
        public_key_c = await cls.aec25519_public_bytes(private_key_c)
        yield public_key_a, public_key_c
        shared_key_ad = await cls.ax25519_exchange(
            private_key_a, public_key_d
        )
        shared_key_cd = await cls.ax25519_exchange(
            private_key_c, public_key_d
        )
        raise UserWarning(sha3_512(shared_key_ad + shared_key_cd))

    @classmethod
    @comprehension()
    def x25519_2dh_server(
        cls,
        private_key_a: X25519PrivateKey,
        public_key_d: bytes,
    ):
        """
        Takes in the user's ``X25519PrivateKey`` & a peer's public key
        bytes to enact a 2DH deniable key exchange.  This yields the
        user's two public keys as bytes, one from the private key which
        was passed in as an argument, one which is ephemeral. Causing
        this coroutine to reach the raise will let the primed,
        ``sha3_512``, kdf object be accessed by the ``result`` method.

        Usage Example:

        skA = server_private_key = Ropake.x25519_key()
        pkD = client_public_key = internet.receive()

        with Ropake.x25519_3dh_server(skA, pkD) as server:
            internet.send(server())
            server()

        shared_key_kdf = server.result()
        """
        private_key_c = cls.x25519_key()
        public_key_a = cls.ec25519_public_bytes(private_key_a)
        public_key_c = cls.ec25519_public_bytes(private_key_c)
        yield public_key_a, public_key_c
        shared_key_ad = cls.x25519_exchange(private_key_a, public_key_d)
        shared_key_cd = cls.x25519_exchange(private_key_c, public_key_d)
        return sha3_512(shared_key_ad + shared_key_cd)

    @classmethod
    @comprehension()
    async def ax25519_3dh_client(cls, private_key_b: X25519PrivateKey):
        """
        Takes in the user's ``X25519PrivateKey`` & two of a peer's
        public keys bytes to enact a 3DH deniable key exchange. This
        yields the user's two public keys as bytes, one from the private
        key which was passed in as an argument, one which is ephemeral.
        Causing this coroutine to reach the raise will let the primed,
        ``sha3_512``, kdf object be accessed by the ``result`` method.

        Usage Example:

        skB = client_private_key = await Ropake.ax25519_key()

        async with Ropake.ax25519_3dh_client(skB) as client:
            client_hello = await client()
            internet.send(client_hello)
            response = internet.receive()
            await client(response)

        shared_key_kdf = await client.aresult()
        """
        private_key_d = await cls.ax25519_key()
        public_key_b = await cls.aec25519_public_bytes(private_key_b)
        public_key_d = await cls.aec25519_public_bytes(private_key_d)
        public_key_a, public_key_c = yield public_key_b, public_key_d
        shared_key_ad = await cls.ax25519_exchange(
            private_key_d, public_key_a
        )
        shared_key_bc = await cls.ax25519_exchange(
            private_key_b, public_key_c
        )
        shared_key_cd = await cls.ax25519_exchange(
            private_key_d, public_key_c
        )
        raise UserWarning(
            sha3_512(shared_key_ad + shared_key_bc + shared_key_cd)
        )

    @classmethod
    @comprehension()
    def x25519_3dh_client(cls, private_key_b: X25519PrivateKey):
        """
        Takes in the user's ``X25519PrivateKey`` & two of a peer's
        public keys bytes to enact a 3DH deniable key exchange. This
        yields the user's two public keys as bytes, one from the private
        key which was passed in as an argument, one which is ephemeral.
        Causing this coroutine to reach the return will let the primed,
        ``sha3_512``, kdf object be accessed by the ``result`` method.

        Usage Example:

        skB = client_private_key = Ropake.x25519_key()

        with Ropake.x25519_3dh_client(skB) as client:
            client_hello = client()
            internet.send(client_hello)
            response = internet.receive()
            client(response)

        shared_key_kdf = client.result()
        """
        private_key_d = cls.x25519_key()
        public_key_b = cls.ec25519_public_bytes(private_key_b)
        public_key_d = cls.ec25519_public_bytes(private_key_d)
        public_key_a, public_key_c = yield public_key_b, public_key_d
        shared_key_ad = cls.x25519_exchange(private_key_d, public_key_a)
        shared_key_bc = cls.x25519_exchange(private_key_b, public_key_c)
        shared_key_cd = cls.x25519_exchange(private_key_d, public_key_c)
        return sha3_512(shared_key_ad + shared_key_bc + shared_key_cd)

    @classmethod
    @comprehension()
    async def ax25519_3dh_server(
        cls,
        private_key_a: X25519PrivateKey,
        public_key_b: bytes,
        public_key_d: bytes,
    ):
        """
        Takes in the user's ``X25519PrivateKey`` & two of a peer's
        public keys bytes to enact a 3DH deniable key exchange. This
        yields the user's two public keys as bytes, one from the private
        key which was passed in as an argument, one which is ephemeral.
        Causing this coroutine to reach the raise will let the primed,
        ``sha3_512``, kdf object be accessed by the ``aresult`` method.

        Usage Example:

        skA = server_private_key = await Ropake.ax25519_key()
        pkB, pkD = client_public_keys = internet.receive()

        async with Ropake.ax25519_3dh_server(skA, pkB, pkD) as server:
            internet.send(await server())
            await server()

        shared_key_kdf = await server.aresult()
        """
        private_key_c = await cls.ax25519_key()
        public_key_a = await cls.aec25519_public_bytes(private_key_a)
        public_key_c = await cls.aec25519_public_bytes(private_key_c)
        yield public_key_a, public_key_c
        shared_key_ad = await cls.ax25519_exchange(
            private_key_a, public_key_d
        )
        shared_key_bc = await cls.ax25519_exchange(
            private_key_c, public_key_b
        )
        shared_key_cd = await cls.ax25519_exchange(
            private_key_c, public_key_d
        )
        raise UserWarning(
            sha3_512(shared_key_ad + shared_key_bc + shared_key_cd)
        )

    @classmethod
    @comprehension()
    def x25519_3dh_server(
        cls,
        private_key_a: X25519PrivateKey,
        public_key_b: bytes,
        public_key_d: bytes,
    ):
        """
        Takes in the user's ``X25519PrivateKey`` & two of a peer's
        public keys bytes to enact a 3DH deniable key exchange. This
        yields the user's two public keys as bytes, one from the private
        key which was passed in as an argument, one which is ephemeral.
        Causing this coroutine to reach the return will let the primed,
        ``sha3_512``, kdf object be accessed by the ``result`` method.

        Usage Example:

        skA = server_private_key = Ropake.x25519_key()
        pkB, pkD = client_public_keys = internet.receive()

        with Ropake.x25519_3dh_server(skA, pkB, pkD) as server:
            internet.send(server())
            server()

        shared_key_kdf = server.result()
        """
        private_key_c = cls.x25519_key()
        public_key_a = cls.ec25519_public_bytes(private_key_a)
        public_key_c = cls.ec25519_public_bytes(private_key_c)
        yield public_key_a, public_key_c
        shared_key_ad = cls.x25519_exchange(private_key_a, public_key_d)
        shared_key_bc = cls.x25519_exchange(private_key_c, public_key_b)
        shared_key_cd = cls.x25519_exchange(private_key_c, public_key_d)
        return sha3_512(shared_key_ad + shared_key_bc + shared_key_cd)


validator = Namespace()


__extras = {
    "AsyncDatabase": AsyncDatabase,
    "Database": Database,
    "Passcrypt": Passcrypt,
    "OneTimePad": OneTimePad,
    "Ropake": Ropake,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "abytes_decrypt": abytes_decrypt,
    "abytes_encrypt": abytes_encrypt,
    "abytes_keys": abytes_keys,
    "abytes_xor": abytes_xor,
    "acheck_key_and_salt": acheck_key_and_salt,
    "ajson_decrypt": ajson_decrypt,
    "ajson_encrypt": ajson_encrypt,
    "akeypair_ratchets": akeypair_ratchets,
    "akeys": akeys,
    "apadding_key": apadding_key,
    "apasscrypt": apasscrypt,
    "aplaintext_stream": aplaintext_stream,
    "axor": axor,
    "bytes_decrypt": bytes_decrypt,
    "bytes_encrypt": bytes_encrypt,
    "bytes_keys": bytes_keys,
    "bytes_xor": bytes_xor,
    "check_key_and_salt": check_key_and_salt,
    "json_decrypt": json_decrypt,
    "json_encrypt": json_encrypt,
    "keypair_ratchets": keypair_ratchets,
    "keys": keys,
    "padding_key": padding_key,
    "passcrypt": passcrypt,
    "plaintext_stream": plaintext_stream,
    "xor": xor,
}


ciphers = Namespace.make_module("ciphers", mapping=__extras)

