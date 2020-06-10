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
    "asubkeys",
    "subkeys",
    "apasscrypt",
    "passcrypt",
    "aencrypt",
    "encrypt",
    "adecrypt",
    "decrypt",
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
    "AsyncDatabase",
    "Database",
]


__doc__ = """
A collection of low-level tools & higher level abstractions which can be
used to create custom security tools & provides a OneTimePad cipher.
"""


import json
import asyncio
import aiofiles
import builtins
from functools import wraps
from hashlib import sha3_512
from multiprocessing import Manager
from multiprocessing import Process
from aiocontext import async_contextmanager
from .paths import *
from .paths import Path
from .asynchs import *
from .commons import *
from .commons import NONE
from .randoms import salt
from .randoms import asalt
from .randoms import csprng
from .randoms import acsprng
from .randoms import make_uuid
from .randoms import amake_uuid
from .randoms import token_bytes
from .generics import astr
from .generics import aiter
from .generics import anext
from .generics import arange
from .generics import generics
from .generics import AsyncInit
from .generics import _zip, azip
from .generics import data, adata
from .generics import pick, apick
from .generics import cycle, acycle
from .generics import order, aorder
from .generics import birth, abirth
from .generics import unpack, aunpack
from .generics import ignore, aignore
from .generics import nc_512, anc_512
from .generics import sha_256, asha_256
from .generics import sha_512, asha_512
from .generics import lru_cache, alru_cache
from .generics import Comprende, comprehension
from .generics import json_encode, ajson_encode
from .generics import json_decode, ajson_decode
from .generics import sha_256_hmac, asha_256_hmac
from .generics import sha_512_hmac, asha_512_hmac


@comprehension()
async def axor(
    *datastreams, key=None, buffer_size=power10[20], convert=True
):
    """
    'The one-time-stream algorithm'

    Gathers both an arbitrary set of async or sync iterable integer
    ``*datastreams``, & a non-repeating async iterable of deterministic
    string ``key`` material, then bitwise xors the streams together
    producing a one-time pad ciphertext. The elements produced by the
    entropy stream will mix with themselves to grow larger than the size
    of each data stream element in discrete jumps of about 256 bytes.

    Restricting the ciphertext to discrete size increments is a measure
    to protect the metadata of plaintext, namely its size, from some
    adversaries that could use such metadata to make informed guesses
    on the contents of the plaintext.
    """
    if convert:
        entropy = key.aint(16).gen.asend
    else:
        entropy = key.gen.asend
    async for items in azip(*datastreams):
        result = 0
        for item in items:
            seed = await entropy(None) * await entropy(None)
            current_key = seed ^ (await entropy(None) * await entropy(None))
            tested = item ^ current_key
            item_size = item * buffer_size
            while tested * 100 > current_key and item_size > current_key:
                current_key = seed ^ (
                    current_key * await entropy(None) * await entropy(None)
                )
                tested = item ^ current_key
            result ^= tested
        yield result


@comprehension()
def xor(*datastreams, key=None, buffer_size=power10[20], convert=True):
    """
    'The one-time-stream algorithm'

    Gathers both an arbitrary set of iterable integer ``*datastreams``,
    & a non-repeating iterable of deterministic string ``key`` material,
    then bitwise xors the streams together producing a one-time pad
    ciphertext. The elements produced by the entropy stream will mix
    with themselves to grow larger than the size of each data stream
    element in discrete jumps of about 256 bytes.

    Restricting the ciphertext to discrete size increments is a measure
    to protect the metadata of plaintext, namely its size, from some
    adversaries that could use such metadata to make informed guesses
    on the contents of the plaintext.
    """
    if convert:
        entropy = key.int(16).gen.send
    else:
        entropy = key.gen.send
    for items in zip(*datastreams):
        result = 0
        for item in items:
            seed = entropy(None) * entropy(None)
            current_key = seed ^ (entropy(None) * entropy(None))
            tested = item ^ current_key
            item_size = item * buffer_size
            while tested * 100 > current_key and item_size > current_key:
                current_key = seed ^ (
                    current_key * entropy(None) * entropy(None)
                )
                tested = item ^ current_key
            result ^= tested
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
async def akeys(key=csprng(), salt=None, pid=0):
    """
    An efficient async generator which produces an unending, non
    repeating, deterministc stream of string key material. Each
    iteration yields 256 hexidecimal characters, iteratively derived
    by the mixing & hashing the permutation of the kwargs, previous
    hashed results, & the ``entropy`` users may send into this generator
    as a coroutine. The ``key`` kwarg is meant to be a longer-term user
    key credential (should be a random 512-bit hex value), the ``salt``
    kwarg is meant to be ephemeral to each stream (also by default a
    random 512-bit hex value), and the user-defined ``pid`` can be used
    to safely parallelize key streams with the same ``key`` & ``salt``
    by specifying a unique ``pid`` to each process, thread or the like,
    which will result in a unique key stream for each.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    salt = salt if salt else await acsprng()
    seed, kdf_0, kdf_1, kdf_2 = await akeypair_ratchets(key, salt, pid)
    async with Comprende().arelay(salt):
        while True:
            ratchet = kdf_0.digest()
            kdf_1.update(ratchet)
            kdf_2.update(ratchet)
            entropy = yield kdf_1.hexdigest() + kdf_2.hexdigest()
            kdf_0.update(str(entropy).encode() + ratchet + seed)


@comprehension()
def keys(key=csprng(), salt=None, pid=0):
    """
    An efficient sync generator which produces an unending, non
    repeating, deterministc stream of string key material. Each
    iteration yields 256 hexidecimal characters, iteratively derived
    by the mixing & hashing the permutation of the kwargs, previous
    hashed results, & the ``entropy`` users may send into this generator
    as a coroutine. The ``key`` kwarg is meant to be a longer-term user
    key credential (should be a random 512-bit hex value), the ``salt``
    kwarg is meant to be ephemeral to each stream (also by default a
    random 512-bit hex value), and the user-defined ``pid`` can be used
    to safely parallelize key streams with the same ``key`` & ``salt``
    by specifying a unique ``pid`` to each process, thread or the like,
    which will result in a unique key stream for each.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    salt = salt if salt else csprng()
    seed, kdf_0, kdf_1, kdf_2 = keypair_ratchets(key, salt, pid)
    with Comprende().relay(salt):
        while True:
            ratchet = kdf_0.digest()
            kdf_1.update(ratchet)
            kdf_2.update(ratchet)
            entropy = yield kdf_1.hexdigest() + kdf_2.hexdigest()
            kdf_0.update(str(entropy).encode() + ratchet + seed)


@comprehension()
async def abytes_keys(key=csprng(), salt=None, pid=0):
    """
    An efficient async generator which produces an unending, non
    repeating, deterministc stream of bytes key material. Each
    iteration yields 256 bytes hexidecimal characters, iteratively
    derived by the mixing & hashing the permutation of the kwargs,
    previous hashed results, & the ``entropy`` users may send into this
    generator as a coroutine. The ``key`` kwarg is meant to be a
    longer-term user key credential (should be a random 512-bit hex
    value), the ``salt`` kwarg is meant to be ephemeral to each stream
    (also by default a random 512-bit hex value), and the user-defined
    ``pid`` can be used to safely parallelize key streams with the same
    ``key`` & ``salt`` by specifying a unique ``pid`` to each process,
    thread or the like, which will result in a unique key stream for
    each.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    salt = salt if salt else await acsprng()
    seed, kdf_0, kdf_1, kdf_2 = await akeypair_ratchets(key, salt, pid)
    async with Comprende().arelay(salt):
        while True:
            ratchet = kdf_0.digest()
            kdf_1.update(ratchet)
            kdf_2.update(ratchet)
            entropy = yield kdf_1.digest() + kdf_2.digest()
            kdf_0.update(str(entropy).encode() + ratchet + seed)


@comprehension()
def bytes_keys(key=csprng(), salt=None, pid=0):
    """
    An efficient sync generator which produces an unending, non
    repeating, deterministc stream of bytes key material. Each
    iteration yields 256 bytes hexidecimal characters, iteratively
    derived by the mixing & hashing the permutation of the kwargs,
    previous hashed results, & the ``entropy`` users may send into this
    generator as a coroutine. The ``key`` kwarg is meant to be a
    longer-term user key credential (should be a random 512-bit hex
    value), the ``salt`` kwarg is meant to be ephemeral to each stream
    (also by default a random 512-bit hex value), and the user-defined
    ``pid`` can be used to safely parallelize key streams with the same
    ``key`` & ``salt`` by specifying a unique ``pid`` to each process,
    thread or the like, which will result in a unique key stream for
    each.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    salt = salt if salt else csprng()
    seed, kdf_0, kdf_1, kdf_2 = keypair_ratchets(key, salt, pid)
    with Comprende().relay(salt):
        while True:
            ratchet = kdf_0.digest()
            kdf_1.update(ratchet)
            kdf_2.update(ratchet)
            entropy = yield kdf_1.digest() + kdf_2.digest()
            kdf_0.update(str(entropy).encode() + ratchet + seed)


@comprehension()
async def asubkeys(key=csprng(), salt=None, pid=0, group_size=512):
    """
    Builds forward-secure branches of key material streams where each
    branch has ``group_size`` subkeys per yielded source key.

    An efficient sync generator which produces an unending, non
    repeating, deterministc stream of string key material. Each
    iteration yields 256 hexidecimal characters, iteratively derived
    by mixing & hashing the permutation of the kwargs, previous
    hashed results, & the ``entropy`` users may send into this generator
    as a coroutine. The ``key`` kwarg is meant to be a longer-term user
    key credential (should be a random 512-bit hex value), the ``salt``
    kwarg is meant to be ephemeral to each stream (also by default a
    random 512-bit hex value), and the user-defined ``pid`` can be used
    to safely parallelize key streams with the same ``key`` & ``salt``
    by specifying a unique ``pid`` to each process, thread or the like,
    which will result in a unique key stream for each.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    elif not group_size >= 1:
        raise ValueError(
            "No infinite loops please. ``group_size`` must be >= 1"
        )
    async with akeys(key=key, salt=salt, pid=pid).arelay() as source:
        entropy = await source()
        branch_keys = await akeys(key, entropy, pid).aprime()
        while True:
            for sub_key in range(group_size):
                entropy = yield await branch_keys(entropy)
            entropy = await source(entropy)


@comprehension()
def subkeys(key=csprng(), salt=None, pid=0, group_size=512):
    """
    Builds forward-secure branches of key material streams where each
    branch has ``group_size`` subkeys per yielded source key.

    An efficient sync generator which produces an unending, non
    repeating, deterministc stream of string key material. Each
    iteration yields 256 hexidecimal characters, iteratively derived
    by the mixing & hashing the permutation of the kwargs, previous
    hashed results, & the ``entropy`` users may send into this generator
    as a coroutine. The ``key`` kwarg is meant to be a longer-term user
    key credential (should be a random 512-bit hex value), the ``salt``
    kwarg is meant to be ephemeral to each stream (also by default a
    random 512-bit hex value), and the user-defined ``pid`` can be used
    to safely parallelize key streams with the same ``key`` & ``salt``
    by specifying a unique ``pid`` to each process, thread or the like,
    which will result in a unique key stream for each.
    """
    if not key:
        raise ValueError("No main symmetric ``key`` was specified.")
    elif not group_size >= 1:
        raise ValueError(
            "No infinite loops please. ``group_size`` must be >= 1"
        )
    with keys(key=key, salt=salt, pid=pid).relay() as source:
        entropy = source()
        branch_keys = keys(key, entropy, pid).prime()
        while True:
            for sub_key in range(group_size):
                entropy = yield branch_keys(entropy)
            entropy = source(entropy)


@comprehension()
async def acipher(data=None, key=None, convert=True):
    """
    A lower-level async generator that feeds two async ``Comprende``
    generators, ``data`` & ``key``, into a stream xor. Both ``key`` &
    ``data`` should yield strings. They are eventually converted within
    the ``axor`` async generator into streams of integers that are
    bitwise xor'd using an algorithm specifically crafted to implement a
    scalable, efficient one-time pad cipher. If ``convert`` is falsey,
    then it's assumed the user's async ``data`` generator will yield
    integer plaintext.
    """
    if convert:
        data = data.aascii_to_int()
    async for ciphertext in axor(data, key=key):
        yield ciphertext


@comprehension()
def cipher(data=None, key=None, convert=True):
    """
    A lower-level sync generator that feeds two sync ``Comprende``
    generators, ``data`` & ``key``, into a stream xor. Both ``key`` &
    ``data`` should yield strings. They are eventually converted within
    the ``xor`` generator into streams of integers that are bitwise
    xor'd using an algorithm specifically crafted to implement a scalable,
    efficient one-time pad cipher. If ``convert`` is falsey, then it's
    assumed the user's ``data`` generator will yield integer plaintext.
    """
    if convert:
        data = data.ascii_to_int()
    for ciphertext in xor(data, key=key):
        yield ciphertext


@comprehension()
async def adecipher(data=None, key=None, convert=True):
    """
    A lower-level async generator that feeds one async ``Comprende``
    generator, ``key``, & a sync or async iterable of enciphered
    integers, ``data``, into a stream xor. ``key`` should yield the same
    stream of string key material that was produced during the cipher
    process.  As well, the integers produced by the async or sync
    iterable ``data`` should be the same integers that were produced by
    the encipherment process. Within the ``axor`` async generator, the
    streams are bitwise xor'd using the same algorithm specifically
    crafted to implement the one-time pad cipher, which reverses the
    process. If ``convert`` is falsey, then it's assumed the user's
    plaintext will be converted from integer chunks manually by the
    user.
    """
    if convert:
        async for plaintext in axor(data, key=key).aint_to_ascii():
            yield plaintext
    else:
        async for plaintext in axor(data, key=key):
            yield plaintext


@comprehension()
def decipher(data=None, key=None, convert=True):
    """
    A lower-level sync generator that feeds one sync ``Comprende``
    generator, ``key``, & an iterable of enciphered integers, ``data``,
    into a stream xor. ``key`` should yield the same stream of string
    key material that was produced during the cipher process. As well,
    the integers produced by the iterable ``data`` should be the same
    integers that were produced by the encipherment process. Within the
    ``xor`` sync generator, the streams are bitwise xor'd using the same
    algorithm specifically crafted to implement the one-time pad cipher,
    which reverses the process. If ``convert`` is falsey, then it's
    assumed the user's plaintext will be converted from integer chunks
    manually by the user.
    """
    if convert:
        for plaintext in xor(data, key=key).int_to_ascii():
            yield plaintext
    else:
        for plaintext in xor(data, key=key):
            yield plaintext


async def aencode_salt(seed=None, key=csprng(), salt=None, pid=0):
    """
    Returns a ciphered ``salt`` that is ciphered with a key stream
    that's derived from the main symmetric ``key``, the ``seed`` which
    is typically the first chunk of ciphertext, & the ``pid`` value.
    This allows the salt to be secret even over a public channel. This
    encriphered salt is then typically inserted as first element in some
    ciphertext.
    """
    if len(salt) != 128:
        raise ValueError(f"Invalid salt, salt != 512-bit hash string.")
    session_entropy = akeys(key=key, salt=seed, pid=pid)
    encode = axor(abirth(salt).aint(16), key=session_entropy)
    return await encode.anext()


def encode_salt(seed=None, key=csprng(), salt=None, pid=0):
    """
    Returns a ciphered ``salt`` that is ciphered with a key stream
    that's derived from the main symmetric ``key``, the ``seed`` which
    is typically the first chunk of ciphertext, & the ``pid`` value.
    This allows the salt to be secret even over a public channel. This
    encriphered salt is then typically inserted as first element in some
    ciphertext.
    """
    if len(salt) != 128:
        raise ValueError(f"Invalid salt, salt != 512-bit hash string.")
    session_entropy = keys(key=key, salt=seed, pid=pid)
    encode = xor(birth(salt).int(16), key=session_entropy)
    return encode.next()


async def adecode_salt(seed=None, key=csprng(), salt=None, pid=0):
    """
    Returns the deciphered ``salt`` that was ciphered with a key stream
    that's derived from the main symmetric ``key``, the ``seed`` which
    is typically the first chunk of ciphertext, & the ``pid`` value.
    This allowed the salt to be secret even over a public channel. This
    encriphered salt is typically inserted as first element in some
    ciphertext.
    """
    entropy = akeys(key, seed, pid=pid)
    decode = axor(abirth(salt), key=entropy)
    decoded_salt = await decode.ahex().azfill(128).anext()
    if len(decoded_salt) == 128:
        return decoded_salt
    else:
        raise ValueError(
            f"Decoding resulted in an invalid salt that != 512-bits."
        )


def decode_salt(seed=None, key=csprng(), salt=None, pid=0):
    """
    Returns the deciphered ``salt`` that was ciphered with a key stream
    that's derived from the main symmetric ``key``, the ``seed`` which
    is typically the first chunk of ciphertext, & the ``pid`` value.
    This allowed the salt to be secret even over a public channel. This
    encriphered salt is typically inserted as first element in some
    ciphertext.
    """
    entropy = keys(key, seed, pid=pid)
    decode = xor(birth(salt), key=entropy)
    decoded_salt = decode.hex().zfill(128).next()
    if len(decoded_salt) == 128:
        return decoded_salt
    else:
        raise ValueError(
            f"Decoding resulted in an invalid salt that != 512-bits."
        )


@comprehension()
async def aorganize_encryption_streams(
    data=None, key=csprng(), salt=None, pid=0, size=246
):
    """
    Creates an interface between the async ``Comprende`` generators that
    iteratively produce plaintext & key material, with specific user
    values:

    ``data``:   A sequence of ascii encoded string plaintext.
    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   A 512-bit hexidecimal string of ephemeral entropic
                material whose str() representation contains the user's
                desired entropy & cryptographic strength.
    ``size``:   The number of elements in the ``data`` sequence that are
                produced per iteration.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes them from each
                other. Designed to safely distinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    """
    entropy = akeys(key=key, salt=salt, pid=pid)
    datastream = adata(sequence=data, size=size)
    async for ciphertext in acipher(data=datastream, key=entropy):
        yield ciphertext
    raise UserWarning(await entropy.aresult(exit=True))


@comprehension()
def organize_encryption_streams(
    data=None, key=csprng(), salt=None, pid=0, size=246
):
    """
    Creates an interface between the sync ``Comprende`` generators that
    iteratively produce plaintext & key material, with specific user
    values:

    ``data``:   A sequence of ascii encoded string plaintext.
    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   A 512-bit hexidecimal string of ephemeral entropic
                material whose str() representation contains the user's
                desired entropy & cryptographic strength.
    ``size``:   The number of elements in the ``data`` sequence that are
                produced per iteration.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes the values they
                produce. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    """
    entropy = keys(key=key, salt=salt, pid=pid)
    datastream = globals()["data"](sequence=data, size=size)
    for ciphertext in cipher(data=datastream, key=entropy):
        yield ciphertext
    return entropy.result(exit=True)


@comprehension()
async def aorganize_decryption_streams(
    data=None, key=None, salt=None, pid=0
):
    """
    Creates an interface between the async ``Comprende`` generators that
    iteratively produce ciphertext & key material, with specific user
    values:

    ``data``:   An async or sync iterable of ciphertext.
    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   A 512-bit hexidecimal string of ephemeral entropic
                material whose str() representation contains the user's
                desired entropy & cryptographic strength.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes them from each
                other. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    """
    entropy = akeys(key=key, salt=salt, pid=pid)
    datastream = aunpack(data)
    async for plaintext in adecipher(data=datastream, key=entropy):
        yield plaintext


@comprehension()
def organize_decryption_streams(data=None, key=None, salt=None, pid=0):
    """
    Creates an interface between the sync ``Comprende`` generators that
    iteratively produce ciphertext & key material, with specific user
    values:

    ``data``:   An sync iterable of ciphertext.
    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   A 512-bit hexidecimal string of ephemeral entropic
                material whose str() representation contains the user's
                desired entropy & cryptographic strength.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes them from each
                other. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    """
    entropy = keys(key=key, salt=salt, pid=pid)
    datastream = unpack(data)
    for plaintext in decipher(data=datastream, key=entropy):
        yield plaintext


@comprehension()
async def aencrypt(data="", key=csprng(), salt=None, pid=0, size=246):
    """
    Creates & organizes user plaintext & key material streams into a
    single stream of integer ciphertext based on user-defined values:

    ``data``:   A sequence of ascii encoded string plaintext.
    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   A 512-bit hexidecimal string of ephemeral entropic
                material whose str() representation contains the user's
                desired entropy & cryptographic strength.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes the values they
                produce. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    ``size``:   The number of elements in the ``data`` sequence that are
                produced per iteration.
    """
    salt = salt if salt else await acsprng()
    encrypting = aorganize_encryption_streams(
        data=data, key=key, salt=salt, pid=pid, size=size
    )
    async with encrypting.arelay(salt):
        session_seed = await encrypting.anext()
        yield await aencode_salt(session_seed, key, salt, pid)
        async for ciphertext in aorder([session_seed], encrypting.iterator):
            yield ciphertext


@comprehension()
def encrypt(data="", key=csprng(), salt=None, pid=0, size=246):
    """
    Creates & organizes user plaintext & key material streams into a
    single stream of integer ciphertext based on user-defined values:

    ``data``:   A sequence of ascii encoded string plaintext.
    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   A 512-bit hexidecimal string of ephemeral entropic
                material whose str() representation contains the user's
                desired entropy & cryptographic strength.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes the values they
                produce. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    ``size``:   The number of elements in the ``data`` sequence that are
                produced per iteration.
    """
    salt = salt if salt else csprng()
    encrypting = organize_encryption_streams(
        data=data, key=key, salt=salt, pid=pid, size=size
    )
    with encrypting.relay(salt):
        session_seed = encrypting.next()
        yield encode_salt(session_seed, key, salt, pid)
        for ciphertext in order([session_seed], encrypting.iterator):
            yield ciphertext


@comprehension()
async def adecrypt(data=(), key=csprng(), pid=0):
    """
    Organizes an async or sync iterable of ciphertext ``data`` & a key
    material stream into a single, async iterable stream of ascii
    encoded plaintext in response to these values:

    ``data``:   An async or sync iterable of ciphertext.
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
    ciphertext = aunpack(data)
    ciphered_salt = await ciphertext.anext()
    session_seed = await ciphertext.anext()

    salt = await adecode_salt(session_seed, key, ciphered_salt, pid)
    decrypting = aorganize_decryption_streams(
        data=aorder([session_seed], ciphertext.iterator),
        key=key,
        salt=salt,
        pid=pid,
    )
    async for plaintext in decrypting:
        yield plaintext


@comprehension()
def decrypt(data=(), key=csprng(), pid=0):
    """
    Organizes a sync iterable of ciphertext ``data`` & a key material
    stream into a single, async iterable stream of ascii encoded
    plaintext in response to these values:

    ``data``:   A sync iterable of ciphertext.
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
    ciphertext = unpack(data)
    ciphered_salt = ciphertext.next()
    session_seed = ciphertext.next()

    salt = decode_salt(session_seed, key, ciphered_salt, pid)
    decrypting = organize_decryption_streams(
        data=order([session_seed], ciphertext.iterator),
        key=key,
        salt=salt,
        pid=pid,
    )
    for plaintext in decrypting:
        yield plaintext


async def ajson_encrypt(data=None, key=csprng(), salt=None, pid=0):
    """
    Returns a json ready dictionary containing one-time pad ciphertext
    of any json serializable ``data`` that's created from a key stream
    derived from permutations of these values:

    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   A 512-bit hexidecimal string of ephemeral entropic
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
    plaintext = adata(json.dumps(data))
    async with plaintext.aencrypt(key, salt, pid=pid) as ciphertext:
        result = await ciphertext.alist(True)
        return {
            "ciphertext": result,
            "hmac": await validator.ahmac(result, key=key),
        }


def json_encrypt(data=None, key=csprng(), salt=None, pid=0):
    """
    Returns a json ready dictionary containing one-time pad ciphertext
    of any json serializable ``data`` that's created from a key stream
    derived from permutations of these values:

    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   A 512-bit hexidecimal string of ephemeral entropic
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
    plaintext = globals()["data"](json.dumps(data))
    with plaintext.encrypt(key, salt, pid=pid) as ciphertext:
        result = ciphertext.list(True)
        return {
            "ciphertext": result, "hmac": validator.hmac(result, key=key)
        }


async def ajson_decrypt(data=None, key=None, pid=0):
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
    try:
        ciphertext = aunpack(data["ciphertext"])
    except TypeError:
        data = json.loads(data)
        ciphertext = aunpack(data["ciphertext"])
    hmac = data.get("hmac")
    if hmac:
        await validator.atest_hmac(data["ciphertext"], key=key, hmac=hmac)
    async with ciphertext.adecrypt(key=key, pid=pid) as plaintext:
        return json.loads(await plaintext.ajoin())


def json_decrypt(data=None, key=None, pid=0):
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
    try:
        ciphertext = unpack(data["ciphertext"])
    except TypeError:
        data = json.loads(data)
        ciphertext = unpack(data["ciphertext"])
    hmac = data.get("hmac")
    if hmac:
        validator.test_hmac(data["ciphertext"], key=key, hmac=hmac)
    with ciphertext.decrypt(key=key, pid=pid) as plaintext:
        return json.loads(plaintext.join())


async def abytes_encrypt(data=None, key=csprng(), salt=None, pid=0):
    """
    Returns a list of the encrypted one-time pad ciphertext of the
    binary ``data`` with a key stream derived from permutations of these
    values:

    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   A 512-bit hexidecimal string of ephemeral entropic
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
    if not data:
        raise ValueError("No ``data`` was specified.")
    encrypting = adata(data).abytes_encrypt(key, salt, pid)
    async with encrypting as ciphertext:
        result = await ciphertext.alist(True)
        hmac = await validator.ahmac(result, key=key)
        return {"ciphertext": result, "hmac": hmac}


def bytes_encrypt(data=None, key=csprng(), salt=None, pid=0):
    """
    Returns a list of the encrypted one-time pad ciphertext of the
    binary ``data`` with a key stream derived from permutations of these
    values:

    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   A 512-bit hexidecimal string of ephemeral entropic
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
    if not data:
        raise ValueError("No ``data`` was specified.")
    encrypting = globals()["data"](data).bytes_encrypt(key, salt, pid)
    with encrypting as ciphertext:
        result = ciphertext.list(True)
        hmac = validator.hmac(result, key=key)
        return {"ciphertext": result, "hmac": hmac}


async def abytes_decrypt(data=None, key=None, pid=0):
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
    if isinstance(data, dict):
        hmac = data.get("hmac")
        data = data.get("ciphertext")
        await validator.atest_hmac(data, key=key, hmac=hmac)
    async with aunpack(data).abytes_decrypt(key, pid) as decrypting:
        return await decrypting.ajoin(b"")


def bytes_decrypt(data=None, key=None, pid=0):
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
    if isinstance(data, dict):
        hmac = data.get("hmac")
        data = data.get("ciphertext")
        validator.test_hmac(data, key=key, hmac=hmac)
    with unpack(data).bytes_decrypt(key, pid) as decrypting:
        return decrypting.join(b"")


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
    decode_salt = staticmethod(decode_salt)
    adecode_salt = staticmethod(adecode_salt)
    encode_salt = staticmethod(encode_salt)
    aencode_salt = staticmethod(aencode_salt)

    def __call__(
        self, password, salt, *, kb=1024, cpu=3, hardness=1024, aio=False
    ):
        settings = dict(kb=kb, cpu=cpu, hardness=hardness)
        if aio:
            return self.anew(password, salt, **settings)
        else:
            return self.new(password, salt, **settings)

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
            raise PermissionError(f"hardness:{hardness} must be int >= 256")
        elif cpu <= 1 or not isinstance(cpu, int):
            raise PermissionError(f"cpu:{cpu} must be int >= 2")
        elif kb < hardness or not isinstance(kb, int):
            raise PermissionError(
                f"kb:{kb} must be int >= hardness:{hardness}"
            )

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
        to_int = int.from_bytes
        cache_width = len(ram)
        next_index = cycle(range(cache_width)).__next__
        choose = lambda: ram[to_int(digest, "big") % cache_width]
        return keyed_scanner

    @classmethod
    async def _apasscrypt(
        cls, password, salt, *, kb=1024, cpu=3, hardness=1024, state=()
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
        cache_width = cls.cache_width(kb, cpu, hardness)
        args = sha_512(password, salt, kb, cpu, hardness).encode()
        async with abytes_keys(password, salt, args)[:cache_width] as cache:
            ram = await cache.alist(mutable=True)
            proof = sha3_512(ram[-1] + args)
            prove = cls._work_memory_prover(proof, ram, cpu)
            for element in ram:
                prove()
                await switch()
            final_proof = azip(ram[:hardness], reversed(ram))
            async with final_proof.asum_sha_256(proof.digest()) as summary:
                state.append(sha_512(await summary.alist(mutable=True)))

    @classmethod
    def _passcrypt(
        cls, password, salt, *, kb=1024, cpu=3, hardness=1024, state=()
    ):
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
        cache_width = cls.cache_width(kb, cpu, hardness)
        args = sha_512(password, salt, kb, cpu, hardness).encode()
        with bytes_keys(password, salt, args)[:cache_width] as cache:
            ram = cache.list(mutable=True)
            proof = sha3_512(ram[-1] + args)
            prove = cls._work_memory_prover(proof, ram, cpu)
            for element in ram:
                prove()
            final_proof = _zip(ram[:hardness], reversed(ram))
            with final_proof.sum_sha_256(proof.digest()) as summary:
                state.append(sha_512(summary.list(mutable=True)))

    @classmethod
    async def anew(cls, password, salt, *, kb=1024, cpu=3, hardness=1024):
        """
        The passcrypt algorithm can be highly memory intensive. These
        resources may not be freed up, & often are not, because of
        python quirks around memory management. This is a huge problem.
        So to force the release of those resources, we run the function
        in another process which is guaranteed to release them.
        """
        if not password:
            raise ValueError("No ``password`` was specified.")
        elif not salt:
            raise ValueError("No ``salt`` was specified.")
        cls._validate_args(kb, cpu, hardness)
        state = Manager().list()
        process = Process(
            target=cls._passcrypt,
            args=(password, salt),
            kwargs=dict(kb=kb, cpu=cpu, hardness=hardness, state=state),
        )
        process.start()
        while process.is_alive():
            await asleep(0.01)
        process.join()
        return state.pop()

    @classmethod
    def new(cls, password, salt, *, kb=1024, cpu=3, hardness=1024):
        """
        The passcrypt algorithm can be highly memory intensive. These
        resources may not be freed up, & often are not, because of
        python quirks around memory management. This is a huge problem.
        So to force the release of those resources, we run the function
        in another process which is guaranteed to release them.
        """
        if not password:
            raise ValueError("No ``password`` was specified.")
        elif not salt:
            raise ValueError("No ``salt`` was specified.")
        cls._validate_args(kb, cpu, hardness)
        state = Manager().list()
        process = Process(
            target=cls._passcrypt,
            args=(password, salt),
            kwargs=dict(kb=kb, cpu=cpu, hardness=hardness, state=state),
        )
        process.start()
        while process.is_alive():
            asynchs.sleep(0.01)
        process.join()
        return state.pop()


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

    instance_methods = {
        akeys,
        keys,
        abytes_keys,
        bytes_keys,
        asubkeys,
        subkeys,
        aencrypt,
        encrypt,
        adecrypt,
        decrypt,
        ajson_encrypt,
        json_encrypt,
        ajson_decrypt,
        json_decrypt,
        abytes_encrypt,
        bytes_encrypt,
        abytes_decrypt,
        bytes_decrypt,
    }

    axor = staticmethod(axor)
    xor = staticmethod(xor)
    adata = staticmethod(adata)
    data = staticmethod(data)
    aunpack = staticmethod(aunpack)
    unpack = staticmethod(unpack)
    akeys = staticmethod(akeys)
    keys = staticmethod(keys)
    abytes_keys = staticmethod(abytes_keys)
    bytes_keys = staticmethod(bytes_keys)
    asubkeys = staticmethod(asubkeys)
    subkeys = staticmethod(subkeys)
    apasscrypt = staticmethod(apasscrypt)
    passcrypt = staticmethod(passcrypt)
    decode_salt = staticmethod(decode_salt)
    adecode_salt = staticmethod(adecode_salt)
    encode_salt = staticmethod(encode_salt)
    aencode_salt = staticmethod(aencode_salt)
    acipher = staticmethod(acipher)
    cipher = staticmethod(cipher)
    adecipher = staticmethod(adecipher)
    decipher = staticmethod(decipher)
    aencrypt = staticmethod(aencrypt)
    encrypt = staticmethod(encrypt)
    adecrypt = staticmethod(adecrypt)
    decrypt = staticmethod(decrypt)
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
    async def _amap_encrypt(self, names=None, entropy=None):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, async one-time-pad encryption algorithm, while also
        keeping some encapsulation of code and functionality.

        When ``names`` is a stream of deterministic key material, this
        algorithm produces a hashmap of ciphertext, such that without
        the key material used to derive the stream, ordering the chunks
        of ciphertext correctly is a guessing game.

        ``entropy`` should be an async ``Comprende`` generator which,
        like ``aiootp.akeys``, yields a stream key material from some
        source key material and a random salt >= 256-bits.

        ``self`` is an instance of a ``Comprende`` generator that yields
        some length of string plaintext per iteration (246 is best for
        the most common plaintext ascii character sets).
        """
        mapped_cipherstream = acipher(data=self, key=entropy).atag(names)
        async for name, ciphertext in mapped_cipherstream:
            yield name, ciphertext

    @comprehension()
    def _map_encrypt(self, names=None, entropy=None):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, sync one-time-pad encryption algorithm, while also
        keeping some encapsulation of code and functionality.

        When ``names`` is a stream of deterministic key material, this
        algorithm produces a hashmap of ciphertext, such that without
        the key material used to derive the stream, ordering the chunks
        of ciphertext correctly is a guessing game.

        ``entropy`` should be an sync ``Comprende`` generator which,
        like ``aiootp.keys``, yields a stream key material from some
        source key material and a random salt >= 256-bits.

        ``self`` is an instance of a ``Comprende`` generator that yields
        some length of string plaintext per iteration (246 is best for
        the most common plaintext ascii character sets).
        """
        for name, ciphertext in cipher(data=self, key=entropy).tag(names):
            yield name, ciphertext

    @comprehension()
    async def _amap_decrypt(self, entropy=None):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, async one-time-pad decryption algorithm, while also
        keeping some encapsulation of code and functionality.

        ``entropy`` should be an async ``Comprende`` generator which,
        like ``aiootp.akeys``, yields a stream key material from some
        source key material and a random salt >= 256-bits. The salt must
        be the same as the one used for encryption.

        ``self`` is an instance of an async ``Comprende`` generator that
        yields a chunk of ciphertext in the correct order each iteration.
        ``entropy`` is the async ``Comprende`` generator that produces
        the same key material stream used during encryption.
        """
        async for plaintext in adecipher(data=self, key=entropy):
            yield plaintext

    @comprehension()
    def _map_decrypt(self, entropy=None):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, sync one-time-pad decryption algorithm, while also
        keeping some encapsulation of code and functionality.

        ``entropy`` should be an sync ``Comprende`` generator which,
        like ``aiootp.keys``, yields a stream key material from some
        source key material and a random salt >= 256-bits. The salt must
        be the same as the one used for encryption.

        ``self`` is an instance of an sync ``Comprende`` generator that
        yields a chunk of ciphertext in the correct order each iteration.
        ``entropy`` is the sync ``Comprende`` generator that produces
        the same key material stream used during encryption.
        """
        for plaintext in decipher(data=self, key=entropy):
            yield plaintext

    @comprehension()
    async def _aotp_encrypt(self, key=csprng(), salt=None, pid=0, size=246):
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
        key for any particular context. This main key & the first chunk
        of ciphertext are combined & used to encrypt / decrypt the
        ``salt`` key. The ciphered salt key is the first transmitted
        chunk in a ciphertext stream.

        The ``salt`` keyword should be a random 512-bit hash. The
        plaintext ``salt`` is used as an ephemeral key to initialize a
        deterministc stream of key material which is unique to a
        particualr ``key``.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.

        The ``size`` keyword argument is the number of characters in the
        plaintext strings that're processed during encryption & turned
        into chunks of ciphertext. If ``size`` is set to ``None`` then
        the plaintext strings are not resized before processing in this
        way. This may be less efficient to the cipher algorithm, but
        allows the decryption process to yield plaintext items exactly
        as they were produced from the plaintext generator. The value
        246 tends to be the most efficient, especially when the
        plaintext contains only 7-bit ascii characters.
        """
        salt = salt if salt else await acsprng()

        entropy = akeys(key=key, salt=salt, pid=pid)
        if not size:
            encrypting = acipher(data=self, key=entropy)
        else:
            encrypting = acipher(data=self.aresize(size), key=entropy)

        session_seed = await encrypting.anext()
        yield await aencode_salt(session_seed, key, salt, pid)
        async for result in aorder([session_seed], encrypting.iterator):
            yield result

    @comprehension()
    def _otp_encrypt(self, key=csprng(), salt=None, pid=0, size=246):
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
        key for any particular context. This main key & the first chunk
        of ciphertext are combined & used to encrypt / decrypt the
        ``salt`` key. The ciphered salt key is the first transmitted
        chunk in a ciphertext stream.

        The ``salt`` keyword should be a random 512-bit hash. The
        plaintext ``salt`` is used as an ephemeral key to initialize a
        deterministc stream of key material which is unique to a
        particualr ``key``.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.

        The ``size`` keyword argument is the number of characters in the
        plaintext strings that're processed during encryption & turned
        into chunks of ciphertext. If ``size`` is set to ``None`` then
        the plaintext strings are not resized before processing in this
        way. This may be less efficient to the cipher algorithm, but
        allows the decryption process to yield plaintext items exactly
        as they were produced from the plaintext generator. The value
        246 tends to be the most efficient, especially when the
        plaintext contains only 7-bit ascii characters.
        """
        salt = salt if salt else csprng()

        entropy = keys(key=key, salt=salt, pid=pid)
        if not size:
            encrypting = cipher(data=self, key=entropy)
        else:
            encrypting = cipher(data=self.resize(size), key=entropy)

        session_seed = encrypting.next()
        yield encode_salt(session_seed, key, salt, pid)
        for result in order([session_seed], encrypting.iterator):
            yield result

    @comprehension()
    async def _aotp_decrypt(self, key=csprng(), pid=0):
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
        key. This main key & the first chunk of ciphertext are combined
        & used to encrypt / decrypt the ``salt`` key. The ciphered salt
        key is the first transmitted chunk in a ciphertext stream, so
        decryption methods don't need to explicitly be passed a
        plaintext salt. The plaintext salt is a random 512-bit hash
        which is used as an ephemeral key to initialize a deterministc
        stream of key material which is unique to a particualr ``key``.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.
        """
        ciphertext = generics.aiter(self)
        ciphered_salt = await ciphertext.anext()
        session_seed = await ciphertext.anext()

        salt = await adecode_salt(session_seed, key, ciphered_salt, pid)
        entropy = akeys(key=key, salt=salt, pid=pid)
        async for plaintext in adecipher(
            data=aorder([session_seed], ciphertext.iterator), key=entropy
        ):
            yield plaintext

    @comprehension()
    def _otp_decrypt(self, key=csprng(), pid=0):
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
        key. This main key & the first chunk of ciphertext are combined
        & used to encrypt / decrypt the ``salt`` key. The ciphered salt
        key is the first transmitted chunk in a ciphertext stream, so
        decryption methods don't need to explicitly be passed a
        plaintext salt. The plaintext salt is a random 512-bit hash
        which is used as an ephemeral key to initialize a deterministc
        stream of key material which is unique to a particualr ``key``.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.
        """
        ciphertext = generics.iter(self)
        ciphered_salt = ciphertext.next()
        session_seed = ciphertext.next()

        salt = decode_salt(session_seed, key, ciphered_salt, pid)
        entropy = keys(key=key, salt=salt, pid=pid)
        for plaintext in decipher(
            data=order([session_seed], ciphertext.iterator), key=entropy
        ):
            yield plaintext

    @comprehension()
    async def _abytes_encrypt(self, key=csprng(), salt=None, pid=0):
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
        key for any particular context. This main key & the first chunk
        of ciphertext are combined & used to encrypt / decrypt the
        ``salt`` key. The ciphered salt key is the first transmitted
        chunk in a ciphertext stream.

        The ``salt`` keyword should be a random 512-bit hash. The
        plaintext ``salt`` is used as an ephemeral key to initialize a
        deterministc stream of key material which is unique to a
        particualr ``key``.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.
        """
        encoder = self.ato_base64().adecode().adelimit()
        async for result in encoder.aencrypt(key, salt, pid):
            yield result

    @comprehension()
    def _bytes_encrypt(self, key=csprng(), salt=None, pid=0):
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
        key for any particular context. This main key & the first chunk
        of ciphertext are combined & used to encrypt / decrypt the
        ``salt`` key. The ciphered salt key is the first transmitted
        chunk in a ciphertext stream.

        The ``salt`` keyword should be a random 512-bit hash. The
        plaintext ``salt`` is used as an ephemeral key to initialize a
        deterministc stream of key material which is unique to a
        particualr ``key``.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.
        """
        encoder = self.to_base64().decode().delimit()
        for result in encoder.encrypt(key, salt, pid):
            yield result

    @comprehension()
    async def _abytes_decrypt(self, key=None, pid=0):
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
        key for any particular context. This main key & the first chunk
        of ciphertext are combined & used to encrypt / decrypt the
        ``salt`` key. The ciphered salt key is the first transmitted
        chunk in a ciphertext stream.

        The ``salt`` keyword should be a random 512-bit hash. The
        plaintext ``salt`` is used as an ephemeral key to initialize a
        deterministc stream of key material which is unique to a
        particualr ``key``.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.
        """
        decrypting = self.adecrypt(key, pid)
        decoder = decrypting.adelimit_resize().afrom_base64()
        async for result in decoder:
            yield result

    @comprehension()
    def _bytes_decrypt(self, key=None, pid=0):
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
        key for any particular context. This main key & the first chunk
        of ciphertext are combined & used to encrypt / decrypt the
        ``salt`` key. The ciphered salt key is the first transmitted
        chunk in a ciphertext stream.

        The ``salt`` keyword should be a random 512-bit hash. The
        plaintext ``salt`` is used as an ephemeral key to initialize a
        deterministc stream of key material which is unique to a
        particualr ``key``.

        The ``pid`` keyword argument is any identifier which is unique
        to a particular pair of ``key`` & ``salt``. This identifier is
        used to create a deterministic stream of key material which is
        unlinkable and unique to other ``pid`` streams with the same
        pair of ``key`` & ``salt``.
        """
        decrypting = self.decrypt(key, pid)
        decoder = decrypting.delimit_resize().from_base64()
        for result in decoder:
            yield result


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

    _METATAG = sha_256(f"__metatags__{NONE}")
    directory = DatabasePath()

    async def __init__(
        self,
        key=None,
        password_depth=0,  # >= 5000 if ``key`` is weak
        preload=True,
        directory=directory,
        metatag=False,
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
            random salt value in their ``self.root_path`` file which is
            encrypted twice. Where metatags only encrypt their salts
            with the outter layer of file encryption. This makes metatag
            child databases more light-weight organizational additions
            to existing databases.
        """
        self.directory = Path(directory)
        self._cache = Namespace()
        self._manifest = Namespace()
        self.root_key, self.root_hash, self.root_filename = (
            await self.ainitialize_keys(key, password_depth)
        )
        if metatag:
            self.is_metatag = True
        else:
            self.is_metatag = False
        await self.aload_manifest()
        await self.ainitialize_metatags()
        if preload:
            await self.aload()

    @staticmethod
    async def ainitialize_keys(key=None, password_depth=0):
        """
        Derives the database's cryptographic root key material and the
        filename of the manifest ledger.
        """
        root_key = await akeys(key, key, key)[password_depth]()
        root_hash = await asha_512_hmac(root_key, key=root_key)
        root_filename = await asha_256_hmac(root_hash, key=root_hash)
        return root_key, root_hash, root_filename

    @property
    def root_path(self):
        """
        Returns a ``pathlib.Path`` object that points to the file that
        contains the manifest ledger.
        """
        return self.directory / self.root_filename

    @property
    def root_session_salt(self):
        """
        Returns the database's most recent random nonce.
        """
        return self.__dict__.get("_root_session_salt")

    @property
    def root_names(self):
        """
        Returns the deterministic key stream used to initially organize
        the encrypted manifest ledger shards as a hash map.
        """
        return akeys(
            self.root_hash, self.root_hash, self.root_session_salt
        ).aresize(64)

    @property
    def root_entropy(self):
        """
        Returns the deterministic key stream used to initially unlock
        the manifest ledger. The manifest also contains an encrypted
        cryptographic key that is used to decrypt & encrypt the rest of
        the database.
        """
        return akeys(self.root_key, self.root_key, self.root_session_salt)

    @property
    @lru_cache(maxsize=2)
    def cache(self):
        """
        Returns the database object's cache of recently loaded & stored
        values.
        """
        return self._cache

    @property
    @lru_cache(maxsize=2)
    def manifest(self):
        """
        Returns the database object's file ledger.
        """
        return self._manifest

    @property
    def maintenance_files(self):
        """
        Returns the filenames of entries in the database that refer to
        administrative values used by objects to track and coordinate
        themselves internally.
        """
        return {self.root_filename, self.metatags_filename}

    @property
    def tags(self):
        """
        Returns a list of all user-defined names for values stored in
        the database object.
        """
        database = dict(self.manifest.namespace)
        for filename in self.maintenance_files:
            del database[filename]
        return list(database.values())

    async def anamestream(self, tag=None):
        """
        Returns a keys object able to build an unlimited, deterministic
        stream of key material, 64 hex characters per iteration. Each
        stream distinguished by the seed value ``tag`` are safely
        different from each other. This allows for cryptographically
        obscuring the order of ciphertext stored in a hash map.

        The database object uses this function internally to pick the
        stream of shard names for ciphertext within files, but first
        passes the user-defined ``tag`` through the
        ``afilename((tag, salt))`` method, thereby making a unique,
        deterministic key stream for each ``tag`` & salt pair.
        """
        return akeys(self.root_hash, self.root_seed, tag).aresize(64)

    async def akeystream(self, tag=None):
        """
        Returns a keys object able to build an unlimited, deterministic
        stream of key material, 256 hex characters per iteration. Each
        stream distinguished by the seed value ``tag`` are safely
        different from each other.

        The database object uses this function internally to pick the
        stream of key material for transparent file encryption, but
        first passes the user-defined ``tag`` through the
        ``afilename((tag, salt))`` method, thereby making a unique,
        deterministic key stream for each ``tag`` & salt pair.
        """
        return akeys(self.root_key, await self.__aroot_salt(), tag)

    async def aopen_manifest(self):
        """
        Loads an existing manifest file ledger from the filesystem.
        """
        async with aiofiles.open(self.root_path, "r") as root_file:
            ciphertext = json.loads(await root_file.read())

        if ciphertext.get("hmac"):
            async with aunpack(ciphertext.items()).asort() as sorting:
                ciphertext = await sorting.adict()
            salt = ciphertext.pop("salt")
            hmac = ciphertext.pop("hmac")
            await validator.atest_hmac(
                ciphertext, hmac=hmac, key=self.root_hash
            )
        else:
            salt = ciphertext.get("salt")
        self._root_session_salt = salt
        names = self.root_names
        entropy = self.root_entropy
        decrypting = apick(names, ciphertext).amap_decrypt(entropy)
        async with decrypting as manifest:
            return json.loads(await manifest.ajoin())

    async def acreate_salting_function(self, salt=None):
        """
        Creates and returns an async function for the instance to
        retrieve a cryptographic ``salt`` key. If the instance is a
        metatag child database, then the returned key is assumed to not
        have been stored encrypted. Otherwise, the ``salt`` is assumed
        to be encrypted, and is decrypted within the created function.
        """
        instance_hash = sha_256_hmac((hash(self), salt), key=self.root_hash)

        @alru_cache()
        async def __aroot_salt(database=instance_hash):
            """
            Keeps the ``root_salt`` tucked away until queried, where
            then it's cached for efficiency.
            """
            if self.is_metatag:
                return salt
            else:
                return await ajson_decrypt(salt, self.root_key)

        return __aroot_salt

    async def ainstall_root_salt(
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
            if self.is_metatag or not auto_encrypt
            else await ajson_encrypt(root_salt, self.root_key)
        )
        self._manifest[self.root_filename] = salt
        self.__aroot_salt = await self.acreate_salting_function(salt)
        self.root_seed = await asha_512_hmac(
            await self.__aroot_salt(), self.root_key
        )

    async def aload_manifest(self):
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """
        if self.root_path.exists():
            self._manifest = Namespace(await self.aopen_manifest())
            root_salt = self._manifest[self.root_filename]
        else:
            self._manifest = Namespace()
            self._root_session_salt = (await acsprng())[:64]
            if self.is_metatag:
                root_salt = (await acsprng())[:64]
            else:
                root_salt = await ajson_encrypt(csprng(), self.root_key)

        await self.ainstall_root_salt(root_salt, auto_encrypt=False)

    async def asave_manifest(self, ciphertext=None):
        """
        Writes the manifest ledger to disk. It contains all database
        filenames & special cryptographic values for initializing the
        database's key derivation functions.
        """
        if not ciphertext:
            raise PermissionError("Invalid write attempted.")
        async with aiofiles.open(self.root_path, "w+") as manifest:
            await manifest.write(json.dumps(ciphertext))

    async def aclose_manifest(self):
        """
        Prepares for & writes the manifest ledger to disk. The manifest
        contains all database filenames & special cryptographic values
        for initializing the database's key derivation functions.
        """
        salt = self._root_session_salt = (await acsprng())[:64]
        names = self.root_names
        entropy = self.root_entropy
        plaintext = adata(json.dumps(self.manifest.namespace))
        encrypting = plaintext.amap_encrypt(names, entropy)
        async with encrypting.asort() as manifest:
            result = await manifest.adict()
            hmac = await validator.ahmac(result, key=self.root_hash)
            await self.asave_manifest(
                {"salt": salt, "hmac": hmac, **result}
            )

    async def aload_metatags(self, *, preload=True):
        """
        Specifically loads all of the database's metatag values into the
        cache. If the ``preload`` keyword argument is falsey then the
        metatag references are populated in the database's instance
        dictionary, but their internal values are not loaded.
        """
        await gather(
            *[
                self.ametatag(metatag, preload=preload)
                for metatag in set(self.metatags)
            ]
        )

    async def aload_tags(self):
        """
        Specifically loads all of the database's tag values into the
        cache.
        """
        database = dict(self.manifest.namespace)
        for maintenance_file in self.maintenance_files:
            del database[maintenance_file]
        await gather(
            *[self.aquery(tag) for filename, tag in database.items()]
        )

    async def aload(self, *, metatags=True):
        """
        Loads all the database object's values from the filesystem into
        the database cache. This brings the database values into the
        cache, enables up-to-date bracket lookup of tag values & dotted
        lookup of metatags. Otherwise, values would have to be queried
        using the awaitable ``aquery`` & ``ametatag`` methods.
        """
        await gather(
            self.aload_metatags(preload=metatags), self.aload_tags()
        )
        return self

    async def afilename(self, tag=None):
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        return await asha_256_hmac(
            (tag, self.root_seed), key=self.root_hash
        )

    @staticmethod
    async def asalt(entropy=csprng()):
        """
        Returns a random 512-bit hexidecimal string.
        """
        return await acsprng(str(entropy).encode())

    async def ahmac(self, *data):
        """
        Creates an HMAC hash of the arguments passed into ``*data`` with
        keys derived from the key used to open the database instance.
        """
        return await asha_256_hmac(
            (data, self.root_hash), key=self.root_seed
        )

    async def atest_hmac(self, *data, hmac=None):
        """
        Tests if ``hmac`` of ``*data`` is valid using database keys.
        Instead of using a constant time character by character check on
        the hmac, the hmac itself is hmac'd with a random salt & is
        checked against the hmac & salt of the correct hmac. This
        non-constant time check on the hmac of the supplied hmac doesn't
        reveal meaningful information about the true hmac if the
        attacker does not have access to the secret key. Nor does it
        gain information about the hmac it supplied since it is salted.
        This scheme is easier to implement correctly & is easier to
        guarantee the infeasibility of a timing attack, since "constant
        time" operations are truly dependant on architectures, languages
        & resource allocation for those operations.
        """
        if not hmac:
            raise ValueError("`hmac` keyword argument was not given.")
        salt = await acsprng()
        true_hmac = await self.ahmac(*data)
        if (
            await self.ahmac(hmac, salt)
            == await self.ahmac(true_hmac, salt)
        ):
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
        algorithm.
        """
        _apasscrypt = globals()["apasscrypt"]
        salted_password = await self.ahmac(password, salt)
        return await _apasscrypt(
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
            name = await (await self.anamestream(category)).anext()
            uuids = await amake_uuid(size, salt=name).aprime()
            salt = salt if salt else csprng()[:64]
            async with uuids.arelay(salt) as ids:
                stamp = None
                while True:
                    stamp = yield await ids(
                        await asha_256(name, salt, stamp)
                    )

        return await _auuids().aprime()

    async def aquery_ciphertext(self, filename=None):
        """
        Retrieves the value stored in the database file that's called
        ``filename``.
        """
        async with aiofiles.open(self.directory / filename, "r") as db_file:
            return json.loads(await db_file.read())

    @comprehension()
    async def adecrypt_stream(
        self, filename=None, stream=None, salt=None
    ):
        """
        Constructs the key stream for the decryption of the ciphertext
        ``stream`` labeled by a ``filename``. Yields plaintext in json
        string chunks.

        ``filename``    Internally, this is the salted & hashed tag that
            labels a piece of data in the database. If a salt is passed,
            this generator isn't being called internally, but by a user.
            In which case, the user's ``filename`` will be hashed again
            with the salt to recreate the correct keystream used during
            encryption.
        ``stream``      This is an async ``Comprende`` generator that
            produces ciphertext chunks in the correct order.
        ``salt``        Is a random ephemeral key of arbitrary size &
            type whose string representation should contain at least 256
            bits of entropy.
        """
        if salt:
            salted_filename = await self.afilename((filename, salt))
        else:
            salted_filename = filename
        entropy = await self.akeystream(salted_filename)
        async for plaintext in stream.amap_decrypt(entropy):
            yield plaintext

    async def aciphertext_stream(
        self, filename=None, ciphertext=None, salt=None
    ):
        """
        Handles taking in a dictionary (hashmap) of ``ciphertext``,
        a random ``salt`` that's typically attached to the ciphertext,
        & the optional ``filename`` that labels the data.
        """
        if salt:
            salted_filename = await self.afilename((filename, salt))
        else:
            salted_filename = filename
        names = await self.anamestream(salted_filename)
        return apick(names, ciphertext)

    async def adecrypt(self, filename=None, ciphertext=None):
        """
        Constructs the key & name streams for the decryption & retrieval
        of the value stored in the database file called ``filename``.
        Returns the complete plaintext loaded from json format.

        ``filename``    This is the hashed tag that labels a piece of
            data in the database. It's then hashed again with the random
            ephemeral salt that was attached to the ciphertext.
        ``ciphertext``  This is a dictionary (hashmap) of ciphertext
            chunks labeled by a stream of cryptographically derived
            names. It should also contain a random ephemeral salt that's
            labeled "salt". The salt should contain at least 256-bits of
            entropy.
        """
        if ciphertext.get("hmac"):
            async with aunpack(ciphertext.items()).asort() as sorting:
                ciphertext = await sorting.adict()
            salt = ciphertext.pop("salt")
            hmac = ciphertext.pop("hmac")
            await self.atest_hmac(ciphertext, hmac=hmac)
        else:
            salt = ciphertext.get("salt")
        salted_filename = await self.afilename((filename, salt))
        stream = await self.aciphertext_stream(salted_filename, ciphertext)
        decrypting = self.adecrypt_stream(salted_filename, stream)
        async with decrypting as plaintext:
            return json.loads(await plaintext.ajoin())

    async def asave_ciphertext(self, filename=None, ciphertext=None):
        """
        Saves the encrypted value ``ciphertext`` in the database file
        called ``filename``.
        """
        async with aiofiles.open(
            self.directory / filename, "w+"
        ) as db_file:
            await db_file.write(json.dumps(ciphertext))

    @comprehension()
    async def aencrypt_stream(self, filename=None, stream=None, salt=None):
        """
        Constructs the key & name streams for the encryption & storage
        in the database of the value ``plaintext`` in the file called
        ``filename``. Yields a tuple of a name & a ciphertext chunk per
        iteration for creating cryptographically ordered & obscured
        hashmaps of encrypted data.

        ``filename``    This is the hashed tag that labels a piece of
            data in the database. It's then hashed again with a random
            ephemeral salt that's created in this method, or it can be
            created prior to using this generator & passed into ``salt``.
        ``stream``      This is an async ``Comprende`` generator that
            yields some length string (usually 246 is best) of plaintext
            per iteration.
        ``salt``        The random ephemeral salt that's used to make
            the key & name streams unique. If it's created in this
            generator instead of being passed in, then the salt is
            returned back to the user in a UserWarning which makes it
            available in the generator's ``aresult`` method at the end
            of the stream.
        """
        random_salt = salt if salt else (await acsprng())[:64]
        salted_filename = await self.afilename((filename, random_salt))
        names = await self.anamestream(salted_filename)
        entropy = await self.akeystream(salted_filename)
        encrypting = stream.amap_encrypt(names, entropy)
        async for name, ciphertext in encrypting:
            yield name, ciphertext
        if not salt:
            raise UserWarning(random_salt)

    async def aencrypt(self, filename=None, plaintext=None):
        """
        Constructs the key & name streams for the encryption & storage
        in the database of the value ``plaintext`` in the file called
        ``filename``. Returns the ciphertext hashmap.

        ``filename``    This is the hashed tag that labels a piece of
            data in the database. It's then hashed again with a random
            ephemeral salt that's created in this method & attached to
            the ciphertext. If this method is being called by a user,
            this can be any arbitrary value that's useful for labeling
            the data being encrypted.
        ``plaintext``   This is any json serializable object that is to
            be encrypted into a hashmap of shards.
        """
        salt = (await acsprng())[:64]
        encoder = ajson_encode(plaintext)
        encrypting = self.aencrypt_stream(filename, encoder, salt)
        async with encrypting.asort() as ciphertext:
            result = await ciphertext.adict()
            hmac = await self.ahmac(result)
            return {"salt": salt, "hmac": hmac, **result}

    async def aset(self, tag=None, data=None):
        """
        Allows users to add the value ``data`` under the name ``tag``
        into the database.
        """
        filename = await self.afilename(tag)
        self.cache[filename] = data
        self.manifest[filename] = tag

    async def aquery(self, tag=None):
        """
        Allows users to retrieve the value stored under the name ``tag``
        from the database.
        """
        filename = await self.afilename(tag)
        if filename in self.cache:
            return self.cache[filename]
        elif filename in self.manifest:
            ciphertext = await self.aquery_ciphertext(filename)
            result = await self.adecrypt(filename, ciphertext)
            self.cache[filename] = result
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
            del self.manifest[filename]
        except KeyError:
            pass
        try:
            del self.cache[filename]
        except KeyError:
            pass
        await self.adelete_file(filename)
        return value

    async def adelete_file(self, filename=None):
        """
        Deletes a file in the database directory by ``filename``.
        """
        try:
            await asynchs.aos.remove(self.directory / filename)
        except FileNotFoundError:
            pass

    async def ainitialize_metatags(self):
        """
        Initializes the values that organize database metatags, which
        are children databases contained within their parent.
        """
        self.metatags_filename = await self.afilename(self._METATAG)
        if self.metatags == None:
            self.manifest[self.metatags_filename] = []

    @property
    def metatags(self):
        """
        Returns the list of metatags that a database contains.
        """
        return self.manifest.namespace.get(self.metatags_filename)

    async def ametatag_key(self, tag=None):
        """
        Derives the metatag's database key given a user-defined ``tag``.
        """
        return await asha_512_hmac((tag, self.root_seed), self.root_hash)

    async def ametatag(self, tag=None, preload=True):
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
            key=await self.ametatag_key(tag),
            password_depth=0,
            preload=preload,
            directory=self.directory,
            metatag=True,
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
            self.cache[filename] = value
            self.manifest[filename] = tag
        async for metatag in its_metatags:
            my_metatag = await self.ametatag(metatag)
            await my_metatag.amirror_database(database.__dict__[metatag])

    async def adelete_database(self):
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        for metatag in self.metatags:
            await (await self.ametatag(metatag)).adelete_database()
        for filename in self.manifest.namespace:
            await self.adelete_file(filename)
        self.cache.namespace.clear()
        self.manifest.namespace.clear()

    async def asave_metatags(self):
        """
        Writes the database's child databases to disk.
        """
        async for metatag in aunpack(set(self.metatags)):
            if self.__dict__.get(metatag):
                await self.__dict__[metatag].asave()

    async def asave_tags(self):
        """
        Writes the database's user-defined tags to disk.
        """
        maintenance_files = self.maintenance_files
        database = dict(self.cache.namespace).items()
        async for filename, plaintext in aunpack(database):
            if filename in maintenance_files:
                continue
            ciphertext = await self.aencrypt(filename, plaintext)
            await self.asave_ciphertext(filename, ciphertext)

    async def asave(self):
        """
        Writes the database's values to disk.
        """
        if self.root_filename not in self.manifest:
            raise PermissionError("The database keys have been deleted.")
        await self.aclose_manifest()
        await gather(self.asave_metatags(), self.asave_tags())

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

        assert namespace.tag == db["tag"]
        assert namespace.tag is db["tag"]
        """
        async with aunpack(self) as namespace:
            return Namespace(await namespace.adict())

    def __contains__(self, tag=None):
        """
        Checks the cache & manifest for the filename associated with the
        user-defined ``tag``.
        """
        filename = sha_256_hmac((tag, self.root_seed), self.root_hash)
        return filename in self.manifest or filename in self.cache

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
        maintenance_files = self.maintenance_files
        for filename, tag in dict(self.manifest.namespace).items():
            if filename in maintenance_files:
                continue
            yield tag, await self.aquery(tag)

    def __setitem__(self, tag=None, data=None):
        """
        Allows users to add the value ``data`` under the name ``tag``
        into the database.
        """
        filename = sha_256_hmac((tag, self.root_seed), self.root_hash)
        self.cache[filename] = data
        self.manifest[filename] = tag

    def __getitem__(self, tag=None):
        """
        Allows users to retrieve the value stored under the name ``tag``
        from the database.
        """
        filename = sha_256_hmac((tag, self.root_seed), self.root_hash)
        if filename in self.cache:
            return self.cache[filename]

    def __delitem__(self, tag=None):
        """
        Allows users to delete the value stored under the name ``tag``
        from the database.
        """
        filename = sha_256_hmac((tag, self.root_seed), self.root_hash)
        try:
            del self.manifest[filename]
        except KeyError:
            pass
        try:
            del self.cache[filename]
        except KeyError:
            pass
        try:
            (self.directory / filename).unlink()
        except FileNotFoundError:
            pass

    __len__ = lambda self: len(self.manifest.namespace)


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

    _METATAG = sha_256(f"__metatags__{NONE}")
    directory = DatabasePath()

    def __init__(
        self,
        key=None,
        password_depth=0,  # >= 5000 if ``key`` is weak
        preload=True,
        directory=directory,
        metatag=False,
    ):
        """
        Sets a database object's basic key generators & cryptographic
        values based on the unique permutations of the ``key`` &
        ``password_depth`` values. If ``key`` is a password, or has very
        low entropy, then ``password_depth`` should be a larger number
        since it will cause the object to compute for that many more
        interations when deterministically deriving its  cryptopraghic
        root keys.

        ``preload``: This boolean value tells the object to -- True --
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
            random salt value in their ``self.root_path`` file which is
            encrypted twice. Where metatags only encrypt their salts
            with the outter layer of file encryption. This makes metatag
            child databases more light-weight organizational additions
            to existing databases.
        """
        self.directory = Path(directory)
        self._cache = Namespace()
        self._manifest = Namespace()
        self.root_key, self.root_hash, self.root_filename = (
            self.initialize_keys(key, password_depth)
        )
        if metatag:
            self.is_metatag = True
        else:
            self.is_metatag = False
        self.load_manifest()
        self.initialize_metatags()
        if preload:
            self.load()

    @staticmethod
    def initialize_keys(key=None, password_depth=0):
        """
        Derives the database's cryptographic root key material and the
        filename of the manifest ledger.
        """
        root_key = keys(key, key, key)[password_depth]()
        root_hash = sha_512_hmac(root_key, key=root_key)
        root_filename = sha_256_hmac(root_hash, key=root_hash)
        return root_key, root_hash, root_filename

    @property
    def root_path(self):
        """
        Returns a ``pathlib.Path`` object that points to the file that
        contains the manifest ledger.
        """
        return self.directory / self.root_filename

    @property
    def root_session_salt(self):
        """
        Returns the database's most recent random nonce.
        """
        return self.__dict__.get("_root_session_salt")

    @property
    def root_names(self):
        """
        Returns the deterministic key stream used to initially organize
        the encrypted manifest ledger shards as a hash map.
        """
        return keys(
            self.root_hash, self.root_hash, self.root_session_salt
        ).resize(64)

    @property
    def root_entropy(self):
        """
        Returns the deterministic key stream used to initially unlock
        the manifest ledger. The manifest also contains an encrypted
        cryptographic key that is used to decrypt & encrypt the rest of
        the database.
        """
        return keys(self.root_key, self.root_key, self.root_session_salt)

    @property
    @lru_cache()
    def cache(self):
        """
        Returns the database object's cache of recently loaded & stored
        values.
        """
        return self._cache

    @property
    @lru_cache()
    def manifest(self):
        """
        Returns the database object's file ledger.
        """
        return self._manifest

    @property
    def maintenance_files(self):
        """
        Returns the filenames of entries in the database that refer to
        administrative values used by objects to track and coordinate
        themselves internally.
        """
        return {self.root_filename, self.metatags_filename}

    @property
    def tags(self):
        """
        Returns a list of all user-defined names for values stored in
        the database object.
        """
        database = dict(self.manifest.namespace)
        for filename in self.maintenance_files:
            del database[filename]
        return list(database.values())

    def namestream(self, tag=None):
        """
        Returns a keys object able to build an unlimited, deterministic
        stream of key material, 64 hex characters per iteration. Each
        stream distinguished by the seed value ``tag`` are safely
        different from each other. This allows for cryptographically
        obscuring the order of ciphertext stored in a hash map.

        The database object uses this function internally to pick the
        stream of shard names for ciphertext within files, but first
        passes the user-defined ``tag`` through the
        ``filename((tag, salt))`` method, thereby making a unique,
        deterministic key stream for each ``tag`` & salt pair.
        """
        return keys(self.root_hash, self.root_seed, tag).resize(64)

    def keystream(self, tag=None):
        """
        Returns a keys object able to build an unlimited, deterministic
        stream of key material, 256 hex characters per iteration. Each
        stream distinguished by the seed value ``tag`` are safely
        different from each other.

        The database object uses this function internally to pick the
        stream of key material for transparent file encryption, but
        first passes the user-defined ``tag`` through the
        ``filename((tag, salt))`` method, thereby making a unique,
        deterministic key stream for each ``tag`` & salt pair.
        """
        return keys(self.root_key, self.__root_salt(), tag)

    def open_manifest(self):
        """
        Loads an existing manifest file ledger from the filesystem.
        """
        with open(self.root_path, "r") as root_file:
            ciphertext = json.load(root_file)

        if ciphertext.get("hmac"):
            with unpack(ciphertext.items()).sort() as sorting:
                ciphertext = sorting.dict()
            salt = ciphertext.pop("salt")
            hmac = ciphertext.pop("hmac")
            validator.test_hmac(ciphertext, hmac=hmac, key=self.root_hash)
        else:
            salt = ciphertext.get("salt")
        self._root_session_salt = salt
        names = self.root_names
        entropy = self.root_entropy
        with pick(names, ciphertext).map_decrypt(entropy) as manifest:
            return json.loads(manifest.join())

    def create_salting_function(self, salt=None):
        """
        Creates and returns a function for the instance to retrieve a
        cryptographic ``salt`` key. If the instance is a metatag child
        database, then the returned key is assumed to not have been
        stored encrypted. Otherwise, the ``salt`` is assumed to be
        encrypted, and is decrypted within the created function.
        """
        instance_hash = sha_256_hmac((hash(self), salt), key=self.root_hash)

        @lru_cache()
        def __root_salt(database=instance_hash):
            """
            Keeps the ``root_salt`` tucked away until queried, where
            then it's cached for efficiency.
            """
            if self.is_metatag:
                return salt
            else:
                return json_decrypt(salt, self.root_key)

        return __root_salt

    def install_root_salt(self, root_salt=None, *, auto_encrypt=True):
        """
        Inserts the database's root entropy source in the manifest
        ledger & the instance's caches of keys. Tags & metatags not
        loaded into the cache will be unretrievable without the
        root_salt that is replaced in this function.
        """
        salt = (
            root_salt
            if self.is_metatag or not auto_encrypt
            else json_encrypt(root_salt, self.root_key)
        )
        self._manifest[self.root_filename] = salt
        self.__root_salt = self.create_salting_function(salt)
        self.root_seed = sha_512_hmac(self.__root_salt(), self.root_key)

    def load_manifest(self):
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """
        if self.root_path.exists():
            self._manifest = Namespace(self.open_manifest())
            root_salt = self._manifest[self.root_filename]
        else:
            self._manifest = Namespace()
            self._root_session_salt = csprng()[:64]
            if self.is_metatag:
                root_salt = csprng()[:64]
            else:
                root_salt = json_encrypt(csprng(), self.root_key)

        self.install_root_salt(root_salt, auto_encrypt=False)

    def save_manifest(self, ciphertext=None):
        """
        Writes the manifest ledger to disk. It contains all database
        filenames & special cryptographic values for initializing the
        database's key derivation functions.
        """
        if not ciphertext:
            raise PermissionError("Invalid write attempted.")
        with open(self.root_path, "w+") as manifest:
            manifest.write(json.dumps(ciphertext))

    def close_manifest(self):
        """
        Prepares for & writes the manifest ledger to disk. The manifest
        contains all database filenames & special cryptographic values
        for initializing the database's key derivation functions.
        """
        salt = self._root_session_salt = csprng()[:64]
        names = self.root_names
        entropy = self.root_entropy
        plaintext = data(json.dumps(self.manifest.namespace))
        with plaintext.map_encrypt(names, entropy).sort() as manifest:
            result = manifest.dict()
            hmac = validator.hmac(result, key=self.root_hash)
            self.save_manifest({"salt": salt, "hmac": hmac, **result})

    def load_metatags(self, *, preload=True):
        """
        Specifically loads all of the database's metatag values into the
        cache. If the ``preload`` keyword argument is falsey then the
        metatag references are populated in the database's instance
        dictionary, but their internal values are not loaded.
        """
        for metatag in set(self.metatags):
            self.metatag(metatag, preload=preload)

    def load_tags(self):
        """
        Specifically loads all of the database's tag values into the
        cache.
        """
        for tag, value in self:
            pass

    def load(self, *, metatags=True):
        """
        Loads all the database object's values from the filesystem into
        the database cache. This brings the database values into the
        cache, enables up-to-date bracket lookup of tag values & dotted
        lookup of metatags.
        """
        self.load_metatags(preload=metatags)
        self.load_tags()
        return self

    def filename(self, tag=None):
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        return sha_256_hmac((tag, self.root_seed), key=self.root_hash)

    @staticmethod
    def salt(entropy=csprng()):
        """
        Returns a random 512-bit hexidecimal string.
        """
        return csprng(str(entropy).encode())

    def hmac(self, *data):
        """
        Creates an HMAC hash of the arguments passed into ``*data`` with
        keys derived from the key used to open the database instance.
        """
        return sha_256_hmac((data, self.root_hash), key=self.root_seed)

    def test_hmac(self, *data, hmac=None):
        """
        Tests if ``hmac`` of ``*data`` is valid using database keys.
        Instead of using a constant time character by character check on
        the hmac, the hmac itself is hmac'd with a random salt & is
        checked against the hmac & salt of the correct hmac. This
        non-constant time check on the hmac of the supplied hmac doesn't
        reveal meaningful information about the true hmac if the
        attacker does not have access to the secret key. Nor does it
        gain information about the hmac it supplied since it is salted.
        This scheme is easier to implement correctly & is easier to
        guarantee the infeasibility of a timing attack, since "constant
        time" operations are truly dependant on architectures, languages
        & resource allocation for those operations.
        """
        if not hmac:
            raise ValueError("`hmac` keyword argument was not given.")
        salt = csprng()
        true_hmac = self.hmac(*data)
        if self.hmac(hmac, salt) == self.hmac(true_hmac, salt):
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
        algorithm.
        """
        _passcrypt = globals()["passcrypt"]
        salted_password = self.hmac(password, salt)
        return _passcrypt(
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
            name = self.namestream(category).next()
            uuids = make_uuid(size, salt=name).prime()
            salt = salt if salt else csprng()[:64]
            with uuids.relay(salt) as ids:
                stamp = None
                while True:
                    stamp = yield ids(sha_256(name, salt, stamp))

        return _uuids().prime()

    def query_ciphertext(self, filename=None):
        """
        Retrieves the value stored in the database file that's called
        ``filename``.
        """
        with open(self.directory / filename, "r") as db_file:
            return json.load(db_file)

    @comprehension()
    def decrypt_stream(self, filename=None, stream=None, salt=None):
        """
        Constructs the key stream for the decryption of the ciphertext
        ``stream`` labeled by a ``filename``. Yields plaintext in json
        string chunks.

        ``filename``    Internally, this is the salted & hashed tag that
            labels a piece of data in the database. If a salt is passed,
            this generator isn't being called internally, but by a user.
            In which case, the user's ``filename`` will be hashed again
            with the salt to recreate the correct keystream used during
            encryption.
        ``stream``      This is any sync ``Comprende`` generator that
            produces ciphertext chunks in the correct order.
        ``salt``        Is a random ephemeral key of arbitrary size &
            type whose string representation should contain at least 256
            bits of entropy.
        """
        if salt:
            salted_filename = self.filename((filename, salt))
        else:
            salted_filename = filename
        entropy = self.keystream(salted_filename)
        for plaintext in stream.map_decrypt(entropy):
            yield plaintext

    def ciphertext_stream(self, filename=None, ciphertext=None, salt=None):
        """
        Handles taking in a dictionary (hashmap) of ``ciphertext``,
        a random ``salt`` that's typically attached to the ciphertext,
        & the optional ``filename`` that labels the data.
        """
        if salt:
            salted_filename = self.filename((filename, salt))
        else:
            salted_filename = filename
        names = self.namestream(salted_filename)
        return pick(names, ciphertext)

    def decrypt(self, filename=None, ciphertext=None):
        """
        Constructs the key & name streams for the decryption & retrieval
        of the value stored in the database file called ``filename``.
        Returns the complete plaintext loaded from json format.

        ``filename``    This is the hashed tag that labels a piece of
            data in the database. It's then hashed again with the random
            ephemeral salt that was attached to the ciphertext.
        ``ciphertext``  This is a dictionary (hashmap) of ciphertext
            chunks labeled by a stream of cryptographically derived
            names. It should also contain a random ephemeral salt that's
            labeled "salt". The salt should contain at least 256-bits of
            entropy.
        """
        if ciphertext.get("hmac"):
            with unpack(ciphertext.items()).sort() as sorting:
                ciphertext = sorting.dict()
            salt = ciphertext.pop("salt")
            hmac = ciphertext.pop("hmac")
            self.test_hmac(ciphertext, hmac=hmac)
        else:
            salt = ciphertext.get("salt")
        salted_filename = self.filename((filename, salt))
        stream = self.ciphertext_stream(salted_filename, ciphertext)
        decrypting = self.decrypt_stream(salted_filename, stream)
        with decrypting as plaintext:
            return json.loads(plaintext.join())

    def save_ciphertext(self, filename=None, ciphertext=None):
        """
        Saves the encrypted value ``ciphertext`` in the database file
        called ``filename``.
        """
        with open(self.directory / filename, "w+") as db_file:
            json.dump(ciphertext, db_file)

    @comprehension()
    def encrypt_stream(self, filename=None, stream=None, salt=None):
        """
        Constructs the key & name streams for the encryption & storage
        in the database of the value ``plaintext`` in the file called
        ``filename``. Yields a tuple of a name & a ciphertext chunk per
        iteration for creating cryptographically ordered & obscured
        hashmaps of encrypted data.

        ``filename``    This is the hashed tag that labels a piece of
            data in the database. It's then hashed again with a random
            ephemeral salt that's created in this method, or it can be
            created prior to using this generator & passed into ``salt``.
        ``stream``      This is any sync ``Comprende`` generator that
            yields some length string (usually 246 is best) of plaintext
            per iteration.
        ``salt``        The random ephemeral salt that's used to make
            the key & name streams unique. If it's created in this
            generator instead of being passed in, then the salt is
            returned back to the user in a UserWarning which makes it
            available in the generator's ``result`` method at the end
            of the stream.
        """
        random_salt = salt if salt else csprng()[:64]
        salted_filename = self.filename((filename, random_salt))
        names = self.namestream(salted_filename)
        entropy = self.keystream(salted_filename)
        encrypting = stream.map_encrypt(names, entropy)
        for name, ciphertext in encrypting:
            yield name, ciphertext
        if not salt:
            return random_salt

    def encrypt(self, filename=None, plaintext=None):
        """
        Constructs the key & name streams for the encryption & storage
        in the database of the value ``plaintext`` in the file called
        ``filename``. Returns the ciphertext hashmap.

        ``filename``    This is the hashed tag that labels a piece of
            data in the database. It's then hashed again with a random
            ephemeral salt that's created in this method & attached to
            the ciphertext. If this method is being called by a user,
            this can be any arbitrary value that's useful for labeling
            the data being encrypted.
        ``plaintext``   This is any json serializable object that is to
            be encrypted into a hashmap of shards.
        """
        salt = csprng()[:64]
        encoder = json_encode(plaintext)
        encrypting = self.encrypt_stream(filename, encoder, salt)
        with encrypting.sort() as ciphertext:
            result = ciphertext.dict()
            hmac = self.hmac(result)
            return {"salt": salt, "hmac": hmac, **result}

    def set(self, tag=None, data=None):
        """
        Allows users to add the value ``data`` under the name ``tag``
        into the database.
        """
        filename = self.filename(tag)
        self.cache[filename] = data
        self.manifest[filename] = tag

    def query(self, tag=None):
        """
        Allows users to retrieve the value stored under the name ``tag``
        from the database.
        """
        filename = self.filename(tag)
        if filename in self.cache:
            return self.cache[filename]
        elif filename in self.manifest:
            ciphertext = self.query_ciphertext(filename)
            result = self.decrypt(filename, ciphertext)
            self.cache[filename] = result
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
            del self.manifest[filename]
        except KeyError:
            pass
        try:
            del self.cache[filename]
        except KeyError:
            pass
        self.delete_file(filename)
        return value

    def delete_file(self, filename=None):
        """
        Deletes a file in the database directory by ``filename``.
        """
        try:
            (self.directory / filename).unlink()
        except FileNotFoundError:
            pass

    def initialize_metatags(self):
        """
        Initializes the values that organize database metatags, which
        are children databases contained within their parent.
        """
        self.metatags_filename = self.filename(self._METATAG)
        if self.metatags == None:
            self.manifest[self.metatags_filename] = []

    @property
    def metatags(self):
        """
        Returns the list of metatags that a database contains.
        """
        return self.manifest.namespace.get(self.metatags_filename)

    def metatag_key(self, tag=None):
        """
        Derives the metatag's database key given a user-defined ``tag``.
        """
        return sha_512_hmac((tag, self.root_seed), self.root_hash)

    def metatag(self, tag=None, preload=True):
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
            key=self.metatag_key(tag),
            password_depth=0,
            preload=preload,
            directory=self.directory,
            metatag=True,
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
                self.cache[filename] = value
                self.manifest[filename] = tag
        else:
            # Works with async databases, but doesn't load unloaded values
            for tag in database.tags:
                filename = self.filename(tag)
                self.cache[filename] = database[tag]
                self.manifest[filename] = tag
        for metatag in its_metatags:
            my_metatag = self.metatag(metatag)
            my_metatag.mirror_database(database.__dict__[metatag])

    def delete_database(self):
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        for metatag in self.metatags:
            self.metatag(metatag).delete_database()
        for filename in self.manifest.namespace:
            self.delete_file(filename)
        self.cache.namespace.clear()
        self.manifest.namespace.clear()

    def save_metatags(self):
        """
        Writes the database's child databases to disk.
        """
        for metatag in set(self.metatags):
            if self.__dict__.get(metatag):
                self.__dict__[metatag].save()

    def save_tags(self):
        """
        Writes the database's user-defined tags to disk.
        """
        maintenance_files = self.maintenance_files
        database = dict(self.cache.namespace).items()
        for filename, plaintext in database:
            if filename in maintenance_files:
                continue
            ciphertext = self.encrypt(filename, plaintext)
            self.save_ciphertext(filename, ciphertext)

    def save(self):
        """
        Writes the database's values to disk.
        """
        if self.root_filename not in self.manifest:
            raise PermissionError("The database keys have been deleted.")
        self.close_manifest()
        self.save_metatags()
        self.save_tags()

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

        assert namespace.tag == db["tag"]
        assert namespace.tag is db["tag"]
        """
        with unpack(self) as namespace:
            return Namespace(namespace.dict())

    def __contains__(self, tag=None):
        """
        Checks the cache & manifest for the filename associated with the
        user-defined ``tag``.
        """
        filename = self.filename(tag)
        return filename in self.manifest or filename in self.cache

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
        self.close()

    def __iter__(self):
        """
        Provides an interface to the names & values stored in databases.
        """
        maintenance_files = self.maintenance_files
        for filename, tag in dict(self.manifest.namespace).items():
            if filename in maintenance_files:
                continue
            yield tag, self.query(tag)

    __delitem__ = pop
    __getitem__ = query
    __setitem__ = vars()["set"]
    __len__ = lambda self: len(self.manifest.namespace)


validator = Namespace()


__extras = {
    "AsyncDatabase": AsyncDatabase,
    "Database": Database,
    "Passcrypt": Passcrypt,
    "OneTimePad": OneTimePad,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "abytes_decrypt": abytes_decrypt,
    "abytes_encrypt": abytes_encrypt,
    "abytes_keys": abytes_keys,
    "acipher": acipher,
    "adecipher": adecipher,
    "adecode_salt": adecode_salt,
    "adecrypt": adecrypt,
    "aencode_salt": aencode_salt,
    "aencrypt": aencrypt,
    "ajson_decrypt": ajson_decrypt,
    "ajson_encrypt": ajson_encrypt,
    "akeypair_ratchets": akeypair_ratchets,
    "akeys": akeys,
    "aorganize_decryption_streams": aorganize_decryption_streams,
    "aorganize_encryption_streams": aorganize_encryption_streams,
    "apasscrypt": apasscrypt,
    "asubkeys": asubkeys,
    "axor": axor,
    "bytes_decrypt": bytes_decrypt,
    "bytes_encrypt": bytes_encrypt,
    "bytes_keys": bytes_keys,
    "cipher": cipher,
    "decipher": decipher,
    "decode_salt": decode_salt,
    "decrypt": decrypt,
    "encode_salt": encode_salt,
    "encrypt": encrypt,
    "json_decrypt": json_decrypt,
    "json_encrypt": json_encrypt,
    "keypair_ratchets": keypair_ratchets,
    "keys": keys,
    "organize_decryption_streams": organize_decryption_streams,
    "organize_encryption_streams": organize_encryption_streams,
    "passcrypt": passcrypt,
    "subkeys": subkeys,
    "xor": xor,
}


ciphers = Namespace.make_module("ciphers", mapping=__extras)

