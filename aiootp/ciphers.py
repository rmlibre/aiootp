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
    "asubkeys",
    "subkeys",
    "aencrypt",
    "encrypt",
    "adecrypt",
    "decrypt",
    "ajson_decrypt",
    "json_decrypt",
    "ajson_encrypt",
    "json_encrypt",
    "OneTimePad",
    "AsyncDatabase",
    "Database",
]


__doc__ = """
A collection of low-level tools & higher level abstractions which can be
used to create custom security tools & provides a OneTimePad cipher.
"""


import json
import aiofiles
import builtins
from os import mkdir
from os import makedirs
from hashlib import sha3_512
from collections import deque
from aiocontext import async_contextmanager
from .paths import *
from .paths import Path
from .commons import *
from .commons import NONE
from .asynchs import *
from .randoms import csprng
from .randoms import acsprng
from .generics import astr
from .generics import azip
from .generics import aiter
from .generics import anext
from .generics import arange
from .generics import generics
from .generics import AsyncInit
from .generics import is_generator
from .generics import is_exception
from .generics import is_async_iterable
from .generics import is_async_generator
from .generics import data, adata
from .generics import pick, apick
from .generics import order, aorder
from .generics import birth, abirth
from .generics import unpack, aunpack
from .generics import ignore, aignore
from .generics import nc_512, anc_512
from .generics import sha_256, asha_256
from .generics import sha_512, asha_512
from .generics import seedrange, aseedrange
from .generics import lru_cache, alru_cache
from .generics import Comprende, comprehension
from .generics import nc_512_hmac, anc_512_hmac
from .generics import sha_256_hmac, asha_256_hmac
from .generics import sha_512_hmac, asha_512_hmac


@comprehension()
async def axor(
    *datastreams, key=None, buffer_size=power10[20], convert=True
):
    """
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
        entropy = key.aint(16)
    else:
        entropy = key
    async for items in azip(*datastreams):
        result = 0
        for item in items:
            seed = await entropy() * await entropy()
            current_key = seed ^ (await entropy() * await entropy())
            tested = item ^ current_key
            item_size = item * buffer_size
            while tested * 100 > current_key and item_size > current_key:
                current_key = seed ^ (
                    current_key * await entropy() * await entropy()
                )
                tested = item ^ current_key
            result ^= tested
        yield result


@comprehension()
def xor(*datastreams, key=None, buffer_size=power10[20], convert=True):
    """
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
        entropy = key.int(16)
    else:
        entropy = key
    for items in zip(*datastreams):
        result = 0
        for item in items:
            seed = entropy() * entropy()
            current_key = seed ^ (entropy() * entropy())
            tested = item ^ current_key
            item_size = item * buffer_size
            while tested * 100 > current_key and item_size > current_key:
                current_key = seed ^ (current_key * entropy() * entropy())
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
    kdf_2 = sha3_512(kdf_1.digest() + kdf_0.digest())
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
    kdf_2 = sha3_512(kdf_1.digest() + kdf_0.digest())
    return seed_1, kdf_0, kdf_1, kdf_2


@comprehension()
async def akeys(key=None, salt=None, pid=0):
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
    salt = salt if salt != None else await acsprng()
    seed, kdf_0, kdf_1, kdf_2 = await akeypair_ratchets(key, salt, pid)
    async with Comprende().arelay(salt):
        while True:
            ratchet = kdf_0.digest()
            kdf_1.update(ratchet)
            kdf_2.update(ratchet)
            entropy = yield kdf_1.hexdigest() + kdf_2.hexdigest()
            kdf_0.update((await astr(entropy)).encode() + ratchet + seed)


@comprehension()
def keys(key=None, salt=None, pid=0):
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
    salt = salt if salt != None else csprng()
    seed, kdf_0, kdf_1, kdf_2 = keypair_ratchets(key, salt, pid)
    with Comprende().relay(salt):
        while True:
            ratchet = kdf_0.digest()
            kdf_1.update(ratchet)
            kdf_2.update(ratchet)
            entropy = yield kdf_1.hexdigest() + kdf_2.hexdigest()
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
    if not group_size >= 1:
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
    if not group_size >= 1:
        raise ValueError(
            "No infinite loops please. ``group_size`` must be >= 1"
        )
    with keys(key=key, salt=salt, pid=pid).relay() as source:
        entropy = source()
        branch_keys = keys(key, entropy, pid).prime()
        while True:
            for branch in range(group_size):
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
    ``salt``:   An aribrary amount & type of ephemeral entropic material
                whose str() representation contains the user's desired
                entropy & cryptographic strength.
    ``size``:   The number of elements in the ``data`` sequence that are
                produced per iteration.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes them from each
                other. Designed to safely destinguish parallelized key
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
    ``salt``:   An aribrary amount & type of ephemeral entropic material
                whose str() representation contains the user's desired
                entropy & cryptographic strength.
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
    ``salt``:   An aribrary amount & type of ephemeral entropic material
                whose str() representation contains the user's desired
                entropy & cryptographic strength.
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
    ``salt``:   An aribrary amount & type of ephemeral entropic material
                whose str() representation contains the user's desired
                entropy & cryptographic strength.
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
async def aencrypt(data="", key=csprng(), salt=None, size=246, pid=0):
    """
    Creates & organizes user plaintext & key material streams into a
    single stream of integer ciphertext based on user-defined values:

    ``data``:   A sequence of ascii encoded string plaintext.
    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   An aribrary amount & type of ephemeral entropic material
                whose str() representation contains the user's desired
                entropy & cryptographic strength.
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
    salt = salt if salt != None else await acsprng(key)
    encrypting = aorganize_encryption_streams(
        data=data, key=key, salt=salt, size=size, pid=pid
    )
    async with encrypting.arelay(result=salt):
        session_seed = await encrypting.anext()
        entropy = akeys(key, session_seed, pid=pid)
        encode_salt = axor(abirth(salt).aint(16), key=entropy)
        yield await encode_salt.anext()
        async for ciphertext in encrypting:
            yield ciphertext


@comprehension()
def encrypt(data="", key=csprng(), salt=None, size=246, pid=0):
    """
    Creates & organizes user plaintext & key material streams into a
    single stream of integer ciphertext based on user-defined values:

    ``data``:   A sequence of ascii encoded string plaintext.
    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   An aribrary amount & type of ephemeral entropic material
                whose str() representation contains the user's desired
                entropy & cryptographic strength.
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
    salt = salt if salt != None else csprng(key)
    encrypting = organize_encryption_streams(
        data=data, key=key, salt=salt, size=size, pid=pid
    )
    with encrypting.relay(result=salt):
        session_seed = encrypting.next()
        entropy = keys(key, session_seed, pid=pid)
        encode_salt = xor(birth(salt).int(16), key=entropy)
        yield encode_salt.next()
        for ciphertext in encrypting:
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

    entropy = akeys(key, session_seed, pid=pid)
    decode_salt = axor(abirth(ciphered_salt), key=entropy)
    salt = await decode_salt.ahex().aslice(2, None).azfill(128).anext()

    decrypting = aorganize_decryption_streams(
        data=ciphertext[1:], key=key, salt=salt, pid=pid
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

    entropy = keys(key, session_seed, pid=pid)
    decode_salt = xor(birth(ciphered_salt), key=entropy)
    salt = decode_salt.hex().slice(2, None).zfill(128).next()

    decrypting = organize_decryption_streams(
        data=ciphertext[1:], key=key, salt=salt, pid=pid
    )
    for plaintext in decrypting:
        yield plaintext


async def ajson_encrypt(data=None, key=None, salt=None, pid=0):
    """
    Returns a json ready dictionary containing one-time pad ciphertext
    of any json serializable ``data`` that's created from a key stream
    derived from permutations of these values:

    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   An aribrary amount & type of ephemeral entropic material
                whose str() representation contains the user's desired
                entropy & cryptographic strength.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes the values they
                produce. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    """
    results = []
    plaintext = json.dumps(data)
    async for result in abirth(plaintext).aencrypt(key, salt, pid=pid):
        results.append(result)
    return {"ciphertext": results}


def json_encrypt(data=None, key=None, salt=None, pid=0):
    """
    Returns a json ready dictionary containing one-time pad ciphertext
    of any json serializable ``data`` that's created from a key stream
    derived from permutations of these values:

    ``key``:    An aribrary amount & type of entropic material whose
                str() representation contains the user's desired entropy
                & cryptographic strength. Designed to be used as a
                longer-term user encryption / decryption key.
    ``salt``:   An aribrary amount & type of ephemeral entropic material
                whose str() representation contains the user's desired
                entropy & cryptographic strength.
    ``pid``:    An arbitrary value that can be used to categorize key
                material streams & safely distinguishes the values they
                produce. Designed to safely destinguish parallelized key
                material streams with the same ``key`` & ``salt``. But
                can be used for any arbitrary categorization of streams
                as long as the encryption & decryption processes for a
                given stream use the same ``pid`` value.
    """
    results = []
    plaintext = json.dumps(data)
    for result in birth(plaintext).encrypt(key, salt, pid=pid):
        results.append(result)
    return {"ciphertext": results}


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
    results = ""
    try:
        ciphertext = data["ciphertext"]
    except TypeError:
        data = json.loads(data)
        ciphertext = data["ciphertext"]
    async for result in aunpack(ciphertext).adecrypt(key=key, pid=pid):
        results += result
    return json.loads(results)


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
    results = ""
    try:
        ciphertext = data["ciphertext"]
    except TypeError:
        data = json.loads(data)
        ciphertext = data["ciphertext"]
    for result in unpack(ciphertext).decrypt(key=key, pid=pid):
        results += result
    return json.loads(results)


class OneTimePad:
    """
    A class composed of the low-level procedures used to implement this
    package's one-time pad cipher, & the higher level interfaces for
    utilizing the one-time pad cipher. This cipher implementation is
    built entirely out of generators & the data processing pipelines
    that are made simple by this package's ``Comprende`` generators.
    """

    axor = staticmethod(axor)
    xor = staticmethod(xor)
    adata = staticmethod(adata)
    data = staticmethod(data)
    akeys = staticmethod(akeys)
    keys = staticmethod(keys)
    asubkeys = staticmethod(asubkeys)
    subkeys = staticmethod(subkeys)
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
        source key material.

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
        source key material.

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
        source key material.

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
        source key material.

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
        instance of ``Comprende``. With that, now all generators that
        are decorated with ``comprehension`` can encrypt valid streams
        of one-time-pad encrypted ciphertext.

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
        salt = salt if salt != None else await acsprng(key)

        entropy = akeys(key=key, salt=salt, pid=pid)
        encrypting = acipher(data=self.aresize(size), key=entropy)

        session_seed = await encrypting.anext()
        session_entropy = akeys(key=key, salt=session_seed, pid=pid)
        encode_salt = axor(abirth(salt).aint(16), key=session_entropy)

        yield await encode_salt.anext()
        async for result in encrypting:
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
        are decorated with ``comprehension`` can encrypt valid streams
        of one-time-pad encrypted ciphertext.

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
        salt = salt if salt != None else csprng(key)

        entropy = keys(key=key, salt=salt, pid=pid)
        encrypting = cipher(data=self.resize(size), key=entropy)

        session_seed = encrypting.next()
        session_entropy = keys(key=key, salt=session_seed, pid=pid)
        encode_salt = xor(birth(salt).int(16), key=session_entropy)

        yield encode_salt.next()
        for result in encrypting:
            yield result

    @comprehension()
    async def _aotp_decrypt(self, key=csprng(), pid=0):
        """
        This function is copied into the ``Comprende`` class dictionary.
        Doing so allows instances of ``Comprende`` generators access to
        a baked-in, async one-time-pad decryption algorithm, while also
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
        ciphertext = generics.aiter(self)
        ciphered_salt = await ciphertext.anext()
        session_seed = await ciphertext.anext()
        session_entropy = akeys(key=key, salt=session_seed, pid=pid)
        decode_salt = axor(abirth(ciphered_salt), key=session_entropy)

        salt = await decode_salt.ahex().aslice(2, None).azfill(128).anext()
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
        session_entropy = keys(key=key, salt=session_seed, pid=pid)
        decode_salt = xor(birth(ciphered_salt), key=session_entropy)

        salt = decode_salt.hex().slice(2, None).zfill(128).next()
        entropy = keys(key=key, salt=salt, pid=pid)
        for plaintext in decipher(
            data=order([session_seed], ciphertext.iterator), key=entropy
        ):
            yield plaintext

    # Copying the addons over into the ``Comprende`` class
    addons = {_amap_encrypt, _map_encrypt, _amap_decrypt, _map_decrypt}
    for addon in addons:
        setattr(Comprende, addon.__name__[1:], addon)
        Comprende.lazy_generators.add(addon.__name__[1:])

    addons = {_otp_encrypt, _otp_decrypt, _aotp_encrypt, _aotp_decrypt}
    for addon in addons:
        name = addon.__name__.replace("_otp_", "").replace("_aotp_", "a")
        setattr(Comprende, name, addon)
        Comprende.lazy_generators.add(name)
    del name
    del addon
    del addons


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
    directory = DatabasePath()

    async def __init__(
        self,
        key=None,
        password_depth=0,           # >= 5000 if ``key`` is weak
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
        self._cache = commons.Namespace()
        self._manifest = commons.Namespace()
        self.root_key = await akeys(key, key, key)[password_depth]()
        self.root_hash = (
            await asha_512_hmac(self.root_key, key=self.root_key)
        )
        self.root_filename = (
            await asha_256_hmac(self.root_hash, key=self.root_hash)
        )
        if metatag:
            self.is_metatag = True
        else:
            self.is_metatag = False
        await self.aload_manifest()
        await self.ainitialize_metatags()
        if preload:
            await self.aload()

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

    async def anamestream(self, tag=None):
        """
        Returns a keys object able to build an unlimited, deterministic
        stream of key material, 64 hex characters per iteration. Each
        stream distinguished by the seed value ``tag`` are safely
        different from each other. This allows for cryptographically
        obscuring the order of ciphertext stored in a hash map.

        The database object uses this function internally to pick the
        stream of shard names for ciphertext within files, but first
        passes the user-defined ``tag`` through the ``filename(tag)``
        method, thereby making a unique, deterministic name stream for
        each ``tag``.
        """
        return await akeys(
            self.root_hash, self.root_seed, tag
        ).aresize(64).aprime()

    async def akeystream(self, tag=None):
        """
        Returns a keys object able to build an unlimited, deterministic
        stream of key material, 256 hex characters per iteration. Each
        stream distinguished by the seed value ``tag`` are safely
        different from each other.

        The database object uses this function internally to pick the
        stream of key material for transparent file encryption, but
        first passes the user-defined ``tag`` through the ``filename(tag)``
        method, thereby making a unique, deterministic key stream for
        each ``tag``.

        The ``keys`` object that's returned is primed & ready for being
        sent in values like a coroutine. Starting on the very first
        iteration, the impacts of the incorporated sent entropy will be
        reflected in a completely distinguished stream being produced,
        from every sent value onwards.
        """
        return await akeys(
            self.root_key, await self.__aroot_salt(), tag
        ).aprime()

    async def aopen_manifest(self):
        """
        Loads an existing manifest file ledger from the filesystem.
        """
        async with aiofiles.open(self.root_path, "r") as root_file:
            ciphertext = json.loads(await root_file.read())

        self._root_session_salt = ciphertext.get("salt")
        names = self.root_names
        entropy = self.root_entropy
        decrypting = apick(names, ciphertext).amap_decrypt(entropy)
        async with decrypting as manifest:
            return json.loads(await manifest.ajoin())

    async def aload_manifest(self):
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """

        if self.root_path.exists():
            manifest = await self.aopen_manifest()
            root_salt = manifest[self.root_filename]
        else:
            if self.is_metatag:
                root_salt = (await acsprng())[:64]
            else:
                root_salt = await ajson_encrypt(csprng(), self.root_key)
            manifest = {self.root_filename: root_salt}
            self._root_session_salt = (await acsprng())[:64]

        @alru_cache()
        async def __aroot_salt(
            database=sha_256_hmac(
                (hash(self), root_salt), key=self.root_hash
            )
        ):
            """
            Keeps the ``root_salt`` tucked away until queried, where
            then it's cached for efficiency.
            """
            if self.is_metatag:
                return root_salt
            else:
                return await ajson_decrypt(root_salt, self.root_key)

        self.__aroot_salt = __aroot_salt
        self._manifest = commons.Namespace(manifest)
        self.root_seed = (
            await asha_512_hmac(await self.__aroot_salt(), self.root_key)
        )

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
        async with plaintext.amap_encrypt(names, entropy) as manifest:
            await self.asave_manifest(
                ciphertext={"salt": salt, **(await manifest.adict())}
            )

    async def aload(self):
        """
        Loads all the database object's values from the filesystem into
        the database cache. This brings the database values into the
        cache, enables up-to-date bracket lookup of tag values & dotted
        lookup of metatags. Otherwise, values would have to be queried
        using the awaitable ``aget`` & ``ametatag`` methods.
        """
        for metatag in self.metatags:
            await (await self.ametatag(metatag)).aload()
        async for tag, value in self:
            pass
        return self

    async def afilename(self, tag=None):
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        return await asha_256_hmac(
            (tag, self.root_seed), key=self.root_hash
        )

    async def asalt(self, entropy=csprng()):
        """
        Returns a random 512-bit hexidecimal string.
        """
        return await acsprng(entropy)

    async def ahmac(self, *data):
        """
        Creates an HMAC hash of the arguments passed into ``*data`` with
        keys derived from the key used to open the database instance.
        """
        return await asha_512_hmac(
            (data, self.root_hash), key=self.root_seed
        )

    async def aquery_ciphertext(self, filename=None):
        """
        Retrieves the value stored in the database file that's called
        ``filename``.
        """
        async with aiofiles.open(self.directory / filename, "r") as db_file:
            return json.loads(await db_file.read())

    async def adecrypt(self, filename=None, ciphertext=None):
        """
        Constructs the key & name streams for the decryption & retrieval
        of the value stored in the database file called ``filename``.
        """
        salted_filename = await asha_256(filename, ciphertext.get("salt"))
        names = await self.anamestream(salted_filename)
        entropy = await self.akeystream(salted_filename)
        decrypting = apick(names, ciphertext).amap_decrypt(entropy)
        async with decrypting as plaintext:
            return json.loads(await plaintext.ajoin())

    async def asave_ciphertext(self, filename=None, ciphertext=None):
        """
        Saves the encrypted value ``ciphertext`` in the database file
        called ``filename``.
        """
        async with aiofiles.open(self.directory / filename, "w+") as db_file:
            await db_file.write(json.dumps(ciphertext))

    async def aencrypt(self, filename=None, plaintext=None):
        """
        Constructs the key & name streams for the encryption & storage
        in the database of the value ``plaintext`` in the file called
        ``filename``.
        """
        salt = (await acsprng())[:64]
        salted_filename = await asha_256(filename, salt)
        names = await self.anamestream(salted_filename)
        entropy = await self.akeystream(salted_filename)
        plaintext = json.dumps(plaintext)
        encrypting = adata(plaintext).amap_encrypt(names, entropy)
        async with encrypting as ciphertext:
            return {"salt": salt, **(await ciphertext.adict())}

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
        value = await self.aquery(tag)
        filename = await self.afilename(tag)
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
        self.metatags_filename = await self.afilename(f"__metatags__{NONE}")
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
        its_metatags = aunpack(list(database.metatags))
        my_metatags += [
            tag
            async for tag in its_metatags
            if tag not in my_metatags
        ]
        async for tag, value in aunpack(database):
            filename = await self.afilename(tag)
            self.cache[filename] = value
            self.manifest[filename] = tag
        async for metatag in its_metatags:
            my_metatag = await self.ametatag(metatag)
            await my_metatag.amirror_database(
                database.__dict__[metatag]
            )

    async def adelete_database(self):
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        self.cache.namespace.clear()
        for metatag in self.metatags:
            await (await self.ametatag(metatag)).adelete_database()
        for filename in self.manifest.namespace:
            await self.adelete_file(filename)
        self.manifest.namespace.clear()

    async def asave(self):
        """
        Writes the database's values to disk.
        """
        if self.root_filename not in self.manifest:
            raise PermissionError("The database keys have been deleted.")
        await self.aclose_manifest()
        database = dict(self.manifest.namespace)
        del database[self.root_filename]
        del database[self.metatags_filename]
        async for metatag in aunpack(self.metatags):
            if self.__dict__.get(metatag):
                await self.__dict__[metatag].asave()
        async for filename in aunpack(database):
            if filename in self.cache:
                ciphertext = await self.aencrypt(
                    filename, self.cache[filename]
                )
                await self.asave_ciphertext(filename, ciphertext)

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
            return commons.Namespace(await namespace.adict())

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
    directory = DatabasePath()

    def __init__(
        self,
        key=None,
        password_depth=0,           # >= 5000 if ``key`` is weak
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
        self._cache = commons.Namespace()
        self._manifest = commons.Namespace()
        self.root_key = keys(key, key, key)[password_depth]()
        self.root_hash = sha_512_hmac(self.root_key, key=self.root_key)
        self.root_filename = sha_256_hmac(
            self.root_hash, key=self.root_hash
        )
        if metatag:
            self.is_metatag = True
        else:
            self.is_metatag = False
        self.load_manifest()
        self.initialize_metatags()
        if preload:
            self.load()

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
        passes the user-defined ``tag`` through the ``filename(tag)``
        method, thereby making a unique, deterministic name stream for
        each ``tag``.
        """
        return keys(self.root_hash, self.root_seed, tag).resize(64).prime()

    def keystream(self, tag=None):
        """
        Returns a keys object able to build an unlimited, deterministic
        stream of key material, 256 hex characters per iteration. Each
        stream distinguished by the seed value ``tag`` are safely
        different from each other.

        The database object uses this function internally to pick the
        stream of key material for transparent file encryption, but
        first passes the user-defined ``tag`` through the ``filename(tag)``
        method, thereby making a unique, deterministic key stream for
        each ``tag``.

        The ``keys`` object that's returned is primed & ready for being
        sent in values like a coroutine. Starting on the very first
        iteration, the impacts of the incorporated sent entropy will be
        reflected in a completely distinguished stream being produced,
        from every sent value onwards.
        """
        return keys(self.root_key, self.__root_salt(), tag).prime()

    def open_manifest(self):
        """
        Loads an existing manifest file ledger from the filesystem.
        """
        with open(self.root_path, "r") as root_file:
            ciphertext = json.load(root_file)

        self._root_session_salt = ciphertext.get("salt")
        names = self.root_names
        entropy = self.root_entropy
        with pick(names, ciphertext).map_decrypt(entropy) as manifest:
            return json.loads(manifest.join())

    def load_manifest(self):
        """
        Initalizes the object with a new database file ledger or loads
        an existing one from the filesystem.
        """
        if self.root_path.exists():
            manifest = self.open_manifest()
            root_salt = manifest[self.root_filename]
        else:
            if self.is_metatag:
                root_salt = csprng()[:64]
            else:
                root_salt = json_encrypt(csprng(), self.root_key)
            manifest = {self.root_filename: root_salt}
            self._root_session_salt = csprng()[:64]

        @lru_cache()
        def __root_salt(
            database=sha_256_hmac(
                (hash(self), root_salt), key=self.root_hash
            )
        ):
            """
            Keeps the ``root_salt`` tucked away until queried, where
            then it's cached for efficiency.
            """
            if self.is_metatag:
                return root_salt
            else:
                return json_decrypt(root_salt, self.root_key)

        self.__root_salt = __root_salt
        self._manifest = commons.Namespace(manifest)
        self.root_seed = sha_512_hmac(self.__root_salt(), self.root_key)

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
        with plaintext.map_encrypt(names, entropy) as manifest:
            self.save_manifest(ciphertext={"salt": salt, **manifest.dict()})

    def load(self):
        """
        Loads all the database object's values from the filesystem into
        the database cache. This brings the database values into the
        cache, enables up-to-date bracket lookup of tag values & dotted
        lookup of metatags.
        Otherwise, values would have to be queried using the awaitable
        ``get`` & ``metatag`` methods.
        """
        for metatag in self.metatags:
            self.metatag(metatag).load()
        for tag, value in self:
            pass
        return self

    def filename(self, tag=None):
        """
        Derives the filename hash given a user-defined ``tag``.
        """
        return sha_256_hmac((tag, self.root_seed), key=self.root_hash)

    def salt(self, entropy=csprng()):
        """
        Returns a random 512-bit hexidecimal string.
        """
        return csprng(entropy)

    def hmac(self, *data):
        """
        Creates an HMAC hash of the arguments passed into ``*data`` with
        keys derived from the key used to open the database instance.
        """
        return sha_512_hmac((data, self.root_hash), key=self.root_seed)

    def query_ciphertext(self, filename=None):
        """
        Retrieves the value stored in the database file that's called
        ``filename``.
        """
        with open(self.directory / filename, "r") as db_file:
            return json.load(db_file)

    def decrypt(self, filename=None, ciphertext=None):
        """
        Constructs the key & name streams for the decryption & retrieval
        of the value stored in the database file called ``filename``.
        """
        salted_filename = sha_256(filename, ciphertext.get("salt"))
        names = self.namestream(salted_filename)
        entropy = self.keystream(salted_filename)
        with pick(names, ciphertext).map_decrypt(entropy) as plaintext:
            return json.loads(plaintext.join())

    def save_ciphertext(self, filename=None, ciphertext=None):
        """
        Saves the encrypted value ``ciphertext`` in the database file
        called ``filename``.
        """
        with open(self.directory / filename, "w+") as db_file:
            json.dump(ciphertext, db_file)

    def encrypt(self, filename=None, plaintext=None):
        """
        Constructs the key & name streams for the encryption & storage
        in the database of the value ``plaintext`` in the file called
        ``filename``.
        """
        salt = csprng()[:64]
        salted_filename = sha_256(filename, salt)
        names = self.namestream(salted_filename)
        entropy = self.keystream(salted_filename)
        plaintext = json.dumps(plaintext)
        with data(plaintext).map_encrypt(names, entropy) as ciphertext:
            return {"salt": salt, **ciphertext.dict()}

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
        value = self.query(tag)
        filename = self.filename(tag)
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
        self.metatags_filename = self.filename(f"__metatags__{NONE}")
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
        its_metatags = list(database.metatags)
        my_metatags += [
            tag
            for tag in its_metatags
            if tag not in my_metatags
        ]
        for tag, value in database:
            filename = self.filename(tag)
            self.cache[filename] = value
            self.manifest[filename] = tag
        for metatag in its_metatags:
            my_metatag = self.metatag(metatag)
            my_metatag.mirror_database(database.__dict__[metatag])

    def delete_database(self):
        """
        Completely clears all of the entries in database instance & its
        associated files.
        """
        self.cache.namespace.clear()
        for metatag in self.metatags:
            self.metatag(metatag).delete_database()
        for filename in self.manifest.namespace:
            self.delete_file(filename)
        self.manifest.namespace.clear()

    def save(self):
        """
        Writes the database's values to disk.
        """
        if self.root_filename not in self.manifest:
            raise PermissionError("The database keys have been deleted.")
        self.close_manifest()
        database = dict(self.manifest.namespace)
        del database[self.root_filename]
        del database[self.metatags_filename]
        for metatag in self.metatags:
            if self.__dict__.get(metatag):
                self.__dict__[metatag].save()
        for filename in database:
            if filename in self.cache:
                ciphertext = self.encrypt(filename, self.cache[filename])
                self.save_ciphertext(filename, ciphertext)

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
            return commons.Namespace(namespace.dict())

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


__extras = {
    "AsyncDatabase": AsyncDatabase,
    "Database": Database,
    "OneTimePad": OneTimePad,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "acipher": acipher,
    "adecipher": adecipher,
    "adecrypt": adecrypt,
    "aencrypt": aencrypt,
    "ajson_decrypt": ajson_decrypt,
    "ajson_encrypt": ajson_encrypt,
    "akeypair_ratchets": akeypair_ratchets,
    "akeys": akeys,
    "aorganize_decryption_streams": aorganize_decryption_streams,
    "aorganize_encryption_streams": aorganize_encryption_streams,
    "asubkeys": asubkeys,
    "axor": axor,
    "cipher": cipher,
    "decipher": decipher,
    "decrypt": decrypt,
    "encrypt": encrypt,
    "json_decrypt": json_decrypt,
    "json_encrypt": json_encrypt,
    "keypair_ratchets": keypair_ratchets,
    "keys": keys,
    "organize_decryption_streams": organize_decryption_streams,
    "organize_encryption_streams": organize_encryption_streams,
    "subkeys": subkeys,
    "xor": xor,
}


ciphers = commons.Namespace.make_module("ciphers", mapping=__extras)

