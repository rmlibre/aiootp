# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = []


__doc__ = """
Coordinates some of the library's UI/UX by inserting higher-level
functionality from dependant modules into lower-level modules in this
package.
"""


from .debuggers import gen_timer, agen_timer
from .generics import azip
from .generics import sha_512, asha_512
from .generics import Comprende, comprehension
from .generics import convert_static_method_to_member
from .randoms import random_sleep as _random_sleep
from .randoms import arandom_sleep as _arandom_sleep
from .ciphers import csprng
from .ciphers import Ropake
from .ciphers import X25519
from .ciphers import validator
from .ciphers import Passcrypt
from .ciphers import OneTimePad
from .ciphers import passcrypt as _passcrypt
from .ciphers import apasscrypt as _apasscrypt
from .ciphers import generate_salt, agenerate_salt
from .keygens import Keys, AsyncKeys
from .keygens import insert_keyrings



@comprehension()
async def adebugger(self, *args, **kwargs):
    """
    Allows users to benchmark & read inspection details of running async
    generators inline as a chainable method.
    """
    args = args if args else self.args
    kwargs = {**self.kwargs, **kwargs}
    async for result in agen_timer(self.func)(*args, **kwargs):
        yield result


@comprehension()
def debugger(self, *args, **kwargs):
    """
    Allows users to benchmark & read inspection details of running sync
    generators inline as a chainable method.
    """
    args = args if args else self.args
    kwargs = {**self.kwargs, **kwargs}
    for result in gen_timer(self.func)(*args, **kwargs):
        yield result


@comprehension()
async def abytes_xor(self, *, key, validator):
    """
    Applies an xor to each result of any underlying async `Comprende`
    generator. ``key`` is an async `Comprende` `abytes_keys` generator.
    The underlying ``self`` async generator needs to produce 256-byte
    integers to be xor'd on each iteration.
    """
    xoring = OneTimePad.abytes_xor.root(self, key=key, validator=validator)
    async for result in xoring:
        yield result


@comprehension()
def bytes_xor(self, *, key, validator):
    """
    Applies an xor to each result of any underlying sync `Comprende`
    generator. ``key`` is a sync `Comprende` `bytes_keys` generator. The
    underlying ``self`` sync generator needs to produce 256-byte
    integers to be xor'd on each iteration.
    """
    xoring = OneTimePad.bytes_xor.root(self, key=key, validator=validator)
    for result in xoring:
        yield result


@comprehension()
async def axor(self, *, key, validator):
    """
    Applies an xor to each result of any underlying async `Comprende`
    generator. ``key`` is an async `Comprende` keystream generator. The
    underlying ``self`` async generator needs to produce 256-byte
    integers to be xor'd on each iteration.
    """
    xoring = OneTimePad.axor.root(self, key=key, validator=validator)
    async for result in xoring:
        yield result


@comprehension()
def xor(self, *, key, validator):
    """
    Applies an xor to each result of any underlying sync `Comprende`
    generator. ``key`` is a sync `Comprende` keystream generator. The
    underlying ``self`` sync generator needs to produce 256-byte
    integers to be xor'd on each iteration.
    """
    xoring = OneTimePad.xor.root(self, key=key, validator=validator)
    for result in xoring:
        yield result


@comprehension()
async def apasscrypt(self, *, kb=1024, cpu=3, hardness=1024):
    """
    Applies the `passcrypt` algorithm on a pseudo-randomly generated
    salt & each value that's yielded from the underlying `Comprende`
    async generator. Each iteration a new salt is produced & is yield
    along with the result of the `passcrypt` operation.
    """
    async for password in self:
        salt = await agenerate_salt()
        result = await _apasscrypt(
            password, salt, kb=kb, cpu=cpu, hardness=hardness
        )
        yield salt, result


@comprehension()
def passcrypt(self, *, kb=1024, cpu=3, hardness=1024):
    """
    Applies the `passcrypt` algorithm on a pseudo-randomly generated
    salt & each value that's yielded from the underlying `Comprende`
    sync generator. Each iteration a new salt is produced & is yield
    along with the result of the `passcrypt` operation.
    """
    for password in self:
        salt = generate_salt()
        result = _passcrypt(
            password, salt, kb=kb, cpu=cpu, hardness=hardness
        )
        yield salt, result


@comprehension()
async def asum_passcrypt(self, salt, *, kb=1024, cpu=3, hardness=1024):
    """
    Cumulatively applies the ``apasscrypt`` algorithm to each value
    that's yielded from the underlying Comprende async generator with
    the previously processed result before yielding the current result.
    """
    summary = await asha_512(salt, kb, cpu, hardness)
    async for password in self:
        pre_key = await asha_512(salt, summary, password)
        summary = await _apasscrypt(
            pre_key, summary, kb=kb, cpu=cpu, hardness=hardness
        )
        yield summary


@comprehension()
def sum_passcrypt(self, salt, *, kb=1024, cpu=3, hardness=1024):
    """
    Cumulatively applies the ``passcrypt`` algorithm to each value
    that's yielded from the underlying Comprende sync generator with
    the previously processed result before yielding the current result.
    """
    summary = sha_512(salt, kb, cpu, hardness)
    for password in self:
        pre_key = sha_512(salt, summary, password)
        summary = _passcrypt(
            pre_key, summary, kb=kb, cpu=cpu, hardness=hardness
        )
        yield summary


@comprehension()
async def arandom_sleep(self, span=1):
    """
    Applies a random sleep before each yielded value from the underlying
    ``Comprende`` async generator.
    """
    async for result in self:
        await _arandom_sleep(span)
        yield result


@comprehension()
def random_sleep(self, span=1):
    """
    Applies a random sleep before each yielded value from the underlying
    ``Comprende`` sync generator.
    """
    for result in self:
        _random_sleep(span)
        yield result


def insert_debuggers():
    """
    Copies the addons over into the ``Comprende`` class.
    """
    addons = {debugger, adebugger}
    for addon in addons:
        setattr(Comprende, addon.__name__, addon)
        Comprende.lazy_generators.add(addon.__name__)


def insert_xor_methods():
    """
    Copies the addons over into the ``Comprende`` class.
    """
    addons = {xor, axor, bytes_xor, abytes_xor}
    for addon in addons:
        setattr(Comprende, addon.__name__, addon)
        Comprende.lazy_generators.add(addon.__name__)


def insert_passcrypt_methods():
    """
    Copies the addons over into the ``Comprende`` class.
    """
    _passcrypt.generate_salt = generate_salt
    _apasscrypt.agenerate_salt = agenerate_salt
    addons = {passcrypt, apasscrypt, sum_passcrypt, asum_passcrypt}
    for addon in addons:
        setattr(Comprende, addon.__name__, addon)
        Comprende.lazy_generators.add(addon.__name__)


def insert_random_sleep_methods():
    """
    Copies the addons over into the ``Comprende`` class.
    """
    addons = {random_sleep, arandom_sleep}
    for addon in addons:
        setattr(Comprende, addon.__name__, addon)
        Comprende.lazy_generators.add(addon.__name__)


def insert_bytes_cipher_methods():
    """
    Copies the addons over into the ``Comprende`` class.
    """
    addons = {
        OneTimePad._bytes_encipher,
        OneTimePad._bytes_decipher,
        OneTimePad._abytes_encipher,
        OneTimePad._abytes_decipher,
    }
    for addon in addons:
        name = addon.__name__[1:]
        setattr(Comprende, name, addon)
        Comprende.lazy_generators.add(name)


def insert_stream_cipher_methods():
    """
    Copies the addons over into the ``Comprende`` class.
    """
    addons = {
        OneTimePad._ascii_encipher,
        OneTimePad._ascii_decipher,
        OneTimePad._aascii_encipher,
        OneTimePad._aascii_decipher,
    }
    for addon in addons:
        name = addon.__name__[1:]
        setattr(Comprende, name, addon)
        Comprende.lazy_generators.add(name)


def insert_hashmap_cipher_methods():
    """
    Copies the addons over into the ``Comprende`` class.
    """
    addons = {
        OneTimePad._map_encipher,
        OneTimePad._map_decipher,
        OneTimePad._amap_encipher,
        OneTimePad._amap_decipher,
    }
    for addon in addons:
        setattr(Comprende, addon.__name__[1:], addon)
        Comprende.lazy_generators.add(addon.__name__[1:])


def insert_stateful_key_generator_objects():
    """
    Copies the addons over into the ``OneTimePad`` class.
    """

    def __init__(self, key=None, *, automate_key_use=True):
        """
        Creates an object which manages a main encryption key for use in
        a set of the package's static functions & generators. This
        simplifies usage of encryption/decryption, key generation, &
        HMAC creation/validation by automatically passing in the key as
        a keyword argument.
        """
        insert_keyrings(self, key, automate_key_use=automate_key_use)
        self._key = self.keyring.key
        self.hmac = self.keyring.hmac
        self.ahmac = self.akeyring.ahmac
        self.test_hmac = self.keyring.test_hmac
        self.atest_hmac = self.akeyring.atest_hmac
        self.passcrypt = self.keyring.passcrypt
        self.apasscrypt = self.akeyring.apasscrypt
        self.time_safe_equality = self.keyring.time_safe_equality
        self.atime_safe_equality = self.akeyring.atime_safe_equality
        if automate_key_use:
            for method in self.instance_methods:
                convert_static_method_to_member(
                    self, method.__name__, method, key=self.key,
                )

    OneTimePad.__init__ = __init__
    OneTimePad.Keys = Keys
    OneTimePad.AsyncKeys = AsyncKeys
    pad = OneTimePad(csprng())
    validator.hmac = pad.hmac
    validator.ahmac = pad.ahmac
    validator.test_hmac = pad.test_hmac
    validator.atest_hmac = pad.atest_hmac
    validator.time_safe_equality = pad.time_safe_equality
    validator.atime_safe_equality = pad.atime_safe_equality


def add_protocols_to_collections():
    """
    Adds the assorted protocols defined throughout the library to the
    relevant list for ease of discovery, consumption & contextualization.
    """
    X25519.protocols.Ropake = Ropake


insert_debuggers()
insert_xor_methods()
insert_passcrypt_methods()
insert_random_sleep_methods()
insert_bytes_cipher_methods()
insert_stream_cipher_methods()
insert_hashmap_cipher_methods()
insert_stateful_key_generator_objects()
add_protocols_to_collections()

