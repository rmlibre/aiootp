# This file is part of aiootp, an asynchronous one-time-pad based crypto
# and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
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
from .generics import Comprende, comprehension
from .generics import convert_static_method_to_member
from .randoms import random_sleep as _random_sleep
from .randoms import arandom_sleep as _arandom_sleep
from .ciphers import validator
from .ciphers import salt, asalt
from .ciphers import OneTimePad
from .ciphers import passcrypt as _passcrypt
from .ciphers import apasscrypt as _apasscrypt
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
async def axor(self, key=None, convert=True):
    """
    Applies an xor to each result of any underlying async ``Comprende``
    generator. ``key`` is an async ``Comprende`` key generator. And,
    ``convert`` if truthy, will automatically convert the stream of key
    material from ``key`` into an integer so it can be used to xor the
    results produced from ``self``. The underlying ``self`` async
    generator needs to produce integers to be xor'd on each iteration.
    """
    async for result in OneTimePad.axor(self, key=key, convert=convert):
        yield result


@comprehension()
def xor(self, key=None, convert=True):
    """
    Applies an xor to each result of any underlying sync ``Comprende``
    generator. ``key`` is a sync ``Comprende`` key generator. And,
    ``convert`` if truthy, will automatically convert the stream of key
    material from ``key`` into an integer so it can be used to xor the
    results produced from ``self``. The underlying ``self`` sync
    generator needs to produce integers to be xor'd on each iteration.
    """
    for result in OneTimePad.xor(self, key=key, convert=convert):
        yield result


@comprehension()
async def apasscrypt(self, salt, *, kb=1024, cpu=3, hardness=1024, of=None):
    """
    Applies the ``apasscrypt`` algorithm to each value that's yielded
    from the underlying Comprende sync generator before yielding the
    result.
    """
    settings = dict(kb=kb, cpu=cpu, hardness=hardness)
    if of != None:
        async for prev, result in azip(self, of):
            yield prev, await _apasscrypt(result, salt, **settings)
    else:
        async for result in self:
            yield await _apasscrypt(result, salt, **settings)


@comprehension()
def passcrypt(self, salt, *, kb=1024, cpu=3, hardness=1024, of=None):
    """
    Applies the ``passcrypt`` algorithm to each value that's yielded
    from the underlying Comprende sync generator before yielding the
    result.
    """
    settings = dict(kb=kb, cpu=cpu, hardness=hardness)
    if of != None:
        for prev, result in zip(self, of):
            yield prev, _passcrypt(result, salt, **settings)
    else:
        for result in self:
            yield _passcrypt(result, salt, **settings)


@comprehension()
async def asum_passcrypt(self, salt, *, kb=1024, cpu=3, hardness=1024):
    """
    Cumulatively applies the ``apasscrypt`` algorithm to each value
    that's yielded from the underlying Comprende async generator with
    the previously processed result before yielding the current result.
    """
    settings = dict(kb=kb, cpu=cpu, hardness=hardness)
    summary = await _apasscrypt(salt, salt, **settings)
    async for result in self:
        summary = await _apasscrypt(result, summary, **settings)
        yield summary


@comprehension()
def sum_passcrypt(self, salt, *, kb=1024, cpu=3, hardness=1024):
    """
    Cumulatively applies the ``passcrypt`` algorithm to each value
    that's yielded from the underlying Comprende sync generator with
    the previously processed result before yielding the current result.
    """
    settings = dict(kb=kb, cpu=cpu, hardness=hardness)
    summary = _passcrypt(salt, salt, **settings)
    for result in self:
        summary = _passcrypt(result, summary, **settings)
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
    addons = {xor, axor}
    for addon in addons:
        setattr(Comprende, addon.__name__, addon)
        Comprende.lazy_generators.add(addon.__name__)


def insert_passcrypt_methods():
    """
    Copies the addons over into the ``Comprende`` class.
    """
    _passcrypt.salt = salt
    _apasscrypt.asalt = asalt
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
        OneTimePad._bytes_encrypt,
        OneTimePad._bytes_decrypt,
        OneTimePad._abytes_encrypt,
        OneTimePad._abytes_decrypt,
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
        OneTimePad._otp_encrypt,
        OneTimePad._otp_decrypt,
        OneTimePad._aotp_encrypt,
        OneTimePad._aotp_decrypt,
    }
    for addon in addons:
        name = addon.__name__.replace("_otp_", "").replace("_aotp_", "a")
        setattr(Comprende, name, addon)
        Comprende.lazy_generators.add(name)


def insert_hashmap_cipher_methods():
    """
    Copies the addons over into the ``Comprende`` class.
    """
    addons = {
        OneTimePad._map_encrypt,
        OneTimePad._map_decrypt,
        OneTimePad._amap_encrypt,
        OneTimePad._amap_decrypt,
    }
    for addon in addons:
        setattr(Comprende, addon.__name__[1:], addon)
        Comprende.lazy_generators.add(addon.__name__[1:])


def insert_stateful_key_generator_objects():
    """
    Copies the addons over into the ``OneTimePad`` class.
    """

    def __init__(self, key=None):
        """
        Creates an object which manages a main encryption key for use in
        a set of the package's static functions & generators. This
        simplifies usage of encryption/decryption, key generation, &
        HMAC creation/validation by automatically passing in the key as
        a keyword argument.
        """
        insert_keyrings(self, key)
        self._key = self.keyring.key
        self.hmac = self.keyring.hmac
        self.ahmac = self.akeyring.ahmac
        self.test_hmac = self.keyring.test_hmac
        self.atest_hmac = self.akeyring.atest_hmac
        for method in self.instance_methods:
            convert_static_method_to_member(
                self, method.__name__, method, key=self.key,
            )

    OneTimePad.__init__ = __init__
    pad = OneTimePad(salt())
    validator.hmac = pad.hmac
    validator.ahmac = pad.ahmac
    validator.test_hmac = pad.test_hmac
    validator.atest_hmac = pad.atest_hmac


insert_debuggers()
insert_xor_methods()
insert_passcrypt_methods()
insert_random_sleep_methods()
insert_bytes_cipher_methods()
insert_stream_cipher_methods()
insert_hashmap_cipher_methods()
insert_stateful_key_generator_objects()

