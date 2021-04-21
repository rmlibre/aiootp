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
    "pad_plaintext",
    "apad_plaintext",
    "depad_plaintext",
    "adepad_plaintext",
]


__doc__ = (
    "Coordinates some of the library's UI/UX by inserting higher-level "
    "functionality from dependant modules into lower-level modules in "
    "this package."
)


from collections import deque
from .debuggers import gen_timer, agen_timer
from .generics import azip
from .generics import Padding
from .generics import Datastream
from .generics import data, adata
from .generics import sha_512, asha_512
from .generics import Comprende, comprehension
from .generics import convert_static_method_to_member
from .randoms import random_sleep as _random_sleep
from .randoms import arandom_sleep as _arandom_sleep
from .ciphers import csprng
from .ciphers import Passcrypt
from .ciphers import Chunky2048
from .ciphers import passcrypt as _passcrypt
from .ciphers import apasscrypt as _apasscrypt
from .ciphers import generate_salt, agenerate_salt
from .keygens import Ropake
from .keygens import X25519
from .keygens import Keys, AsyncKeys
from .keygens import insert_keygens


@comprehension(chained=True)
async def adebugger(self, *args, **kwargs):
    """
    Allows users to benchmark & read inspection details of running async
    generators inline as a chainable method.
    """
    args = args if args else self.args
    kwargs = {**self.kwargs, **kwargs}
    async for result in agen_timer(self.func)(*args, **kwargs):
        yield result


@comprehension(chained=True)
def debugger(self, *args, **kwargs):
    """
    Allows users to benchmark & read inspection details of running sync
    generators inline as a chainable method.
    """
    args = args if args else self.args
    kwargs = {**self.kwargs, **kwargs}
    for result in gen_timer(self.func)(*args, **kwargs):
        yield result


@comprehension(chained=True)
async def abytes_xor(self, *, key, validator):
    """
    Applies an xor to each result of any underlying async `Comprende`
    generator. ``key`` is an async `Comprende` `abytes_keys` generator.
    The underlying ``self`` async generator needs to produce 256-byte
    integers to be xor'd on each iteration.
    """
    xoring = Chunky2048.abytes_xor.root(self, key=key, validator=validator)
    async for result in xoring:
        yield result


@comprehension(chained=True)
def bytes_xor(self, *, key, validator):
    """
    Applies an xor to each result of any underlying sync `Comprende`
    generator. ``key`` is a sync `Comprende` `bytes_keys` generator. The
    underlying ``self`` sync generator needs to produce 256-byte
    integers to be xor'd on each iteration.
    """
    xoring = Chunky2048.bytes_xor.root(self, key=key, validator=validator)
    for result in xoring:
        yield result


@comprehension(chained=True)
async def axor(self, *, key, validator):
    """
    Applies an xor to each result of any underlying async `Comprende`
    generator. ``key`` is an async `Comprende` keystream generator. The
    underlying ``self`` async generator needs to produce 256-byte
    integers to be xor'd on each iteration.
    """
    xoring = Chunky2048.axor.root(self, key=key, validator=validator)
    async for result in xoring:
        yield result


@comprehension(chained=True)
def xor(self, *, key, validator):
    """
    Applies an xor to each result of any underlying sync `Comprende`
    generator. ``key`` is a sync `Comprende` keystream generator. The
    underlying ``self`` sync generator needs to produce 256-byte
    integers to be xor'd on each iteration.
    """
    xoring = Chunky2048.xor.root(self, key=key, validator=validator)
    for result in xoring:
        yield result


@comprehension(chained=True)
async def apasscrypt(
    self,
    *,
    kb=Passcrypt._DEFAULT_KB,
    cpu=Passcrypt._DEFAULT_CPU,
    hardness=Passcrypt._DEFAULT_HARDNESS,
):
    """
    Applies the `passcrypt` algorithm on a pseudo-randomly generated
    salt & each value that's yielded from the underlying `Comprende`
    async generator. Each iteration a new salt is produced & is yield
    along with the result of the `passcrypt` operation.
    """
    got = None
    passcrypt = Passcrypt(kb=kb, cpu=cpu, hardness=hardness)
    while True:
        salt = await agenerate_salt()
        result = await passcrypt.anew(await self.asend(got), salt)
        got = yield salt, result


@comprehension(chained=True)
def passcrypt(
    self,
    *,
    kb=Passcrypt._DEFAULT_KB,
    cpu=Passcrypt._DEFAULT_CPU,
    hardness=Passcrypt._DEFAULT_HARDNESS,
):
    """
    Applies the `passcrypt` algorithm on a pseudo-randomly generated
    salt & each value that's yielded from the underlying `Comprende`
    sync generator. Each iteration a new salt is produced & is yield
    along with the result of the `passcrypt` operation.
    """
    got = None
    _passcrypt = Passcrypt(kb=kb, cpu=cpu, hardness=hardness)
    try:
        while True:
            salt = generate_salt()
            result = _passcrypt.new(self.send(got), salt)
            got = yield salt, result
    except StopIteration:
        pass


@comprehension(chained=True)
async def asum_passcrypt(
    self,
    salt,
    *,
    kb=Passcrypt._DEFAULT_KB,
    cpu=Passcrypt._DEFAULT_CPU,
    hardness=Passcrypt._DEFAULT_HARDNESS,
):
    """
    Cumulatively applies the ``apasscrypt`` algorithm to each value
    that's yielded from the underlying Comprende async generator with
    the previously processed result before yielding the current result.
    """
    got = None
    passcrypt = Passcrypt(kb=kb, cpu=cpu, hardness=hardness)
    summary = await asha_512(salt, kb, cpu, hardness)
    while True:
        pre_key = await asha_512(salt, summary, await self.asend(got))
        summary = await passcrypt.anew(pre_key, summary)
        got = yield summary


@comprehension(chained=True)
def sum_passcrypt(
    self,
    salt,
    *,
    kb=Passcrypt._DEFAULT_KB,
    cpu=Passcrypt._DEFAULT_CPU,
    hardness=Passcrypt._DEFAULT_HARDNESS,
):
    """
    Cumulatively applies the ``passcrypt`` algorithm to each value
    that's yielded from the underlying Comprende sync generator with
    the previously processed result before yielding the current result.
    """
    got = None
    passcrypt = Passcrypt(kb=kb, cpu=cpu, hardness=hardness)
    summary = sha_512(salt, kb, cpu, hardness)
    try:
        while True:
            pre_key = sha_512(salt, summary, self.send(got))
            summary = passcrypt.new(pre_key, summary)
            got = yield summary
    except StopIteration:
        pass


@comprehension(chained=True)
async def arandom_sleep(self, span=1):
    """
    Applies a random sleep before each yielded value from the underlying
    ``Comprende`` async generator.
    """
    got = None
    asend = self.asend
    while True:
        await _arandom_sleep(span)
        got = yield await asend(got)


@comprehension(chained=True)
def random_sleep(self, span=1):
    """
    Applies a random sleep before each yielded value from the underlying
    ``Comprende`` sync generator.
    """
    got = None
    send = self.send
    try:
        while True:
            _random_sleep(span)
            got = yield send(got)
    except StopIteration:
        pass


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
        Chunky2048._bytes_encipher,
        Chunky2048._bytes_decipher,
        Chunky2048._abytes_encipher,
        Chunky2048._abytes_decipher,
    }
    for addon in addons:
        name = addon.__name__[1:]
        setattr(Comprende, name, addon)
        Comprende.lazy_generators.add(name)


def insert_stateful_key_generator_objects():
    """
    Copies the addons over into the ``Chunky2048`` class.
    """

    def __init__(self, key=None, *, automate_key_use=True):
        """
        Creates an object which manages a main encryption key for use in
        a set of the package's static functions & generators. This
        simplifies usage of encryption/decryption, key generation, &
        HMAC creation/validation by automatically passing in the key as
        a keyword argument.
        """
        insert_keygens(self, key, automate_key_use=automate_key_use)
        self._key = self.keygen.key
        self.hmac = self.keygen.hmac
        self.ahmac = self.akeygen.ahmac
        self.test_hmac = self.keygen.test_hmac
        self.atest_hmac = self.akeygen.atest_hmac
        self.passcrypt = self.keygen.passcrypt
        self.apasscrypt = self.akeygen.apasscrypt
        self.time_safe_equality = self.keygen.time_safe_equality
        self.atime_safe_equality = self.akeygen.atime_safe_equality
        if automate_key_use:
            for method in self.instance_methods:
                convert_static_method_to_member(
                    self, method.__name__, method, key=self.key
                )

    Chunky2048.__init__ = __init__
    Chunky2048.Keys = Keys
    Chunky2048.AsyncKeys = AsyncKeys


def add_protocols_to_collections():
    """
    Adds the assorted protocols defined throughout the library to the
    relevant list for ease of discovery, consumption & contextualization.
    """
    X25519.protocols.Ropake = Ropake


def insert_padding_methods():
    """
    Gives the `Padding` class access to methods defined in higher level
    modules.
    """
    global pad_plaintext
    global apad_plaintext
    global depad_plaintext
    global adepad_plaintext

    Padding.derive_key = Chunky2048.padding_key
    Padding.aderive_key = Chunky2048.apadding_key
    pad_plaintext, apad_plaintext, depad_plaintext, adepad_plaintext = (
        Padding.pad_plaintext,
        Padding.apad_plaintext,
        Padding.depad_plaintext,
        Padding.adepad_plaintext,
    )
    addons = {
        Padding._pad_plaintext,
        Padding._depad_plaintext,
        Padding._apad_plaintext,
        Padding._adepad_plaintext,
    }
    for addon in addons:
        setattr(Comprende, addon.__name__[1:], addon)
        Comprende.lazy_generators.add(addon.__name__[1:])


insert_debuggers()
insert_xor_methods()
insert_passcrypt_methods()
insert_random_sleep_methods()
insert_bytes_cipher_methods()
insert_stateful_key_generator_objects()
add_protocols_to_collections()
insert_padding_methods()

