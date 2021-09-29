# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["gentools"]


__doc__ = (
    "Coordinates some of the library's UI/UX by inserting higher-level "
    "functionality from dependant modules into lower-level modules in "
    "this package."
)


from ._typing import Typing
from .debuggers import gen_timer, agen_timer
from .generics import sha3__512, asha3__512
from .generics import Comprende, comprehension
from .randoms import random_sleep as _random_sleep
from .randoms import arandom_sleep as _arandom_sleep
from .ciphers import generate_salt, agenerate_salt
from .ciphers import plaintext_stream, aplaintext_stream
from .ciphers import bytes_encipher, abytes_encipher
from .ciphers import bytes_decipher, abytes_decipher
from . import *
from . import AsyncKeys, Keys
from . import Ed25519, X25519
from . import Processes, Threads
from . import AsyncDatabase, Database
from . import Namespace, OpenNamespace
from . import Domains, DomainKDF, Hasher, Passcrypt, Chunky2048
from . import BytesIO, Padding, KeyAADBundle, StreamHMAC, Chunky2048


@comprehension(chained=True)
async def adebugger(self: Comprende, *args, **kwargs):
    """
    Allows users to benchmark & read inspection details of running async
    generators inline as a chainable method.
    """
    args = args if args else self._args
    kwargs = {**self._kwargs, **kwargs}
    async for result in agen_timer(self._func)(*args, **kwargs):
        yield result


@comprehension(chained=True)
def debugger(self: Comprende, *args, **kwargs):
    """
    Allows users to benchmark & read inspection details of running sync
    generators inline as a chainable method.
    """
    args = args if args else self._args
    kwargs = {**self._kwargs, **kwargs}
    yield from gen_timer(self._func)(*args, **kwargs)


@comprehension(chained=True)
async def abytes_xor(
    self: Comprende,*, key: Typing.AsyncKeystream, validator: StreamHMAC
):
    """
    Applies an xor to each result of any underlying async `Comprende`
    generator. ``key`` is an async `Comprende` `abytes_keys` generator.
    The underlying ``self`` async generator needs to produce 256-byte
    integers to be xor'd on each iteration.
    """
    xoring = ciphers.abytes_xor.root(self, key=key, validator=validator)
    async for result in xoring:
        yield result


@comprehension(chained=True)
def bytes_xor(
    self: Comprende, *, key: Typing.Keystream, validator: StreamHMAC
):
    """
    Applies an xor to each result of any underlying sync `Comprende`
    generator. ``key`` is a sync `Comprende` `bytes_keys` generator. The
    underlying ``self`` sync generator needs to produce 256-byte
    integers to be xor'd on each iteration.
    """
    xoring = ciphers.bytes_xor.root(self, key=key, validator=validator)
    yield from xoring


@comprehension(chained=True)
async def apasscrypt(
    self: Comprende,
    *,
    kb: int = Passcrypt._DEFAULT_KB,
    cpu: int = Passcrypt._DEFAULT_CPU,
    hardness: int = Passcrypt._DEFAULT_HARDNESS,
):
    """
    Applies the `passcrypt` algorithm on a pseudo-randomly generated
    salt & each value that's yielded from the underlying `Comprende`
    async generator. Each iteration a new salt is produced & is yield
    along with the result of the `passcrypt` operation.
    """
    got = None
    pcrypt = Passcrypt(kb=kb, cpu=cpu, hardness=hardness)
    while True:
        salt = await agenerate_salt(size=Passcrypt._SALT_BYTES)
        result = await pcrypt.anew(await self.asend(got), salt)
        got = yield salt, result


@comprehension(chained=True)
def passcrypt(
    self: Comprende,
    *,
    kb: int = Passcrypt._DEFAULT_KB,
    cpu: int = Passcrypt._DEFAULT_CPU,
    hardness: int = Passcrypt._DEFAULT_HARDNESS,
):
    """
    Applies the `passcrypt` algorithm on a pseudo-randomly generated
    salt & each value that's yielded from the underlying `Comprende`
    sync generator. Each iteration a new salt is produced & is yield
    along with the result of the `passcrypt` operation.
    """
    got = None
    pcrypt = Passcrypt(kb=kb, cpu=cpu, hardness=hardness)
    try:
        while True:
            salt = generate_salt(size=Passcrypt._SALT_BYTES)
            result = pcrypt.new(self.send(got), salt)
            got = yield salt, result
    except StopIteration:
        pass


@comprehension(chained=True)
async def asum_passcrypt(
    self: Comprende,
    salt: Typing.EntropicRepr,
    *,
    kb: int = Passcrypt._DEFAULT_KB,
    cpu: int = Passcrypt._DEFAULT_CPU,
    hardness: int = Passcrypt._DEFAULT_HARDNESS,
):
    """
    Cumulatively applies the ``apasscrypt`` algorithm to each value
    that's yielded from the underlying Comprende async generator with
    the previously processed result before yielding the current result.
    """
    got = None
    asend = self.asend
    pcrypt = Passcrypt(kb=kb, cpu=cpu, hardness=hardness)
    summary = await asha3__512(salt, kb, cpu, hardness, hex=False)
    while True:
        pre_key = await asha3__512(
            salt, summary, await asend(got), hex=False
        )
        summary = await pcrypt.anew(pre_key, summary)
        got = yield summary


@comprehension(chained=True)
def sum_passcrypt(
    self: Comprende,
    salt: Typing.EntropicRepr,
    *,
    kb: int = Passcrypt._DEFAULT_KB,
    cpu: int = Passcrypt._DEFAULT_CPU,
    hardness: int = Passcrypt._DEFAULT_HARDNESS,
):
    """
    Cumulatively applies the ``passcrypt`` algorithm to each value
    that's yielded from the underlying Comprende sync generator with
    the previously processed result before yielding the current result.
    """
    got = None
    send = self.send
    pcrypt = Passcrypt(kb=kb, cpu=cpu, hardness=hardness)
    summary = sha3__512(salt, kb, cpu, hardness, hex=False)
    try:
        while True:
            pre_key = sha3__512(salt, summary, send(got), hex=False)
            summary = pcrypt.new(pre_key, summary)
            got = yield summary
    except StopIteration:
        pass


@comprehension(chained=True)
async def arandom_sleep(
    self: Comprende, span: Typing.Union[int, float] = 1
):
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
def random_sleep(self: Comprende, span: Typing.Union[int, float] = 1):
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


def insert_debuggers():
    """
    Copies the addons over into the ``Comprende`` class.
    """
    addons = {debugger, adebugger}
    for addon in addons:
        setattr(Comprende, addon.__name__, addon)
        Comprende.lazy_generators.add(addon.__name__)


def insert_gentools_pointers():
    """
    Inserts generator function pointers into the gentools namespace.
    """
    gentools.aplaintext_stream = aplaintext_stream
    gentools.plaintext_stream = plaintext_stream
    gentools.abytes_encipher = abytes_encipher
    gentools.bytes_encipher = bytes_encipher
    gentools.abytes_decipher = abytes_decipher
    gentools.bytes_decipher = bytes_decipher


def insert_passcrypt_methods():
    """
    Copies the addons over into the ``Comprende`` class.
    """
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


def insert_types():
    """
    Gives the package's type-hinting helper class access to the higher
    level classes.
    """
    Typing.AsyncDatabase = AsyncDatabase
    Typing.AsyncKeys = AsyncKeys
    Typing.BytesIO = BytesIO
    Typing.Chunky2048 = Chunky2048
    Typing.Comprende = Comprende
    Typing.Database = Database
    Typing.DomainKDF = DomainKDF
    Typing.Domains = Domains
    Typing.Ed25519 = Ed25519
    Typing.Hasher = Hasher
    Typing.KeyAADBundle = KeyAADBundle
    Typing.Keys = Keys
    Typing.Namespace = Namespace
    Typing.OpenNamespace = OpenNamespace
    Typing.Padding = Padding
    Typing.Passcrypt = Passcrypt
    Typing.Processes = Processes
    Typing.StreamHMAC = StreamHMAC
    Typing.Threads = Threads
    Typing.X25519 = X25519


def insert_xor_methods():
    """
    Copies the addons over into the ``Comprende`` class.
    """
    addons = {bytes_xor, abytes_xor}
    for addon in addons:
        setattr(Comprende, addon.__name__, addon)
        Comprende.lazy_generators.add(addon.__name__)


insert_bytes_cipher_methods()
insert_debuggers()
insert_gentools_pointers()
insert_passcrypt_methods()
insert_random_sleep_methods()
insert_types()
insert_xor_methods()

