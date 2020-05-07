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


from .generics import Comprende
from .randoms import random_sleep as _random_sleep
from .randoms import arandom_sleep as _arandom_sleep
from .ciphers import OneTimePad
from .keygens import insert_keyrings


async def arandom_sleep(self, span=1):
    """
    Applies a random sleep before each yielded value from the underlying
    ``Comprende`` async generator.
    """
    async for result in self:
        await _arandom_sleep(span)
        yield result


def random_sleep(self, span=1):
    """
    Applies a random sleep before each yielded value from the underlying
    ``Comprende`` sync generator.
    """
    for result in self:
        _random_sleep(span)
        yield result


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
    OneTimePad.__init__ = insert_keyrings


insert_random_sleep_methods()
insert_bytes_cipher_methods()
insert_stream_cipher_methods()
insert_hashmap_cipher_methods()
insert_stateful_key_generator_objects()

