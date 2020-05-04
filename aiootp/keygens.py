# This file is part of aiootp, an asynchronous one-time-pad based crypto
# and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["keygens", "AsyncKeys", "Keys"]


__doc__ = """
A collection of highlevel tools for creating & managing symmetric keys.
"""


from .asynchs  import *
from .commons import primes
from .commons import commons
from .randoms import csprng
from .randoms import acsprng
from .ciphers import keys
from .ciphers import akeys
from .ciphers import subkeys
from .ciphers import asubkeys
from .ciphers import OneTimePad
from .ciphers import keypair_ratchets
from .ciphers import akeypair_ratchets
from .generics import is_iterable
from .generics import comprehension
from .generics import sha_256_hmac
from .generics import asha_256_hmac
from .generics import MemberFromStaticMethod


@comprehension()
async def atable_key_gen(key=None, table=commons.ASCII_TABLE):
    """
    This table based key generator function converts any key string
    containing an arbitrary set of characters, into another key string
    containing the set of characters provided by the table argument.
    This generator produces the elements one at a time until the size
    limit has been reached, or produces an unending stream of elements
    if no size is specified.

    The ASCII_TABLE that's provided as a default, is a comprehensive set
    of ascii characters that are legible, unique, and have single octet
    byte representations. This ensures keys can be converted into a
    cryptographically secure byte stream of binary numbers from 32 to
    126.

    This generator function provides either deterministic keys from a
    user key, or generates a random sha_512 hash key and derives a
    random key with the desired table elements from this hash. The
    result is a random, normal distribution of characters from among the
    items within the table. The table argument can also contain an
    aribtrary set of objects. In this case, this generator function is
    essentially analogous to one that generates a series of random
    choices from the table, with the added functionality of allowing
    deterministic outputs that coincide with the key and size arguments.

    Usage Examples:

    # To produce a 60 byte key of characters from the default table
    key = "hotdiggitydog_thischowisyummy"
    new_key = ""
    async for char in atable_key_gen(key=key, size=60):
        new_key += char
    print(new_key)
    >>> keVDn~;NrEu/or9#KoXnncfNN5q;o"R!VeuQB=?fgd:0"+-C`~_LlpoOBzqR
    """
    if key == None:
        key = await acsprng(None)
    if not is_iterable(table):
        raise TypeError("table is not iterable")
    elif isinstance(table, dict):
        table = list(table.keys())
    prime = primes[32][0]
    table_size = len(table)
    async for index in akeys(key, key).aresize(16).aint(16):
        yield table[index % prime % table_size]


@comprehension()
def table_key_gen(key=None, table=commons.ASCII_TABLE):
    """
    This table based key generator function converts any key string
    containing an arbitrary set of characters, into another key string
    containing the set of characters provided by the table argument.
    This generator produces the characters one at a time until the size
    limit has been reached.

    The ASCII_TABLE that's provided as a default, is a comprehensive set
    of ascii characters that are legible, unique, and have single octet
    byte representations. This ensures keys can be converted into a
    cryptographically secure byte stream of binary numbers from 32 to
    126.

    This generator function provides either deterministic keys from a
    user key, or generates a random sha_512 hash key and derives a
    random key with the desired table elements from this hash. The
    result is a random, normal distribution of characters from among the
    items within the table. The table argument can also contain an
    aribtrary set of objects. In this case, this generator function is
    essentially analogous to one that generates a series of random
    choices from the table, with the added functionality of allowing
    deterministic outputs that coincide with the key and size arguments.

    The size parameter determines the number of bytes/elements the
    output will contain.

    Usage Example:
    key = "hotdiggitydog_thischowisyummy"
    new_key = ""
    for char in table_key_gen(key=key, size=60):
        new_key += char
    print(new_key)
    >>> keVDn~;NrEu/or9#KoXnncfNN5q;o"R!VeuQB=?fgd:0"+-C`~_LlpoOBzqR
    """
    if key == None:
        key = csprng(None)
    if not is_iterable(table):
        raise TypeError("table is not iterable")
    elif isinstance(table, dict):
        table = list(table.keys())
    prime = primes[32][0]
    table_size = len(table)
    for index in keys(key, key).resize(16).int(16):
        yield table[index % prime % table_size]


async def atable_key(key=None, table=commons.ASCII_TABLE, size=64):
    """
    This table based key function converts any key string containing
    any arbitrary set of characters, into another key string containing
    the set of items provided by the table argument.

    The ASCII_TABLE that's provided as a default, is a comprehensive set
    of ascii characters that are all legible, with unique, single octet
    byte representations. This ensures keys can be converted into byte
    streams of binary numbers from 32 to 126, with no duplicate values.

    This function provides either deterministic keys from a user key,
    or generates a random sha_512 hash key and derives a random key with
    the desired table elements from this hash. The result is a random,
    normal distribution of characters from among the items within
    the table. The table argument can also contain an aribtrary set of
    objects. In this case, this function is essentially analogous to
    one that generates list of random choices from the table, with the
    added functionality of allowing deterministic outputs that coincide
    with the key and size arguments.

    Usage Examples:

    key = "smellycaaaat, smelly caaaaat!"
    new_key = table_key(key=key, table="0123456789abcdef")
    print(new_key)
    >>> 4f271c61b0e615a7d3e9ac0161497034d047d4ecddc650ae054f829b3416818c

    new_key = table_key(key=key, size=len(key))
    print(new_key)
    >>> #mE)bOQD@lY%]Qwpb9Zi^32]jteVg
    """
    async with atable_key_gen(key=key, table=table)[:size] as generator:
        try:
            return await generator.ajoin()
        except:
            return await generator.alist()


def table_key(key=None, table=commons.ASCII_TABLE, size=64):
    """
    This table based key function converts any key string containing
    any arbitrary set of characters, into another key string containing
    the set of items provided by the table argument.

    The ASCII_TABLE that's provided as a default, is a comprehensive set
    of ascii characters that are all legible, with unique, single octet
    byte representations. This ensures keys can be converted into byte
    streams of binary numbers from 32 to 126, with no duplicate values.

    This function provides either deterministic keys from a user key,
    or generates a random sha_512 hash key and derives a random key with
    the desired table elements from this hash. The result is a random,
    normal distribution of characters from among the items within
    the table. The table argument can also contain an aribtrary set of
    objects. In this case, this function is essentially analogous to
    one that generates list of random choices from the table, with the
    added functionality of allowing deterministic outputs that coincide
    with the key and size arguments.

    The size parameter determines the number of bytes/elements the
    output will contain.


    Usage Examples:
    key = "smellycaaaat, smelly caaaaat!"
    new_key = table_key(key=key, table="0123456789abcdef")
    print(new_key)
    >>> 4f271c61b0e615a7d3e9ac0161497034d047d4ecddc650ae054f829b3416818c

    new_key = table_key(key=key, size=len(key))
    print(new_key)
    >>> #mE)bOQD@lY%]Qwpb9Zi^32]jteVg
    """
    with table_key_gen(key=key, table=table)[:size] as generator:
        try:
            return generator.join()
        except:
            return generator.list()


async def akeypair(entropy=csprng()):
    """
    Returns a pair of symmetric 512-bit hexidecimal keys from our fast
    cryptographically secure pseudo-random number generator.
    """
    return await acsprng(entropy), await acsprng(entropy)


def keypair(entropy=csprng()):
    """
    Returns a pair of symmetric 512-bit hexidecimal keys from our fast
    cryptographically secure pseudo-random number generator.
    """
    return csprng(entropy), csprng(entropy)


class Keys:
    """
    This simple class coordinates and manages a pair of symmetric keys
    for establishing an arbitrary number of secure, deterministic
    streams of key material through instances' ``__getitem__``, ``keys``
    & ``subkeys`` methods. The class also contains static method key
    generators which function independantly from instance states.
    """
    seed = csprng
    keys = staticmethod(keys)
    subkeys = staticmethod(subkeys)
    keypair = staticmethod(keypair)
    table_key = staticmethod(table_key)
    table_key_gen = staticmethod(table_key_gen)
    keypair_ratchets = staticmethod(keypair_ratchets)

    def __init__(self, key=None):
        """
        Creates a symmetric key pair used to create deterministic streams
        of key material.
        """
        self.key = key
        self.reset(both=False if key else True)

    def __getitem__(self, salt=""):
        """
        Provides a simple interface for users to create deterministic
        & externally uncorrelatable key material from a name or ``salt``.
        """
        return self.keys(key=self.key, salt=self.salt, pid=salt)

    def hmac(self, data=None, key=None, *, hasher=sha_256_hmac):
        """
        Creates an HMAC code of ``data`` using ``key`` & the hashing
        function ``hasher``.
        """
        return hasher(data, key=key if key else self.key)

    def test_hmac(
        self, data=None, key=None, hmac=None, *, hasher=sha_256_hmac
    ):
        """
        Tests the ``hmac`` code against the derived HMAC of ``data``
        using ``key`` & the hashing function ``hasher``.
        """
        if hmac == self.hmac(
            data=data, key=key if key else self.key, hasher=hasher
        ):
            return True
        else:
            raise ValueError("HMAC of ``data`` isn't valid.")

    def state(self):
        """
        Returns both the main ``self.key`` & the ephemeral ``self.salt``.
        """
        return self.key, self.salt

    def reset(self, both=True):
        """
        Creates a new pair of symmetric keys if ``both`` is truthy, else
        just updates the ephemeral ``self.salt`` key.
        """
        if both:
            self.key, self.salt = keypair()
        else:
            self.salt = csprng(csprng())
        method_tools = MemberFromStaticMethod()
        for method in [keys, subkeys]:
            method_tools.convert(
                self, method.__name__, method, key=self.key, salt=self.salt
            )


class AsyncKeys:
    """
    This simple class coordinates and manages a pair of symmetric keys
    for establishing an arbitrary number of secure, deterministic
    streams of key material through its ``__getitem__``, ``akeys``,
    & ``asubkeys`` methods. The class also contains static method key
    generators which function independantly from instance states.
    """
    aseed = acsprng
    akeys = staticmethod(akeys)
    asubkeys = staticmethod(asubkeys)
    akeypair = staticmethod(akeypair)
    atable_key = staticmethod(atable_key)
    atable_key_gen = staticmethod(atable_key_gen)
    akeypair_ratchets = staticmethod(akeypair_ratchets)

    def __init__(self, key=None):
        """
        Creates a symmetric key pair used to create deterministic streams
        of key material.
        """
        self.key, self.salt = key, csprng(key) if key else keypair()
        method_tools = MemberFromStaticMethod()
        for method in [keys, subkeys]:
            method_tools.convert(
                self, method.__name__, method, key=self.key, salt=self.salt
            )

    def __getitem__(self, salt=""):
        """
        Provides a simple interface for users to create deterministic
        & externally uncorrelatable key material from a name or ``salt``.
        """
        return self.akeys(key=self.key, salt=self.salt, pid=salt)

    async def ahmac(
        self, data=None, key=None, *, hasher=asha_256_hmac
    ):
        """
        Creates an HMAC code of ``data`` using ``key`` & the hashing
        function ``hasher``.
        """
        return await hasher(data, key=key if key else self.key)

    async def atest_hmac(
        self, data=None, key=None, hmac=None, *, hasher=sha_256_hmac
    ):
        """
        Tests the ``hmac`` code against the derived HMAC of ``data``
        using ``key`` & the async hashing function ``hasher``.
        """
        if hmac == await self.ahmac(
            data=data, key=key if key else self.key, hasher=hasher
        ):
            return True
        else:
            raise ValueError("HMAC of ``data`` isn't valid.")

    async def astate(self):
        """
        Returns both the main ``self.key`` & the ephemeral ``self.salt``.
        """
        return self.key, self.salt

    async def areset(self, both=True):
        """
        Creates a new pair of symmetric keys if ``both`` is truthy, else
        just updates the ephemeral ``self.salt`` key.
        """
        if both:
            self.key, self.salt = await akeypair()
        else:
            self.salt = await acsprng(csprng())
        method_tools = MemberFromStaticMethod()
        for method in [keys, subkeys]:
            method_tools.convert(
                self, method.__name__, method, key=self.key, salt=self.salt
            )


async def ainsert_keyrings(self, key=None):
    """
    A generic __init__ function that can be copied into abitrary class
    or instance dictionaries to give those objects access to stateful
    & ephemeral key material generators.
    """
    self.keyring = Keys(key=key)
    self.akeyring = AsyncKeys(key=key)


def insert_keyrings(self, key=None):
    """
    A generic __init__ function that can be copied into abitrary class
    or instance dictionaries to give those objects access to stateful
    & ephemeral key material generators.
    """
    self.keyring = Keys(key=key)
    self.akeyring = AsyncKeys(key=key)


OneTimePad.__init__ = insert_keyrings


__extras = {
    "AsyncKeys": AsyncKeys,
    "Keys": Keys,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "ainsert_keyrings": ainsert_keyrings,
    "insert_keyrings": insert_keyrings,
    "akeys": akeys,
    "keys": keys,
    "asubkeys": asubkeys,
    "subkeys": subkeys,
    "akeypair": akeypair,
    "keypair": keypair,
    "akeypair_ratchets": akeypair_ratchets,
    "keypair_ratchets": keypair_ratchets,
    "atable_key": atable_key,
    "table_key": table_key,
    "atable_key_gen": atable_key_gen,
    "table_key_gen": table_key_gen,
}


keygens = commons.Namespace.make_module("keygens", mapping=__extras)

