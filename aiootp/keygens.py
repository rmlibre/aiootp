# This file is part of aiootp, an asynchronous one-time-pad based crypto
# and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["keygens", "AsyncKeys", "Keys", "amnemonic", "mnemonic"]


__doc__ = """
A collection of highlevel tools for creating & managing symmetric keys.
"""


from .asynchs import *
from .commons import *
from .randoms import salt
from .randoms import asalt
from .randoms import csprng
from .randoms import acsprng
from .ciphers import keys
from .ciphers import akeys
from .ciphers import subkeys
from .ciphers import asubkeys
from .ciphers import passcrypt
from .ciphers import apasscrypt
from .ciphers import bytes_keys
from .ciphers import abytes_keys
from .ciphers import OneTimePad
from .ciphers import keypair_ratchets
from .ciphers import akeypair_ratchets
from .generics import azip
from .generics import is_iterable
from .generics import comprehension
from .generics import sha_256_hmac
from .generics import asha_256_hmac
from .generics import convert_static_method_to_member


@comprehension()
async def atable_key_gen(key=None, table=ASCII_TABLE):
    """
    This table based key generator function converts any key string
    containing an arbitrary set of characters, into another key string
    containing the set of characters provided by the table argument.
    This is an infinite generator that produces the elements one at a
    time.

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
    async for char in atable_key_gen(key=key)[:60]:
        new_key += char
    print(new_key)
    >>> Hx`4^ej;u&/]qOF21Ea2~(6f"smp'DvMk[(wy'lME%CpCo|1ZWt> &tu=Mw_
    """
    if key == None:
        key = await acsprng(await acsprng())
    if not is_iterable(table):
        raise TypeError("table is not iterable")
    elif isinstance(table, dict):
        table = list(table.keys())
    prime = primes[32][0]
    table_size = len(table)
    async for index in akeys(key, key).aresize(16).aint(16):
        yield table[index % prime % table_size]


@comprehension()
def table_key_gen(key=None, table=ASCII_TABLE):
    """
    This table based key generator function converts any key string
    containing an arbitrary set of characters, into another key string
    containing the set of characters provided by the table argument.
    This is an infinite generator that produces the elements one at a
    time.

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
    for char in table_key_gen(key=key)[:60]:
        new_key += char
    print(new_key)
    >>> Hx`4^ej;u&/]qOF21Ea2~(6f"smp'DvMk[(wy'lME%CpCo|1ZWt> &tu=Mw_
    """
    if key == None:
        key = csprng(csprng())
    if not is_iterable(table):
        raise TypeError("table is not iterable")
    elif isinstance(table, dict):
        table = list(table.keys())
    prime = primes[32][0]
    table_size = len(table)
    for index in keys(key, key).resize(16).int(16):
        yield table[index % prime % table_size]


async def atable_key(key=None, table=ASCII_TABLE, size=64):
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
        if type(table) == dict:
            return await generator.alist()
        else:
            try:
                return await generator.ajoin()
            except TypeError:
                return await generator.ajoin(b"")


def table_key(key=None, table=ASCII_TABLE, size=64):
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
        if type(table) == dict:
            return generator.list()
        else:
            try:
                return generator.join()
            except TypeError:
                return generator.join(b"")


@comprehension()
async def amnemonic(key, salt=None, words=WORD_LIST):
    """
    Creates a stream of words for a mnemonic key from a user password
    ``key`` & random salt. If a salt isn't passed, then a random salt is
    generated & is available by calling ``result(exit=True)`` on the
    generator object. The ``words`` used for the mnemonic can be passed
    in, but by default are a 2048 word list of unique, all lowercase
    english words.
    """
    translate = None
    length = len(words)
    salt = salt if salt else await asalt()
    key = await apasscrypt(key, salt)
    entropy = abytes_keys(key, salt, key)
    async with entropy.abytes_to_int().arelay(salt) as indexes:
        while True:
            if translate:
                await entropy.gen.asend(translate)
            translate = yield words[await indexes() % length]


@comprehension()
def mnemonic(key, salt=None, words=WORD_LIST):
    """
    Creates a stream of words for a mnemonic key from a user password
    ``key`` & random salt. If a salt isn't passed, then a random salt is
    generated & is available by calling ``result(exit=True)`` on the
    generator object. The ``words`` used for the mnemonic can be passed
    in, but by default are a 2048 word list of unique, all lowercase
    english words.
    """
    translate = None
    length = len(words)
    salt = salt if salt else globals()["salt"]()
    key = passcrypt(key, salt)
    entropy = bytes_keys(key, salt, key)
    with entropy.bytes_to_int().relay(salt) as indexes:
        while True:
            if translate:
                entropy.gen.send(translate)
            translate = yield words[indexes() % length]


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


class AsyncKeys:
    """
    This simple class coordinates and manages a symmetric key for
    establishing an arbitrary number of secure, deterministic
    streams of key material through an instance's ``__getitem__`` method.
    The class also contains static method key generators which function
    independantly from instance states, as well as the ability to create
    & validate HMAC code.
    """

    instance_methods = {
        akeys, asubkeys, abytes_keys, amnemonic, atable_key, atable_key_gen
    }

    aseed = staticmethod(asalt)
    akeys = staticmethod(akeys)
    asubkeys = staticmethod(asubkeys)
    akeypair = staticmethod(akeypair)
    amnemonic = staticmethod(amnemonic)
    apasscrypt = staticmethod(apasscrypt)
    abytes_keys = staticmethod(abytes_keys)
    atable_key = staticmethod(atable_key)
    atable_key_gen = staticmethod(atable_key_gen)
    akeypair_ratchets = staticmethod(akeypair_ratchets)

    def __init__(self, key=None):
        """
        Stores a key in the instance used to create deterministic
        streams of key material &, create & validate HMAC codes. If a
        ``key`` argument is not passed then a new 512-bit random key is
        created.
        """
        self._key = key if key else salt()
        for method in self.instance_methods:
            convert_static_method_to_member(
                self, method.__name__, method, key=self.key,
            )

    def __getitem__(self, pid=""):
        """
        Provides a simple interface for users to create deterministic
        & externally uncorrelatable key material stream from a user-
        defined ``pid`` value.

        Usage Example:

        import aiootp

        keyring = aiootp.AsyncKeys(key)
        keystream = keyring["conversation"]
        datastream = aiootp.adata("Hey, when's the party?").aascii_to_int()

        async with datastream.axor(keystream) as ciphering:
            ciphered = await ciphering.alist()

        salt = await keystream.aresult(exit=True)

        derived_keystream = keyring.akeys(salt=salt, pid="conversation")
        deciphering = aiootp.aunpack(ciphered).axor(derived_keystream)
        async with deciphering.aint_to_ascii() as plaintext:
            assert "Hey, when's the party?" == await plaintext.ajoin()
        """
        return akeys(key=self.key, pid=pid)

    @property
    def key(self):
        """
        Returns the instance's main symmetric key.
        """
        return self._key

    async def ahmac(
        self, data=None, *, key=None, hasher=asha_256_hmac
    ):
        """
        Creates an HMAC code of ``data`` using ``key``  or the
        instance's ``self.key`` if it's not supplied & the hashing
        function ``hasher``.
        """
        return await hasher(data, key=key if key else self.key)

    async def atest_hmac(
        self, data=None, hmac=None, *, key=None, hasher=asha_256_hmac
    ):
        """
        Tests if ``hmac`` of ``data`` is valid using ``key`` or the
        instance's ``self.key`` if it's not supplied. Instead of using a
        constant time character by character check on the hmac, the hmac
        itself is hmac'd with a random salt & is checked against the
        hmac & salt of the correct hmac. This non-constant time check on
        the hmac of the supplied hmac doesn't reveal meaningful
        information about the true hmac if the attacker does not have
        access to the secret key. Nor does it gain information about the
        hmac it supplied since it is salted. This scheme is easier to
        implement correctly & is easier to guarantee the infeasibility
        of a timing attack, since "constant time" operations are truly
        dependant on architectures, languages & resource allocation for
        those operations. An async ``hasher`` function can also be
        supplied to use that algorithm instead of the default
        ``asha_256_hmac``.
        """
        if not hmac:
            raise ValueError("`hmac` keyword argument was not given.")
        salt = await acsprng(hmac)
        key = key if key else self.key
        true_hmac = await self.ahmac(data=data, key=key, hasher=hasher)
        if (
            await self.ahmac((hmac, salt), key=key)
            == await self.ahmac((true_hmac, salt), key=key)
        ):
            return True
        else:
            raise ValueError("HMAC of ``data`` isn't valid.")

    async def areset(self, key=None):
        """
        Replaces the stored instance key used to create deterministic
        streams of key material &, create & validate HMAC codes.
        """
        self._key = key if key else await asalt()
        for method in self.instance_methods:
            convert_static_method_to_member(
                self, method.__name__, method, key=self.key,
            )
            await switch()


class Keys:
    """
    This simple class coordinates and manages a symmetric key for
    establishing an arbitrary number of secure, deterministic
    streams of key material through an instance's ``__getitem__`` method.
    The class also contains static method key generators which function
    independantly from instance states, as well as the ability to create
    & validate HMAC code.
    """

    instance_methods = {
        keys, subkeys, bytes_keys, mnemonic, table_key, table_key_gen
    }

    seed = staticmethod(salt)
    keys = staticmethod(keys)
    subkeys = staticmethod(subkeys)
    keypair = staticmethod(keypair)
    amnemonic = staticmethod(amnemonic)
    passcrypt = staticmethod(passcrypt)
    bytes_keys = staticmethod(bytes_keys)
    table_key = staticmethod(table_key)
    table_key_gen = staticmethod(table_key_gen)
    keypair_ratchets = staticmethod(keypair_ratchets)

    def __init__(self, key=None):
        """
        Stores a key in the instance used to create deterministic
        streams of key material &, create & validate HMAC codes. If a
        ``key`` argument is not passed then a new 512-bit random key is
        created.
        """
        self.reset(key)

    def __getitem__(self, pid=""):
        """
        Provides a simple interface for users to create deterministic
        & externally uncorrelatable key material stream from a user-
        defined ``pid`` value.

        Usage Example:

        import aiootp

        keyring = aiootp.Keys(key)
        keystream = keyring["conversation"]
        datastream = aiootp.data("Hey, when's the party?").ascii_to_int()

        with datastream.xor(keystream) as ciphering:
            ciphered = ciphering.list()

        salt = keystream.result(exit=True)

        derived_keystream = keyring.keys(salt=salt, pid="conversation")
        deciphering = aiootp.unpack(ciphered).xor(derived_keystream)
        with deciphering.int_to_ascii() as plaintext:
            assert "Hey, when's the party?" == plaintext.join()
        """
        return keys(key=self.key, pid=pid)

    @property
    def key(self):
        """
        Returns the instance's main symmetric key.
        """
        return self._key

    def hmac(self, data=None, *, key=None, hasher=sha_256_hmac):
        """
        Creates an HMAC code of ``data`` using ``key``  or the
        instance's ``self.key`` if it's not supplied & the hashing
        function ``hasher``.
        """
        return hasher(data, key=key if key else self.key)

    def test_hmac(
        self, data=None, hmac=None, *, key=None, hasher=sha_256_hmac
    ):
        """
        Tests if ``hmac`` of ``data`` is valid using ``key`` or the
        instance's ``self.key`` if it's not supplied. Instead of using a
        constant time character by character check on the hmac, the hmac
        itself is hmac'd with a random salt & is checked against the
        hmac & salt of the correct hmac. This non-constant time check on
        the hmac of the supplied hmac doesn't reveal meaningful
        information about the true hmac if the attacker does not have
        access to the secret key. Nor does it gain information about the
        hmac it supplied since it is salted. This scheme is easier to
        implement correctly & is easier to guarantee the infeasibility
        of a timing attack, since "constant time" operations are truly
        dependant on architectures, languages & resource allocation for
        those operations.  A sync ``hasher`` function can also be
        supplied to use that algorithm instead of the default
        ``sha_256_hmac``.
        """
        if not hmac:
            raise ValueError("`hmac` keyword argument was not given.")
        salt = csprng(hmac)
        key = key if key else self.key
        true_hmac = self.hmac(data=data, key=key, hasher=hasher)
        if (
            self.hmac((hmac, salt), key=key)
            == self.hmac((true_hmac, salt), key=key)
        ):
            return True
        else:
            raise ValueError("HMAC of ``data`` isn't valid.")

    def reset(self, key=None):
        """
        Replaces the stored instance key used to create deterministic
        streams of key material &, create & validate HMAC codes.
        """
        self._key = key if key else salt()
        for method in self.instance_methods:
            convert_static_method_to_member(
                self, method.__name__, method, key=self.key,
            )


async def ainsert_keyrings(self, key=None):
    """
    A generic __init__ function that can be copied into abitrary class
    or instance dictionaries to give those objects access to stateful
    & ephemeral key material generators.
    """
    key = key if key else await asalt()
    self.keyring = Keys(key=key)
    self.akeyring = AsyncKeys(key=key)


def insert_keyrings(self, key=None):
    """
    A generic __init__ function that can be copied into abitrary class
    or instance dictionaries to give those objects access to stateful
    & ephemeral key material generators.
    """
    key = key if key else salt()
    self.keyring = Keys(key=key)
    self.akeyring = AsyncKeys(key=key)


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
    "mnemonic": mnemonic,
    "asubkeys": asubkeys,
    "subkeys": subkeys,
    "akeypair": akeypair,
    "keypair": keypair,
    "akeypair_ratchets": akeypair_ratchets,
    "keypair_ratchets": keypair_ratchets,
    "amnemonic": amnemonic,
    "atable_key": atable_key,
    "table_key": table_key,
    "atable_key_gen": atable_key_gen,
    "table_key_gen": table_key_gen,
}


keygens = Namespace.make_module("keygens", mapping=__extras)

