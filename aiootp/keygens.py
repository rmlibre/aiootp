# This file is part of aiootp, an asynchronous one-time-pad based crypto
# and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "keygens",
    "AsyncKeys",
    "Keys",
    "amnemonic",
    "mnemonic",
    "akeypair",
    "keypair",
]


__doc__ = """
A collection of highlevel tools for creating & managing symmetric keys.
"""


from .asynchs import *
from .commons import *
from .randoms import salt, asalt
from .randoms import csprbg, acsprbg
from .randoms import csprng, acsprng
from .randoms import random_256, arandom_256
from .randoms import random_512, arandom_512
from .randoms import token_bytes, atoken_bytes
from .ciphers import Ropake
from .ciphers import X25519
from .ciphers import Ed25519
from .ciphers import Passcrypt
from .ciphers import OneTimePad
from .ciphers import keys, akeys
from .ciphers import passcrypt, apasscrypt
from .ciphers import bytes_keys, abytes_keys
from .ciphers import padding_key, apadding_key
from .ciphers import keypair_ratchets, akeypair_ratchets
from .generics import azip
from .generics import is_iterable
from .generics import comprehension
from .generics import sha_256, asha_256
from .generics import sha_256_hmac, asha_256_hmac
from .generics import convert_static_method_to_member


@comprehension()
async def atable_keystream(key=None, table=ASCII_TABLE):
    """
    This table based key generator function converts any key string
    containing an arbitrary set of characters, into another key string
    containing the set of characters provided by the table argument.
    This is an infinite generator that produces the elements one at a
    time.

    The ASCII_TABLE that's provided as a default, is a comprehensive set
    of ascii characters that are legible, unique, and have single octet
    byte representations. This ensures keys can be converted into a
    cryptographically secure byte stream of numbers from 32 to
    126.

    This generator function provides either deterministic keys from a
    user key, or generates a random 512-bit hash and derives a random
    key with the desired table elements from this hash. The result is a
    random, normal distribution of characters from among the items
    within the table.

    Usage Examples:

    # To produce a 60 byte key of characters from the default table
    key = "hotdiggitydog_thischowisyummy"
    async with atable_keystream(key=key) as generator:
        new_key = await generator()
        assert new_key != await generator()
    print(new_key)
    >>> Hx`4^ej;u&/]qOF21Ea2~(6f"smp'DvMk[(wy'lME%CpCo|1ZWt> &tu=Mw_
    """
    if not key:
        key = await acsprng()
    size = len(table[:])
    keystream = akeys(key, salt=key).aint(16).ato_base(size, table)
    async for key_portion in keystream:
        yield key_portion


@comprehension()
def table_keystream(key=None, table=ASCII_TABLE):
    """
    This table based key generator function converts any key string
    containing an arbitrary set of characters, into another key string
    containing the set of characters provided by the table argument.
    This is an infinite generator that produces the elements one at a
    time.

    The ASCII_TABLE that's provided as a default, is a comprehensive set
    of ascii characters that are legible, unique, and have single octet
    byte representations. This ensures keys can be converted into a
    cryptographically secure byte stream of numbers from 32 to
    126.

    This generator function provides either deterministic keys from a
    user key, or generates a random 512-bit hash and derives a random
    key with the desired table elements from this hash. The result is a
    random, normal distribution of characters from among the items
    within the table.

    Usage Example:
    key = "hotdiggitydog_thischowisyummy"
    with table_keystream(key=key) as generator:
        new_key = generator()
        assert new_key != generator()
    print(new_key)
    >>> Hx`4^ej;u&/]qOF21Ea2~(6f"smp'DvMk[(wy'lME%CpCo|1ZWt> &tu=Mw_
    """
    if not key:
        key = csprng()
    size = len(table[:])
    keystream = keys(key, salt=key).int(16).to_base(size, table)
    for key_portion in keystream:
        yield key_portion


async def atable_key(key=None, table=ASCII_TABLE, size=64):
    """
    This table based key function converts any key string containing
    any arbitrary set of characters, into another key string containing
    the set of items provided by the table argument.

    The ASCII_TABLE that's provided as a default, is a comprehensive set
    of ascii characters that are all legible, with unique, single octet
    byte representations. This ensures keys can be converted into byte
    streams of numbers from 32 to 126, with no duplicate values.

    This generator function provides either deterministic keys from a
    user key, or generates a random 512-bit hash and derives a random
    key with the desired table elements from this hash. The result is a
    random, normal distribution of characters from among the items
    within the table.

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
    async with atable_keystream(key=key, table=table) as generator:
        new_key = await generator()
        while len(new_key) < size:
            new_key += await generator()
        return new_key[:size]


def table_key(key=None, table=ASCII_TABLE, size=64):
    """
    This table based key function converts any key string containing
    any arbitrary set of characters, into another key string containing
    the set of items provided by the table argument.

    The ASCII_TABLE that's provided as a default, is a comprehensive set
    of ascii characters that are all legible, with unique, single octet
    byte representations. This ensures keys can be converted into byte
    streams of numbers from 32 to 126, with no duplicate values.

    This generator function provides either deterministic keys from a
    user key, or generates a random 512-bit hash and derives a random
    key with the desired table elements from this hash. The result is a
    random, normal distribution of characters from among the items
    within the table.

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
    with table_keystream(key=key, table=table) as generator:
        new_key = generator()
        while len(new_key) < size:
            new_key += generator()
        return new_key[:size]


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
    salt = salt if salt else await acsprng()
    key = await apasscrypt(key, salt)
    entropy = abytes_keys(key, salt=salt, pid=key)
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
    salt = salt if salt else csprng()
    key = passcrypt(key, salt)
    entropy = bytes_keys(key, salt=salt, pid=key)
    with entropy.bytes_to_int().relay(salt) as indexes:
        while True:
            if translate:
                entropy.gen.send(translate)
            translate = yield words[indexes() % length]


async def akeypair(entropy=csprbg()):
    """
    Returns a pair of symmetric hexidecimal keys from our fast
    cryptographically secure pseudo-random number generator. One is a
    512-bit encryption key, the other is a 256-bit salt.
    """
    return commons.Namespace(
        key=await acsprng(entropy), salt=await asalt(entropy)
    )


def keypair(entropy=csprbg()):
    """
    Returns a pair of symmetric hexidecimal keys from our fast
    cryptographically secure pseudo-random number generator. One is a
    512-bit encryption key, the other is a 256-bit salt.
    """
    return commons.Namespace(key=csprng(entropy), salt=salt(entropy))


class AsyncKeys:
    """
    This simple class coordinates and manages a symmetric key for
    establishing an arbitrary number of secure, deterministic streams of
    key material through an instance's ``__getitem__`` method.
    The class also contains static method key generators which function
    independantly from instance states, as well as the ability to create
    & validate HMAC code.
    """

    instance_methods = {
        akeys, abytes_keys, amnemonic, atable_key, atable_keystream
    }

    asalt = staticmethod(asalt)
    akeys = staticmethod(akeys)
    akeypair = staticmethod(akeypair)
    amnemonic = staticmethod(amnemonic)
    apadding_key = staticmethod(apadding_key)
    apasscrypt = staticmethod(apasscrypt)
    abytes_keys = staticmethod(abytes_keys)
    atable_key = staticmethod(atable_key)
    atable_keystream = staticmethod(atable_keystream)
    akeypair_ratchets = staticmethod(akeypair_ratchets)

    def __init__(self, key=None):
        """
        Stores a key in the instance used to create deterministic
        streams of key material &, create & validate HMAC codes. If a
        ``key`` argument is not passed then a new 512-bit random key is
        created.
        """
        self._reset(key=key)
        self.apasscrypt = self._apasscrypt

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
        deciphering = aiootp.aunpack(ciphered).axor(key=derived_keystream)

        async with deciphering.aint_to_ascii() as plaintext:
            deciphered = (await plaintext.ajoin()).replace("\x00", "")
            assert deciphered == "Hey, when's the party?"
        """
        return akeys(key=self.key, pid=pid)

    @property
    def key(self):
        """
        Returns the instance's main symmetric key.
        """
        return self._key

    async def ahmac(
        self, data, *, key=None, hasher=asha_256_hmac
    ):
        """
        Creates an HMAC code of ``data`` using ``key``  or the
        instance's ``self.key`` if it's not supplied & the hashing
        function ``hasher``.
        """
        return await hasher(data, key=key if key else self.key)

    async def atime_safe_equality(
        self, value_0=None, value_1=None, *, key=None
    ):
        """
        Tests if ``value_0`` is equal to ``value_1`` with a non-constant
        time comparison on the hash of each value appended with a salt
        prior to hashing. The algorithm prepends the instance's
        ``self.key`` if ``key`` is not supplied to further make the
        tested outputs undeterminable to an attacker. The random salt
        & key allow the hashes to be compared normally in non-constant
        time, without revealing meaningful information, since an
        attacker wouldn't have access to either. This scheme is easier
        to implement correctly & is easier to prove guarantees of the
        infeasibility of timing attacks.
        """
        salt = await atoken_bytes(32)
        key = key if key else self.key
        if (
            await asha_256(key, value_0, salt)
            == await asha_256(key, value_1, salt)
        ):
            return True
        else:
            return False

    async def atest_hmac(
        self, data, *, hmac=None, key=None, hasher=asha_256_hmac
    ):
        """
        Tests if the given ``hmac`` of some ``data`` is valid with a
        non-constant time comparison on the hash of each the supplied &
        derived HMACs, appended with a salt prior to hashing. The
        algorithm prepends the instance's ``self.key`` if ``key`` is not
        supplied to further make the tested outputs undeterminable to an
        attacker. The random salt & key allow the hashes to be compared
        normally in non-constant time, without revealing meaningful
        information, since an attacker wouldn't have access to either.
        This scheme is easier to implement correctly & is easier to
        prove guarantees of the infeasibility of timing attacks. Any
        async ``hasher`` function can be specified as the HMAC function,
        which is by default ``asha_256_hmac``.
        """
        if not hmac:
            raise ValueError("``hmac`` argument was not given.")
        key = key if key else self.key
        true_hmac = await self.ahmac(data=data, key=key, hasher=hasher)
        if await self.atime_safe_equality(hmac, true_hmac, key=key):
            return True
        else:
            raise ValueError("HMAC of ``data`` isn't valid.")

    def _reset(self, key=None):
        """
        Replaces the stored instance key used to create deterministic
        streams of key material &, create & validate HMAC codes.
        """
        self._key = key if key else csprng()
        for method in self.instance_methods:
            convert_static_method_to_member(
                self, method.__name__, method, key=self.key,
            )

    async def areset(self, key=None):
        """
        Replaces the stored instance key used to create deterministic
        streams of key material &, create & validate HMAC codes.
        """
        self._key = key if key else await acsprng()
        for method in self.instance_methods:
            convert_static_method_to_member(
                self, method.__name__, method, key=self.key,
            )
            await switch()

    async def _apasscrypt(
        self, password, salt, *, kb=1024, cpu=3, hardness=1024
    ):
        """
        A tunably memory & cpu hard method which returns a key from a
        user password & salt. This method also protects the passwords
        it processes with the instance's key, which forces attackers to
        also find a way to retrieve it in order to crack the passwords.
        """
        Passcrypt._check_inputs(password, salt)
        salted_password = await self.ahmac((password, salt))
        return await apasscrypt(
            salted_password, salt, kb=kb, cpu=cpu, hardness=hardness
        )


class Keys:
    """
    This simple class coordinates and manages a symmetric key for
    establishing an arbitrary number of secure, deterministic streams of
    key material through an instance's ``__getitem__`` method.
    The class also contains static method key generators which function
    independantly from instance states, as well as the ability to create
    & validate HMAC code.
    """

    instance_methods = {
        keys, bytes_keys, mnemonic, table_key, table_keystream
    }

    salt = staticmethod(salt)
    keys = staticmethod(keys)
    keypair = staticmethod(keypair)
    mnemonic = staticmethod(mnemonic)
    padding_key = staticmethod(padding_key)
    passcrypt = staticmethod(passcrypt)
    bytes_keys = staticmethod(bytes_keys)
    table_key = staticmethod(table_key)
    table_keystream = staticmethod(table_keystream)
    keypair_ratchets = staticmethod(keypair_ratchets)

    def __init__(self, key=None):
        """
        Stores a key in the instance used to create deterministic
        streams of key material &, create & validate HMAC codes. If a
        ``key`` argument is not passed then a new 512-bit random key is
        created.
        """
        self.reset(key)
        self.passcrypt = self._passcrypt

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
        deciphering = aiootp.unpack(ciphered).xor(key=derived_keystream)

        with deciphering.int_to_ascii() as plaintext:
            deciphered = plaintext.join().replace("\x00", "")
            assert deciphered == "Hey, when's the party?"
        """
        return keys(key=self.key, pid=pid)

    @property
    def key(self):
        """
        Returns the instance's main symmetric key.
        """
        return self._key

    def hmac(self, data, *, key=None, hasher=sha_256_hmac):
        """
        Creates an HMAC code of ``data`` using ``key``  or the
        instance's ``self.key`` if it's not supplied & the hashing
        function ``hasher``.
        """
        return hasher(data, key=key if key else self.key)

    def time_safe_equality(self, value_0=None, value_1=None, *, key=None):
        """
        Tests if ``value_0`` is equal to ``value_1`` with a non-constant
        time comparison on the hash of each value appended with a salt
        prior to hashing. The algorithm prepends the instance's
        ``self.key`` if ``key`` is not supplied to further make the
        tested outputs undeterminable to an attacker. The random salt
        & key allow the hashes to be compared normally in non-constant
        time, without revealing meaningful information, since an
        attacker wouldn't have access to either. This scheme is easier
        to implement correctly & is easier to prove guarantees of the
        infeasibility of timing attacks.
        """
        salt = token_bytes(32)
        key = key if key else self.key
        if sha_256(key, value_0, salt) == sha_256(key, value_1, salt):
            return True
        else:
            return False

    def test_hmac(
        self, data, *, hmac=None, key=None, hasher=sha_256_hmac
    ):
        """
        Tests if the given ``hmac`` of some ``data`` is valid with a
        non-constant time comparison on the hash of each the supplied &
        derived HMACs, appended with a salt prior to hashing. The
        algorithm prepends the instance's ``self.key`` if ``key`` is not
        supplied to further make the tested outputs undeterminable to an
        attacker. The random salt & key allow the hashes to be compared
        normally in non-constant time, without revealing meaningful
        information, since an attacker wouldn't have access to either.
        This scheme is easier to implement correctly & is easier to
        prove guarantees of the infeasibility of timing attacks. Any
        sync ``hasher`` function can be specified as the HMAC function,
        which is by default ``sha_256_hmac``.
        """
        if not hmac:
            raise ValueError("``hmac`` argument was not given.")
        key = key if key else self.key
        true_hmac = self.hmac(data=data, key=key, hasher=hasher)
        if self.time_safe_equality(hmac, true_hmac, key=key):
            return True
        else:
            raise ValueError("HMAC of ``data`` isn't valid.")

    def reset(self, key=None):
        """
        Replaces the stored instance key used to create deterministic
        streams of key material &, create & validate HMAC codes.
        """
        self._key = key if key else csprng()
        for method in self.instance_methods:
            convert_static_method_to_member(
                self, method.__name__, method, key=self.key,
            )

    def _passcrypt(
        self, password, salt, *, kb=1024, cpu=3, hardness=1024
    ):
        """
        A tunably memory & cpu hard method which returns a key from a
        user password & salt. This method also protects the passwords
        it processes with the instance's key, which forces attackers to
        also find a way to retrieve it in order to crack the passwords.
        """
        Passcrypt._check_inputs(password, salt)
        salted_password = self.hmac((password, salt))
        return passcrypt(
            salted_password, salt, kb=kb, cpu=cpu, hardness=hardness
        )


async def ainsert_keyrings(self, key=None):
    """
    A generic __init__ function that can be copied into abitrary class
    or instance dictionaries to give those objects access to stateful
    & ephemeral key material generators.
    """
    key = key if key else await acsprng()
    self.keyring = Keys(key=key)
    self.akeyring = AsyncKeys(key=key)


def insert_keyrings(self, key=None):
    """
    A generic __init__ function that can be copied into abitrary class
    or instance dictionaries to give those objects access to stateful
    & ephemeral key material generators.
    """
    key = key if key else csprng()
    self.keyring = Keys(key=key)
    self.akeyring = AsyncKeys(key=key)


__extras = {
    "AsyncKeys": AsyncKeys,
    "Keys": Keys,
    "X25519": X25519,
    "Ed25519": Ed25519,
    "Passcrypt": Passcrypt,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "_ainsert_keyrings": ainsert_keyrings,
    "_insert_keyrings": insert_keyrings,
    "asalt": asalt,
    "salt": salt,
    "acsprng": acsprng,
    "csprng": csprng,
    "acsprbg": acsprbg,
    "csprbg": csprbg,
    "akeys": akeys,
    "keys": keys,
    "abytes_keys": abytes_keys,
    "bytes_keys": bytes_keys,
    "amnemonic": amnemonic,
    "mnemonic": mnemonic,
    "apasscrypt": apasscrypt,
    "passcrypt": passcrypt,
    "akeypair": akeypair,
    "keypair": keypair,
    "akeypair_ratchets": akeypair_ratchets,
    "keypair_ratchets": keypair_ratchets,
    "apadding_key": apadding_key,
    "padding_key": padding_key,
    "protocols": X25519.protocols,
    "atable_key": atable_key,
    "table_key": table_key,
    "atable_keystream": atable_keystream,
    "table_keystream": table_keystream,
    "arandom_256": arandom_256,
    "random_256": random_256,
    "arandom_512": arandom_512,
    "random_512": random_512,
}


keygens = Namespace.make_module("keygens", mapping=__extras)

