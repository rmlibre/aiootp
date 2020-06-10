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
    "commons",
    "bits",
    "primes",
    "power10",
    "Namespace",
    "WORD_LIST",
    "ASCII_TABLE",
    "BYTES_TABLE",
    "BASE_64_TABLE",
    "ONION_CHAR_TABLE",
    "ASCII_ALPHANUMERIC",
]


__doc__ = """
A module used to aggregate commonly used constants & arbitrary utilities.
"""


import sys
import copy
import types
import asyncio
from os import linesep
from .__datasets import *


async def aimport_namespace(
    dictionary=None, *, mapping=None, deepcopy=False
):
    """
    Takes a ``dictionary``, such as ``globals()``, and copies the
    key-value pairs from the ``mapping`` kwarg into ``dictionary``.
    """
    if deepcopy == True:
        dictionary.update(copy.deepcopy(mapping))
    else:
        dictionary.update(dict(mapping))
    await asyncio.sleep(0)


def import_namespace(dictionary=None, *, mapping=None, deepcopy=False):
    """
    Takes a ``dictionary``, such as ``globals()``, and copies the
    key-value pairs from the ``mapping`` kwarg into ``dictionary``.
    """
    if deepcopy == True:
        dictionary.update(copy.deepcopy(mapping))
    else:
        dictionary.update(dict(mapping))


async def acreate_namespace(mapping=None, **kwargs):
    """
    Takes in a mapping of key-value pairs and returns a Namespace object
    that allows dotted lookup & assignment on the mapping. The
    mappings are mutated when the user mutates Namespace object values.
    """
    return Namespace(mapping, **kwargs)


def create_namespace(mapping=None, **kwargs):
    """
    Takes in a mapping of key-value pairs and returns a Namespace object
    that allows dotted lookup & assignment on the mapping. The
    mappings are mutated when the user mutates Namespace object values.
    """
    return Namespace(mapping, **kwargs)


async def amake_module(name=None, *, mapping=None, deepcopy=False):
    """
    Turns a mapping into a module object version of a Namespace which is
    importable using normal python syntax.
    """
    module = types.ModuleType(name)
    await aimport_namespace(
        module.__dict__, mapping=mapping, deepcopy=deepcopy
    )
    sys.modules[name] = module
    return Namespace(module.__dict__)


def make_module(name=None, *, mapping=None, deepcopy=False):
    """
    Turns a mapping into a module object version of a Namespace which is
    importable using normal python syntax.
    """
    module = types.ModuleType(name)
    import_namespace(module.__dict__, mapping=mapping, deepcopy=deepcopy)
    sys.modules[name] = module
    return Namespace(module.__dict__)


class Namespace:
    """
    A simple wrapper for turning mappings into Namespace objects that
    allow dotted lookup and assignment on those mappings. Also, provides
    utilities for copying mappings into other containers, & turning
    mappings into stand-alone, first-class modules.
    """

    amake_module = staticmethod(amake_module)
    make_module = staticmethod(make_module)
    acreate_namespace = staticmethod(acreate_namespace)
    create_namespace = staticmethod(create_namespace)
    aimport_namespace = staticmethod(aimport_namespace)
    import_namespace = staticmethod(import_namespace)

    def __init__(self, mapping=None, **kwargs):
        """
        Maps the user-defined mapping & kwargs to the Namespace's
        instance dictionary.
        """
        self.__dict__.update(
            {**mapping, **kwargs} if mapping else {**kwargs}
        )

    @property
    def __all__(self):
        """
        Allows users that have turned their Namespace into a Module
        object to do a ``from namespace import *`` on the contents of
        the namespace's mapping. This method excludes exporting dunder
        methods.
        """
        exports = {
            var: val for var, val in self.__dict__.items()
            if not (var.startswith("__") and var.endswith("__"))
        }
        return exports

    def __len__(self):
        """
        Returns the number of elements in the Namespace's mapping.
        """
        return len(self.__dict__)

    def __str__(self, *, tab=4 * " "):
        """
        Pretty displays the Namespace's mapping.
        """
        result = self.__class__.__qualname__
        result += f"({linesep}" + "    mapping={"
        for variable, value in self:
            result += f"{linesep + 2 * tab}{variable}:\t{repr(value)},"
        return result + f"{linesep}" + "    }" + f"{linesep})"

    def __repr__(self):
        """
        Pretty displays the Namespace's mapping.
        """
        return str(self)

    def __dir__(self):
        """
        Returns the list of names in the Namespace's mapping.
        """
        return list(self.__dict__.keys())

    def __setitem__(self, variable, value):
        """
        Transforms bracket item assignment into dotted assignment on the
        Namespace's mapping.
        """
        self.__dict__[variable] = value

    def __getitem__(self, variable):
        """
        Transforms bracket lookup into dotted access on the Namespace's
        mapping.
        """
        try:
            return self.__dict__[variable]
        except KeyError:
            return getattr(self, variable)

    def __iter__(self):
        """
        Allows Namespace's to be unpacked with tools like ``dict`` &
        ``list``.
        """
        for variable, value in dict(self.__dict__).items():
            yield variable, value

    async def __aiter__(self):
        """
        Allows Namespace's to be unpacked with with async iteration.
        """
        for variable, value in dict(self.__dict__).items():
            yield variable, value
            await asyncio.sleep(0)

    def __contains__(self, variable=None):
        """
        Returns a bool of ``variable``'s membership in the instance
        dictionary.
        """
        return variable in self.__dict__

    def __delitem__(self, variable=None):
        """
        Deletes the item ``variable`` from the instance dictionary.
        """
        del self.__dict__[variable]

    @property
    def namespace(self):
        """
        Cleaner name for users to access the instance's dictionary.
        """
        return self.__dict__


__extras = {
    # A domain-specific namespace for networking & communications
    "ACTIVE": "active_connection",
    "ADDRESS": "address",
    "ADMIN": "admin",
    "AGE": "age_of_connection",
    "ASCII_ALPHANUMERIC": ASCII_ALPHANUMERIC,
    "ASCII_TABLE": ASCII_TABLE,
    "BASE_64_TABLE": BASE_64_TABLE,
    "BYTES_TABLE": BYTES_TABLE,
    "CHANNEL": "channel",
    "CHANNELS": "channels",
    "CIPHERED_SALT": "ciphered_salt",
    "CIPHERTEXT": "ciphertext",
    "CLIENT": "client",
    "CORRUPT": "corrupt_connection",
    "DECRYPT": "decrypt",
    "DIRECTORY": "directory",
    "ENCRYPT": "encrypt",
    "FAILED": "failed",
    "GUEST": "guest",
    "HMAC": "hmac",
    "HTTP": "http",
    "HTTPS": "https",
    "ID": "contact_identifier",
    "INACTIVE": "terminated_connection",
    "KEEP_ALIVE": "keep_alive",
    "KEY": "shared_key",
    "LISTENING": "listening",
    "MAINTAINING": "maintaining",
    "MESSAGE_ID": "message_id",
    "MESSAGES": "message_archive",
    "METADATA": "metadata",
    "NEW_CONTACT": "new_contact",
    "NONE": NONE,
    "NUM": NUM,
    "Namespace": Namespace,
    "OLD_KEY": "last_shared_key",
    "OLD_VERIFID": "last_verification_code",
    "ONION": "onion",
    "ONION_CHAR_TABLE": ONION_CHAR_TABLE,
    "PHASE": "phase",
    "PLAINTEXT": "plaintext",
    "PORT": 8081,
    "RACHET": "rachet_shared_key",
    "RECEIVING": "receiving",
    "RETRY": "retry",
    "SALT": "salt",
    "SEED": "shared_seed",
    "SENDER": "sender",
    "SENDING": "sending",
    "SERVER": "server",
    "SERVER_BASE": "server_prime_base",
    "SERVER_PUB": "server_public_key_part",
    "SERVER_SECRET": "server_secret",
    "STATUS": "status",
    "SUCCESS": "success",
    "TB_PORT": 9150,
    "TOR_PORT": 9050,
    "UNSENT_MESSAGES": "unsent_message_archive",
    "URL": "url",
    "USER_MOD": "user_prime_modulus",
    "USER_PUB": "user_public_key_part",
    "USER_SECRET": "user_secret",
    "VERIFID": "verification_code",
    "WORD_LIST": WORD_LIST,
    "__doc__": __doc__,
    "__main_exports__": __all__,
    "__package__": "aiootp",
    "acreate_namespace": acreate_namespace,
    "create_namespace": create_namespace,
    "aimport_namespace": aimport_namespace,
    "import_namespace": import_namespace,
    "bits": bits,
    "power10": power10,
    "primes": primes,
}


commons = make_module("commons", mapping=__extras, deepcopy=True)


import_namespace(globals(), mapping=__extras)

