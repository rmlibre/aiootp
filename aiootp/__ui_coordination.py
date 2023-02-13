# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["_containers", "_exceptions", "_typing"]


__doc__ = (
    "Coordinates some of the library's UI/UX by inserting higher-level "
    "functionality from dependant modules into lower-level modules in t"
    "his package."
)


from . import *
from . import _typing, _containers, _exceptions
from ._exceptions import is_exception
from ._typing import Typing
from ._debuggers import gen_timer, agen_timer
from .asynchs import Processes, Threads, AsyncInit
from .commons import Namespace, OpenNamespace, Slots
from .commons import make_module
from .gentools import Comprende, comprehension
from .generics import Hasher, Domains, BytesIO, Padding, Clock
from .randoms import SequenceID
from .ciphers import StreamHMAC, SyntheticIV, Chunky2048
from .ciphers import generate_salt, agenerate_salt
from .keygens import KeyAADBundle
from .keygens import Ed25519, X25519, DomainKDF, Passcrypt
from .keygens import PackageSigner, PackageVerifier
from .databases import Database, AsyncDatabase


@comprehension()
async def adebugger(
    self: Comprende, *args, **kwargs
) -> Typing.AsyncGenerator:
    """
    Allows users to benchmark & read inspection details of running async
    generators inline as a chainable method.
    """
    args = args if args else self._args
    kwargs = {**self._kwargs, **kwargs}
    async for result in agen_timer(self._func)(*args, **kwargs):
        yield result


@comprehension()
def debugger(self: Comprende, *args, **kwargs) -> Typing.Generator:
    """
    Allows users to benchmark & read inspection details of running sync
    generators inline as a chainable method.
    """
    args = args if args else self._args
    kwargs = {**self._kwargs, **kwargs}
    yield from gen_timer(self._func)(*args, **kwargs)


def insert_debuggers() -> None:
    """
    Copies the addons over into the ``Comprende`` class.
    """
    addons = (debugger, adebugger)
    for addon in addons:
        setattr(Comprende, addon.__name__, addon)
        Comprende.lazy_generators.add(addon.__name__)


def insert_types() -> None:
    """
    Gives the package's type-hinting helper class access to the higher
    level classes.
    """
    Typing.add_type("AsyncCipherStream", AsyncCipherStream)
    Typing.add_type("AsyncDecipherStream", AsyncDecipherStream)
    Typing.add_type("AsyncInit", AsyncInit)
    Typing.add_type("CipherStream", CipherStream)
    Typing.add_type("DecipherStream", DecipherStream)
    Typing.add_type("AsyncDatabase", AsyncDatabase)
    Typing.add_type("BytesIO", BytesIO)
    Typing.add_type("Chunky2048", Chunky2048)
    Typing.add_type("Clock", Clock)
    Typing.add_type("Comprende", Comprende)
    Typing.add_type("Database", Database)
    Typing.add_type("DomainKDF", DomainKDF)
    Typing.add_type("Domains", Domains)
    Typing.add_type("Ed25519", Ed25519)
    Typing.add_type("GUID", GUID)
    Typing.add_type("Hasher", Hasher)
    Typing.add_type("KeyAADBundle", KeyAADBundle)
    Typing.add_type("Slots", Slots)
    Typing.add_type("Namespace", Namespace)
    Typing.add_type("OpenNamespace", OpenNamespace)
    Typing.add_type("PackageSigner", PackageSigner)
    Typing.add_type("PackageVerifier", PackageVerifier)
    Typing.add_type("Padding", Padding)
    Typing.add_type("Passcrypt", Passcrypt)
    Typing.add_type("PasscryptInstance", Passcrypt().__class__)
    Typing.add_type(
        "PasscryptSession", Passcrypt._passcrypt.__annotations__["session"]
    )
    Typing.add_type("Processes", Processes)
    Typing.add_type("SequenceID", SequenceID)
    Typing.add_type("StreamHMAC", StreamHMAC)
    Typing.add_type("SyntheticIV", SyntheticIV)
    Typing.add_type("Threads", Threads)
    Typing.add_type("X25519", X25519)
    for name, cls in _containers.__dict__.items():
        if (
            hasattr(cls, "mro")
            and issubclass(cls, Slots)
            and not hasattr(Typing, name)
        ):
            Typing.add_type(name, cls)
    for name, exc in _exceptions.__dict__.items():
        if is_exception(exc):
            Typing.add_type(name, exc)


def overwrite_containers_module() -> None:
    """
    Overwrites the package's `_containers.py` variable which will then
    be accessible to the user.
    """
    global _containers

    mapping = OpenNamespace(
        **{
            name: getattr(_containers, name) for name in _containers.__all__
        },
        __all__=_containers.__all__,
        __doc__=_containers.__doc__,
        __package__=_containers.__package__,
    )
    _containers = make_module("_containers", mapping=mapping)


def overwrite_exceptions_module() -> None:
    """
    Overwrites the package's `_exceptions.py` variable which will then
    be accessible to the user.
    """
    global _exceptions

    mapping = OpenNamespace(
        **{
            name: getattr(_exceptions, name) for name in _exceptions.__all__
        },
        __all__=_exceptions.__all__,
        __doc__=_exceptions.__doc__,
        __package__=_exceptions.__package__,
    )
    _exceptions = make_module("_exceptions", mapping=mapping)


def overwrite_typing_module() -> None:
    """
    Overwrites the package's `_typing.py` variable which will then be
    accessible to the user.
    """
    global _typing

    mapping = OpenNamespace(
        Typing=_typing.Typing,
        __all__=_typing.__all__,
        __doc__=_typing.__doc__,
        __package__=_typing.__package__,
    )
    _typing = make_module("_typing", mapping=mapping)


insert_debuggers()
insert_types()
overwrite_containers_module()
overwrite_exceptions_module()
overwrite_typing_module()

