# This file is part of aiootp, an asynchronous crypto and anonymity
# library. Home of the Chunky2048 psuedo one-time pad stream cipher.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = []


__doc__ = (
    "A module used to aggregate commonly used constants & arbitrary oth"
    "er namespace utilities."
)


import sys
import copy
import json
import types
import asyncio
from math import ceil
from secrets import token_bytes
from os import linesep as sep
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from .__constants import *
from ._typing import Typing as t
from ._exceptions import Issue


class DeletedAttribute:
    """
    Creates objects which raise the result of a callback function if the
    object is queried for attributes.
    """

    __slots__ = ("_callback",)

    def __init__(self, callback: t.Callable[..., Exception]) -> None:
        self._callback = callback

    def __getattr__(self, name: str) -> None:
        raise self._callback()


class Slots:
    """
    A base class which allow subclasses to create very efficient
    instances, with explicitly declared attributes in their `__slots__`.
    """

    __slots__ = ()

    def __init__(self, mapping: t.JSONSerializable = {}, **kwargs) -> None:
        """
        Maps the user-defined kwargs to the instance attributes. If a
        subclass defines a `__slots__` list, then only variables with
        names in the list can be admitted to the instance. Defining
        classes with __slots__ can greatly increase memory efficiency if
        a system instantiates many objects of the class.
        """
        if mapping.__class__ in JSON_DESERIALIZABLE_TYPES:
            mapping = json.loads(mapping)
        for name, value in {**mapping, **kwargs}.items():
            setattr(self, name, value)

    def __bool__(self) -> bool:
        """
        If the instance is empty then return False, otherwise True.
        """
        return any(self)

    def __len__(self) -> int:
        """
        Returns the number of elements in the instance.
        """
        return sum(1 for name in self.__slots__ if hasattr(self, name))

    def __dir__(self) -> t.List[str]:
        """
        Returns the list of names in the instance.
        """
        return [name for name in self.__slots__ if hasattr(self, name)]

    def __contains__(self, name: str) -> bool:
        """
        Returns a bool of ``name``'s membership in the instance.
        """
        return hasattr(self, name)

    def __setitem__(self, name: str, value: t.Any) -> None:
        """
        Transforms bracket item assignment into dotted assignment on the
        instance.
        """
        setattr(self, name, value)

    def __getitem__(self, name: str) -> t.Any:
        """
        Transforms bracket lookup into dotted access on the instance.
        """
        return getattr(self, name)

    def __delitem__(self, name: str) -> None:
        """
        Deletes the item ``name`` from the instance.
        """
        delattr(self, name)

    def __repr__(self, *, mask: bool = True) -> str:
        """
        Pretty displays the instance & its attributes.
        """
        from ._debuggers import DebugControl

        if not mask or DebugControl.is_debugging():
            items = f',{sep}    '.join(
                f"{var}={repr(val)}"
                for var, val in self.items()
                if not str(var).startswith("_")
            )
        else:
            items = f',{sep}    '.join(
                f"{var}="
                f"{OMITTED} of {type(val)} "
                f"{(val and 'is <truthy>') or 'is <falsey>'}"
                for var, val in self.items()
                if not str(var).startswith("_")
            )
        cls = self.__class__.__qualname__
        return f"{cls}({f'{sep}    {items},{sep}' if items else ''})"

    async def __aiter__(self) -> t.AsyncGenerator[None, t.Any]:
        """
        Allows an instance to be unpacked with with async iteration.
        """
        for name in self.__slots__:
            if hasattr(self, name):
                await asyncio.sleep(0)
                yield name

    def __iter__(self) -> t.Generator[None, t.Any, None]:
        """
        Allows an instance to be unpacked with tools like ``dict`` &
        ``list``.
        """
        for name in self.__slots__:
            if hasattr(self, name):
                yield name

    def keys(self) -> t.Generator[None, t.Any, None]:
        """
        Yields the names of all items in the instance.
        """
        yield from (
            name
            for name in self.__slots__
            if hasattr(self, name)
        )

    def values(self) -> t.Generator[None, t.Any, None]:
        """
        Yields the values of all items in the instance.
        """
        yield from (
            getattr(self, name)
            for name in self.__slots__
            if hasattr(self, name)
        )

    def items(self) -> t.Generator[None, t.Tuple[t.Any, t.Any], None]:
        """
        Yields the name, value pairs of all items in the instance.
        """
        yield from (
            (name, getattr(self, name))
            for name in self.__slots__
            if hasattr(self, name)
        )


class FrozenSlots(Slots):
    """
    A version of the `Slots` class which enables instances of subclasses
    to have attributes that are frozen once they're set.
    """
    __slots__ = ()

    def __setattr__(self, name: str, value: t.Any) -> None:
        """
        Denies the setting attributes after they have already been set.
        """
        if hasattr(self, name):
            raise Issue.cant_overwrite_existing_attribute(name)
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """
        Denies the deletion of attributes after they have been set.
        """
        raise Issue.cant_delete_frozen_object_attribute(name)


class Namespace(Slots):
    """
    A simple wrapper for turning mappings into Namespace objects that
    allow dotted lookup and assignment on those mappings. Also, provides
    utilities for copying mappings into other containers, & turning
    mappings into stand-alone, first-class modules.
    """

    __slots__ = ("__dict__",)

    def __init__(self, mapping={}, **kwargs) -> None:
        """
        Maps the user-defined mapping & kwargs to the Namespace's
        instance dictionary.
        """
        if mapping.__class__ in JSON_DESERIALIZABLE_TYPES:
            mapping = json.loads(mapping)
        self.__dict__.update(mapping) if mapping else 0
        self.__dict__.update(kwargs) if kwargs else 0

    @property
    def __all__(self) -> t.Generator[None, t.Hashable, None]:
        """
        Allows users that have turned their Namespace into a Module
        object to do a ``from namespace import *`` on the contents of
        the namespace's mapping. This method excludes exporting private
        methods & attributes.
        """
        return [var for var in self.__dict__ if str(var)[0] != "_"]

    @property
    def namespace(self) -> dict:
        """
        Cleaner name for users to access the instance's dictionary.
        """
        return self.__dict__

    def __bool__(self) -> bool:
        """
        If the namespace is empty then return False, otherwise True.
        """
        return bool(self.__dict__)

    def __len__(self) -> int:
        """
        Returns the number of elements in the Namespace's mapping.
        """
        return len(self.__dict__)

    def __dir__(self) -> t.List[t.Hashable]:
        """
        Returns the list of names in the Namespace's mapping.
        """
        return [*self.__dict__]

    def __contains__(self, variable=None) -> bool:
        """
        Returns a bool of ``variable``'s membership in the instance
        dictionary.
        """
        return variable in self.__dict__

    def __setitem__(self, name: str, value: t.Any) -> None:
        """
        Transforms bracket item assignment into dotted assignment on the
        instance.
        """
        try:
            self.__dict__[name] = value
        except KeyError:
            setattr(self, name, value)

    def __getitem__(self, name: str) -> t.Any:
        """
        Transforms bracket lookup into dotted access on the instance.
        """
        try:
            return self.__dict__[name]
        except KeyError:
            return getattr(self, name)

    def __delitem__(self, name: str) -> None:
        """
        Deletes the item ``name`` from the instance.
        """
        try:
            del self.__dict__[name]
        except KeyError:
            delattr(self, name)

    async def __aiter__(self) -> t.AsyncGenerator[None, t.Hashable]:
        """
        Allows Namespace's to be unpacked with async iteration.
        """
        for variable in self.__dict__:
            await asyncio.sleep(0)
            yield variable

    def __iter__(self) -> t.Generator[None, t.Hashable, None]:
        """
        Allows Namespace's to be unpacked with tools like ``dict`` &
        ``list``.
        """
        yield from self.__dict__

    def keys(self) -> t.Generator[None, t.Hashable, None]:
        """
        Yields the names of all items in the instance.
        """
        yield from self.__dict__

    def values(self) -> t.Generator[None, t.Hashable, None]:
        """
        Yields the values of all items in the instance.
        """
        yield from self.__dict__.values()

    def items(self) -> t.Generator[None, t.Tuple[t.Hashable, t.Any], None]:
        """
        Yields the name, value pairs of all items in the instance.
        """
        yield from self.__dict__.items()


class OpenNamespace(Namespace):
    """
    A version of the `Namespace` class which doesn't omit instance
    repr's by default.
    """

    def __repr__(self, mask: bool = False) -> str:
        """
        Pretty displays the instance & its attributes.
        """
        return super().__repr__(mask=mask)


async def aimport_namespace(
    dictionary: dict, *, mapping: dict, deepcopy: bool = False
) -> None:
    """
    Takes a ``dictionary``, such as ``globals()``, and copies the
    key-value pairs from the ``mapping`` kwarg into it.
    """
    await asyncio.sleep(0)
    if deepcopy == True:
        dictionary.update(copy.deepcopy(mapping))
    else:
        dictionary.update(mapping)


def import_namespace(
    dictionary: dict, *, mapping: dict, deepcopy: bool = False
) -> None:
    """
    Takes a ``dictionary``, such as ``globals()``, and copies the
    key-value pairs from the ``mapping`` kwarg into it.
    """
    if deepcopy == True:
        dictionary.update(copy.deepcopy(mapping))
    else:
        dictionary.update(mapping)


async def amake_module(
    name: str, *, mapping: dict, deepcopy: bool = False
) -> Namespace:
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


def make_module(
    name: str, *, mapping: dict, deepcopy: bool = False
) -> Namespace:
    """
    Turns a mapping into a module object version of a Namespace which is
    importable using normal python syntax.
    """
    module = types.ModuleType(name)
    import_namespace(module.__dict__, mapping=mapping, deepcopy=deepcopy)
    sys.modules[name] = module
    return Namespace(module.__dict__)


constants = make_module(
    "constants",
    mapping=dict(
        misc=make_module("misc", mapping=misc.__dict__),
        datasets=make_module("datasets", mapping=datasets.__dict__),
        passcrypt=make_module("passcrypt", mapping=passcrypt.__dict__),
        slick256=make_module("slick256", mapping=slick256.__dict__),
        chunky2048=make_module("chunky2048", mapping=chunky2048.__dict__),
    ),
)


extras = dict(
    Namespace=Namespace,
    OpenNamespace=OpenNamespace,
    Slots=Slots,
    FrozenSlots=FrozenSlots,
    __doc__=__doc__,
    __package__=__package__,
    aimport_namespace=aimport_namespace,
    amake_module=amake_module,
    constants=constants,
    import_namespace=import_namespace,
    make_module=make_module,
)


commons = make_module("commons", mapping=extras, deepcopy=True)

