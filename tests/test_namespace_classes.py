# This file is part of aiootp, an asynchronous crypto and anonymity
# library. Home of the Chunky2048 psuedo one-time pad stream cipher.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


# create subclasses to modify and test


IDENTIFIER_ITEMS = {"arachnid": 0, "breakfast": 1}
NON_IDENTIFIER_ITEMS = {0: "afro", 1: "bicycle"}


class SlotsExample(Slots):
    __slots__ = tuple(IDENTIFIER_ITEMS)

    class_variable: Typing.Any = "accessible"

    async def aiter(self):
        return [name async for name in self]


class FrozenSlotsExample(FrozenSlots):
    __slots__ = tuple(IDENTIFIER_ITEMS)

    class_variable: Typing.Any = "accessible"

    async def aiter(self):
        return [name async for name in self]


class OpenNamespaceExample(OpenNamespace):
    class_variable: Typing.Any = "accessible"

    async def aiter(self):
        return [name async for name in self]


# begin extracted test methods


async def len_is_number_of_items_in_instance(cls, obj, items):
    assert len(obj) == len(items)
    assert len(obj) == sum(1 for name in obj)
    assert len(obj) == sum(1 for name in await obj.aiter())


async def dir_is_list_of_keys_to_instance_values(cls, obj, items):
    assert dir(obj) == list(items)
    assert dir(obj) == [*obj]
    assert dir(obj) == await obj.aiter()


async def instances_store_key_values_like_dicts(cls, obj, items):
    assert items == {**obj}
    assert [*obj] == [*obj.keys()]
    assert [obj[name] for name in obj] == [*obj.values()]
    assert [(name, obj[name]) for name in obj] == [*obj.items()]


async def all_is_list_of_non_private_keys_to_instance_values(cls, obj, items):
    assert all((key in obj) for key in items)
    assert all((key not in cls()) for key in items)
    if hasattr(obj, "__all__"):
        assert [*obj.__dict__] == obj.__all__
        obj._private = True
        assert [*obj.__dict__] != obj.__all__
        assert "_private" not in obj.__all__
        assert "_private" in obj.__dict__
        if "Frozen" not in cls.__qualname__:
            del obj._private


async def getattr_and_getitem_are_interchangable(cls, obj, items):
    for name, value in items.items():
        assert name in obj
        if type(name) is str:
            assert getattr(obj, name) == value
        assert obj[name] == value


async def instance_values_change_correctly_when_reset(cls, obj, items):
    assert obj
    for name, value in items.items():
        del obj[name]
        assert name not in obj
        obj[name] = 2 * value
        if type(name) is str:
            assert getattr(obj, name) == 2 * value
        assert obj[name] == 2 * value
        obj[name] = value
        assert obj[name] == value
        del obj[name]
    assert not obj


async def instance_values_cannot_be_changed_once_set(cls, obj, items):
    problem = "instance value was changed or deleted!"
    assert obj
    for name, value in items.items():
        with ignore(PermissionError, if_else=violation(problem)):
            del obj[name]
        assert name in obj
        with ignore(PermissionError, if_else=violation(problem)):
            obj[name] = 2 * value
        assert obj[name] == value
        with ignore(PermissionError, if_else=violation(problem)):
            obj[name] = value
        assert obj[name] == value


async def mask_kwarg_hides_instance_values_from_repr(cls, obj, items):
    for name in obj:
        if str(name).startswith("_"):
            continue
        assert str(name) in obj.__repr__(mask=False), name
        assert str(obj[name]) in obj.__repr__(mask=False), name
        assert str(name) in obj.__repr__(mask=True), name
        assert str(obj[name]) not in obj.__repr__(mask=True), name


async def debug_control_toggles_hidden_repr(cls, obj, items):
        DebugControl.enable_debugging()
        assert all(
            (name in obj.__repr__() and str(obj[name]) in obj.__repr__())
            for name in obj
        )
        DebugControl.disable_debugging()
        assert all(
            (name in obj.__repr__() and str(obj[name]) not in obj.__repr__())
            for name in obj
        )


async def dunder_tests(cls, obj, items):
    """
    Consolidate the tests into a general structure that can be run for
    the various types of namespace and slots classes.
    """
    await len_is_number_of_items_in_instance(cls, obj, items)
    await dir_is_list_of_keys_to_instance_values(cls, obj, items)
    await instances_store_key_values_like_dicts(cls, obj, items)
    await all_is_list_of_non_private_keys_to_instance_values(cls, obj, items)
    await getattr_and_getitem_are_interchangable(cls, obj, items)
    await mask_kwarg_hides_instance_values_from_repr(cls, obj, items)
    if not issubclass(cls, OpenNamespace):
        await debug_control_toggles_hidden_repr(cls, obj, items)
    assert obj["class_variable"] == "accessible"
    if "Frozen" in cls.__qualname__:
        await instance_values_cannot_be_changed_once_set(cls, obj, items)
    else:
        await instance_values_change_correctly_when_reset(cls, obj, items)
    assert obj["class_variable"] == "accessible"


class BaseTestNamespaceClasses:
    _type: t.Any

    async def test_dunders(self):
        items = IDENTIFIER_ITEMS.copy()
        await dunder_tests(self._type, self._type(items), items)
        await dunder_tests(self._type, self._type(**items), items)
        await dunder_tests(self._type, self._type(json.dumps(items)), items)
        assert items == IDENTIFIER_ITEMS


class BaseTestNonIdentifierNamespaceClasses(BaseTestNamespaceClasses):
    _type: t.Any

    async def test_dunders_with_non_identifier_items(self):
        items = NON_IDENTIFIER_ITEMS.copy()
        await dunder_tests(self._type, self._type(items), items)
        assert items == NON_IDENTIFIER_ITEMS


class TestSlots(BaseTestNamespaceClasses):
    _type: t.Any = SlotsExample


class TestFrozenSlots(BaseTestNamespaceClasses):
    _type: t.Any = FrozenSlotsExample


class TestOpenNamespace(BaseTestNonIdentifierNamespaceClasses):
    _type: t.Any = OpenNamespaceExample


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

