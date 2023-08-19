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
    ITEMS = IDENTIFIER_ITEMS

    async def aiter(self):
        return [name async for name in self]


class FrozenSlotsExample(FrozenSlots):
    __slots__ = tuple(IDENTIFIER_ITEMS)

    class_variable: Typing.Any = "accessible"
    ITEMS = IDENTIFIER_ITEMS

    async def aiter(self):
        return [name async for name in self]


class OpenNamespaceExample(OpenNamespace):

    class_variable: Typing.Any = "accessible"
    ITEMS = IDENTIFIER_ITEMS

    async def aiter(self):
        return [name async for name in self]


# begin extracted test methods


async def len_is_number_of_items_in_instance(cls, obj):
    assert len(obj) == len(cls.ITEMS)
    assert len(obj) == sum(1 for name in obj)
    assert len(obj) == sum(1 for name in await obj.aiter())


async def dir_is_list_of_keys_to_instance_values(cls, obj):
    assert dir(obj) == list(cls.ITEMS)
    assert dir(obj) == [*obj]
    assert dir(obj) == await obj.aiter()


async def instances_store_key_values_like_dicts(cls, obj):
    assert cls.ITEMS == {**obj}
    assert [*obj] == [*obj.keys()]
    assert [obj[name] for name in obj] == [*obj.values()]
    assert [(name, obj[name]) for name in obj] == [*obj.items()]


async def all_is_list_of_non_private_keys_to_instance_values(cls, obj):
    assert all((key in obj) for key in cls.ITEMS)
    assert all((key not in cls()) for key in cls.ITEMS)
    if hasattr(obj, "__all__"):
        assert [*obj.__dict__] == obj.__all__
        obj._private = True
        assert [*obj.__dict__] != obj.__all__
        assert "_private" not in obj.__all__
        assert "_private" in obj.__dict__
        del obj._private


async def getattr_and_getitem_are_interchangable(cls, obj):
    for name, value in cls.ITEMS.items():
        assert name in obj
        if type(name) is str:
            assert getattr(obj, name) == value
        assert obj[name] == value


async def instance_values_change_correctly_when_reset(cls, obj):
    assert obj
    for name, value in cls.ITEMS.items():
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


async def instance_values_cannot_be_changed_once_set(cls, obj):
    problem = "instance value was changed or deleted!"
    assert obj
    for name, value in cls.ITEMS.items():
        with ignore(ValueError, if_else=violation(problem)):
            del obj[name]
        assert name in obj
        with ignore(ValueError, if_else=violation(problem)):
            obj[name] = 2 * value
        assert obj[name] == value
        with ignore(ValueError, if_else=violation(problem)):
            obj[name] = value
        assert obj[name] == value


async def mask_kwarg_hides_instance_values_from_repr(cls, obj):
    for name in obj:
        if str(name).startswith("_"):
            continue
        assert str(name) in obj.__repr__(mask=False), name
        assert str(obj[name]) in obj.__repr__(mask=False), name
        assert str(name) in obj.__repr__(mask=True), name
        assert str(obj[name]) not in obj.__repr__(mask=True), name


async def debug_control_toggles_hidden_repr(cls, obj):
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


async def dunder_tests(cls, obj):
    """
    Consolidate the tests into a general structure that can be run for
    the various types of namespace and slots classes.
    """
    await len_is_number_of_items_in_instance(cls, obj)
    await dir_is_list_of_keys_to_instance_values(cls, obj)
    await instances_store_key_values_like_dicts(cls, obj)
    await all_is_list_of_non_private_keys_to_instance_values(cls, obj)
    await getattr_and_getitem_are_interchangable(cls, obj)
    await mask_kwarg_hides_instance_values_from_repr(cls, obj)
    if not issubclass(cls, OpenNamespace):
        await debug_control_toggles_hidden_repr(cls, obj)
    assert obj["class_variable"] == "accessible"
    if issubclass(cls, FrozenSlots):
        await instance_values_cannot_be_changed_once_set(cls, obj)
    else:
        await instance_values_change_correctly_when_reset(cls, obj)
    assert obj["class_variable"] == "accessible"


class TestSlots:
    async def test_dunders(self):
        """
        Default Slots dunder methods don't fail when used.
        """
        cls = SlotsExample
        obj = cls(**IDENTIFIER_ITEMS)
        await dunder_tests(cls, obj)

        cls = FrozenSlotsExample
        obj = cls(**IDENTIFIER_ITEMS)
        await dunder_tests(cls, obj)


class TestOpenNamespace:
    async def test_dunders(self):
        """
        Default Slots dunder methods don't fail when used.
        """
        cls = OpenNamespaceExample
        obj = cls(**IDENTIFIER_ITEMS)
        await dunder_tests(cls, obj)

        # an object initialized with a mapping functions exactly the
        # same as initializing with keyword arguments
        obj = cls(json.dumps(dict(**IDENTIFIER_ITEMS)))
        await dunder_tests(cls, obj)

        # an object functions correctly with non-identifier keys stored
        # in __dict__
        control_items = NON_IDENTIFIER_ITEMS.copy()
        cls.ITEMS = NON_IDENTIFIER_ITEMS
        obj = cls(NON_IDENTIFIER_ITEMS)
        await dunder_tests(cls, obj)
        assert control_items == cls.ITEMS


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

