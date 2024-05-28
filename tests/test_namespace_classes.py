# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2024 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *

from aiootp.commons.slots import *
from aiootp.commons.namespaces import *
from aiootp.commons.configs import *


class BaseVariableHoldingClassTests:
    _items: t.Dict[str, t.Any] = dict(_private=True, one=1, string="value")
    _type: type
    _open: bool
    _frozen: bool

    async def test_init_accepts_mapping_and_keywords(self) -> None:
        obj_from_mapping = self._type(self._items)
        obj_from_keywords = self._type(**self._items)
        for name, value in self._items.items():
            assert value == getattr(obj_from_mapping, name)
            assert value == getattr(obj_from_keywords, name)


class BaseReprControlledTests(BaseVariableHoldingClassTests):

    async def test_instance_repr_shows_values(self) -> None:
        DebugControl.disable_debugging()
        obj = self._type(self._items)
        string = repr(obj)
        for name, value in self._items.items():
            if (name[0] == "_"):
                assert name not in string
            else:
                assert name in string, name
                assert self._open ^ (str(value) not in string), value
                assert self._open ^ (str(value.__class__) in string), value


class BaseMaskableReprTests(BaseVariableHoldingClassTests):

    async def test_mask_hides_or_shows_repr(self) -> None:
        DebugControl.disable_debugging()
        obj = self._type(self._items)
        for name in self._items:
            if str(name).startswith("_"):
                continue
            assert str(name) in obj.__repr__(mask=False), name
            assert str(getattr(obj, name)) in obj.__repr__(mask=False), name
            assert str(name) in obj.__repr__(mask=True), name
            assert str(getattr(obj, name)) not in obj.__repr__(mask=True), name
            DebugControl.enable_debugging(silence_warnings=True)
            assert str(name) in repr(obj), name
            assert str(getattr(obj, name)) in repr(obj), name
            DebugControl.disable_debugging()


class BaseFrozenTests(BaseVariableHoldingClassTests):

    async def test_instance_values_cant_be_changed_once_set(self) -> None:
        problem = (
            "An instance was allowed to be mutated."
        )
        obj = self._type()
        for name, value in self._items.items():
            setattr(obj, name, value)
            with Ignore(PermissionError, if_else=violation(problem)):
                setattr(obj, name, value)
            with Ignore(PermissionError, if_else=violation(problem)):
                delattr(obj, name)


class BaseModuleNamespaceTests(BaseVariableHoldingClassTests):

    async def test_all_doesnt_include_private_variables(self) -> None:
        obj = self._type(self._items)
        assert "_private" not in obj.__all__


class BaseDictLikeTests(BaseVariableHoldingClassTests):

    async def test_mapping_methods(self) -> None:
        items = {**self._items.copy(), 123: "number"}
        obj = self._type()
        for i, (name, value) in enumerate(items.items(), start=1):
            obj[name] = value
            assert name in obj
            assert i == len(obj)
            with Ignore(PermissionError, if_except=lambda _: self._frozen):
                del obj[name]
                assert name not in obj
                obj[name] = value

        assert set(items.keys()).issuperset(obj.keys())
        assert set(items.values()).issuperset(obj.values())
        assert set(items.items()).issuperset(obj.items())

        items.update(dict(new_value=True))
        obj.update(dict(new_value=True))
        assert obj["new_value"] == True
        assert obj["new_value"] == items["new_value"]


class BaseIndexableTests(BaseVariableHoldingClassTests):

    async def test_unmapped_attributes_arent_in_dir(self) -> None:
        obj = self._type(self._items)
        if not hasattr(obj, "_UNMAPPED_ATTRIBUTES"):
            return
        if all((type(item) is str) for item in self._items):
            assert not set(
                obj.__class__._UNMAPPED_ATTRIBUTES
            ).intersection(value for value in dir(obj))

    async def test_len_is_number_of_items_in_instance(self) -> None:
        obj = self._type(self._items)
        assert len(obj) == len(self._items)
        assert len(obj) == sum(1 for name in obj)

    async def test_indexable_iterations(self) -> None:
        obj = self._type(self._items)
        async for name in obj:
            assert name in obj
            assert name in self._items
            assert obj[name] == self._items[name]
        for name in obj:
            assert name in obj
            assert name in self._items
            assert obj[name] == self._items[name]

    async def test_item_indexing(self) -> None:
        names, values = list(self._items), list(self._items.values())
        items = {}
        obj = self._type()

        for name, value in zip(names, values):
            obj[name] = value
            items[name] = value
            assert obj[name] == items[name]
            assert dict(obj) == dict(items)

        with Ignore(PermissionError, if_except=lambda _: self._frozen):
            del obj[names[0]]
            del items[names[0]]
            assert dict(obj) == dict(items)


# Slots

class SlotsType(Slots):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)


class OpenSlotsType(OpenSlots):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)


class FrozenSlotsType(FrozenSlots):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)


class OpenFrozenSlotsType(OpenFrozenSlots):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)


class FrozenInstanceType(FrozenInstance):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)


class TestSlots(
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseIndexableTests,
):
    _type: type = SlotsType
    _open: bool = False
    _frozen: bool = False


class TestOpenSlots(
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseIndexableTests,
):
    _type: type = OpenSlotsType
    _open: bool = True
    _frozen: bool = False


class TestFrozenSlots(
    BaseFrozenTests,
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseIndexableTests,
):
    _type: type = FrozenSlotsType
    _open: bool = False
    _frozen: bool = True


class TestOpenFrozenSlots(
    BaseFrozenTests,
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseIndexableTests,
):
    _type: type = OpenFrozenSlotsType
    _open: bool = True
    _frozen: bool = True


class TestFrozenInstance(BaseReprControlledTests, BaseFrozenTests):
    _type: type = FrozenInstanceType
    _open: bool = False
    _frozen: bool = True


# Configs

class ConfigType(Config):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)

    slots_types = dict({
        name: BaseVariableHoldingClassTests._items[name].__class__
        for name in BaseVariableHoldingClassTests._items
    })


class TestConfig(
    BaseFrozenTests,
    BaseReprControlledTests,
    BaseIndexableTests,
):
    _type: type = ConfigType
    _open: bool = True
    _frozen: bool = True


# Namespaces

class TestNamespaceMapping(
    BaseDictLikeTests,
    BaseIndexableTests,
):
    _type: type = t.NamespaceMapping
    _open: bool = True
    _frozen: bool = False


class TestNamespace(
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseDictLikeTests,
    BaseIndexableTests,
):
    _type: type = Namespace
    _open: bool = False
    _frozen: bool = False


class TestOpenNamespace(
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseDictLikeTests,
    BaseIndexableTests,
):
    _type: type = OpenNamespace
    _open: bool = True
    _frozen: bool = False


class TestFrozenNamespace(
    BaseFrozenTests,
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseModuleNamespaceTests,
    BaseDictLikeTests,
    BaseIndexableTests,
):
    _type: type = FrozenNamespace
    _open: bool = False
    _frozen: bool = True


class TestOpenFrozenNamespace(
    BaseFrozenTests,
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseModuleNamespaceTests,
    BaseDictLikeTests,
    BaseIndexableTests,
):
    _type: type = OpenFrozenNamespace
    _open: bool = True
    _frozen: bool = True


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

