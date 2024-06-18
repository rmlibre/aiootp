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

from aiootp.commons.instances import *
from aiootp.commons.slots import *
from aiootp.commons.namespaces import *
from aiootp.commons.configs import *


class SlotsAttributes:
    __slots__ = ()

    _items: t.Dict[str, t.Any] = dict(
        _private=True, one=1, mapped="value", unmapped="attr"
    )
    _MAPPED_ATTRIBUTES: t.Tuple[str] = tuple(
        name for name in _items if name != "unmapped"
    )
    _UNMAPPED_ATTRIBUTES: t.Tuple[str] = (
        *Slots._UNMAPPED_ATTRIBUTES, "mapped", "unmapped"
    )                       # Being mapped overrides being unmapped


class NamespaceAttributes(SlotsAttributes):
    __slots__ = ()

    _UNMAPPED_ATTRIBUTES: t.Tuple[str] = (
        *Namespace._UNMAPPED_ATTRIBUTES, "mapped", "unmapped"
    )                       # Being mapped overrides being unmapped


class BaseVariableHoldingClassTests:
    _items = dict(SlotsAttributes._items)
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
            if name[0] == "_":
                assert name not in string
            elif (
                hasattr(obj, "_is_mapped_attribute")
                and not obj._is_mapped_attribute(name)
            ):
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
            if (
                str(name) in getattr(obj, "_UNMAPPED_ATTRIBUTES", ())
                or str(name).startswith("_")
            ):
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
        private_name = "_private"
        assert hasattr(obj, private_name)
        assert private_name not in obj.__all__


class BaseDictLikeTests(BaseVariableHoldingClassTests):

    def frozen_violation_catcher(self, name: str) -> Ignore:
        if_except = lambda _: self._frozen
        if_else = lambda _: (
            (not self._frozen) or raise_exception(AssertionError(name))
        )
        return Ignore(PermissionError, if_except=if_except, if_else=if_else)

    async def test_inclusion_exclusion_logic(self) -> None:
        items = {**self._items, 123: "number"}
        obj = self._type()
        unmapped = set()
        MAPPED = getattr(obj, "_MAPPED_ATTRIBUTES", ())
        UNMAPPED = getattr(obj, "_UNMAPPED_ATTRIBUTES", ())
        for i, (name, value) in enumerate(items.items(), start=1):
            if name in MAPPED or name not in UNMAPPED:
                pass
            else:
                unmapped.add(name)
            obj[name] = value
            assert name in obj
            assert value == obj[name]
            assert i == len(obj) + len(unmapped)
            with self.frozen_violation_catcher(name):
                del obj[name]
                assert name not in obj
            with self.frozen_violation_catcher(name):
                obj[name] = value

    async def test_mapping_methods(self) -> None:
        items = {**self._items, 123: "number"}
        obj = self._type()
        for name, value in items.items():
            obj[name] = value

        assert set(items.keys()).issuperset(obj.keys())
        assert set(items.values()).issuperset(obj.values())
        assert set(items.items()).issuperset(obj.items())

        items.update(dict(new_value=True))
        obj.update(dict(new_value=True))
        assert obj["new_value"] == True
        assert obj["new_value"] == items["new_value"]

        with self.frozen_violation_catcher("new_value"):
            obj.update(dict(new_value=True).items())
            assert obj["new_value"] == True
        with self.frozen_violation_catcher("new_value"):
            obj.update(**dict(new_value=False))
            assert obj["new_value"] == False
        with self.frozen_violation_catcher("new_value"):
            obj.update(dict(new_value=False), **dict(new_value=True))
            assert obj["new_value"] == True


class BaseIndexableTests(BaseVariableHoldingClassTests):

    async def test_unmapped_attributes_arent_in_dir(self) -> None:
        obj = self._type(self._items)
        if not hasattr(obj, "_UNMAPPED_ATTRIBUTES"):
            return
        if all((type(item) is str) for item in self._items):
            assert not (
                set(obj.__class__._UNMAPPED_ATTRIBUTES)
                .difference(obj.__class__._MAPPED_ATTRIBUTES)
            ).intersection(value for value in dir(obj))

    async def test_len_is_number_of_mapped_items_in_instance(self) -> None:
        obj = self._type(self._items)
        assert len(obj) == sum(1 for name in obj)
        assert len(obj) == len(
            set(self._items)
            .difference(getattr(obj, "_UNMAPPED_ATTRIBUTES", ()))
            .union(getattr(obj, "_MAPPED_ATTRIBUTES", ()))
        )

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
        all_items = {}
        obj = self._type()

        for name, value in zip(names, values):
            obj[name] = value
            all_items[name] = value
            if name in dict(obj):
                items[name] = value
                assert obj[name] == items[name]
            else:
                assert name in obj._UNMAPPED_ATTRIBUTES
            assert obj[name] == all_items[name]

        with Ignore(PermissionError, if_except=lambda _: self._frozen):
            del obj[names[0]]
            del items[names[0]]
            assert dict(obj) == dict(items)

    async def test_false_contains_logic(self) -> None:
        obj = self._type()
        assert randoms.token_bytes(4).hex() not in obj
        assert randoms.token_bits(32) not in obj
        assert None not in obj


# Slots

class SlotsType(SlotsAttributes, Slots):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)


class OpenSlotsType(SlotsAttributes, OpenSlots):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)


class FrozenSlotsType(SlotsAttributes, FrozenSlots):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)


class FrozenSlotsDictType(NamespaceAttributes, FrozenSlots):
    __slots__ = ("__dict__", *BaseVariableHoldingClassTests._items)


class OpenFrozenSlotsType(SlotsAttributes, OpenFrozenSlots):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)


class FrozenInstanceType(SlotsAttributes, FrozenInstance):
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


class TestFrozenSlotsDict(
    BaseFrozenTests,
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseDictLikeTests,
    BaseIndexableTests,
):
    _type: type = FrozenSlotsDictType
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


class TestFrozenInstance(
    BaseReprControlledTests,
    BaseFrozenTests,
):
    _type: type = FrozenInstanceType
    _open: bool = False
    _frozen: bool = True


# Configs

class ConfigType(SlotsAttributes, Config):
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

class NamespaceType(NamespaceAttributes, Namespace):
    pass


class OpenNamespaceType(NamespaceAttributes, OpenNamespace):
    pass


class FrozenNamespaceType(NamespaceAttributes, FrozenNamespace):
    pass


class OpenFrozenNamespaceType(NamespaceAttributes, OpenFrozenNamespace):
    pass


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
    _type: type = NamespaceType
    _open: bool = False
    _frozen: bool = False


class TestOpenNamespace(
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseDictLikeTests,
    BaseIndexableTests,
):
    _type: type = OpenNamespaceType
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
    _type: type = FrozenNamespaceType
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
    _type: type = OpenFrozenNamespaceType
    _open: bool = True
    _frozen: bool = True


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

