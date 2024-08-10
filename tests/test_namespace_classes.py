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


from conftest import *

from aiootp._typing import tuples
from aiootp.commons.instances import *
from aiootp.commons.slots import *
from aiootp.commons.typed_slots import *
from aiootp.commons.namespaces import *
from aiootp.commons.configs import *


class SlotsAttributes:
    __slots__ = ()

    _items: t.Dict[str, t.Any] = dict(
        _private=True, one=1, mapped="value", unmapped=tuple("attr")
    )
    _MAPPED_ATTRIBUTES: t.Tuple[str] = tuple(
        name for name in _items if name != "unmapped"
    )
    _UNMAPPED_ATTRIBUTES: t.Tuple[str] = (
        *Slots._UNMAPPED_ATTRIBUTES,
        "mapped",
        "unmapped",
    )  # Being mapped overrides being unmapped


class NamespaceAttributes(SlotsAttributes):
    __slots__ = ()

    _UNMAPPED_ATTRIBUTES: t.Tuple[str] = (
        *Namespace._UNMAPPED_ATTRIBUTES,
        "mapped",
        "unmapped",
    )  # Being mapped overrides being unmapped


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

    async def test_attribute_access(self) -> None:
        obj = self._type()
        obj.mapped = self._items["mapped"]
        assert obj.mapped == self._items["mapped"]

        if_else = lambda _: not self._frozen or raise_exception(_.error)
        if_except = lambda _: self._frozen or raise_exception(_.error)
        with Ignore(PermissionError, if_else=if_else, if_except=if_except):
            del obj.mapped

        assert self._frozen or not hasattr(obj, "mapped")

    async def test_item_access(self) -> None:
        obj = self._type()

        try:
            obj[123] = True
        except (TypeError, AttributeError) as feature_broken:
            if hasattr(obj, "__dict__"):
                raise feature_broken
            else:
                return
        assert 123 in obj
        assert obj[123] is True

        if_except = lambda _: self._frozen
        if_else = lambda _: not self._frozen or raise_exception(_.error)
        with Ignore(PermissionError, if_except=if_except, if_else=if_else):
            del obj[123]

        assert self._frozen or 123 not in obj


class BaseReprControlledTests(BaseVariableHoldingClassTests):
    async def test_instance_repr_shows_values(self) -> None:
        DebugControl.disable_debugging()
        obj = self._type(self._items)
        string = repr(obj)
        for name, value in self._items.items():
            if (
                name[0] == "_"
                or hasattr(obj, "_is_mapped_attribute")
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
            if str(name) in getattr(obj, "_UNMAPPED_ATTRIBUTES", ()) or str(
                name
            ).startswith("_"):
                continue
            assert str(name) in obj.__repr__(mask=False), name
            assert str(getattr(obj, name)) in obj.__repr__(mask=False), name
            assert str(name) in obj.__repr__(mask=True), name
            assert str(getattr(obj, name)) not in obj.__repr__(
                mask=True
            ), name
            DebugControl.enable_debugging(silence_warnings=True)
            assert str(name) in repr(obj), name
            assert str(getattr(obj, name)) in repr(obj), name
            DebugControl.disable_debugging()


class BaseFrozenTests(BaseVariableHoldingClassTests):
    async def test_instance_values_cant_be_changed_once_set(self) -> None:
        problem = (  # fmt: skip
            "An instance was allowed to be mutated."
        )
        obj = self._type()
        for name, value in self._items.items():
            setattr(obj, name, value)
            with Ignore(PermissionError, if_else=violation(problem)):
                setattr(obj, name, value)
            with Ignore(PermissionError, if_else=violation(problem)):
                delattr(obj, name)


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
        assert obj["new_value"] is True
        assert obj["new_value"] == items["new_value"]

        with self.frozen_violation_catcher("new_value"):
            obj.update(dict(new_value=True).items())
            assert obj["new_value"] is True
        with self.frozen_violation_catcher("new_value"):
            obj.update(**dict(new_value=False))
            assert obj["new_value"] is False
        with self.frozen_violation_catcher("new_value"):
            obj.update(dict(new_value=False), **dict(new_value=True))
            assert obj["new_value"] is True

    async def test_strange_slots_dict_interplay_exists_but_is_avoided(
        self,
    ) -> None:
        if not hasattr(self._type, "__slots__"):
            return

        try:

            class MisusedSubclass(self._type):
                __slots__ = ("attr_0", "attr_1", "__dict__")
                slots_types = dict(attr_0=int, attr_1=int)
        except TypeError:

            class MisusedSubclass(self._type):
                __slots__ = ("attr_0", "attr_1")
                slots_types = dict(attr_0=int, attr_1=int)

        ok_obj = MisusedSubclass(attr_0=0, attr_1=1)  # this is ok!
        assert "attr_0" not in ok_obj.__dict__
        assert "attr_1" not in ok_obj.__dict__
        assert 0 == ok_obj.attr_0
        assert 1 == ok_obj.attr_1

        ok_obj = MisusedSubclass()
        ok_obj.update(dict(attr_0=0, attr_1=1))  # this is ok!
        assert "attr_0" not in ok_obj.__dict__
        assert "attr_1" not in ok_obj.__dict__
        assert 0 == ok_obj.attr_0
        assert 1 == ok_obj.attr_1

        bad_obj = MisusedSubclass()
        bad_obj.__dict__.update(dict(attr_0=0, attr_1=1))  # this is bad
        # See: https://github.com/rmlibre/aiootp/pull/11
        assert "attr_0" in bad_obj.__dict__
        assert "attr_1" in bad_obj.__dict__
        assert not hasattr(bad_obj, "attr_0")
        assert not hasattr(bad_obj, "attr_1")
        problem = (  # fmt: skip
            "Very strange __dict__ / __slots__ interplay didn't manifest?"
        )
        with Ignore(AttributeError, if_else=violation(problem)):
            assert bad_obj.attr_0
        with Ignore(AttributeError, if_else=violation(problem)):
            assert bad_obj.attr_1


class BaseIndexableTests(BaseVariableHoldingClassTests):
    async def test_unmapped_attributes_arent_in_dir(self) -> None:
        obj = self._type(self._items)
        if not hasattr(obj, "_UNMAPPED_ATTRIBUTES"):
            return
        if all((type(item) is str) for item in self._items):
            assert not (
                set(obj.__class__._UNMAPPED_ATTRIBUTES).difference(
                    obj.__class__._MAPPED_ATTRIBUTES
                )
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

    async def test_frozen_state_is_enforced(self) -> None:
        problem = (  # fmt: skip
            "A mutation was allowed on a frozen object."
        )
        if not self._frozen:
            return

        obj = self._type(self._items)
        with Ignore(PermissionError, if_else=violation(problem)):
            obj.__init__(self._items)

        obj = self._type(self._items)
        for name, value in self._items.items():
            with Ignore(PermissionError, if_else=violation(problem)):
                obj[name] = value


class BaseTypedSubclassDefinitionsTests(BaseVariableHoldingClassTests):
    async def test_slots_contains_all_names_in_slots_types(
        self,
    ) -> None:
        problem = (  # fmt: skip
            "A type was created with a mismatch in variable declarations."
        )
        with Ignore(t.MissingDeclaredVariables, if_else=violation(problem)):

            class Subclass(self._type):
                __slots__ = ()
                slots_types = dict(swell=bool)

    async def test_slots_types_contains_all_names_in_slots(self) -> None:
        problem = (  # fmt: skip
            "A type was created with a mismatch in variable declarations."
        )
        with Ignore(t.MissingDeclaredVariables, if_else=violation(problem)):

            class Subclass(self._type):
                __slots__ = ("swell",)
                slots_types = {}

    async def test_declared_types_are_enforced(self) -> None:
        problem = (  # fmt: skip
            "A typed class didn't enforce a type in their `slots_types`."
        )
        obj = self._type()
        cls_set = set(obj.slots_types.values())

        for name, cls in sorted(
            obj.slots_types.items(), key=lambda _: csprng()
        ):
            wrong_cls = randoms.choice([*cls_set.difference({cls})])

            def is_vague_type(
                _: Ignore, name=name, cls=cls, wrong_cls=wrong_cls
            ) -> bool:
                error = AssertionError(
                    f"{problem=} : {name=} : {cls=} : {wrong_cls=}"
                )
                return issubclass(wrong_cls, cls) or raise_exception(error)

            with Ignore(TypeError, if_else=is_vague_type):
                obj[name] = wrong_cls()

    async def test_slots_types_correctly_allows_type_tuples(self) -> None:
        problem = (  # fmt: skip
            "A slotted value's type didn't match a type in its declared "
            "tuple of types."
        )
        assert tuples.BytesLike == (bytes, bytearray)

        class Subclass(self._type):
            __slots__ = ("bytes_like",)
            slots_types = dict(bytes_like=tuples.BytesLike)

        for acceptable_value in (b"test", bytearray(b"test")):
            ok_obj = Subclass()
            ok_obj.bytes_like = acceptable_value
            assert ok_obj.bytes_like == acceptable_value

            ok_obj = Subclass(bytes_like=acceptable_value)
            assert ok_obj.bytes_like == acceptable_value

        for unacceptable_value in ("test", list(b"test")):
            bad_obj = Subclass()
            with Ignore(TypeError, if_else=violation(problem)):
                bad_obj.bytes_like = unacceptable_value

            with Ignore(TypeError, if_else=violation(problem)):
                Subclass(bytes_like=unacceptable_value)


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


# Typed Slots


class TypedSlotsType(SlotsAttributes, TypedSlots):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)

    slots_types = {
        name: BaseVariableHoldingClassTests._items[name].__class__
        for name in BaseVariableHoldingClassTests._items
    }


class OpenTypedSlotsType(SlotsAttributes, OpenTypedSlots):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)

    slots_types = {
        name: BaseVariableHoldingClassTests._items[name].__class__
        for name in BaseVariableHoldingClassTests._items
    }


class FrozenTypedSlotsType(SlotsAttributes, FrozenTypedSlots):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)

    slots_types = {
        name: BaseVariableHoldingClassTests._items[name].__class__
        for name in BaseVariableHoldingClassTests._items
    }


class FrozenTypedSlotsDictType(NamespaceAttributes, FrozenTypedSlots):
    __slots__ = ("__dict__", *BaseVariableHoldingClassTests._items)

    slots_types = {
        name: BaseVariableHoldingClassTests._items[name].__class__
        for name in BaseVariableHoldingClassTests._items
    }


class OpenFrozenTypedSlotsType(SlotsAttributes, OpenFrozenTypedSlots):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)

    slots_types = {
        name: BaseVariableHoldingClassTests._items[name].__class__
        for name in BaseVariableHoldingClassTests._items
    }


class TestTypedSlots(
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseIndexableTests,
    BaseTypedSubclassDefinitionsTests,
):
    _type: type = TypedSlotsType
    _open: bool = False
    _frozen: bool = False


class TestOpenTypedSlots(
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseIndexableTests,
    BaseTypedSubclassDefinitionsTests,
):
    _type: type = OpenTypedSlotsType
    _open: bool = True
    _frozen: bool = False


class TestFrozenTypedSlots(
    BaseFrozenTests,
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseIndexableTests,
    BaseTypedSubclassDefinitionsTests,
):
    _type: type = FrozenTypedSlotsType
    _open: bool = False
    _frozen: bool = True


class TestFrozenTypedSlotsDict(
    BaseFrozenTests,
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseDictLikeTests,
    BaseIndexableTests,
    BaseTypedSubclassDefinitionsTests,
):
    _type: type = FrozenTypedSlotsDictType
    _open: bool = False
    _frozen: bool = True


class TestOpenFrozenTypedSlots(
    BaseFrozenTests,
    BaseReprControlledTests,
    BaseMaskableReprTests,
    BaseIndexableTests,
    BaseTypedSubclassDefinitionsTests,
):
    _type: type = OpenFrozenTypedSlotsType
    _open: bool = True
    _frozen: bool = True


# Configs


class ConfigType(SlotsAttributes, Config):
    __slots__ = tuple(BaseVariableHoldingClassTests._items)

    slots_types = {
        name: BaseVariableHoldingClassTests._items[name].__class__
        for name in BaseVariableHoldingClassTests._items
    }


class TestConfigType(
    BaseFrozenTests,
    BaseReprControlledTests,
    BaseIndexableTests,
    BaseTypedSubclassDefinitionsTests,
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
    BaseDictLikeTests,
    BaseIndexableTests,
):
    _type: type = OpenFrozenNamespaceType
    _open: bool = True
    _frozen: bool = True


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
