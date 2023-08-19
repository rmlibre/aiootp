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


IDENTIFIER_ITEMS = {"a": 0, "b": 1}
NON_IDENTIFIER_ITEMS = {0: "a", 1: "b"}


class SlotsExample(Slots):
    __slots__ = ("a", "b")

    class_variable: Typing.Any = "accessible"
    ITEMS = IDENTIFIER_ITEMS

    async def aiter(self):
        return [name async for name in self]


class OpenNamespaceExample(OpenNamespace):

    class_variable: Typing.Any = "accessible"
    ITEMS = IDENTIFIER_ITEMS

    async def aiter(self):
        return [name async for name in self]


async def dunder_tests(cls, obj):
    assert len(obj) == len(cls.ITEMS)
    assert len(obj) == sum(1 for name in obj)
    assert len(obj) == sum(1 for name in await obj.aiter())
    assert dir(obj) == list(cls.ITEMS)
    assert dir(obj) == [*obj]
    assert dir(obj) == [*obj.keys()]
    assert dir(obj) == await obj.aiter()
    assert all((key in obj) for key in cls.ITEMS)
    assert all((key not in cls()) for key in cls.ITEMS)
    for name, value in cls.ITEMS.items():
        assert name in obj
        if type(name) is str:
            assert getattr(obj, name) == value
        assert obj[name] == value
        del obj[name]
        assert name not in obj
        obj[name] = 2 * value
        if type(name) is str:
            assert getattr(obj, name) == 2 * value
        assert obj[name] == 2 * value
    assert [obj[name] for name in obj] == [*obj.values()]
    assert [(name, obj[name]) for name in obj] == [*obj.items()]
    assert all(
        (str(name) in obj.__repr__(mask=False) and str(obj[name]) in obj.__repr__(mask=False))
        for name in obj
    )
    assert all(
        (str(name) in obj.__repr__(mask=True) and str(obj[name]) not in obj.__repr__(mask=True))
        for name in obj
    )
    # debug mode toggles value viewability on and off
    if not issubclass(cls, OpenNamespace):
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
    if hasattr(obj, "__all__"):
        assert [*obj.__dict__] == obj.__all__
        obj._private = True
        assert [*obj.__dict__] != obj.__all__
        assert "_private" not in obj.__all__
        assert "_private" in obj.__dict__
    assert obj["class_variable"] == "accessible"
    assert obj
    for name in [*obj]:
        del obj[name]
    assert not obj


class TestSlots:
    async def test_dunders(self):
        """
        Default Slots dunder methods don't fail when used.
        """
        cls = SlotsExample
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

