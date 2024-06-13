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


class TestTypingClass:

    async def test_added_type_names_must_have_valid_identifiers(
        self
    ) -> None:
        problem = (
            "A type with non-identifier name was allowed to be registered."
        )
        NonIdentifierNamedType = type("123Type", (), {})
        with Ignore(ValueError, if_else=violation(problem)):
            t.add_type(NonIdentifierNamedType)

    async def test_cant_register_type_more_than_once(
        self
    ) -> None:
        problem = (
            "A type was registered more than once."
        )
        with Ignore(AttributeError, if_else=violation(problem)):
            t.add_type(Domains)

    async def test_mixed_case_type_cant_be_registered(
        self
    ) -> None:
        problem = (
            "A mixed-case type was registered."
        )
        Mixed_Case_Type = type("Mixed_Case_Type", (), {})
        with Ignore(ValueError, if_else=violation(problem)):
            t.add_type(Mixed_Case_Type)

    async def test_non_capitalized_type_cant_be_registered(
        self
    ) -> None:
        problem = (
            "A non-capitalized type was registered."
        )
        nonCapitalizedType = type("nonCapitalizedType", (), {})
        with Ignore(ValueError, if_else=violation(problem)):
            t.add_type(nonCapitalizedType)

    async def test_non_class_object_cant_be_registered(
        self
    ) -> None:
        problem = (
            "A non-class object was registered."
        )
        non_class_objects = (
            1, 1.1, None, "test", b"test", [], {}, t.PositiveRealNumber
        )
        errors = (AttributeError, ValueError, TypeError)
        for obj in non_class_objects:
            with Ignore(*errors, if_else=violation(problem)):
                t.add_type(obj)


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

