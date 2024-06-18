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


class ExampleType:
    pass


class FalseConfig:

    def set_config_id(self, config_id: t.Hashable) -> None:
        self.CONFIG_ID = config_id


class TestConfig:
    types_tested = (int, str, bytes, list, dict, ExampleType)
    uncheckable_types = (t.List[int], t.PositiveRealNumber)

    def test_slots_types_enforces_types(self) -> None:
        problem = (
            "A mismatch between an attribute type & a `slot_types` "
            "delcaration was allowed."
        )
        for declaration in self.types_tested:
            class ExampleConfig(Config):
                __slots__ = ("VAR",)
                slots_types = dict(VAR=declaration)
                def __init__(self, *, var: declaration) -> None:
                    self.VAR = var

            for attr_type in set(self.types_tested).difference([declaration]):
                with Ignore(TypeError, if_else=violation(problem)):
                    config = ExampleConfig(var=attr_type)

    def test_runtime_uncheckable_types_are_detected(self) -> None:
        problem = (
            "A runtime-uncheckable type declaration didn't proc an error."
        )
        for declaration in self.uncheckable_types:
            with Ignore(TypeUncheckableAtRuntime, if_else=violation(problem)):
                class ExampleConfig(Config):
                    __slots__ = ("VAR",)
                    slots_types = dict(VAR=declaration)
                    def __init__(self, *, var: declaration) -> None:
                        self.VAR = var


class TestConfigMap:

    def test_mapping_registers_config_by_id(
        self, mapping: ConfigMap
    ) -> None:
        for config_id in ("one", b"one", 1):
            config = ExampleConfig(number=420, string="word")

            mapping[config_id] = config
            assert config_id == config.CONFIG_ID
            assert config is mapping[config_id]

    def test_config_id_cannot_change(
        self, config: t.ConfigType, mapping: ConfigMap
    ) -> None:
        problem = (
            "config_id changed without error."
        )
        config_id = 1
        mapping[config_id] = config
        with Ignore(ValueError, if_else=violation(problem)):
            config.CONFIG_ID = 2

        assert config.CONFIG_ID == 1

    def test_config_must_be_config_subclass(
        self, config: t.ConfigType, mapping: ConfigMap
    ) -> None:
        problem = (
            "non-`Config` subclass was allowed to be registered."
        )
        config_id = 1
        with Ignore(TypeError, if_else=violation(problem)):
            ConfigMap(config_type=FalseConfig)
        with Ignore(TypeError, if_else=violation(problem)):
            mapping[config_id] = FalseConfig()

    def test_cannot_be_reassigned(
        self, config: t.ConfigType, mapping: ConfigMap
    ) -> None:
        problem = (
            "a config was allowed to be reassigned to the map."
        )
        config_id = 1
        mapping[config_id] = config
        with Ignore(PermissionError, if_else=violation(problem)):
            mapping[config_id] = ExampleConfig(number=111, string="abd")

    def test_reassigning_doesnt_throw_when_same_object(
        self, config: t.ConfigType, mapping: ConfigMap
    ) -> None:
        config_id = 1
        mapping[config_id] = config
        mapping[config_id] = config


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

