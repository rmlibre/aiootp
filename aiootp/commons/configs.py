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


"""
Utilities for creating & managing immutable configurations.
"""

__all__ = ["Config", "ConfigMap"]


from aiootp._typing import Typing as t
from aiootp._constants import CONFIG_ID, CONFIG_TYPE
from aiootp._exceptions import Issue

from .typed_slots import OpenFrozenTypedSlots
from .namespaces import OpenFrozenNamespace


class Config(OpenFrozenTypedSlots):
    """
    Creates frozen instances for caching static settings. This
    facilitates highly configurable objects with declarative, structured
    composition instead of deep class hierarchies. The cacheability
    improves runtime performance, while also allowing configuration to
    be defined with data, separating setup logic from object behavior.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp.commons.configs import Config, ConfigMap

    class CalculatorConfig(Config):
        __slots__ = ("UNIT_SYSTEM", "LANGUAGE")

        slots_types = dict(UNIT_SYSTEM=str, LANGUAGE=str)

        def __init__(self, *, unit_system: str, language: str) -> None:
            self.UNIT_SYSTEM = unit_system
            self.LANGUAGE = language

    class Calculator:
        __slots__ = ("config",)

        _configs = ConfigMap(
            english_us=CalculatorConfig(
                unit_system="imperial", language="english"
            ),
            english_uk=CalculatorConfig(
                unit_system="metric", language="english"
            ),
            config_type=CalculatorConfig,
        )

        def __init__(self, *, config_id: typing.Hashable) -> None:
            self.config = self._configs[config_id]

    calculator = Calculator(config_id="english_us")
    """

    __slots__ = (CONFIG_ID,)

    slots_types: t.Mapping[str, t.Any] = dict(CONFIG_ID=t.Hashable)

    def __setitem__(self, name: str, value: t.Any, /) -> None:
        """
        Validates the type of the `value` based on the class' type
        definition of the `name` attribute. Sets the attribute if the
        type is correct.
        """
        if name == CONFIG_ID:
            self.set_config_id(value)
        else:
            super().__setitem__(name, value)

    def set_config_id(self, config_id: t.Hashable, /) -> None:
        """
        Gives the instance knowledge of its own `config_id` reference
        that's used by configuration trackers like `ConfigMap`.
        """
        self._validate_type(CONFIG_ID, config_id)
        if not hasattr(self, CONFIG_ID):
            object.__setattr__(self, CONFIG_ID, config_id)
        elif config_id != self.CONFIG_ID:
            raise Issue.value_must(
                f"{config_id=}", f"match {self.CONFIG_ID=}"
            )


class ConfigMap(OpenFrozenNamespace):
    """
    A container type which is the interface to predefined settings that
    are referenced by configuration IDs. This facilitates highly
    configurable objects with declarative, structured composition
    instead of deep class hierarchies. The cacheability improves runtime
    performance, while also allowing configuration to be defined with
    data, separating setup logic from object behavior.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp.commons.configs import Config, ConfigMap

    class CalculatorConfig(Config):
        __slots__ = ("UNIT_SYSTEM", "LANGUAGE")

        slots_types = dict(UNIT_SYSTEM=str, LANGUAGE=str)

        _UNIT_SYSTEMS = unit_translation_repository()
        _LANGUAGES = language_repository()

        def __init__(self, *, unit_system: str, language: str) -> None:
            self.UNIT_SYSTEM = self._UNIT_SYSTEMS[unit_system]
            self.LANGUAGE = self._LANGUAGES[language]

    class Calculator:
        __slots__ = ("config",)

        _configs = ConfigMap(
            english_us=CalculatorConfig(
                unit_system="imperial", language="english"
            ),
            english_uk=CalculatorConfig(
                unit_system="metric", language="english"
            ),
            config_type=CalculatorConfig,
        )

        def __init__(self, *, config_id: typing.Hashable) -> None:
            self.config = self._configs[config_id]

    calculator = Calculator(config_id="english_us")
    """

    __slots__ = (CONFIG_TYPE,)

    _UNMAPPED_ATTRIBUTES: t.Tuple[str] = (
        *OpenFrozenNamespace._UNMAPPED_ATTRIBUTES,
        CONFIG_TYPE,
    )

    def __init__(
        self,
        /,
        mapping: t.Mapping[t.Hashable, t.ConfigType] = {},
        *,
        config_type: type,
        **kw: t.Any,
    ) -> None:
        """
        Defines the configurations to be stored in the instance from the
        provided mappings of config IDs to config objects.
        """
        if not issubclass(config_type, Config):
            raise Issue.value_must_be_subtype(f"{config_type=}", Config)
        object.__setattr__(self, CONFIG_TYPE, config_type)
        super().__init__(mapping, **kw)

    def __setitem__(
        self, config_id: t.Hashable, config: t.ConfigType, /
    ) -> None:
        """
        Sets a `config` by its `config_id` reference. If the `config_id`
        is already in the instance & the `config` isn't the same object,
        then `PermissionError` is raised.
        """
        config.set_config_id(config_id)
        if not issubclass(config.__class__, self.CONFIG_TYPE):
            raise Issue.value_must_be_type("config", self.CONFIG_TYPE)
        elif config_id in self and self[config_id] is not config:
            raise Issue.cant_reassign_attribute(f"{config_id=}")
        if config_id.__class__ is str:
            object.__setattr__(self, config_id, config)
        else:
            self.__dict__[config_id] = config


module_api = dict(
    Config=t.add_type(Config),
    ConfigMap=t.add_type(ConfigMap),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
