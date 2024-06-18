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


__all__ = ["Config", "ConfigMap"]


__doc__ = "Utilities for creating & managing immutable configurations."


from aiootp._typing import Typing as t
from aiootp._constants import CONFIG_ID, CONFIG_TYPE
from aiootp._exceptions import Issue, TypeUncheckableAtRuntime
from aiootp._exceptions import raise_exception

from .slots import OpenFrozenSlots
from .namespaces import OpenFrozenNamespace


class Config(OpenFrozenSlots):
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

    from aiootp.commons import Config, ConfigMap

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

    @classmethod
    def _make_frozen_class_slots_types_container(
        cls, slots_types: t.Mapping[str, type], /
    ) -> OpenFrozenSlots:
        """
        Creates a class-specific type to govern type correctness.
        """
        cls_name = f"{cls.__qualname__}SlotsTypes"
        cls_dict = dict(
            __slots__=tuple(sorted(slots_types)),
            __module__=__name__,
        )
        container = type(cls_name, (OpenFrozenSlots,), cls_dict)
        return container(**slots_types)

    @classmethod
    def _make_frozen_class_slots_types(cls, /) -> OpenFrozenSlots:
        """
        Creates & populates a class-specific type to govern type
        correctness.
        """
        slots_types = {}
        for base in reversed(cls.__mro__):
            if not issubclass(base, Config):
                continue
            for name, value in base.slots_types.items():
                try:
                    isinstance(value, value)
                except TypeError as error:
                    raise TypeUncheckableAtRuntime(name, value) from error
                slots_types[name] = value
        return cls._make_frozen_class_slots_types_container(slots_types)

    def __init_subclass__(cls, /, *a, **kw) -> None:
        """
        Installs a prepared an class-specific type to govern type
        correctness to all subclasses.
        """
        cls.slots_types = cls._make_frozen_class_slots_types()

    def _validate_type(self, name: str, value: t.Any, /) -> None:
        """
        Validates the type of the `value` based on the class' type
        definition of the `name` attribute.
        """
        value_type = getattr(self.slots_types, name)
        value_is_compliant_type = isinstance(value, value_type)
        if not value_is_compliant_type:
            raise Issue.value_must_be_type(name, value_type)

    def __setattr__(self, name: str, value: t.Any, /) -> None:
        """
        Validates the type of the `value` based on the class' type
        definition of the `name` attribute. Sets the attribute if the
        type is correct.
        """
        if name == CONFIG_ID:
            self.set_config_id(value)
        else:
            self._validate_type(name, value)
            super().__setattr__(name, value)

    def set_config_id(self, config_id: t.Hashable, /) -> None:
        """
        Gives the instance knowledge of its own `config_id` reference
        that's used by configuration trackers like `ConfigMap`.
        """
        self._validate_type(CONFIG_ID, config_id)
        if not hasattr(self, CONFIG_ID):
            object.__setattr__(self, CONFIG_ID, config_id)
        elif config_id != self.CONFIG_ID:
            raise Issue.value_must(f"{config_id=}", f"{self.CONFIG_ID=}")


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

    from aiootp.commons import Config, ConfigMap

    class CalculatorConfig(Config):
        __slots__ = ("UNIT_SYSTEM", "LANGUAGE")

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
        *OpenFrozenNamespace._UNMAPPED_ATTRIBUTES, CONFIG_TYPE
    )

    def __init__(
        self,
        /,
        mapping: t.Mapping[t.Hashable, t.Any] = {},
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
        setattr(self, CONFIG_TYPE, config_type)
        for config_id, config in {**mapping, **kw}.items():
            self[config_id] = config

    def __setitem__(self, config_id: t.Hashable, config: t.Any, /) -> None:
        """
        Sets a `config` by its `config_id` reference. If the `config_id`
        is already in the instance, then `PermissionError` is raised.
        """
        config.set_config_id(config_id)
        if not issubclass(config.__class__, self.CONFIG_TYPE):
            raise Issue.value_must_be_type("config", self.CONFIG_TYPE)
        elif config_id in self and self[config_id] is not config:
            raise Issue.cant_reassign_attribute(f"{config_id=}")
        if config_id.__class__ is str:
            setattr(self, config_id, config)
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

