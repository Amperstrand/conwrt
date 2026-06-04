"""Use case presets for conwrt.

Each use case module defines:
  name, description, packages, packages_remove, params
  build_configure(params) -> shell script
  packages_via, configure_via, test_status
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional

PackageDelivery = Literal["image", "opkg", "auto"]
ConfigureDelivery = Literal["firstboot", "ssh", "both"]
TestStatus = Literal["tested", "experimental", "untested"]


def _empty_configure(_: dict[str, Any]) -> str:
    return ""


@dataclass
class ParamDef:
    """Definition of a use-case configuration parameter."""
    type: type = str
    default: Any = None
    required: bool = False
    description: str = ""
    choices: tuple[Any, ...] | None = None
    min_value: int | None = None
    max_value: int | None = None
    allow_empty: bool = True


@dataclass
class UseCase:
    name: str
    description: str
    packages: list[str] = field(default_factory=list)
    packages_remove: list[str] = field(default_factory=list)
    params: dict[str, ParamDef] = field(default_factory=dict)
    build_configure: Callable[[dict[str, Any]], str] = field(default=_empty_configure)
    build_configure_ops: Optional[Callable[[dict[str, Any]], list]] = None
    packages_via: PackageDelivery = "auto"
    configure_via: ConfigureDelivery = "both"
    test_status: TestStatus = "untested"
    tested_notes: str = ""
    post_install_notes: str = ""
    requires_capabilities: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.build_configure_ops is not None and self.build_configure is _empty_configure:
            from profile.ops import render_shell

            _ops_fn = self.build_configure_ops
            self.build_configure = lambda params: render_shell(_ops_fn(params))

_registry: dict[str, UseCase] = {}
_discovered: bool = False


def register(uc: UseCase) -> None:
    _registry[uc.name] = uc


def registry() -> dict[str, UseCase]:
    global _discovered
    if not _discovered:
        _discover()
        _discovered = True
    return dict(_registry)


def get(name: str) -> Optional[UseCase]:
    return registry().get(name)


def apply_defaults(name: str, user_params: dict[str, Any]) -> dict[str, Any]:
    uc = get(name)
    if uc is None:
        raise ValueError(f"Unknown use case: {name}")
    unknown = sorted(set(user_params) - set(uc.params))
    if unknown:
        allowed = ", ".join(sorted(uc.params))
        raise ValueError(f"Use case '{name}' has unknown param(s): {', '.join(unknown)}. Allowed: {allowed}")
    merged: dict[str, Any] = {}
    for pname, pdef in uc.params.items():
        if pname in user_params:
            value = user_params[pname]
        elif pdef.required:
            raise ValueError(f"Use case '{name}' requires param '{pname}': {pdef.description}")
        elif pdef.default is not None:
            value = pdef.default
        else:
            continue
        merged[pname] = _validate_param(name, pname, pdef, value)
    return merged


def _validate_param(name: str, pname: str, pdef: ParamDef, value: Any) -> Any:
    expected = pdef.type
    if expected is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"Use case '{name}' param '{pname}' must be int")
        if pdef.min_value is not None and value < pdef.min_value:
            raise ValueError(f"Use case '{name}' param '{pname}' must be >= {pdef.min_value}")
        if pdef.max_value is not None and value > pdef.max_value:
            raise ValueError(f"Use case '{name}' param '{pname}' must be <= {pdef.max_value}")
    elif not isinstance(value, expected):
        raise TypeError(f"Use case '{name}' param '{pname}' must be {expected.__name__}")
    if isinstance(value, str) and not pdef.allow_empty and value == "":
        raise ValueError(f"Use case '{name}' param '{pname}' must not be empty")
    if pdef.choices is not None and value not in pdef.choices:
        choices = ", ".join(str(v) for v in pdef.choices)
        raise ValueError(f"Use case '{name}' param '{pname}' must be one of: {choices}")
    return value


def _discover() -> None:
    package_dir = __path__
    for _importer, modname, _ispkg in pkgutil.iter_modules(package_dir):
        if modname.startswith("_"):
            continue
        importlib.import_module(f".{modname}", __package__)
