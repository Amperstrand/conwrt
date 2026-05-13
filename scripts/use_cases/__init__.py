"""Use case presets for conwrt.

Each use case is a module in this package that defines:
  NAME        - str, unique identifier (e.g. "android-tether")
  DESCRIPTION - str, one-line human description
  PACKAGES    - list[str], packages to add to the ASU image build
  PACKAGES_REMOVE - list[str], packages to remove (e.g. conflicting wpad variants)
  PARAMS      - dict[str, ParamDef], accepted configuration parameters
  build_defaults(params) -> str, returns shell script lines for first-boot

Usage:
    from use_cases import registry
    for uc in registry.values():
        print(uc.NAME, uc.PACKAGES)
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class ParamDef:
    """Definition of a use-case configuration parameter."""
    type: type = str
    default: Any = None
    required: bool = False
    description: str = ""


@dataclass
class UseCase:
    """A registered use case preset."""
    name: str
    description: str
    packages: list[str] = field(default_factory=list)
    packages_remove: list[str] = field(default_factory=list)
    params: dict[str, ParamDef] = field(default_factory=dict)
    build_defaults: Callable[[dict[str, Any]], str] = field(default=lambda _: "")


_registry: dict[str, UseCase] = {}


def register(uc: UseCase) -> None:
    _registry[uc.name] = uc


def registry() -> dict[str, UseCase]:
    if not _registry:
        _discover()
    return dict(_registry)


def get(name: str) -> Optional[UseCase]:
    return registry().get(name)


def apply_defaults(name: str, user_params: dict[str, Any]) -> dict[str, Any]:
    uc = get(name)
    if uc is None:
        raise ValueError(f"Unknown use case: {name}")
    merged: dict[str, Any] = {}
    for pname, pdef in uc.params.items():
        if pname in user_params:
            merged[pname] = user_params[pname]
        elif pdef.required:
            raise ValueError(f"Use case '{name}' requires param '{pname}': {pdef.description}")
        elif pdef.default is not None:
            merged[pname] = pdef.default
    return merged


def _discover() -> None:
    package_dir = __path__
    for _importer, modname, _ispkg in pkgutil.iter_modules(package_dir):
        if modname.startswith("_"):
            continue
        importlib.import_module(f".{modname}", __package__)
