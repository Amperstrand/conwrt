"""Flows — composite, multi-step, router-aware deployment recipes.

A Flow sequences Steps (flash, WiFi uplink, package install, apply a use case)
that together deploy a feature like net4sats onto a router. Each Step is
declarative data; ``flows/render`` renders a flow to a host shell script or
Markdown for a given target profile (model + version) and the user's filled
params. The same flow drives live execution, the generated script, the
Markdown, and the web wizard — one source of truth, four targets.
"""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Any

from use_cases import ParamDef  # reuse the same param definition type (DRY)


@dataclass
class Step:
    kind: str
    title: str
    detail: str = ""
    package: str = ""
    version: str = ""
    channel: str = ""
    artifact_url: str = ""
    artifact_urls: dict[str, str] = field(default_factory=dict)
    band: str = ""
    ssid_param: str = ""
    key_param: str = ""
    encryption: str = "psk2"
    use_case: str = ""
    use_case_params: dict[str, Any] = field(default_factory=dict)
    password: str = ""
    hostname: str = ""


@dataclass
class Flow:
    name: str
    description: str
    params: dict[str, ParamDef] = field(default_factory=dict)
    steps: list[Step] = field(default_factory=list)


_registry: dict[str, Flow] = {}
_discovered: bool = False


def register(flow: Flow) -> None:
    _registry[flow.name] = flow


def registry() -> dict[str, Flow]:
    global _discovered
    if not _discovered:
        for _importer, modname, _ispkg in pkgutil.iter_modules(__path__):
            if not modname.startswith("_"):
                importlib.import_module(f".{modname}", __package__)
        _discovered = True
    return dict(_registry)


def get(name: str) -> Flow | None:
    return registry().get(name)
