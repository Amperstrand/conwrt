"""Composable add-ons — optional extras stacked on top of a flow.

Each add-on is a small, self-contained capability (set a password, rename the
host, open WAN SSH) with its own params. The CLI (``--addon``) and the web
wizard let the user toggle any combination; selected add-ons are appended to the
flow's steps and render to every target. Add-ons are independent and stack.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from use_cases import ParamDef

from . import Step


@dataclass
class AddOn:
    name: str
    title: str
    description: str
    params: dict[str, ParamDef] = field(default_factory=dict)
    build_step: Optional[Callable[[dict], Step]] = None


_REGISTRY: dict[str, AddOn] = {}


def register(addon: AddOn) -> None:
    _REGISTRY[addon.name] = addon


def registry() -> dict[str, AddOn]:
    return dict(_REGISTRY)


def get(name: str) -> AddOn | None:
    return _REGISTRY.get(name)


register(AddOn(
    name="random-password",
    title="Set a random root password",
    description="Generate a random 16-char root password and print it once.",
    build_step=lambda p: Step(kind="password", title="Set a random root password"),
))

register(AddOn(
    name="set-password",
    title="Set a specific root password",
    description="Set the root password to a value you choose.",
    params={"root_password": ParamDef(type=str, required=True, allow_empty=False,
                                      description="The root password to set")},
    build_step=lambda p: Step(kind="set_password", title="Set root password",
                              password=p.get("root_password", "")),
))

register(AddOn(
    name="hostname",
    title="Set the router hostname",
    description="Rename the router (e.g. to 'net4sats').",
    params={"hostname": ParamDef(type=str, required=True, allow_empty=False,
                                 description="The hostname to set")},
    build_step=lambda p: Step(kind="hostname", title="Set hostname",
                              hostname=p.get("hostname", "")),
))

register(AddOn(
    name="wan-ssh",
    title="Enable SSH on the WAN port",
    description="Open port 22 on the WAN firewall zone so the router is reachable from upstream.",
    build_step=lambda p: Step(kind="wan_ssh", title="Enable SSH on WAN"),
))
