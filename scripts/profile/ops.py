"""Structured UCI operations for transport-agnostic device configuration.

Each Op represents a single atomic configuration action. Operations are generated
by use cases and profile builders, then rendered to a target transport (SSH shell
or ubus HTTP) by a renderer.

Design inspired by pyinfra's command-object pattern: define WHAT to do, then
render HOW to send it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

# -- Op types ------------------------------------------------------------------

# Values can be a single string or a list of strings (for UCI list options).
# When a list is used, the shell renderer emits `uci add_list` calls;
# the ubus renderer sends arrays.
OpValue = Union[str, list[str]]


@dataclass
class UciSet:
    """Set one or more options on an existing UCI section.

    Shell: ``uci set {config}.{section}.{key}='{value}'``
    ubus:  ``uci.set {{config, section, values}}``
    """

    config: str
    section: str
    values: dict[str, OpValue] = field(default_factory=dict)


@dataclass
class UciAdd:
    """Add a new anonymous or named UCI section with initial values.

    Shell: ``uci add {config} {type}`` then ``uci set {config}.@{type}[-1].{key}='{value}'``
    ubus:  ``uci.add {{config, type, name?, values}}``
    """

    config: str
    type: str
    name: str = ""
    values: dict[str, OpValue] = field(default_factory=dict)


@dataclass
class UciDelete:
    """Delete a UCI section or a specific option within a section.

    Shell: ``uci delete {config}.{section}`` or ``uci delete {config}.{section}.{option}``
    ubus:  ``uci.delete {{config, section, option?}}``
    """

    config: str
    section: str
    option: str = ""


@dataclass
class UciAddList:
    """Append a value to a UCI list option.

    Shell: ``uci add_list {config}.{section}.{option}='{value}'``
    ubus:  ``uci.set {{config, section, values: {{option: [value]}}}}``
    """

    config: str
    section: str
    option: str
    value: str


@dataclass
class UciCommit:
    """Commit pending UCI changes for a config.

    Shell: ``uci commit {config}``
    ubus:  ``uci.commit {{config}}``
    """

    config: str


@dataclass
class ServiceAction:
    """Start, stop, restart, reload, enable, or disable an init.d service.

    Shell: ``/etc/init.d/{name} {action}``
    ubus:  ``rc.init {{name, action}}``
    """

    name: str
    action: str  # "start", "stop", "restart", "reload", "enable", "disable"


@dataclass
class ShellCommand:
    """Escape hatch for operations that cannot be expressed as UCI.

    Only rendered to shell. Not available via ubus transport.
    Use sparingly — prefer typed ops for testability and transport independence.
    """

    command: str


# Union of all operation types.
Op = Union[UciSet, UciAdd, UciDelete, UciAddList, UciCommit, ServiceAction, ShellCommand]


# -- Shell renderer ------------------------------------------------------------

def render_shell(ops: list[Op]) -> str:
    """Render a list of structured operations to a shell script.

    Produces the same output that conwrt currently generates via raw f-strings,
    so the transition from string-based to op-based generation is byte-for-byte
    identical for the shell transport.

    Uses single-quote escaping (sh_quote style) for values.
    """
    from shell_safe import sh_quote

    lines: list[str] = []
    for op in ops:
        if isinstance(op, UciSet):
            for key, val in op.values.items():
                if isinstance(val, list):
                    for item in val:
                        lines.append(f"uci add_list {op.config}.{op.section}.{key}={sh_quote(item)}")
                else:
                    lines.append(f"uci set {op.config}.{op.section}.{key}={sh_quote(val)}")

        elif isinstance(op, UciAdd):
            lines.append(f"uci add {op.config} {op.type}")
            ref = f"@{op.type}[-1]"
            if op.name:
                lines.append(f"uci set {op.config}.{ref}.name={sh_quote(op.name)}")
            for key, val in op.values.items():
                if isinstance(val, list):
                    for item in val:
                        lines.append(f"uci add_list {op.config}.{ref}.{key}={sh_quote(item)}")
                else:
                    lines.append(f"uci set {op.config}.{ref}.{key}={sh_quote(val)}")

        elif isinstance(op, UciDelete):
            if op.option:
                lines.append(f"uci delete {op.config}.{op.section}.{op.option}")
            else:
                lines.append(f"uci delete {op.config}.{op.section}")

        elif isinstance(op, UciAddList):
            lines.append(f"uci add_list {op.config}.{op.section}.{op.option}={sh_quote(op.value)}")

        elif isinstance(op, UciCommit):
            lines.append(f"uci commit {op.config}")

        elif isinstance(op, ServiceAction):
            lines.append(f"/etc/init.d/{op.name} {op.action}")

        elif isinstance(op, ShellCommand):
            lines.append(op.command)

    return "\n".join(lines)


# -- ubus RPC call representation ------------------------------------------------

@dataclass
class RpcCall:
    object_name: str
    method: str
    params: dict


# -- ubus renderer ---------------------------------------------------------------

def render_ubus(ops: list[Op]) -> list[RpcCall]:
    """Render a list of structured operations to ubus RPC calls.

    Each typed op maps to a ubus uci.* or rc.* call.
    ShellCommand ops map to a sys.exec call (requires rpcd exec plugin)
    and are tagged with ``fallback=True`` so the transport layer can
    decide whether to skip or execute them.
    """
    calls: list[RpcCall] = []
    for op in ops:
        if isinstance(op, UciSet):
            calls.append(RpcCall(
                object_name="uci",
                method="set",
                params={"config": op.config, "section": op.section, "values": dict(op.values)},
            ))

        elif isinstance(op, UciAdd):
            params: dict = {"config": op.config, "type": op.type}
            if op.name:
                params["name"] = op.name
            if op.values:
                params["values"] = dict(op.values)
            calls.append(RpcCall(object_name="uci", method="add", params=params))

        elif isinstance(op, UciDelete):
            params = {"config": op.config, "section": op.section}
            if op.option:
                params["option"] = op.option
            calls.append(RpcCall(object_name="uci", method="delete", params=params))

        elif isinstance(op, UciAddList):
            calls.append(RpcCall(
                object_name="uci",
                method="set",
                params={
                    "config": op.config,
                    "section": op.section,
                    "values": {op.option: [op.value]},
                },
            ))

        elif isinstance(op, UciCommit):
            calls.append(RpcCall(
                object_name="uci",
                method="commit",
                params={"config": op.config},
            ))

        elif isinstance(op, ServiceAction):
            calls.append(RpcCall(
                object_name="rc",
                method=op.action,
                params={"name": op.name},
            ))

        elif isinstance(op, ShellCommand):
            calls.append(RpcCall(
                object_name="exec",
                method="command",
                params={"command": op.command, "fallback": True},
            ))

    return calls
