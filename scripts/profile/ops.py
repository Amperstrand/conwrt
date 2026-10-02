"""Structured UCI operations for transport-agnostic device configuration.

Each Op represents a single atomic configuration action. Operations are generated
by use cases and profile builders, then rendered to a target transport (SSH shell
or ubus HTTP) by a renderer.

Design inspired by pyinfra's command-object pattern: define WHAT to do, then
render HOW to send it.
"""
from __future__ import annotations

import re
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
class WriteFile:
    """Write a file on the target with the given content.

    Shell: heredoc (``cat > 'path' <<'OPENWRT_EOF'``) followed by ``chmod``.
    ubus:  not natively representable — mapped to a ``sys.exec`` fallback call.

    Used for artifacts that are not UCI (credentials files, ``.ovpn`` profiles,
    or on-device helper scripts). ``mode`` is an octal string (default ``600``).
    """

    path: str
    content: str
    mode: str = "600"


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


@dataclass
class Comment:
    """Shell comment line — for human readability in generated scripts.

    render_shell emits ``# {text}``. render_ubus silently skips.
    """

    text: str


@dataclass
class BlankLine:
    """Empty line separator — for human readability in generated scripts.

    render_shell emits a blank line. render_ubus silently skips.
    """


# Union of all operation types.
Op = Union[
    UciSet, UciAdd, UciDelete, UciAddList, UciCommit,
    ServiceAction, WriteFile, ShellCommand, Comment, BlankLine,
]


# -- WriteFile helpers ---------------------------------------------------------

_MODE_RE = re.compile(r"^[0-7]{3,4}$")


def _writefile_path(path: str) -> str:
    if not path.startswith("/"):
        raise ValueError(f"WriteFile path must be absolute, got: {path!r}")
    if "'" in path or any(c in path for c in "\n\r\x00"):
        raise ValueError(f"WriteFile path contains unsafe characters: {path!r}")
    return path


def _writefile_mode(mode: str) -> str:
    if not _MODE_RE.fullmatch(mode):
        raise ValueError(f"WriteFile mode must be octal (e.g. '600'), got: {mode!r}")
    return mode


def _heredoc_delimiter(content: str) -> str:
    base = "OPENWRT_EOF"
    delim = base
    existing = set(content.splitlines())
    i = 0
    while delim in existing:
        i += 1
        delim = f"{base}_{i}"
    return delim


def render_writefile(op: "WriteFile") -> str:
    """Render a WriteFile op to a shell heredoc + chmod snippet."""
    from shell_safe import sh_quote

    path = _writefile_path(op.path)
    mode = _writefile_mode(op.mode)
    delim = _heredoc_delimiter(op.content)
    body = op.content if op.content.endswith("\n") else op.content + "\n"
    return (
        f"cat > {sh_quote(path)} <<'{delim}'\n"
        f"{body}{delim}\n"
        f"chmod {mode} {path}"
    )



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

        elif isinstance(op, WriteFile):
            lines.append(render_writefile(op))

        elif isinstance(op, ShellCommand):
            lines.append(op.command)

        elif isinstance(op, Comment):
            lines.append(f"# {op.text}")

        elif isinstance(op, BlankLine):
            lines.append("")

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

        elif isinstance(op, WriteFile):
            calls.append(RpcCall(
                object_name="exec",
                method="command",
                params={"command": render_writefile(op), "fallback": True},
            ))

        elif isinstance(op, ShellCommand):
            calls.append(RpcCall(
                object_name="exec",
                method="command",
                params={"command": op.command, "fallback": True},
            ))

    return calls
