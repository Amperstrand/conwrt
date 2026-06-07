"""Shared UCI shell helpers for idempotent OpenWrt configuration.

These helpers generate shell snippets that safely clean up stale UCI sections
and modify firewall zone membership by name (not index). They are the single
source of truth for these patterns — all use cases and profile builders should
call these instead of hand-rolling shell loops.

Two forms are provided for each helper:
  - ``*_sh()`` returns a raw shell string (for embedding in larger scripts)
  - ``*()`` returns a ``ShellCommand`` op (for the ops pipeline)
"""
from __future__ import annotations

from profile.ops import ShellCommand


def uci_cleanup_sections_sh(config: str, match_pattern: str) -> str:
    """Shell snippet: while-loop cleanup of stale UCI sections matching pattern.

    Finds all sections in *config* where ``uci show`` matches *match_pattern*,
    deletes them one by one until none remain. Idempotent — safe to run on
    every configure invocation.

    Args:
        config: UCI config name (e.g. ``"firewall"``, ``"wireless"``).
        match_pattern: Grep pattern to match (e.g. ``"name='vpn'"``).
    """
    return (
        f"while uci show {config} 2>/dev/null | grep -q \"{match_pattern}\"; do"
        f" _s=$(uci show {config} 2>/dev/null | grep \"{match_pattern}\""
        f" | head -1 | cut -d. -f2 | cut -d= -f1);"
        f" uci delete \"{config}.$_s\" 2>/dev/null;"
        f" done; true"
    )


def uci_cleanup_sections(config: str, match_pattern: str) -> ShellCommand:
    """ShellCommand: while-loop cleanup of stale UCI sections matching pattern."""
    return ShellCommand(command=uci_cleanup_sections_sh(config, match_pattern))


def uci_add_to_wan_zone_sh(iface: str) -> str:
    """Shell snippet: find wan zone by name, del_list then add_list (idempotent).

    Iterates firewall zones by ``name`` attribute (not by index), removes the
    interface from the wan zone's ``network`` list if present, then adds it.
    This prevents accumulation across reconfigure runs.
    """
    return (
        f"for _z in $(uci show firewall 2>/dev/null | grep '=zone'"
        f" | cut -d. -f2 | cut -d= -f1 || true); do"
        f" [ \"$(uci -q get firewall.$_z.name)\" = 'wan' ] &&"
        f" uci del_list firewall.$_z.network='{iface}' 2>/dev/null;"
        f" uci add_list firewall.$_z.network='{iface}';"
        f" break; done"
    )


def uci_add_to_wan_zone(iface: str) -> ShellCommand:
    """ShellCommand: add interface to wan firewall zone by name (idempotent)."""
    return ShellCommand(command=uci_add_to_wan_zone_sh(iface))
