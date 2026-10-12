"""Functional tests for UCI shell helpers using a stubbed ``uci`` binary.

These run the generated shell against a fake ``uci`` that models a two-zone
firewall (lan, wan), so we can assert the helper manipulates the right zone.
Hardware-safe: no router, no root, everything in a temp dir.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from profile.uci_helpers import uci_add_to_wan_zone_sh

# Minimal uci emulation: two zones (zone[0]=lan, zone[1]=wan); get/del_list/
# add_list are logged to $UCI_LOG.
_UCI_STUB = r"""#!/usr/bin/env bash
args=("$@")
if [ "${args[0]:-}" = "-q" ]; then
  args=("${args[@]:1}")
fi
cmd="${args[0]:-}"
case "$cmd" in
  show)
    printf '%s\n' \
      "firewall.@zone[0]=zone" \
      "firewall.@zone[0].name='lan'" \
      "firewall.@zone[0].network='lan'" \
      "firewall.@zone[1]=zone" \
      "firewall.@zone[1].name='wan'" \
      "firewall.@zone[1].network='wan' 'wan6'"
    ;;
  get)
    case "${args[1]:-}" in
      *'@zone[0].name') echo lan ;;
      *'@zone[1].name') echo wan ;;
    esac
    ;;
  del_list|add_list)
    echo "$cmd ${args[1]:-}" >> "$UCI_LOG"
    ;;
esac
"""


def _run(snippet: str, tmp_path: Path) -> list[str]:
    stub = tmp_path / "uci"
    stub.write_text(_UCI_STUB)
    stub.chmod(0o755)
    log = tmp_path / "uci.log"
    log.write_text("")
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "UCI_LOG": str(log)}
    result = subprocess.run(["bash", "-c", snippet], env=env,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return [ln for ln in log.read_text().splitlines() if ln]


class TestUciAddToWanZone:
    def test_adds_only_to_the_wan_zone(self, tmp_path: Path) -> None:
        calls = _run(uci_add_to_wan_zone_sh("wwan"), tmp_path)
        adds = [c for c in calls if c.startswith("add_list")]
        # The bug: without a proper guard, add_list ran on the first zone (lan).
        assert adds == ["add_list firewall.@zone[1].network=wwan"]

    def test_removes_iface_from_non_wan_zones(self, tmp_path: Path) -> None:
        calls = _run(uci_add_to_wan_zone_sh("wwan"), tmp_path)
        dels = [c for c in calls if c.startswith("del_list")]
        assert "del_list firewall.@zone[0].network=wwan" in dels  # lan cleaned up
        assert "del_list firewall.@zone[1].network=wwan" in dels  # wan del before add

    def test_idempotent_single_add_list(self, tmp_path: Path) -> None:
        calls = _run(uci_add_to_wan_zone_sh("wwan"), tmp_path)
        assert sum(1 for c in calls if c.startswith("add_list")) == 1
