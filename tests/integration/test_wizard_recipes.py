"""Wizard-recipe tests — catch recipe rot in docs/wizard-bundle.json before users do.

Issue #42. Two layers:

Layer 1 (no VM; also runs in CI):
  - bundle freshness: regenerating from code must reproduce the committed bundle
    (minus generated_at) — the published site can never drift from the CLI
  - every render substitutes cleanly (no leftover {{placeholders}}) and parses
    as POSIX shell (sh -n)
  - no hardcoded router IPs outside the single `IP=${IP:-...}` default line
  - pinned blossom artifacts download and their sha256 matches the filename
    (catches dead links and silently re-uploaded artifacts)

Layer 2 (session VM):
  - the device-side heredoc blocks of a representative render per flow are
    applied to the VM and the resulting state is asserted
  - package-install blocks are skipped on the VM (the 24.10 opkg VM cannot
    install 25.12 apk artifacts); their mechanics are covered by the Layer-1
    URL/hash checks
  - the lan_ip unfilled-placeholder guard is exercised on real BusyBox sh
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE = REPO_ROOT / "docs" / "wizard-bundle.json"

HEREDOC_OPEN = "ssh root@$IP sh <<'CONWRT_EOF'"
HEREDOC_CLOSE = "CONWRT_EOF"

PARAM_VALUES = {
    "upstream_ssid": "TestUplink",
    "upstream_key": "test-key-1234",
    "upstream_band": "5ghz",
    "lan_ip": "100.64.0.42",
    "root_password": "test-root-pw",
    "hostname": "test-hostname",
}

# The recipe felix must hardware-verify (#32) — maximal relevance.
VM_MODEL = "comfast-cf-wr632ax"


def _load_bundle() -> dict:
    return json.loads(BUNDLE.read_text())


def _all_renders(bundle: dict):
    for model, flows in bundle["rendered"].items():
        for flow, versions in flows.items():
            for version, rend in versions.items():
                yield model, flow, version, rend["shell"]


def _substitute(shell: str, skip: set[str] | None = None) -> str:
    out = shell
    for name, value in PARAM_VALUES.items():
        if name in (skip or set()):
            continue
        out = out.replace("{{" + name + "}}", value)
    return out


def _device_blocks(shell: str) -> list[str]:
    """Extract the router-side payloads the recipe ships inside ssh heredocs."""
    blocks = []
    parts = shell.split(HEREDOC_OPEN)
    for part in parts[1:]:
        blocks.append(part.split(HEREDOC_CLOSE)[0].strip("\n"))
    return blocks


def _is_install_block(block: str) -> bool:
    return "apk add" in block or "opkg install" in block


def _blossom_urls(shell: str) -> set[str]:
    return set(re.findall(r"curl -L -o '[^']+' '(https://[^']+)'", shell))


# ---------------------------------------------------------------------------
# Layer 1 — static bundle checks (no VM)
# ---------------------------------------------------------------------------


class TestBundleFreshness:
    def test_committed_bundle_matches_code(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from generate_site import build_bundle
        committed = _load_bundle()
        regenerated = build_bundle()
        committed.pop("generated_at", None)
        regenerated.pop("generated_at", None)
        assert committed == regenerated, (
            "docs/wizard-bundle.json is stale — run: python3 scripts/generate_site.py"
        )

    def test_bundle_has_models_flows_renders(self):
        bundle = _load_bundle()
        assert len(bundle["models"]) >= 20
        assert {f["name"] for f in bundle["flows"]} == {"net4sats", "tollgate"}
        assert len(bundle["rendered"]) == len(bundle["models"])
        assert bundle["versions"], "no versions rendered"


class TestRenderSubstitution:
    def test_all_placeholders_substitutable(self):
        for model, flow, version, shell in _all_renders(_load_bundle()):
            substituted = _substitute(shell)
            leftover = re.findall(r"\{\{\w+\}\}", substituted)
            assert not leftover, (
                f"{model}/{flow}@{version}: placeholders {leftover} not fillable "
                "with the known param set — recipe references an unknown param"
            )

    def test_renders_parse_as_posix_shell(self, tmp_path):
        for model, flow, version, shell in _all_renders(_load_bundle()):
            script = tmp_path / f"{model}-{flow}-{version}.sh"
            script.write_text(_substitute(shell))
            r = subprocess.run(["sh", "-n", str(script)], capture_output=True, text=True)
            assert r.returncode == 0, (
                f"{model}/{flow}@{version}: sh -n failed: {r.stderr}"
            )


class TestNoHardcodedRouterIps:
    def test_default_ip_appears_only_in_ip_assignment(self):
        for model, flow, version, shell in _all_renders(_load_bundle()):
            for i, line in enumerate(shell.splitlines(), 1):
                if "192.168.1.1" in line and not line.lstrip().startswith("#"):
                    assert line.startswith("IP=${IP:-"), (
                        f"{model}/{flow}@{version}:{i}: hardcoded router IP "
                        f"outside the IP= default: {line.strip()}"
                    )


class TestPinnedArtifacts:
    def test_artifact_installs_verify_hash_before_shipping(self):
        """Every curl-pinned artifact must be sha256-checked on the host
        before it is scp'd to the device (regression guard for #32's
        'no sha256 pinning' defect)."""
        for model, flow, version, shell in _all_renders(_load_bundle()):
            if "curl -L -o" not in shell:
                continue
            assert "sha256sum -c" in shell, (
                f"{model}/{flow}@{version}: artifact download without "
                "sha256 verification"
            )
            # the check must run BEFORE the scp, not after
            curl_pos = shell.index("curl -L -o")
            scp_pos = shell.index("scp -O ")
            check_pos = shell.index("sha256sum -c")
            assert curl_pos < check_pos < scp_pos

    def test_gateway_flows_install_nodogsplash(self):
        """The captive portal is the product — the flows must install
        nodogsplash, not assume it (regression guard for #32's
        'nodogsplash dep' defect)."""
        for model, flow, version, shell in _all_renders(_load_bundle()):
            if flow not in ("net4sats", "tollgate"):
                continue
            header = shell.splitlines()[2] if len(shell.splitlines()) > 2 else ""
            expected = "apk add nodogsplash" if "apk" in header else "opkg install nodogsplash"
            assert expected in shell, (
                f"{model}/{flow}@{version}: gateway flow does not install nodogsplash"
            )

    def test_blossom_artifacts_download_and_hash_match(self, tmp_path):
        urls: set[str] = set()
        bundle = _load_bundle()
        for _m, _f, _v, shell in _all_renders(bundle):
            urls |= _blossom_urls(shell)
        assert urls, "no pinned artifact URLs found in renders"

        failures = []
        for url in sorted(urls):
            filename = url.rsplit("/", 1)[-1]
            expected_sha = filename.split(".")[0]
            local = tmp_path / filename
            r = subprocess.run(
                ["curl", "-sfL", "--retry", "2", "-o", str(local), url],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode != 0:
                failures.append(f"{url}: download failed ({r.stderr.strip()[:120]})")
                continue
            actual = hashlib.sha256(local.read_bytes()).hexdigest()
            if actual != expected_sha:
                failures.append(
                    f"{url}: sha256 mismatch — pinned {expected_sha[:12]}… "
                    f"got {actual[:12]}… (artifact re-uploaded?)"
                )
        assert not failures, "pinned artifact rot:\n" + "\n".join(failures)


# ---------------------------------------------------------------------------
# Layer 2 — apply device-side recipe blocks on the session VM
# ---------------------------------------------------------------------------


def _vm_ssh(vm, command, timeout=30):
    r = subprocess.run(
        ["ssh",
         "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "ConnectTimeout=5",
         "-i", vm["key"],
         "-p", str(vm["port"]),
         f"root@{vm['host']}", command],
        capture_output=True, text=True, timeout=timeout,
    )
    return r


def _seed_package_configs(vm):
    """Simulate the package-installed state the skipped install blocks provide:
    config sections and init.d scripts the recipes expect to exist. uci refuses
    to operate on configs whose /etc/config file does not exist, so touch them."""
    _vm_ssh(vm, (
        "touch /etc/config/wireless; "
        "uci -q get wireless.radio1 >/dev/null || { "
        "uci set wireless.radio1=wifi-device; uci commit wireless; }; "
        "[ -s /etc/config/nodogsplash ] || { "
        "touch /etc/config/nodogsplash; "
        "uci add nodogsplash nodogsplash; "
        "uci commit nodogsplash; }; "
        "for svc in nodogsplash tollgate-wrt; do "
        "[ -x /etc/init.d/$svc ] || { "
        "printf '#!/bin/sh\\nexit 0\\n' > /etc/init.d/$svc; "
        "chmod +x /etc/init.d/$svc; }; done"
    ))


def _apply_recipe(vm, shell, lan_ip):
    """Run the recipe's device-side blocks in order, skipping installs."""
    results = []
    for block in _device_blocks(shell):
        if _is_install_block(block):
            continue
        block = _substitute(block, skip={"lan_ip"})
        block = block.replace("{{lan_ip}}", lan_ip)
        r = _vm_ssh(vm, f"sh -s <<'WIZEOF'\n{block}\nWIZEOF", timeout=60)
        results.append((block.splitlines()[0], r.returncode, r.stderr))
    return results


def _wait_vm_back(vm, seconds=60):
    for _ in range(seconds // 3):
        if _vm_ssh(vm, "true", timeout=10).returncode == 0:
            return True
        time.sleep(3)
    return False


def _vm_lan_ip(vm):
    """The VM's LAN runs proto=dhcp (no static ipaddr option) — read the
    live address instead of uci."""
    out = _vm_ssh(vm, "ip -4 addr show dev eth0 | grep -oE 'inet [0-9.]+' | head -1").stdout
    ip = out.replace("inet", "").strip()
    assert ip, "could not read the VM's current LAN IP"
    return ip


@pytest.fixture(scope="module")
def applied_net4sats(openwrt_vm):
    _seed_package_configs(openwrt_vm)
    bundle = _load_bundle()
    version = sorted(bundle["rendered"][VM_MODEL]["net4sats"])[-1]
    shell = bundle["rendered"][VM_MODEL]["net4sats"][version]["shell"]
    current_lan = _vm_lan_ip(openwrt_vm)
    results = _apply_recipe(openwrt_vm, shell, lan_ip=current_lan)
    assert _wait_vm_back(openwrt_vm), "VM did not come back after network restart"
    return {"results": results, "lan_ip": current_lan, "version": version}


class TestNet4satsOnVm:
    def test_all_blocks_ran_without_error(self, applied_net4sats):
        failures = [
            (head, rc, err) for head, rc, err in applied_net4sats["results"]
            # `wifi` is absent on the radio-less VM; recipes tolerate that (no set -e in the heredoc)
            if rc != 0 and "wifi" not in err.lower()
        ]
        assert not failures, f"recipe blocks failed: {failures}"

    def test_wifi_sta_config_written(self, openwrt_vm, applied_net4sats):
        # No radios on the VM → the recipe's network restart re-detection empties
        # /etc/config/wireless; on real hardware it survives. Re-seed, re-apply
        # the wifi block alone (no restart after) and assert what it wrote.
        _seed_package_configs(openwrt_vm)
        bundle = _load_bundle()
        shell = bundle["rendered"][VM_MODEL]["net4sats"][applied_net4sats["version"]]["shell"]
        wifi_blocks = [b for b in _device_blocks(shell) if "wifi-iface" in b]
        assert wifi_blocks, "no wifi STA block in recipe"
        r = _vm_ssh(openwrt_vm,
                    f"sh -s <<'WIZEOF'\n{_substitute(wifi_blocks[0])}\nWIZEOF", timeout=60)
        assert r.returncode != 0 or "wifi" in r.stderr.lower(), (
            f"expected only the wifi reload to fail: rc={r.returncode} {r.stderr}"
        )
        out = _vm_ssh(openwrt_vm, "uci show wireless").stdout
        assert "sta1.ssid='TestUplink'" in out
        assert "sta1.mode='sta'" in out
        assert "sta1.network='wwan'" in out
        assert "sta1.encryption='psk2'" in out

    def test_wwan_interface_created(self, openwrt_vm):
        out = _vm_ssh(openwrt_vm, "uci show network.wwan").stdout
        assert "proto='dhcp'" in out

    def test_hostname_branded(self, openwrt_vm):
        uci = _vm_ssh(openwrt_vm, "uci get system.@system[0].hostname").stdout.strip()
        live = _vm_ssh(openwrt_vm, "cat /proc/sys/kernel/hostname").stdout.strip()
        assert uci == "net4sats"
        assert live == "net4sats"

    def test_nodogsplash_branded(self, openwrt_vm):
        out = _vm_ssh(openwrt_vm, "uci show nodogsplash").stdout
        assert "gatewayname='net4sats'" in out
        assert "gatewaydomainname='net4sats.lan'" in out
        assert "clientid='mac'" in out
        assert "allow tcp port 2121" in out
        assert "allow tcp port 2050" in out

    def test_hotplug_restarts_tollgate_on_wwan_up(self, openwrt_vm):
        r = _vm_ssh(openwrt_vm,
                    "test -x /etc/hotplug.d/iface/95-tollgate-restart && echo exec-ok || echo missing")
        assert "exec-ok" in r.stdout
        content = _vm_ssh(openwrt_vm, "cat /etc/hotplug.d/iface/95-tollgate-restart").stdout
        assert '"$INTERFACE" = "wwan"' in content
        assert "tollgate-wrt restart" in content

    def test_lan_readback_holds(self, openwrt_vm, applied_net4sats):
        out = _vm_ssh(openwrt_vm, "uci -q get network.lan.ipaddr").stdout.strip()
        assert out == applied_net4sats["lan_ip"]


class TestTollgateOnVm:
    def test_tollgate_blocks_apply_and_brand(self, openwrt_vm):
        _seed_package_configs(openwrt_vm)
        bundle = _load_bundle()
        version = sorted(bundle["rendered"][VM_MODEL]["tollgate"])[-1]
        shell = bundle["rendered"][VM_MODEL]["tollgate"][version]["shell"]
        current_lan = _vm_lan_ip(openwrt_vm)
        results = _apply_recipe(openwrt_vm, shell, lan_ip=current_lan)
        assert _wait_vm_back(openwrt_vm)
        failures = [
            (h, rc, e) for h, rc, e in results
            if rc != 0 and "wifi" not in e.lower()
        ]
        assert not failures, f"tollgate recipe blocks failed: {failures}"
        out = _vm_ssh(openwrt_vm, "uci show nodogsplash").stdout
        assert "gatewayname='TollGate'" in out


class TestLanIpGuard:
    def test_unfilled_placeholder_refused_on_device(self, openwrt_vm):
        bundle = _load_bundle()
        version = sorted(bundle["rendered"][VM_MODEL]["net4sats"])[-1]
        shell = bundle["rendered"][VM_MODEL]["net4sats"][version]["shell"]
        lan_blocks = [b for b in _device_blocks(shell) if "LAN_IP=" in b]
        assert lan_blocks, "no LAN block found in recipe"
        block = lan_blocks[0]
        r = _vm_ssh(openwrt_vm, f"sh -s <<'WIZEOF'\n{block}\nWIZEOF", timeout=30)
        assert r.returncode != 0, "guard did not refuse an unfilled lan_ip"
        assert "lan_ip was not filled in" in (r.stdout + r.stderr)


class TestAddonsOnVm:
    def _addon_block(self, name, params=None):
        bundle = _load_bundle()
        addon = next(a for a in bundle["addons"] if a["name"] == name)
        shell = addon["shell"]
        for key, value in {**PARAM_VALUES, **(params or {})}.items():
            shell = shell.replace("{{" + key + "}}", value)
        blocks = _device_blocks(shell)
        assert blocks, f"addon {name} rendered no device-side block"
        return blocks[0]

    def _run_block(self, vm, block):
        return _vm_ssh(vm, f"sh -s <<'WIZEOF'\n{block}\nWIZEOF", timeout=30)

    def test_hostname_addon_sets_hostname(self, openwrt_vm):
        r = self._run_block(openwrt_vm, self._addon_block("hostname"))
        assert r.returncode == 0, r.stderr
        out = _vm_ssh(openwrt_vm, "uci get system.@system[0].hostname").stdout.strip()
        assert out == "test-hostname"

    def test_wan_ssh_addon_opens_firewall(self, openwrt_vm):
        r = self._run_block(openwrt_vm, self._addon_block("wan-ssh"))
        assert r.returncode == 0, r.stderr
        out = _vm_ssh(openwrt_vm, "uci show firewall.wan_ssh").stdout
        assert "dest_port='22'" in out
        assert "target='ACCEPT'" in out

    def test_set_password_addon_sets_root_hash(self, openwrt_vm):
        r = self._run_block(openwrt_vm, self._addon_block("set-password"))
        assert r.returncode == 0, (
            f"set-password addon failed on real BusyBox: {r.stderr} — "
            "recipe uses a tool the device does not have"
        )
        shadow = _vm_ssh(openwrt_vm, "grep '^root:' /etc/shadow | cut -d: -f2").stdout.strip()
        assert shadow.startswith("$"), f"root password hash not set: {shadow!r}"

    def test_random_password_addon_sets_root_hash(self, openwrt_vm):
        r = self._run_block(openwrt_vm, self._addon_block("random-password"))
        assert r.returncode == 0, (
            f"random-password addon failed on real BusyBox: {r.stderr} — "
            "recipe uses a tool the device does not have"
        )
        assert "root password:" in r.stdout
        shadow = _vm_ssh(openwrt_vm, "grep '^root:' /etc/shadow | cut -d: -f2").stdout.strip()
        assert shadow.startswith("$"), f"root password hash not set: {shadow!r}"
