"""Preflight-flash regression tests (#763 P3 — safety-critical diagnostic).

The script gates irreversible-write sessions; every FAIL class in it
maps to a real incident (session-4 recovery-window loss, device-2
brick). These tests pin each class: canned `sh()` outputs per command,
real tmp files for payload/rollback/heartbeat, and the run() contract
(rc 0 clean / rc 2 on any FAIL, RESULTS carrying the failing check).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "preflight-flash.py"


def load_module():
    spec = importlib.util.spec_from_file_location("preflight_flash", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def pf(monkeypatch):
    mod = load_module()
    mod.RESULTS.clear()
    canned: dict[str, str] = {}

    def fake_sh(cmd):
        for key, out in canned.items():
            if key in cmd:
                return out
        return ""

    monkeypatch.setattr(mod, "sh", fake_sh)
    return mod, canned


def _base_cfg(tmp_path: Path, payload: Path) -> dict:
    data = b"TRIGGER-IMAGE-BYTES" * 8
    payload.write_bytes(data)
    import hashlib
    return {
        "nic": "en9", "recovery_ip": "192.168.0.10",
        "device_ip": "192.168.0.1", "device_mac": "aa:bb:cc:dd:ee:01",
        "payload": {
            "path": str(payload), "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "expect_magic": {"offset": 0, "hex": "54524947", "what": "TRIG ascii"},
        },
        "rollback": {"path": str(payload),
                     "sha256": hashlib.sha256(data).hexdigest()},
        "serial": {"attached": True},
    }


def _green_sh(canned, cfg):
    """Canned outputs for a fully-PASS run."""
    nic, rip, dip = cfg["nic"], cfg["recovery_ip"], cfg["device_ip"]
    canned[f"ip link show {nic}"] = f"2: {nic}: <BROADCAST> state UP mode DEFAULT"
    canned["ip -4 addr show"] = (f"2: {nic}: <BROADCAST>\n"
                                 f"    inet {rip}/24 scope global {nic}\n")
    canned[f"ip route get {dip}"] = f"{dip} dev {nic} src {rip}"
    canned["ss -ulnp"] = ('udp UNCONN 0 0 0.0.0.0:69 '
                          'users:(("flashd",pid=4242,fd=4))')
    canned["/proc/"] = "python3 scripts/zte-blankdl-flashd.py --image x"
    canned["ufw status"] = "Status: inactive"
    canned["nft list ruleset"] = "3"  # udp dport 69 rules present
    canned[f"ethtool {nic}"] = "Speed: 1000Mb/s Link detected: yes"
    canned[f"ip neigh"] = (f"192.168.0.1 dev {nic} lladdr "
                           f"{_base_cfg_mac} REACHABLE")
    canned[f"ping -c1 -W2 -I {nic} {dip}"] = "alive"


_base_cfg_mac = "aa:bb:cc:dd:ee:01"


class TestCleanRun:
    def test_all_green_passes(self, pf, tmp_path, capsys):
        mod, canned = pf
        payload = tmp_path / "trigger.bin"
        cfg = _base_cfg(tmp_path, payload)
        _green_sh(canned, cfg)
        rc = mod.run(cfg, None)
        assert rc == 0
        out = capsys.readouterr().out
        assert "PASS — proceed" in out
        statuses = {r["check"]: r["status"] for r in mod.RESULTS}
        assert statuses["nic exists"] == "PASS"
        assert statuses["recovery IP unique + on campaign NIC"] == "PASS"
        assert statuses["payload sha256 pinned"] == "PASS"
        assert statuses["payload magic @0x0 (TRIG ascii)"] == "PASS"
        assert statuses["rollback artifact staged+hashed (pair the corrective)"] == "PASS"
        assert statuses["serial console attached"] == "PASS"


class TestFailureClasses:
    def test_nic_missing(self, pf, tmp_path):
        mod, canned = pf
        cfg = _base_cfg(tmp_path, tmp_path / "t.bin")
        # no canned ip link output -> nic "not present"
        rc = mod.run(cfg, None)
        assert rc == 2
        assert any(r["check"] == "nic exists" and r["status"] == "FAIL"
                   for r in mod.RESULTS)

    def test_duplicate_recovery_ip_two_interfaces(self, pf, tmp_path):
        mod, canned = pf
        cfg = _base_cfg(tmp_path, tmp_path / "t.bin")
        nic, rip = cfg["nic"], cfg["recovery_ip"]
        canned[f"ip link show {nic}"] = f"state UP"
        canned["ip -4 addr show"] = (
            f"2: {nic}: <BROADCAST>\n    inet {rip}/24 scope global {nic}\n"
            f"3: en10: <BROADCAST>\n    inet {rip}/24 scope global en10\n")
        rc = mod.run(cfg, None)
        assert rc == 2
        fail = next(r for r in mod.RESULTS
                    if r["check"] == "recovery IP unique + on campaign NIC")
        assert fail["status"] == "FAIL"
        assert "duplicate" in fail["detail"] or "en10" in fail["detail"]

    def test_foreign_fence_listener(self, pf, tmp_path):
        mod, canned = pf
        cfg = _base_cfg(tmp_path, tmp_path / "t.bin")
        _green_sh(canned, cfg)
        # ss shows a listener whose pid-cmdline is neither flashd nor tftp
        canned["ss -ulnp"] = ("udp UNCONN 0 0 0.0.0.0:69 0.0.0.0:* "
                              "users:((\"dnsmasq\",pid=4242,fd=4))")
        # and the pid's cmdline proves a foreign owner (not flashd/tftp)
        canned["/proc/"] = "/usr/sbin/dnsmasq --no-resolv"
        rc = mod.run(cfg, None)
        assert rc == 2
        fail = next(r for r in mod.RESULTS if "fence :69" in r["check"])
        assert fail["status"] == "FAIL"
        assert "foreign" in fail["detail"]

    def test_ufw_active_without_udp69_rule(self, pf, tmp_path):
        mod, canned = pf
        cfg = _base_cfg(tmp_path, tmp_path / "t.bin")
        _green_sh(canned, cfg)
        canned["ufw status"] = "Status: active"
        # the 69/udp rule grep must return nothing; the stub is
        # substring-keyed, so insert the SPECIFIC key first (it wins over
        # the generic 'ufw status' key for the rule-grep command only)
        reordered = {"grep -i '69/udp'": ""}
        reordered.update(canned)
        canned.clear()
        canned.update(reordered)
        rc = mod.run(cfg, None)
        assert rc == 2
        fail = next(r for r in mod.RESULTS
                    if "firewall allows udp/69" in r["check"])
        assert fail["status"] == "FAIL"
        assert "DROPPED" in fail["detail"]

    def test_payload_sha_mismatch(self, pf, tmp_path):
        mod, canned = pf
        cfg = _base_cfg(tmp_path, tmp_path / "t.bin")
        _green_sh(canned, cfg)
        cfg["payload"]["sha256"] = "0" * 64
        rc = mod.run(cfg, None)
        assert rc == 2
        assert any(r["check"] == "payload sha256 pinned" and r["status"] == "FAIL"
                   for r in mod.RESULTS)

    def test_zeros_are_not_triggers_magic_mismatch(self, pf, tmp_path):
        mod, canned = pf
        cfg = _base_cfg(tmp_path, tmp_path / "t.bin")
        _green_sh(canned, cfg)
        # all-zero payload with a magic expectation: the device-2 brick class
        payload = tmp_path / "zeros.bin"
        payload.write_bytes(b"\x00" * 64)
        cfg["payload"]["path"] = str(payload)
        cfg["payload"]["size"] = 64
        import hashlib
        cfg["payload"]["sha256"] = hashlib.sha256(b"\x00" * 64).hexdigest()
        rc = mod.run(cfg, None)
        assert rc == 2
        fail = next(r for r in mod.RESULTS if "magic" in r["check"])
        assert fail["status"] == "FAIL"
        assert "ZEROS/ERASED ARE NOT TRIGGERS" in fail["detail"]

    def test_missing_rollback_warns_rule5(self, pf, tmp_path):
        mod, canned = pf
        cfg = _base_cfg(tmp_path, tmp_path / "t.bin")
        _green_sh(canned, cfg)
        cfg.pop("rollback")
        rc = mod.run(cfg, None)
        assert rc == 0  # WARN, not FAIL
        warn = next(r for r in mod.RESULTS if "rollback artifact" in r["check"])
        assert warn["status"] == "WARN"
        assert "rule 5" in warn["detail"]

    def test_watcher_dead_fails(self, pf, tmp_path):
        mod, canned = pf
        cfg = _base_cfg(tmp_path, tmp_path / "t.bin")
        _green_sh(canned, cfg)
        wl = tmp_path / "watch.log"
        wl.write_text("tick\n")
        cfg["watch_log"] = str(wl)
        cfg["watch_proc"] = "my_watcher.py"
        # no pgrep output -> process dead
        rc = mod.run(cfg, None)
        assert rc == 2
        assert any(r["check"] == "watcher process alive" and r["status"] == "FAIL"
                   for r in mod.RESULTS)

    def test_serial_missing_fails_rule4(self, pf, tmp_path):
        mod, canned = pf
        cfg = _base_cfg(tmp_path, tmp_path / "t.bin")
        _green_sh(canned, cfg)
        cfg["serial"] = {}
        rc = mod.run(cfg, None)
        assert rc == 2
        fail = next(r for r in mod.RESULTS if "serial console" in r["check"])
        assert fail["status"] == "FAIL"
        assert "rule 4" in fail["detail"]

    def test_serial_waiver_warns(self, pf, tmp_path):
        mod, canned = pf
        cfg = _base_cfg(tmp_path, tmp_path / "t.bin")
        _green_sh(canned, cfg)
        cfg["serial"] = {"waiver_reason": "unit has no console port"}
        rc = mod.run(cfg, None)
        assert rc == 0
        assert any("WAIVED" in r["detail"] for r in mod.RESULTS)


class TestJsonMode:
    def test_json_cli_emits_checks_and_rc(self, pf, tmp_path):
        """The --json contract: quiet run, JSON with rc + every check."""
        import subprocess
        mod, canned = pf
        cfg = _base_cfg(tmp_path, tmp_path / "t.bin")
        _green_sh(canned, cfg)
        # serialize the green config but sabotage the payload hash so the
        # run FAILS deterministically without host state
        cfg["payload"]["sha256"] = "1" * 64
        cfg_path = tmp_path / "preflight.json"
        cfg_path.write_text(json.dumps(cfg))
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--config", str(cfg_path), "--json"],
            capture_output=True, text=True, timeout=60, cwd=str(REPO))
        assert proc.returncode == 2
        payload = json.loads(proc.stdout)
        assert payload["rc"] == 2
        checks = {c["check"]: c["status"] for c in payload["checks"]}
        assert checks["payload sha256 pinned"] == "FAIL"
        assert checks["serial console attached"] == "PASS"


class TestRustNostdParityGuard:
    """Pin the no_std parity guard's own self-test in the fast tier (#763:
    a guard that can drift out of the tested set guards nothing)."""

    def test_self_test_passes(self):
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "rust_nostd_parity.py"),
             "--self-test"],
            capture_output=True, text=True, timeout=120, cwd=str(REPO))
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "self-test PASS" in proc.stdout
