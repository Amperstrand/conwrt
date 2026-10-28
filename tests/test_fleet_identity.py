"""fleet-identity + fleet_secrets tests.

Locks three things:
1. The Python derivation (determinism, domain separation, salt/MAC handling).
2. Shell parity — the BusyBox pipeline shipped by the fleet_identity use
   case must produce byte-identical passwords (host `sh` stands in for ash;
   same sha256sum/cut semantics as the mac_hash parity tests).
3. The use-case script shape — salt embedded, single-line-safe for the
   &&-joined SSH transport, passwd-not-chpasswd, marker carries no secret.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import fleet_secrets  # noqa: E402
from fleet_secrets import (  # noqa: E402
    clean_mac,
    derive_all,
    hostname,
    root_password,
    wifi_password,
    wifi_ssid,
)
from use_cases import apply_defaults, registry  # noqa: E402

SALT = "unit-test-salt-0123456789abcdef"
MAC = "78:C5:7D:13:91:9C"


class TestDerivation:
    def test_deterministic(self):
        assert root_password(MAC, SALT) == root_password(clean_mac(MAC), SALT)

    def test_length(self):
        assert len(root_password(MAC, SALT)) == 20
        assert len(root_password(MAC, SALT, length=8)) == 8

    def test_domain_separation(self):
        assert root_password(MAC, SALT) != wifi_password(MAC, SALT)
        assert wifi_password(MAC, SALT, "fleet") != wifi_password(MAC, SALT, "guest")

    def test_salt_changes_everything(self):
        assert root_password(MAC, SALT) != root_password(MAC, "another-salt-87654321")

    def test_mac_format_insensitive(self):
        a = root_password(MAC, SALT)
        assert a == root_password("78-c5-7d-13-91-9c", SALT)
        assert a == root_password("78c57d13919c", SALT)

    def test_salt_charset_enforced(self):
        for bad in ("short", "has space", "has'quote", 'has"dquote', ""):
            try:
                root_password(MAC, bad)
            except ValueError:
                continue
            raise AssertionError(f"salt {bad!r} accepted")

    def test_length_bounds(self):
        for bad in (7, 33):
            try:
                root_password(MAC, SALT, length=bad)
            except ValueError:
                continue
            raise AssertionError(f"length {bad} accepted")

    def test_names(self):
        assert hostname(MAC, "nr7101") == "nr7101-78c57d13919c"
        assert wifi_ssid(MAC) == "nr7101_78c57d13919c"

    def test_derive_all_shape(self):
        info = derive_all(MAC, SALT)
        assert set(info) == {"mac", "hostname", "wifi_ssid", "root_password", "wifi_password", "lan_ip"}
        assert info["lan_ip"].startswith("10.") and info["lan_ip"].endswith(".1")


class TestShellParity:
    """The exact pipeline the use-case script ships."""

    def _shell_pw(self, mac: str, salt: str, length: int = 20) -> str:
        m = clean_mac(mac)
        cmd = f"printf '%s' '{fleet_secrets.DOMAIN_VERSION}:root:{salt}:{m}' | sha256sum | cut -c1-{length}"
        r = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=10)
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()

    def test_root_password_parity(self):
        assert root_password(MAC, SALT) == self._shell_pw(MAC, SALT)

    def test_parity_helper(self):
        assert fleet_secrets.shell_parity_check(MAC, SALT)

    def test_parity_custom_length(self):
        assert root_password(MAC, SALT, 16) == self._shell_pw(MAC, SALT, 16)

    def test_wifi_domain_parity(self):
        m = clean_mac(MAC)
        cmd = f"printf '%s' '{fleet_secrets.DOMAIN_VERSION}:wifi:fleet:{SALT}:{m}' | sha256sum | cut -c1-20"
        r = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=10)
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == wifi_password(MAC, SALT)


class TestUseCase:
    def test_registered(self):
        assert "fleet_identity" in registry()

    def test_defaults(self):
        p = apply_defaults("fleet_identity", {"salt": SALT})
        assert p["hostname_prefix"] == "fleet"
        assert p["password_length"] == 20
        assert p["disarm_dhcp"] == "1"

    def test_salt_required(self):
        try:
            apply_defaults("fleet_identity", {})
        except ValueError:
            return
        raise AssertionError("missing salt accepted")

    def test_bad_salt_rejected_at_build(self):
        uc = registry()["fleet_identity"]
        try:
            uc.build_configure({"salt": "has'quote"})
        except ValueError:
            return
        raise AssertionError("quoting-unsafe salt accepted at build time")

    def test_script_shape(self):
        uc = registry()["fleet_identity"]
        script = uc.build_configure({"salt": SALT, "hostname_prefix": "nr7101"})
        assert f"conwrt-fleet-v1:root:{SALT}:$_m" in script
        assert "passwd root" in script
        assert "chpasswd" not in script
        assert 'uci set system.@system[0].hostname="nr7101-$_m"' in script
        # Rogue-dhcp disarm present by default
        assert "dhcp.lan.ignore" in script or "uci set dhcp.lan.ignore='1'" in script
        # Every ShellCommand line stays single-line: the SSH transport
        # &&-joins lines; a newline inside the derivation chain would break
        # variable scope across execs.
        for line in script.splitlines():
            if "_pw=$(printf" in line:
                assert "\n" not in line
                assert line.startswith("_mac=$(cat")
        # The marker write (final &&-segment of the chain) carries no secret
        marker = [ln for ln in script.splitlines() if "> /etc/fleet/identity" in ln]
        assert marker, "no /etc/fleet/identity marker write found"
        marker_write = marker[0].split("> /etc/fleet/identity")[0].rsplit("&&", 1)[-1]
        assert "passwd" not in marker_write and "$_pw" not in marker_write

    def test_ap_block_shape(self):
        uc = registry()["fleet_identity"]
        script = uc.build_configure({"salt": SALT, "hostname_prefix": "nr7101"})
        assert 'uci set wireless.default_radio0.ssid="nr7101_$_m"' in script
        assert 'uci set wireless.default_radio0.key="$_wpw"' in script
        assert 'uci set wireless.default_radio0.encryption="psk2"' in script
        assert 'uci set wireless.default_radio0.network="lan"' in script
        assert "uci -q get wireless.radio0" in script
        ap_line = next(ln for ln in script.splitlines() if "wireless.radio0" in ln and ln.startswith("if "))
        assert "wifi reload 2>/dev/null || true; fi" in ap_line
        r = subprocess.run(["sh", "-n"], input=script, capture_output=True, text=True, timeout=10)
        assert r.returncode == 0, r.stderr

    def test_ap_block_disabled(self):
        uc = registry()["fleet_identity"]
        script = uc.build_configure({"salt": SALT, "configure_ap": "0"})
        assert "wireless.radio0" not in script
        assert "wifi:" not in script

    def test_derivation_line_parses_and_derives_in_sh(self):
        """The shipped one-liner is valid sh and its derivation segment
        (everything before the passwd feed) produces the Python-side
        password on a host `sh`. No device commands run on the host:
        only the leading derivation segment executes, with the /sys MAC
        read replaced by a literal."""
        uc = registry()["fleet_identity"]
        script = uc.build_configure({"salt": SALT, "hostname_prefix": "nr7101", "disarm_dhcp": "0"})
        chain = next(ln for ln in script.splitlines() if ln.startswith("_mac=$(cat"))
        r = subprocess.run(["sh", "-n", "-c", chain], capture_output=True, text=True, timeout=10)
        assert r.returncode == 0, r.stderr
        seg = chain.split("printf '%s\\n%s\\n'")[0]
        seg = seg[: seg.rfind("&&")].rstrip()
        seg = seg.replace("_mac=$(cat /sys/class/net/eth0/address)", f"_mac={clean_mac(MAC)}")
        r = subprocess.run(
            ["sh", "-c", seg + ' && printf "%s|%s" "$_pw" "$_wpw"'],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert r.returncode == 0, r.stderr
        assert r.stdout == f"{root_password(MAC, SALT)}|{wifi_password(MAC, SALT)}"
