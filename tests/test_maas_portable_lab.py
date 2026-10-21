"""Tests for the maas-portable-lab use case (PR #322 Codex findings).

Covers: registry registration, operator-private defaults removal,
credential quoting, DHCP disable, LAN-IP readback gate, SSH-key
preservation, bash beacons, and the gated completion beacon.
"""
from __future__ import annotations

import shlex
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import use_cases as uc  # noqa: E402
from use_cases import maas_portable_lab as mpl  # noqa: E402


def _params(**overrides) -> dict:
    base = {
        "uplink_ssid": "house-5g",
        "uplink_password": "wpa-pass 'quote",
        "bench_subnet": "192.168.77.0/24",
        "bench_gateway": "192.168.77.1",
        "maas_ip": "192.168.77.5",
        "dhcp_range_start": "192.168.77.100",
        "dhcp_range_end": "192.168.77.200",
        "beacon_listener_ip": "192.168.77.127",
        "beacon_listener_mac": "aa:bb:cc:dd:ee:ff",
        "maas_admin_password": "s3cr3t-$tart`tick\"now",
    }
    base.update(overrides)
    return base


# -- registration -------------------------------------------------------------


def test_registered_in_discovery_registry():
    reg = uc.registry()
    assert "maas-portable-lab" in reg
    u = reg["maas-portable-lab"]
    assert u.configure_via == "ssh"
    assert u.build_configure(_params())  # renders a script


def test_apply_defaults_requires_operator_params():
    with pytest.raises(ValueError, match="bench_subnet"):
        uc.apply_defaults("maas-portable-lab", {"uplink_ssid": "a", "uplink_password": "b"})
    merged = uc.apply_defaults("maas-portable-lab", _params())
    assert merged["bench_subnet"] == "192.168.77.0/24"
    assert merged["zram_percent"] == mpl.DEFAULTS["zram_percent"]


# -- no committed operator network plan (AGENTS.md private-data rules) --------


def test_no_committed_bench_defaults():
    for value in mpl.DEFAULTS.values():
        assert "10.50" not in str(value)
        assert "00:e0:4c" not in str(value)
    for req in ("bench_subnet", "bench_gateway", "maas_ip", "dhcp_range_start",
                "dhcp_range_end", "beacon_listener_ip", "beacon_listener_mac"):
        assert req in mpl.REQUIRED


# -- validate() gates ---------------------------------------------------------


def test_validate_rejects_default_admin_password():
    errors = mpl.validate(_params(maas_admin_password="changeme"))
    assert any("changeme" in e for e in errors)


def test_validate_rejects_changeme_break_glass():
    errors = mpl.validate(_params(break_glass_password="changeme"))
    assert any("break_glass_password" in e for e in errors)


def test_validate_requires_an_access_path():
    errors = mpl.validate(_params())
    assert any("access path" in e for e in errors)
    assert not any("access path" in e for e in mpl.validate(_params(ssh_key="ssh-ed25519 AAA x")))


def test_get_pi_user_data_rejects_missing_admin_password():
    with pytest.raises(ValueError, match="maas_admin_password"):
        mpl.get_pi_user_data(
            {k: v for k, v in _params().items() if k != "maas_admin_password"}
        )


# -- first-boot script (x1860) -------------------------------------------------


def test_ssh_key_absent_leaves_authorized_keys_untouched():
    script = mpl.get_first_boot_script(_params())
    assert "> /etc/dropbear/authorized_keys" not in script
    assert "left untouched" in script


def test_ssh_key_present_installs_key():
    script = mpl.get_first_boot_script(_params(ssh_key="ssh-ed25519 AAAA key"))
    assert "> /etc/dropbear/authorized_keys" in script
    assert shlex.quote("ssh-ed25519 AAAA key") in script


def test_wifi_credentials_shell_quoted():
    ssid = "my'net"
    password = "p'q\"r$s"
    script = mpl.get_first_boot_script(_params(uplink_ssid=ssid, uplink_password=password))
    assert shlex.quote(ssid) in script
    assert shlex.quote(password) in script
    assert f"'{ssid}'" not in script  # naive single-quote interpolation gone


def test_lan_ip_readback_verified_before_commit():
    script = mpl.get_first_boot_script(_params())
    set_idx = script.index("uci set network.lan.ipaddr=")
    readback_idx = script.index("$(uci get network.lan.ipaddr)")
    commit_idx = script.index("\nuci commit")
    assert set_idx < readback_idx < commit_idx
    assert '!= ' in script
    assert "exit 1" in script


def test_router_dhcp_disabled_for_maas_segment():
    script = mpl.get_first_boot_script(_params())
    assert "uci set dhcp.lan.ignore='1'" in script


# -- Pi user-data --------------------------------------------------------------


def test_admin_password_shell_quoted_in_createadmin():
    pw = 'a$b`c"d\\e'
    user_data = mpl.get_pi_user_data(_params(maas_admin_password=pw))
    assert f"--password {shlex.quote(pw)}" in user_data
    assert f'--password "{pw}"' not in user_data


def test_beacons_use_bash_not_dash():
    user_data = mpl.get_pi_user_data(_params())
    assert "#!/bin/bash" in user_data
    assert "bash -c '" in user_data  # bootcmd
    assert "#!/bin/sh\n      echo \"[maas-boot]" not in user_data


def test_completion_beacon_only_after_all_phases_succeed():
    user_data = mpl.get_pi_user_data(_params())
    assert "beacon FIRST-BOOT-COMPLETE" in user_data
    assert "beacon FIRST-BOOT-FAILED" in user_data
    gate_idx = user_data.index('if [ "$INIT_OK" = 1 ]')
    complete_idx = user_data.index("beacon FIRST-BOOT-COMPLETE")
    assert gate_idx < complete_idx
    # retry loops record success instead of silently exhausting
    assert "{ INIT_OK=1; break; }" in user_data
    assert "{ ADMIN_OK=1; break; }" in user_data
    assert "{ LOGIN_OK=1; break; }" in user_data


def test_no_beacon_listener_defaults_leak():
    user_data = mpl.get_pi_user_data(_params())
    assert "10.50.0.127" not in user_data
    assert "00:e0:4c" not in user_data


def test_flash_config_declares_digest_and_whitelist_requirements():
    cfg = mpl.get_flash_config({})
    assert cfg["serial_whitelist_required"] is True
    assert cfg["sha256_required"] is True
